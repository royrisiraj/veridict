"""Readiness checks against explicitly supplied frontend/backend origins.

Creates only existing fixture investigations/copies; never signs or deploys a contract.
Run separately after publishing. Local execution is not a production deployment test.
"""
import argparse
import os
from urllib.parse import urlsplit
import httpx


def protection_headers(request, frontend_url, backend_url):
    """Operator-only bypasses, restricted to the two explicit deployment origins."""
    def key(url):
        return (url.scheme, url.host, url.port)
    name = ("FRONTEND_PROTECTION_BYPASS" if key(request.url) == key(httpx.URL(frontend_url))
        else "BACKEND_PROTECTION_BYPASS" if key(request.url) == key(httpx.URL(backend_url)) else None)
    if name and os.getenv(name):
        request.headers["x-vercel-protection-bypass"] = os.environ[name]


def origin(value):
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
        raise argparse.ArgumentTypeError("Provide an HTTP(S) origin without path, query or credentials")
    return value.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-url", type=origin, required=True)
    parser.add_argument("--backend-url", type=origin, required=True)
    parser.add_argument("--live-url", help="Explicitly run one real scan through the protected frontend proxy (never registers a transaction)")
    parser.add_argument("--require-public-chain", action="store_true", help="Require all six fixture roots to be actually verified by the backend's public RPC")
    args = parser.parse_args()
    def add_protection_header(request):
        protection_headers(request, args.frontend_url, args.backend_url)
    expected = {"suspicious-1": "CONFIRMED_MALICIOUS", "suspicious-2": "CONFIRMED_MALICIOUS", "suspicious-3": "SUSPICIOUS", "benign-1": "LOW_RISK", "benign-2": "LOW_RISK", "benign-3": "INCONCLUSIVE"}
    with httpx.Client(timeout=60, trust_env=False, follow_redirects=False, event_hooks={"request": [add_protection_header]}) as client:
        def get_json(url):
            response = client.get(url)
            response.raise_for_status()
            return response.json()
        def post_json(url, body):
            response = client.post(url, json=body)
            response.raise_for_status()
            return response.json()
        home = client.get(args.frontend_url)
        home.raise_for_status()
        assert "VERIDICT" in home.text
        health = get_json(args.backend_url + "/health")
        assert health["status"] == "ok" and health["service"] == "veridict-api"
        proxied = get_json(args.frontend_url + "/api/health")
        assert proxied["verification_mode"] == health["verification_mode"]
        assert health["verification_mode"] != "UNAVAILABLE"
        fixtures = get_json(args.frontend_url + "/api/fixtures")
        assert {f["fixture_id"] for f in fixtures} == set(expected)
        for fixture in fixtures:
            report = post_json(args.frontend_url + "/api/investigate", fixture["input"])
            bundle = report["bundle"]
            assert bundle["risk"] == expected[fixture["fixture_id"]]
            assert bundle["evidence"] and bundle["ai_claims"]
            assert bundle["provenance"]["analyzer"] == "fixture"
            for evidence in bundle["evidence"]:
                if evidence["type"] == "threat_intel" and evidence["status"] != "COMPLETE":
                    assert evidence["data"]["matched"] is None
            if health["verification_mode"] == "DEMO_FIXTURE":
                assert not health["chain_connected"]
                assert report["chain_receipt"]["mode"] == "fixture" and report["chain_receipt"]["tx_hash"] is None
            report_id = bundle["report_id"]
            page = client.get(args.frontend_url + f"/report/{report_id}")
            page.raise_for_status()  # HTML shell; real evidence rendering is a browser check.
            base = args.frontend_url + f"/api/reports/{report_id}"
            assert get_json(base)["bundle"] == bundle
            checked = post_json(base + "/verify", {})
            assert checked["status"] == "SUPPORTED"
            if args.require_public_chain:
                assert checked.get("public_chain_status") == "VERIFIED"
            mutation = post_json(base + "/tamper-demo", {"mutation": "tls_cert"})
            assert mutation["verification"]["status"] == "TAMPERED" and not mutation["verification"]["root_match"]
            assert post_json(base + "/verify", {})["status"] == "SUPPORTED"
            print(f"PASS {fixture['fixture_id']}: verdict, report route/data, reference verification, tamper, reset")
        if args.live_url:
            parsed = urlsplit(args.live_url)
            assert parsed.scheme == "https" and not parsed.username and not parsed.query and not parsed.fragment
            assert health["live_scanning_enabled"] and health["report_storage"] == "vercel_blob"
            live = post_json(args.frontend_url + "/api/investigate", {"url": args.live_url})
            assert live["bundle"]["provenance"]["collection"] == "live"
            assert live["chain_receipt"]["mode"] == "unanchored" and live["chain_receipt"]["tx_hash"] is None
            assert all(e["mode"] == "live" for e in live["bundle"]["evidence"])
            assert live["verification"]["status"] == "SUPPORTED"
            live_id = live["bundle"]["report_id"]
            base = args.frontend_url + f"/api/reports/{live_id}"
            with httpx.Client(timeout=60, trust_env=False, follow_redirects=False, event_hooks={"request": [add_protection_header]}) as fresh:
                reloaded = fresh.get(base)
                reloaded.raise_for_status()
                assert reloaded.json()["bundle"] == live["bundle"]
            for mutation, expected_status in [("tls_cert", "TAMPERED"), ("drop_threat_intel", "NOT_SUPPORTED"), ("alter_redirect", "TAMPERED"), ("unground_ai_claim", "NOT_SUPPORTED")]:
                mutated = post_json(base + "/tamper-demo", {"mutation": mutation})
                assert mutated["verification"]["status"] == expected_status
                assert get_json(base)["bundle"] == live["bundle"]
            assert post_json(base + "/verify", {})["status"] == "SUPPORTED"
            print(f"PASS live scan: provider observations, durable readback, four mutations/reset; report={live_id}")
        print(f"PASS homepage, backend health, same-origin proxy, six fixtures; verification mode={health['verification_mode']}")
        print("Browser rendering, deployment secrets and public-chain registration require their separate documented checks.")


if __name__ == "__main__":
    main()
