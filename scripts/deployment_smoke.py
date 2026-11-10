"""Readiness checks against explicitly supplied frontend/backend origins.

Creates only existing fixture investigations/copies; never signs or deploys a contract.
Run separately after publishing. Local execution is not a production deployment test.
"""
import argparse
from urllib.parse import urlsplit
import httpx


def origin(value):
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
        raise argparse.ArgumentTypeError("Provide an HTTP(S) origin without path, query or credentials")
    return value.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontend-url", type=origin, required=True)
    parser.add_argument("--backend-url", type=origin, required=True)
    args = parser.parse_args()
    expected = {"suspicious-1": "CONFIRMED_MALICIOUS", "suspicious-2": "CONFIRMED_MALICIOUS", "suspicious-3": "SUSPICIOUS", "benign-1": "LOW_RISK", "benign-2": "LOW_RISK", "benign-3": "INCONCLUSIVE"}
    with httpx.Client(timeout=60, trust_env=False, follow_redirects=False) as client:
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
            assert post_json(base + "/verify", {})["status"] == "SUPPORTED"
            mutation = post_json(base + "/tamper-demo", {"mutation": "tls_cert"})
            assert mutation["verification"]["status"] == "TAMPERED" and not mutation["verification"]["root_match"]
            assert post_json(base + "/verify", {})["status"] == "SUPPORTED"
            print(f"PASS {fixture['fixture_id']}: verdict, report route/data, reference verification, tamper, reset")
        print(f"PASS homepage, backend health, same-origin proxy, six fixtures; verification mode={health['verification_mode']}")
        print("Browser rendering, deployment secrets and public-chain registration require their separate documented checks.")


if __name__ == "__main__":
    main()
