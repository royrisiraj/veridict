import copy
import pytest
from app.models import EvidenceBundle


@pytest.mark.parametrize("mutation,status,grounded", [("tls_cert", "TAMPERED", True), ("drop_threat_intel", "NOT_SUPPORTED", False), ("alter_redirect", "TAMPERED", True), ("unground_ai_claim", "NOT_SUPPORTED", False)])
def test_repeatable_mutations_preserve_genuine_report(client, report, mutation, status, grounded):
    report_id = report["bundle"]["report_id"]
    for _ in range(2):
        response = client.post(f"/api/reports/{report_id}/tamper-demo", json={"mutation": mutation})
        assert response.status_code == 200, response.text
        result = response.json()
        verification = result["verification"]
        assert verification["status"] == status
        assert verification["claim_grounding"] is grounded
        assert not verification["root_match"]
        assert result["expected_root"] == report["merkle"]["root"] != result["computed_root"]
        assert not verification["leaf_validity"][result["tampered_leaf_id"]]
        if mutation == "tls_cert":
            assert verification["leaf_validity"]["ti:1"]
        assert client.get(f"/api/reports/{report_id}").json() == report
        assert client.post(f"/api/reports/{report_id}/verify", json={}).json()["status"] == "SUPPORTED"


@pytest.mark.parametrize("field,value", [("created_at", "2030-01-01T00:00:00Z"), ("normalized_url", "https://changed.example/"), ("risk", "LOW_RISK"), ("limitations", ["altered"]), ("report_id", "0x" + "a" * 64)])
def test_all_metadata_is_committed(client, report, field, value):
    candidate = copy.deepcopy(report["bundle"])
    candidate[field] = value
    result = client.post(f"/api/reports/{report['bundle']['report_id']}/verify", json={"candidate_bundle": candidate}).json()
    assert result["status"] == "TAMPERED"
    assert not result["leaf_validity"]["meta:1"]


def test_order_is_canonicalized_but_ids_must_be_unique(client, report):
    candidate = copy.deepcopy(report["bundle"])
    candidate["evidence"].reverse()
    candidate["ai_claims"].reverse()
    url = f"/api/reports/{report['bundle']['report_id']}/verify"
    assert client.post(url, json={"candidate_bundle": candidate}).json()["status"] == "SUPPORTED"
    candidate["evidence"].append(candidate["evidence"][0])
    assert client.post(url, json={"candidate_bundle": candidate}).status_code == 422


def test_equivalent_report_hash_casing_is_normalized(client, report):
    candidate = copy.deepcopy(report["bundle"])
    candidate["report_id"] = candidate["report_id"].upper()
    response = client.post(f"/api/reports/{report['bundle']['report_id']}/verify", json={"candidate_bundle": candidate})
    assert response.status_code == 200 and response.json()["status"] == "SUPPORTED"


def test_unknown_target_and_wrong_mutation_type(client, report):
    url = f"/api/reports/{report['bundle']['report_id']}"
    assert client.post(url + "/verify", json={"evidence_id": "missing:1"}).json()["status"] == "TAMPERED"
    assert client.post(url + "/tamper-demo", json={"mutation": "tls_cert", "evidence_id": "ti:1"}).status_code == 422


def test_corrupted_stored_proof_cannot_be_reported_supported(client, report):
    import json
    report_id = report["bundle"]["report_id"]
    report["merkle"]["proofs_by_id"]["tls:1"] = ["0x" + "0" * 64]
    database = client.app.state.database
    with database.connection:
        database.connection.execute("UPDATE reports SET payload=? WHERE report_id=?", (json.dumps(report), report_id))
    result = client.post(f"/api/reports/{report_id}/verify", json={}).json()
    assert result["root_match"] and result["status"] == "TAMPERED"
    assert not result["leaf_validity"]["tls:1"]
