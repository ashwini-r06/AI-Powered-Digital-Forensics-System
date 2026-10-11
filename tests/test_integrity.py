from core.evidence_integrity import create_evidence_manifest, verify_evidence_integrity

def test_hash_verifies():
    content=b"sample"
    manifest=create_evidence_manifest("sample.csv",content)
    assert verify_evidence_integrity(manifest["sha256"],content)["integrity_verified"]

def test_hash_mismatch():
    manifest=create_evidence_manifest("sample.csv",b"original")
    assert not verify_evidence_integrity(manifest["sha256"],b"changed")["integrity_verified"]
