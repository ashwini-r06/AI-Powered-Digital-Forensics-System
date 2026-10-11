"""SHA-256 fingerprints for evidence integrity verification."""
import hashlib
from pathlib import Path
from datetime import datetime, timezone

def calculate_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def calculate_file_sha256(file_path) -> str:
    digest=hashlib.sha256()
    with open(file_path,"rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest()

def create_evidence_manifest(filename: str, content: bytes) -> dict:
    return {"filename":Path(filename).name,"hash_algorithm":"SHA-256","sha256":calculate_sha256(content),"file_size":len(content),"created_at_utc":datetime.now(timezone.utc).isoformat()}

def verify_evidence_integrity(original_sha256: str, current_content: bytes) -> dict:
    actual=calculate_sha256(current_content)
    verified=bool(original_sha256) and actual.lower()==str(original_sha256).lower()
    return {"integrity_verified":verified,"integrity_status":"VERIFIED" if verified else "MISMATCH","expected_sha256":original_sha256,"actual_sha256":actual}
