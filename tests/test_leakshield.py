import pytest
import io
import zipfile
from core.entropy import calculate_shannon_entropy, is_high_entropy
from core.redaction import redact_secret, generate_fingerprint, mask_evidence_line
from core.rules import is_placeholder
from core.risk_scoring import calculate_risk_score
from core.engine import SecretDetectionEngine
from core.scanners import scan_safe_zip

def test_shannon_entropy_calculation():
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0
    assert calculate_shannon_entropy("password123") < 3.5
    high_ent = calculate_shannon_entropy("wJalrXUtnFEMIK7MDENGbPxRfiCY")
    assert high_ent > 4.2
    assert is_high_entropy("wJalrXUtnFEMIK7MDENGbPxRfiCY", threshold=4.0)

def test_redaction_and_fingerprinting():
    raw = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(raw)
    assert "AKIA" in redacted and "EXAMPLE" in redacted and "OSFODNN7" not in redacted
    assert generate_fingerprint(raw) == generate_fingerprint(raw)
    masked = mask_evidence_line(f"export AWS_KEY={raw}", raw)
    assert raw not in masked and redacted in masked

def test_placeholder_filtering():
    assert is_placeholder("your_api_key") is True
    assert is_placeholder("ghp_ABC1234567890abcdefghijklmnopqrstuvw") is False

def test_risk_scoring_scale():
    assert calculate_risk_score("Critical", 90) == 90.0
    assert calculate_risk_score("Low", 50) == 10.0

def test_detection_engine_aws_and_github():
    engine = SecretDetectionEngine()
    sample = """
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
    GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    DUMMY = "your_api_key"
    """
    findings = engine.scan_content(sample, "test_file.py")
    rule_ids = [f["rule_id"] for f in findings]
    assert "LS-AWS-001" in rule_ids
    assert "LS-GH-002" in rule_ids
    assert not any("DUMMY" in f["redacted_evidence"] for f in findings)

def test_safe_zip_slip_protection():
    engine = SecretDetectionEngine()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zf.writestr("safe_config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    zip_buffer.seek(0)
    findings, count = scan_safe_zip(engine, zip_buffer)
    assert all("etc/passwd" not in f["file_path"] for f in findings)
    assert count == 1
