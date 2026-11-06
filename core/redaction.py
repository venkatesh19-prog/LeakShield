import hashlib

def generate_fingerprint(secret: str) -> str:
    """Generates a non-reversible SHA-256 fingerprint for deduplication."""
    return hashlib.sha256(secret.encode("utf-8", errors="ignore")).hexdigest()[:16]

def redact_secret(secret: str) -> str:
    clean_secret = secret.strip().strip("'\"`")
    sec_len = len(clean_secret)
    if sec_len <= 6:
        return "*" * sec_len
    elif sec_len <= 12:
        return f"{clean_secret[:2]}{'*' * (sec_len - 4)}{clean_secret[-2:]}"
    elif sec_len <= 24:
        return f"{clean_secret[:4]}{'*' * (sec_len - 11)}{clean_secret[-7:]}"
    else:
        return f"{clean_secret[:4]}{'*' * (sec_len - 8)}{clean_secret[-4:]}"

def mask_evidence_line(line: str, raw_secret: str) -> str:
    if not raw_secret or raw_secret not in line:
        return line.strip()
    redacted = redact_secret(raw_secret)
    return line.replace(raw_secret, redacted).strip()
