import re
from typing import List, Dict, Any
from core.entropy import calculate_shannon_entropy
from core.redaction import redact_secret, generate_fingerprint, mask_evidence_line
from core.rules import BUILTIN_RULES, SUSPICIOUS_VARIABLE_NAMES, is_placeholder
from core.risk_scoring import calculate_risk_score

class SecretDetectionEngine:
    def __init__(self, custom_rules: List[Dict[str, Any]] = None, rule_states: Dict[str, bool] = None):
        self.rules = []
        states = rule_states or {}
        for r in BUILTIN_RULES:
            rc = dict(r)
            if rc["id"] in states:
                rc["enabled"] = states[rc["id"]]
            self.rules.append(rc)
        if custom_rules:
            for cr in custom_rules:
                crc = dict(cr)
                if crc["id"] in states:
                    crc["enabled"] = states[crc["id"]]
                self.rules.append(crc)

    def scan_content(self, content: str, filename: str) -> List[Dict[str, Any]]:
        findings = []
        seen_fingerprints = set()
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#!/"):
                continue

            lower_line = stripped.lower()
            has_suspicious_context = any(k in lower_line for k in SUSPICIOUS_VARIABLE_NAMES)

            for rule in self.rules:
                if not rule.get("enabled", True):
                    continue

                pattern = rule["pattern"]
                try:
                    matches = re.finditer(pattern, line)
                except Exception:
                    continue

                for match in matches:
                    raw_secret = match.group(0)
                    if match.groups():
                        for g in match.groups():
                            if g:
                                raw_secret = g
                                break
                    raw_secret = raw_secret.strip().strip("'\"`")

                    if len(raw_secret) < 4 or is_placeholder(raw_secret):
                        continue

                    entropy = calculate_shannon_entropy(raw_secret)
                    if entropy < rule.get("min_entropy", 0.0):
                        continue

                    fingerprint = generate_fingerprint(f"{filename}:{line_idx}:{raw_secret}")
                    if fingerprint in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fingerprint)

                    base_conf = int(rule.get("confidence", 80))
                    if has_suspicious_context and base_conf < 95:
                        base_conf = min(99, base_conf + 8)
                    if entropy >= 4.5 and base_conf < 95:
                        base_conf = min(99, base_conf + 5)

                    severity = rule.get("severity", "Medium")
                    risk_score = calculate_risk_score(severity, base_conf)

                    findings.append({
                        "rule_id": rule.get("id", "CUSTOM-001"),
                        "rule_name": rule.get("name", "Custom Rule"),
                        "category": rule.get("category", "General Secret"),
                        "severity": severity,
                        "confidence": base_conf,
                        "risk_score": risk_score,
                        "entropy": entropy,
                        "file_path": filename,
                        "line_number": line_idx,
                        "redacted_evidence": mask_evidence_line(line, raw_secret),
                        "redacted_secret": redact_secret(raw_secret),
                        "fingerprint": generate_fingerprint(raw_secret),
                        "description": rule.get("description", "Exposed sensitive credential."),
                        "remediation": rule.get("remediation", "Rotate credential and remove from codebase."),
                        "status": "Open"
                    })

        return findings
