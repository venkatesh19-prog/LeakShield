import json
import csv
import io
from typing import List, Dict, Any

def generate_json_report(scan_meta: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    payload = {
        "report_engine": "LeakShield Enterprise v2026.1",
        "scan_metadata": scan_meta,
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "Critical"),
            "high": sum(1 for f in findings if f["severity"] == "High"),
            "medium": sum(1 for f in findings if f["severity"] == "Medium"),
            "low": sum(1 for f in findings if f["severity"] == "Low")
        },
        "findings": findings
    }
    return json.dumps(payload, indent=2)

def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    if not findings:
        return "Finding_ID,Rule_ID,Category,Severity,Risk_Score,File_Path,Line_Number,Status,Redacted_Secret\n"
    writer = csv.DictWriter(output, fieldnames=[
        "id", "rule_id", "category", "severity", "risk_score", "file_path",
        "line_number", "status", "redacted_secret", "remediation"
    ], extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow(f)
    return output.getvalue()

def generate_html_report(scan_meta: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    rows = ""
    for f in findings:
        badge_color = {
            "Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04",
            "Low": "#2563eb", "Informational": "#475569"
        }.get(f["severity"], "#475569")
        rows += f"""
        <tr>
            <td><span style="background-color: {badge_color}; color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{f['severity']}</span></td>
            <td><strong>{f['category']}</strong><br><small style="color: #64748b;">{f['rule_id']}</small></td>
            <td><code>{f['file_path']}:{f['line_number']}</code></td>
            <td><code>{f['redacted_secret']}</code></td>
            <td><strong style="color: #9333ea;">{f['risk_score']}</strong></td>
            <td style="font-size: 12px; color: #334155;">{f['remediation']}</td>
        </tr>
        """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LeakShield Security Audit Report - {scan_meta.get('scan_name', 'Audit')}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 40px; }}
    .container {{ max-width: 1100px; margin: 0 auto; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 32px; border: 1px solid #e2e8f0; }}
    .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }}
    .title {{ font-size: 24px; font-weight: 800; color: #0f172a; margin: 0; }}
    .meta-box {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; background: #f1f5f9; padding: 16px; border-radius: 6px; margin-bottom: 24px; }}
    .meta-item strong {{ display: block; font-size: 11px; text-transform: uppercase; color: #64748b; margin-bottom: 4px; }}
    .meta-item span {{ font-size: 16px; font-weight: 700; color: #0f172a; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th {{ background: #0f172a; color: #ffffff; text-align: left; padding: 10px 12px; font-size: 12px; text-transform: uppercase; }}
    td {{ padding: 12px; border-bottom: 1px solid #e2e8f0; font-size: 13px; vertical-align: top; }}
    code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1 class="title">LEAKSHIELD SECURITY AUDIT REPORT</h1>
            <p style="margin: 4px 0 0 0; color: #64748b; font-size: 14px;">Automated Secret & Sensitive Credential Exposure Assessment</p>
        </div>
        <div style="text-align: right; font-size: 12px; color: #64748b;">Confidential Assessment | Zero-Raw-Secret Exposure Policy</div>
    </div>
    <div class="meta-box">
        <div class="meta-item"><strong>Scan Target</strong><span>{scan_meta.get('scan_name', 'N/A')}</span></div>
        <div class="meta-item"><strong>Target Type</strong><span>{scan_meta.get('scan_type', 'N/A')}</span></div>
        <div class="meta-item"><strong>Files Evaluated</strong><span>{scan_meta.get('files_scanned', 0)}</span></div>
        <div class="meta-item"><strong>Total Findings</strong><span>{len(findings)}</span></div>
    </div>
    <h2>Vulnerability Findings Table</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Location</th>
                <th>Redacted Proof</th>
                <th>Risk Score</th>
                <th>Remediation Advice</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else '<tr><td colspan="6" style="text-align:center; padding: 20px;">No secrets or data leaks detected.</td></tr>'}
        </tbody>
    </table>
</div>
</body>
</html>"""
