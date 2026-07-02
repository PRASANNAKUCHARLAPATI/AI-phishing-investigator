from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from whitelist import get_config

logger = logging.getLogger(__name__)

MITRE_TECHNIQUES = [
    {"technique_id": "T1566.002", "name": "Phishing: Link", "url": "https://attack.mitre.org/techniques/T1566/002/"},
    {"technique_id": "T1583.001", "name": "Acquire Infrastructure: Domains", "url": "https://attack.mitre.org/techniques/T1583/001/"},
    {"technique_id": "T1583.003", "name": "Acquire Infrastructure: VPS", "url": "https://attack.mitre.org/techniques/T1583/003/"},
    {"technique_id": "T1056.004", "name": "Input Capture: Credential Phishing", "url": "https://attack.mitre.org/techniques/T1056/004/"},
]


def _case_id(email_path: str | Path, email_data: Dict[str, Any]) -> str:
    raw = str(email_path) + str(email_data.get("headers", {}).get("Message-Id", ""))
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _filename_base(case_id: str, ts: str) -> str:
    return f"phish_report_{case_id}_{ts}"


def generate_case_directory(email_path: str | Path, email_data: Dict[str, Any], output_dir: Optional[Path] = None) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    source_stem = Path(email_path).stem if email_path else "unknown"
    safe_stem = re.sub(r'[^a-zA-Z0-9_-]', '_', source_stem)[:40]
    base_name = f"{ts}_{safe_stem}"
    if output_dir is None:
        output_dir = Path("reports")
    case_dir = output_dir / base_name
    case_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Case directory created: %s", case_dir)
    return case_dir


def _safe_case_id(case_dir: Path) -> str:
    return case_dir.name


def _auth_summary(auth_results: Dict[str, bool]) -> Dict[str, str]:
    spf = "FAIL" if auth_results.get("spf_fail") else "PASS"
    dkim = "NOT PRESENT" if not auth_results.get("dkim_pass") else "PASS"
    dmarc = "FAIL" if auth_results.get("dmarc_fail") else "PASS"
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc}


def _classify_iocs(iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    whitelist = get_config()
    malicious_urls: List[str] = []
    legit_urls: List[str] = []
    malicious_domains: List[str] = []
    legit_domains: List[str] = []

    for u in iocs.get("urls", []):
        try:
            from urllib.parse import urlparse
            domain = urlparse(u).netloc.lower()
            if whitelist.is_whitelisted(domain):
                legit_urls.append(u)
            else:
                if u not in malicious_urls:
                    malicious_urls.append(u)
        except Exception:
            malicious_urls.append(u)

    for d in iocs.get("domains", []):
        if whitelist.is_whitelisted(d):
            if d not in legit_domains:
                legit_domains.append(d)
        else:
            if d not in malicious_domains:
                malicious_domains.append(d)

    return {
        "malicious_urls": malicious_urls,
        "legit_urls": legit_urls,
        "malicious_domains": malicious_domains,
        "legit_domains": legit_domains,
        "ips": iocs.get("ips", []),
        "emails": iocs.get("emails", []),
    }


def _confidence(score: int) -> str:
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def _recommendations(verdict: str, classified: Dict[str, Any]) -> List[str]:
    recs: List[str] = []
    if verdict == "PHISHING":
        recs.append("[HIGH PRIORITY - PHISHING DETECTED]")
        recs.append("1. Block sending IP in firewall/email gateway")
        recs.append("2. Block all malicious domains in web proxy/email gateway")
        recs.append("3. Block only malicious URLs in web filtering systems")
        for d in classified["malicious_domains"]:
            recs.append(f"4. Search SIEM logs for connections to: {d}")
        for ip in classified["ips"]:
            recs.append(f"5. Search SIEM logs for traffic from: {ip}")
        recs.append("6. Reset affected user passwords (if applicable)")
        recs.append("7. Notify incident response team")
        recs.append("8. Add sender to email blocklist")
        recs.append("9. Report phishing domain to abuse contacts")
    elif verdict == "SUSPICIOUS":
        recs.append("[MONITOR - SUSPICIOUS EMAIL]")
        recs.append("1. Monitor user account for suspicious activity")
        recs.append("2. Search logs for connections to suspicious domains")
        recs.append("3. Consider blocking suspicious domains/IPs")
        recs.append("4. Alert user about potential phishing attempt")
    else:
        recs.append("[LOW RISK - NO IMMEDIATE ACTION REQUIRED]")
        recs.append("1. Log for trend analysis")
        recs.append("2. No containment actions recommended")
    return recs


def generate_report(
    email_data: Dict[str, Any],
    iocs: Dict[str, List[str]],
    analysis_result: Dict[str, Any],
    email_path: str | Path = "unknown.eml",
    case_dir: Optional[Path] = None,
) -> str:
    if case_dir is None:
        case_dir = generate_case_directory(email_path, email_data)
    else:
        case_dir.mkdir(parents=True, exist_ok=True)

    base_name = case_dir.name
    classified = _classify_iocs(iocs)
    auth = _auth_summary(analysis_result.get("auth_results", {}))
    confidence = _confidence(analysis_result["score"])
    verdict = analysis_result["verdict"]
    recs = _recommendations(verdict, classified)

    report_lines = [
        "=" * 60,
        "PHISHING INVESTIGATION REPORT",
        "=" * 60,
        f"Case ID     : {_safe_case_id(case_dir)}",
        f"Source file : {email_path}",
        "",
        "VERDICT",
        "-" * 60,
        f"Verdict   : {verdict}",
        f"Score     : {analysis_result['score']}",
        f"Confidence: {confidence}",
        "",
        "DETECTION REASONS",
        "-" * 60,
    ]
    for reason in analysis_result["reasons"]:
        report_lines.append(f"  - {reason}")
    report_lines.append("")

    report_lines.extend([
        "EXTRACTED IoCs",
        "-" * 60,
        "Malicious URLs:",
    ])
    if classified["malicious_urls"]:
        for u in classified["malicious_urls"]:
            report_lines.append(f"  - {u}")
    else:
        report_lines.append("  (none)")
    report_lines.append("")

    report_lines.extend([
        "Legitimate URLs (used for disguise):",
    ])
    if classified["legit_urls"]:
        for u in classified["legit_urls"]:
            report_lines.append(f"  - {u}")
    else:
        report_lines.append("  (none)")
    report_lines.append("")

    report_lines.extend([
        "Malicious Domains:",
    ])
    if classified["malicious_domains"]:
        for d in classified["malicious_domains"]:
            report_lines.append(f"  - {d}")
    else:
        report_lines.append("  (none)")
    report_lines.append("")

    report_lines.append("Legitimate Domains (used to appear safe):")
    if classified["legit_domains"]:
        for d in classified["legit_domains"]:
            report_lines.append(f"  - {d}")
    else:
        report_lines.append("  (none)")
    report_lines.append("")

    report_lines.extend([
        "IP Addresses:",
    ])
    if classified["ips"]:
        for ip in classified["ips"]:
            report_lines.append(f"  - {ip}")
    else:
        report_lines.append("  (none)")
    report_lines.append("")

    report_lines.extend([
        "Email Addresses:",
    ])
    if classified["emails"]:
        for e in classified["emails"]:
            report_lines.append(f"  - {e}")
    else:
        report_lines.append("  (none)")
    report_lines.append("")

    report_lines.extend([
        "EMAIL DETAILS",
        "-" * 60,
        f"From    : {email_data.get('headers', {}).get('From', 'N/A')}",
        f"To      : {email_data.get('headers', {}).get('To', 'N/A')}",
        f"Subject : {email_data.get('headers', {}).get('Subject', 'N/A')}",
        f"Date    : {email_data.get('headers', {}).get('Date', 'N/A')}",
        "",
        "EMAIL AUTHENTICATION SUMMARY",
        "-" * 60,
        f"SPF   : {auth['spf']}",
        f"DKIM  : {auth['dkim']}",
        f"DMARC : {auth['dmarc']}",
        "",
        "ATTACK TECHNIQUE OBSERVED",
        "-" * 60,
        "Technique: Brand Impersonation + Infrastructure Camouflage",
        "",
        "The attacker may use trusted CDN domains to appear legitimate",
        "while hosting the credential harvesting page on a malicious domain.",
        "",
        "MITRE ATT&CK MAPPING",
        "-" * 60,
    ])
    for tech in MITRE_TECHNIQUES:
        report_lines.append(f"{tech['technique_id']} - {tech['name']}")
    report_lines.append("")

    report_lines.extend([
        "RISK TO ORGANIZATION",
        "-" * 60,
        "If a user clicks the malicious link, attackers may harvest credentials,",
        "leading to account takeover, internal phishing spread, and data breach.",
        "",
        "RECOMMENDED ACTIONS FOR SOC",
        "-" * 60,
    ])
    for rec in recs:
        report_lines.append(f"  {rec}")
    report_lines.append("")
    report_lines.append("=" * 60)
    report_lines.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 60)

    report_content = "\n".join(report_lines)

    txt_path = case_dir / f"{base_name}.txt"
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(report_content)
    logger.info("Text report written to %s", txt_path)

    json_path = case_dir / f"{base_name}.json"
    json_payload = {
        "case_id": _safe_case_id(case_dir),
        "source_file": str(email_path),
        "generated_at": datetime.now().isoformat(),
        "verdict": verdict,
        "score": analysis_result["score"],
        "confidence": confidence,
        "reasons": analysis_result["reasons"],
        "auth_results": analysis_result.get("auth_results", {}),
        "iocs": classified,
        "email_details": {
            "from": email_data.get("headers", {}).get("From", "N/A"),
            "to": email_data.get("headers", {}).get("To", "N/A"),
            "subject": email_data.get("headers", {}).get("Subject", "N/A"),
            "date": email_data.get("headers", {}).get("Date", "N/A"),
        },
        "mitre_attack": MITRE_TECHNIQUES,
        "recommendations": recs,
        "attachments": [
            {
                "filename": a.get("filename", ""),
                "content_type": a.get("content_type", ""),
                "size": a.get("size", 0),
                "md5": a.get("md5", ""),
                "sha256": a.get("sha256", ""),
            }
            for a in email_data.get("attachments", [])
        ],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(json_payload, fh, indent=2)
    logger.info("JSON report written to %s", json_path)

    return str(txt_path)


def generate_mitre_navigator_layer(analysis_result: Dict[str, Any], case_id: str, output_path: str | Path) -> str:
    verdict = analysis_result["verdict"]
    score = analysis_result["score"]
    techniques = []

    if "SPF" in " ".join(analysis_result["reasons"]) or "DKIM" in " ".join(analysis_result["reasons"]):
        techniques.append({"techniqueID": "T1583", "comment": "Authentication bypass indicators"})

    if "domain" in " ".join(analysis_result["reasons"]).lower() or "brand" in " ".join(analysis_result["reasons"]).lower():
        techniques.append({"techniqueID": "T1583.001", "comment": "Suspicious domain detected"})

    if "VPS" in " ".join(analysis_result["reasons"]) or "cloud" in " ".join(analysis_result["reasons"]).lower():
        techniques.append({"techniqueID": "T1583.003", "comment": "Cloud VPS infrastructure"})

    techniques.append({"techniqueID": "T1566.002", "comment": "Phishing link detected"})
    techniques.append({"techniqueID": "T1056.004", "comment": "Credential phishing indicators"})

    layer = {
        "version": "4.5",
        "name": f"Phishing Investigation - {case_id}",
        "domain": "enterprise-attack",
        "description": f"Automated phishing detection results. Verdict: {verdict}, Score: {score}",
        "techniques": techniques,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2)
    logger.info("MITRE Navigator layer written to %s", path)
    return str(path)
