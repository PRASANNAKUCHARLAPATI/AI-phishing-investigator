from __future__ import annotations

from typing import Any, Dict, List, Tuple

from rules.auth_rules import AuthFailureRule
from rules.base import CompositeRule, Rule
from rules.content_rules import FearLanguageRule, FormExfilRule
from rules.domain_rules import DomainRule
from rules.header_rules import SuspiciousHostRule
from rules.ip_rules import CloudVPSRule
from whitelist import get_config


def build_detector() -> CompositeRule:
    whitelist = get_config()
    rules: List[Rule] = [
        AuthFailureRule(),
        SuspiciousHostRule(),
        DomainRule(whitelist=whitelist),
        FearLanguageRule(),
        FormExfilRule(whitelist=whitelist),
        CloudVPSRule(),
    ]
    return CompositeRule(rules)


def analyze_email(data: Dict[str, Any]) -> Dict[str, Any]:
    detector = build_detector()
    total_score = 0
    reasons: List[str] = []
    auth_results = {
        "spf_fail": "spf=temperror" in data.get("headers", "").lower() or "spf=fail" in data.get("headers", "").lower(),
        "dkim_pass": "dkim=pass" in data.get("headers", "").lower(),
        "dkim_fail": "dkim=none" in data.get("headers", "").lower() or "dkim=fail" in data.get("headers", "").lower(),
        "dmarc_fail": "dmarc=temperror" in data.get("headers", "").lower() or "dmarc=fail" in data.get("headers", "").lower(),
    }

    if hasattr(detector, "rules"):
        for rule in detector.rules:
            try:
                triggered, score, reason = rule.check(data)
                if triggered:
                    total_score += score
                    reasons.append(reason)
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning("Rule %s failed: %s", rule.name, exc)

    if total_score >= 8:
        verdict = "PHISHING"
    elif total_score >= 4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "score": total_score,
        "verdict": verdict,
        "reasons": reasons,
        "auth_results": auth_results,
        "iocs": {
            "urls": data.get("urls", []),
            "domains": data.get("domains", []),
            "ips": data.get("ips", []),
        },
    }
