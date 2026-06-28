from __future__ import annotations

import re
import logging
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

from rules.base import Rule

logger = logging.getLogger(__name__)

SUSPICIOUS_TLD_RE = re.compile(r'\.(?:xyz|top|click|link|work|men|loan|gq|cf|tk|ml|ga)$', re.IGNORECASE)

BRANDED_DOMAINS = {
    "google.com": ["g00gle.com", "go0gle.com", "google.cm", "googIe.com"],
    "microsoft.com": ["micr0soft.com", "microsoft-support.com", "ms-security.com"],
    "apple.com": ["apple-support.com", "app1e.com", "appleid-verify.com"],
    "amazon.com": ["amaz0n.com", "amazon-security.com", "amazon-verify.com"],
    "facebook.com": ["faceb00k.com", "facebook-security.com"],
    "paypal.com": ["paypa1.com", "paypal-security.com", "paypal-verify.com"],
    "netflix.com": ["netf1ix.com", "netflix-account.com"],
}


class DomainRule(Rule):
    name = "domain_analysis"
    description = "Analyzes domains for suspicious patterns and brand impersonation"
    mitre_techniques = ["T1583.001"]

    def __init__(self, whitelist: Any) -> None:
        self.whitelist = whitelist

    def _similarity(self, a: str, b: str) -> float:
        return SequenceMatcher(None, a, b).ratio()

    def _check_brand_impersonation(self, domain: str) -> Optional[Tuple[str, str]]:
        domain_lower = domain.lower()
        for brand, variants in BRANDED_DOMAINS.items():
            for variant in variants:
                if domain_lower == variant or self._similarity(domain_lower, brand) > 0.8:
                    return brand, variant
        return None

    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        domains: List[str] = data.get("domains", [])
        score = 0
        reasons: List[str] = []
        seen: set = set()

        for domain in domains:
            domain_lower = domain.lower().strip()
            if domain_lower in seen:
                continue
            seen.add(domain_lower)

            if self.whitelist.is_whitelisted(domain_lower):
                continue

            if SUSPICIOUS_TLD_RE.search(domain_lower):
                score += 2
                reasons.append(f"Suspicious TLD in domain: {domain_lower}")

            brand_check = self._check_brand_impersonation(domain_lower)
            if brand_check:
                brand, variant = brand_check
                score += 4
                reasons.append(f"Brand impersonation: {domain_lower} mimics {brand}")

            if len(domain_lower) > 30 and "-" in domain_lower:
                score += 1
                reasons.append(f"Unusually long/hyphenated domain: {domain_lower}")

        if score > 0:
            return True, score, "; ".join(reasons)
        return False, 0, ""
