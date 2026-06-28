from __future__ import annotations

import re
import logging
from typing import Any, Dict, Tuple

from rules.base import Rule

logger = logging.getLogger(__name__)


class AuthFailureRule(Rule):
    name = "auth_failure"
    description = "Detects SPF/DKIM/DMARC failures"
    mitre_techniques = ["T1583.001", "T1583.003"]

    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        headers = data.get("headers", "").lower()
        score = 0
        reasons: list[str] = []

        if "spf=temperror" in headers or "spf=fail" in headers:
            score += 2
            reasons.append("SPF failure")
        elif "spf=softfail" in headers:
            score += 1
            reasons.append("SPF softfail")

        if "dkim=none" in headers or "dkim=fail" in headers:
            score += 2
            reasons.append("DKIM failure / missing signature")
        elif "dkim=pass" not in headers:
            score += 1
            reasons.append("DKIM result missing")

        if "dmarc=fail" in headers or "dmarc=temperror" in headers:
            score += 2
            reasons.append("DMARC failure")
        elif "dmarc=pass" not in headers:
            score += 1
            reasons.append("DMARC result missing")

        if score > 0:
            return True, score, "; ".join(reasons)
        return False, 0, ""
