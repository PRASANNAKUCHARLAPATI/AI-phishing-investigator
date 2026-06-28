from __future__ import annotations

import re
import logging
from typing import Any, Dict, Tuple

from rules.base import Rule

logger = logging.getLogger(__name__)


class SuspiciousHostRule(Rule):
    name = "suspicious_host"
    description = "Detects Linux VPS hostnames and root user indicators"
    mitre_techniques = ["T1583.003"]

    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        headers = data.get("headers", "").lower()
        reasons: list[str] = []
        score = 0

        if "ubuntu" in headers and ("return-path" in headers or "received" in headers):
            score += 2
            reasons.append("Suspicious hostname (Linux VPS indicators in headers)")
        if "root@" in headers:
            score += 2
            reasons.append("Suspicious return-path (root@)")
        if "postfix" in headers and ("userid 0" in headers or "uid 0" in headers):
            score += 2
            reasons.append("Suspicious MTA (Postfix running as root)")

        reply_to = re.search(r'reply-to:\s*(.+)', headers)
        from_hdr = re.search(r'from:\s*(.+)', headers)
        if reply_to and from_hdr and reply_to.group(1).strip() != from_hdr.group(1).strip():
            score += 1
            reasons.append("Reply-To differs from From address")

        if score > 0:
            return True, score, "; ".join(reasons)
        return False, 0, ""
