from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from rules.base import Rule

logger = logging.getLogger(__name__)


class CloudVPSRule(Rule):
    name = "cloud_vps"
    description = "Detects cloud VPS IP ranges commonly used for phishing infrastructure"
    mitre_techniques = ["T1583.003"]

    VPS_PREFIXES = {
        "137.": "DigitalOcean",
        "104.": "Hetzner",
        "45.": "Hetzner",
        "185.": "Hetzner",
        "149.": "Hetzner",
        "23.": "Hetzner",
        "167.": "Hetzner",
        "162.": "Hetzner",
    }

    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        ips: List[str] = data.get("ips", [])
        score = 0
        reasons: List[str] = []

        for ip in ips:
            for prefix, provider in self.VPS_PREFIXES.items():
                if ip.startswith(prefix):
                    score += 2
                    reasons.append(f"Cloud VPS IP ({provider}): {ip}")
                    break

        if score > 0:
            return True, score, "; ".join(reasons)
        return False, 0, ""
