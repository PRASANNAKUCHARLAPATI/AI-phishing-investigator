from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Tuple

from rules.base import Rule

logger = logging.getLogger(__name__)

FEAR_LANGUAGE_RE = re.compile(
    r'\b(?:urgent|immediately|suspend|expire|expiring|verify|confirm|action required|'
    r'limited time|act now|failure to|unauthorized|suspicious activity|locked|restricted|'
    r'update your|click here|verify your|confirm your|account will)\b',
    re.IGNORECASE,
)


class FearLanguageRule(Rule):
    name = "fear_language"
    description = "Detects fear/urgency language in email body"
    mitre_techniques = ["T1566.002"]

    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        body_text = data.get("body_text", "") + " " + data.get("body_html", "")
        matches = FEAR_LANGUAGE_RE.findall(body_text)
        unique = set(m.lower() for m in matches)
        score = min(len(unique), 5)

        if score > 0:
            return True, score, f"Fear/urgency language in body ({score} indicators)"
        return False, 0, ""


class FormExfilRule(Rule):
    name = "form_exfil"
    description = "Detects HTML forms posting to external domains"
    mitre_techniques = ["T1056.004"]

    def __init__(self, whitelist: Any) -> None:
        self.whitelist = whitelist

    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        forms: List[Dict[str, str]] = data.get("forms", [])
        for form in forms:
            action = form.get("action", "")
            if not action:
                continue
            try:
                from urllib.parse import urlparse
                domain = urlparse(action).netloc.lower()
                if domain and not self.whitelist.is_whitelisted(domain):
                    return True, 3, f"HTML form posts to external domain: {domain}"
            except Exception:
                pass
        return False, 0, ""
