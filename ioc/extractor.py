from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

URL_RE = re.compile(r'https?://[^\s"<>]+', re.IGNORECASE)
IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
SUSPICIOUS_TLD_RE = re.compile(r'\.(?:xyz|top|click|link|work|men|loan|gq|cf|tk|ml|ga)$', re.IGNORECASE)


def _normalize_domain(domain: str) -> str:
    domain = domain.lower().strip()
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


def extract_iocs(text: str) -> Dict[str, List[str]]:
    urls: Set[str] = set(URL_RE.findall(text))
    domains: Set[str] = set()
    ips: Set[str] = set(IP_RE.findall(text))
    emails: Set[str] = set(EMAIL_RE.findall(text))

    for url in urls:
        try:
            parsed = urlparse(url)
            netloc = _normalize_domain(parsed.netloc)
            if netloc:
                domains.add(netloc)
        except Exception:
            logger.debug("Failed to parse URL: %s", url)

    for match in EMAIL_RE.finditer(text):
        emails.add(match.group(0).lower())

    result = {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ips": sorted(ips),
        "emails": sorted(emails),
    }

    logger.info(
        "Extracted %d URLs, %d domains, %d IPs, %d emails",
        len(result["urls"]), len(result["domains"]), len(result["ips"]), len(result["emails"])
    )
    return result
