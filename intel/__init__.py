from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class ThreatIntelError(Exception):
    pass


class ThreatIntelProvider(ABC):
    name: str = "base"
    requires_api_key: bool = False

    @abstractmethod
    def check_url(self, url: str) -> Dict[str, Any]:
        ...

    @abstractmethod
    def check_domain(self, domain: str) -> Dict[str, Any]:
        ...

    @abstractmethod
    def check_ip(self, ip: str) -> Dict[str, Any]:
        ...


class URLhausProvider(ThreatIntelProvider):
    name = "urlhaus"
    requires_api_key = False
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def check_url(self, url: str) -> Dict[str, Any]:
        try:
            resp = requests.post(f"{self.BASE_URL}/url/", data={"url": url}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return {
                "provider": self.name,
                "query": url,
                "status": data.get("url_status", "unknown"),
                "threat": data.get("threat", "unknown"),
                "tags": data.get("tags", []),
                "reference": data.get("urlhaus_reference", ""),
            }
        except Exception as exc:
            logger.warning("URLhaus check failed for %s: %s", url, exc)
            return {"provider": self.name, "query": url, "error": str(exc)}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"provider": self.name, "query": domain, "note": "URLhaus does not support domain-only lookups"}
        return result

    def check_ip(self, ip: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"provider": self.name, "query": ip, "note": "URLhaus does not support IP-only lookups"}
        return result


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    requires_api_key = True
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def check_url(self, url: str) -> Dict[str, Any]:
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = self.session.get(f"{self.BASE_URL}/urls/{url_id}", timeout=30)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "provider": self.name,
                "query": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "permalink": data.get("attributes", {}).get("permalink", ""),
            }
        except Exception as exc:
            logger.warning("VirusTotal check failed for %s: %s", url, exc)
            return {"provider": self.name, "query": url, "error": str(exc)}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        try:
            resp = self.session.get(f"{self.BASE_URL}/domains/{domain}", timeout=30)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "provider": self.name,
                "query": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "creation_date": data.get("attributes", {}).get("creation_date", ""),
                "permalink": data.get("attributes", {}).get("permalink", ""),
            }
        except Exception as exc:
            logger.warning("VirusTotal domain check failed for %s: %s", domain, exc)
            return {"provider": self.name, "query": domain, "error": str(exc)}

    def check_ip(self, ip: str) -> Dict[str, Any]:
        try:
            resp = self.session.get(f"{self.BASE_URL}/ip_addresses/{ip}", timeout=30)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "provider": self.name,
                "query": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "country": data.get("attributes", {}).get("country", ""),
                "as_owner": data.get("attributes", {}).get("as_owner", ""),
                "permalink": data.get("attributes", {}).get("permalink", ""),
            }
        except Exception as exc:
            logger.warning("VirusTotal IP check failed for %s: %s", ip, exc)
            return {"provider": self.name, "query": ip, "error": str(exc)}


def get_provider(name: str, api_key: Optional[str] = None) -> ThreatIntelProvider:
    name_lower = name.lower()
    if name_lower == "urlhaus":
        return URLhausProvider()
    if name_lower == "virustotal":
        if not api_key:
            raise ValueError("VirusTotal requires an API key")
        return VirusTotalProvider(api_key=api_key)
    raise ValueError(f"Unsupported threat intel provider: {name}")


def enrich_iocs(iocs: Dict[str, List[str]], provider: ThreatIntelProvider) -> Dict[str, List[Dict[str, Any]]]:
    enriched: Dict[str, List[Dict[str, Any]]] = {"urls": [], "domains": [], "ips": []}

    for url in iocs.get("urls", []):
        result = provider.check_url(url)
        enriched["urls"].append(result)

    for domain in iocs.get("domains", []):
        result = provider.check_domain(domain)
        enriched["domains"].append(result)

    for ip in iocs.get("ips", []):
        result = provider.check_ip(ip)
        enriched["ips"].append(result)

    return enriched
