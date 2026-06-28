from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_WHITELIST_PATH = "whitelist.txt"


class MatcherMode(Enum):
    EXACT = "exact"
    SUBDOMAIN = "subdomain"


@dataclass
class WhitelistConfig:
    path: Path = Path(DEFAULT_WHITELIST_PATH)
    mode: MatcherMode = MatcherMode.SUBDOMAIN
    domains: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.domains:
            self._load()

    def _load(self) -> None:
        if not self.path.exists():
            logger.warning("Whitelist file %s not found. Using built-in defaults.", self.path)
            self.domains = [
                "googleapis.com",
                "gstatic.com",
                "google.com",
                "microsoft.com",
                "office.com",
                "amazonaws.com",
            ]
            return

        with open(self.path, "r", encoding="utf-8") as fh:
            self.domains = [
                line.strip().lower()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
        logger.info("Loaded %d whitelist entries from %s", len(self.domains), self.path)

    def reload(self) -> None:
        self.domains = []
        self._load()

    def is_whitelisted(self, domain: str) -> bool:
        domain = domain.lower().strip()
        for entry in self.domains:
            if self.mode == MatcherMode.EXACT:
                if domain == entry:
                    return True
            else:
                if domain == entry or domain.endswith("." + entry):
                    return True
        return False


_config: Optional[WhitelistConfig] = None


def get_config() -> WhitelistConfig:
    global _config
    if _config is None:
        _config = WhitelistConfig()
    return _config


def set_config(config: WhitelistConfig) -> None:
    global _config
    _config = config
