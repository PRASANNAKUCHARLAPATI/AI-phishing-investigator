from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class Rule(ABC):
    name: str = "base_rule"
    description: str = "Base rule class"
    mitre_techniques: List[str] = []

    @abstractmethod
    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        raise NotImplementedError


class CompositeRule(Rule):
    def __init__(self, rules: List[Rule]) -> None:
        self.rules = rules
        self.name = "composite"
        self.description = "Composite rule containing multiple sub-rules"

    def check(self, data: Dict[str, Any]) -> Tuple[bool, int, str]:
        for rule in self.rules:
            try:
                triggered, score, reason = rule.check(data)
                if triggered:
                    logger.debug("Rule '%s' triggered: %s", rule.name, reason)
                    return True, score, reason
            except Exception as exc:
                logger.warning("Rule '%s' failed: %s", rule.name, exc)
        return False, 0, ""
