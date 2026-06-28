import email
from email import policy
from pathlib import Path

import pytest

from parser.email_parser import EmailData, parse_email
from ioc.extractor import extract_iocs
from whitelist import WhitelistConfig, get_config, set_config, MatcherMode


@pytest.fixture
def sample_eml(tmp_path: Path) -> Path:
    return Path(__file__).parent.parent / "sample.eml"


@pytest.fixture
def clean_eml(tmp_path: Path) -> Path:
    clean_content = """From: sender@example.com
To: recipient@example.com
Subject: Weekly Newsletter
Date: Mon, 1 Jan 2024 10:00:00 +0000
Content-Type: text/plain

Hello,

This is a legitimate newsletter with a link to https://example.com and an email sender@example.com.

Regards,
Sender
"""
    p = tmp_path / "clean.eml"
    p.write_text(clean_content, encoding="utf-8")
    return p


@pytest.fixture
def whitelist_exact() -> None:
    set_config(WhitelistConfig(path=Path("whitelist.txt"), mode=MatcherMode.EXACT))


@pytest.fixture
def whitelist_subdomain() -> None:
    set_config(WhitelistConfig(path=Path("whitelist.txt"), mode=MatcherMode.SUBDOMAIN))


class TestEmailParser:
    def test_parse_sample_eml(self, sample_eml: Path) -> None:
        result = parse_email(sample_eml)
        assert isinstance(result, EmailData)
        assert "From" in result.headers
        assert "Subject" in result.headers
        assert len(result.body_text) == 0  # sample is HTML-only
        assert len(result.body_html) > 0
        assert result.urls_from_html is not None

    def test_parse_clean_eml(self, clean_eml: Path) -> None:
        result = parse_email(clean_eml)
        assert "example.com" in result.body_text or "example.com" in result.body_html
        assert len(result.attachments) == 0

    def test_missing_file(self) -> None:
        with pytest.raises((FileNotFoundError, ValueError)):
            parse_email("nonexistent_file.eml")

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.eml"
        p.write_text("", encoding="utf-8")
        with pytest.raises(ValueError):
            parse_email(p)

    def test_html_form_extraction(self, tmp_path: Path) -> None:
        html_content = """<html><body>
<form action="https://evil.com/phish" method="POST">
<input name="user" /><input name="pass" />
</form>
</body></html>"""
        content = b"From: a@b.com\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + html_content.encode()
        p = tmp_path / "form.eml"
        p.write_bytes(content)
        result = parse_email(p)
        assert len(result.forms) == 1
        assert result.forms[0]["action"] == "https://evil.com/phish"


class TestIOCExtraction:
    def test_extract_urls(self) -> None:
        text = "Visit https://evil.com/login and http://test.phish/page for more info."
        iocs = extract_iocs(text)
        assert len(iocs["urls"]) >= 2
        assert any("evil.com" in u for u in iocs["urls"])
        assert any("test.phish" in u for u in iocs["urls"])

    def test_extract_domains(self) -> None:
        text = "Go to https://evil.com/login or https://sub.evil.com/page"
        iocs = extract_iocs(text)
        assert "evil.com" in iocs["domains"]
        assert "sub.evil.com" in iocs["domains"]

    def test_extract_ips(self) -> None:
        text = "Connect to 1.2.3.4 or 192.168.1.1 for details."
        iocs = extract_iocs(text)
        assert "1.2.3.4" in iocs["ips"]
        assert "192.168.1.1" in iocs["ips"]

    def test_extract_emails(self) -> None:
        text = "Contact admin@example.com or support@test.co.uk"
        iocs = extract_iocs(text)
        assert "admin@example.com" in iocs["emails"]
        assert "support@test.co.uk" in iocs["emails"]

    def test_deduplication(self) -> None:
        text = "Visit https://evil.com/page https://evil.com/page again"
        iocs = extract_iocs(text)
        assert iocs["urls"].count("https://evil.com/page") == 1


