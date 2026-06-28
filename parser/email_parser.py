from __future__ import annotations

import email
import hashlib
import logging
import os
from dataclasses import dataclass
from email import policy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    md5: str
    sha256: str


@dataclass
class EmailData:
    headers: Dict[str, str]
    body_text: str
    body_html: str
    urls_from_html: List[str]
    forms: List[Dict[str, str]]
    attachments: List[AttachmentInfo]
    raw_message: email.message.EmailMessage


def _hash_payload(payload: bytes) -> Tuple[str, str]:
    md5 = hashlib.md5(payload).hexdigest()
    sha256 = hashlib.sha256(payload).hexdigest()
    return md5, sha256


def _extract_html_info(html_content: str) -> Tuple[List[str], List[Dict[str, str]]]:
    soup = BeautifulSoup(html_content, "lxml")
    urls: List[str] = []
    forms: List[Dict[str, str]] = []

    for tag in soup.find_all(["a", "img", "script", "link", "iframe", "video", "audio"]):
        href = tag.get("href") or tag.get("src") or tag.get("data-src")
        if href and isinstance(href, str):
            urls.append(href)

    for form in soup.find_all("form"):
        action = form.get("action", "")
        forms.append({
            "action": action,
            "method": (form.get("method", "GET")).upper(),
            "inputs": [inp.get("name", "") for inp in form.find_all(["input", "textarea"])],
        })

    return urls, forms


def parse_email(file_path: str | Path) -> EmailData:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"Email file is empty: {path}")

    try:
        with open(path, "rb") as fh:
            msg = email.message_from_binary_file(fh, policy=policy.default)
    except Exception as exc:
        raise ValueError(f"Failed to parse email file {path}: {exc}") from exc

    headers = {k: v for k, v in msg.items()}
    body_text = ""
    body_html = ""
    urls_from_html: List[str] = []
    forms: List[Dict[str, str]] = []
    attachments: List[AttachmentInfo] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "")
            charset = part.get_content_charset() or "utf-8"

            if "attachment" in content_disposition:
                payload = part.get_payload(decode=True) or b""
                md5, sha256 = _hash_payload(payload)
                attachments.append(AttachmentInfo(
                    filename=part.get_filename() or "unknown",
                    content_type=content_type,
                    size=len(payload),
                    md5=md5,
                    sha256=sha256,
                ))
                continue

            if content_type == "text/plain":
                body_text += part.get_content()
            elif content_type == "text/html":
                html_content = part.get_content()
                if html_content:
                    body_html += html_content
                    urls_from_html, forms = _extract_html_info(body_html)
    else:
        charset = msg.get_content_charset() or "utf-8"
        if msg.get_content_type() == "text/plain":
            body_text = msg.get_content()
        elif msg.get_content_type() == "text/html":
            body_html = msg.get_content()
            if body_html:
                urls_from_html, forms = _extract_html_info(body_html)

    logger.info(
        "Parsed email from %s: %d headers, %d chars text, %d chars html, %d URLs, %d forms, %d attachments",
        path, len(headers), len(body_text), len(body_html), len(urls_from_html), len(forms), len(attachments)
    )

    return EmailData(
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        urls_from_html=urls_from_html,
        forms=forms,
        attachments=attachments,
        raw_message=msg,
    )
