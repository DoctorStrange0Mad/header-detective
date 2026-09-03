"""Safe, lightweight conversion of email content to NLP-ready text."""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in {"script", "style"}:
            self._ignored_depth += 1
        elif tag.lower() in {"br", "p", "div", "li", "tr", "h1", "h2", "h3"}:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1
        elif tag.lower() in {"p", "div", "li", "tr"}:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


def coerce_text(value: object | None) -> str:
    return "" if value is None else str(value)


def html_to_text(value: object | None) -> str:
    """Extract readable text without removing URLs, punctuation, or currency."""
    raw = coerce_text(value)
    if not raw:
        return ""
    parser = _TextExtractor()
    try:
        parser.feed(raw)
        parser.close()
        extracted = "".join(parser.parts)
    except Exception:
        extracted = re.sub(r"<[^>]+>", " ", raw)
    return html.unescape(extracted)


def normalize_text(value: object | None, *, html_body: bool = False) -> str:
    text = html_to_text(value) if html_body else coerce_text(value)
    return re.sub(r"\s+", " ", text).strip()


def build_classifier_text(subject: object | None, body: object | None, *, body_is_html: bool = False) -> tuple[str, str, str]:
    """Return (classifier input, clean subject, clean body)."""
    clean_subject = normalize_text(subject)
    raw_body = coerce_text(body)
    is_html = body_is_html or bool(re.search(r"<\s*(html|body|p|div|br)\b", raw_body, re.I))
    clean_body = normalize_text(raw_body, html_body=is_html)
    return f"Subject: {clean_subject}\n\nBody: {clean_body}", clean_subject, clean_body
