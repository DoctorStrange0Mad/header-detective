"""Public Language Detective API for text and .eml files."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from pathlib import Path

from .classifier import classify
from .ner import extract_entities
from .preprocessing import build_classifier_text
from .rules import analyze_rules


def _classification(score: float) -> str:
    if score < 0.25:
        return "low_risk"
    if score < 0.50:
        return "medium_risk"
    if score < 0.75:
        return "high_risk"
    return "critical_risk"


def analyze_email(subject: object | None, body: object | None, sender: str | None = None, *, body_is_html: bool = False) -> dict:
    classifier_text, clean_subject, clean_body = build_classifier_text(subject, body, body_is_html=body_is_html)
    evidence_text = f"{clean_subject}\n{clean_body}".strip()
    indicators, rule_score, summary = analyze_rules(evidence_text)
    entities, warnings = extract_entities(evidence_text)
    model = classify(classifier_text)
    if model["available"]:
        language_score = round(min(1.0, max(0.0, 0.70 * model["phishing_probability"] + 0.30 * rule_score)), 6)
    else:
        language_score = rule_score
        warnings.append(model.pop("warning", "ML model unavailable"))
        warnings.append("ML model unavailable; language score is rule-based only.")
    if not evidence_text:
        warnings.append("Email subject and body were empty.")
    return {"language_analysis": {"model": model, "rule_score": rule_score, "language_threat_score": language_score, "classification": _classification(language_score), "indicators": indicators, "entities": entities, "summary": summary, "warnings": warnings}}


def _payload_text(message) -> tuple[str, bool]:
    if message.is_multipart():
        plain, html = "", ""
        for part in message.walk():
            if part.get_content_maintype() == "multipart" or part.get_content_disposition() == "attachment":
                continue
            content_type = part.get_content_type()
            if content_type == "text/plain" and not plain:
                plain = part.get_content()
            elif content_type == "text/html" and not html:
                html = part.get_content()
        return (plain, False) if plain else (html, bool(html))
    return message.get_content(), message.get_content_type() == "text/html"


def analyze_eml(filepath: str | Path) -> dict:
    """Extract subject/body locally from an .eml without logging its contents."""
    # Reuse the repository's existing mail-parser dependency first, keeping the
    # standard-library parser below as a resilient fallback for malformed mail.
    try:
        import mailparser
        parsed = mailparser.parse_from_file(str(filepath))
        subject = parsed.headers.get("Subject", "")
        plain = getattr(parsed, "text_plain", None) or ""
        html = getattr(parsed, "text_html", None) or ""
        if isinstance(plain, list):
            plain = "\n".join(str(item) for item in plain)
        if isinstance(html, list):
            html = "\n".join(str(item) for item in html)
        if plain:
            return analyze_email(subject, plain, parsed.headers.get("From"), body_is_html=False)
        if html:
            return analyze_email(subject, html, parsed.headers.get("From"), body_is_html=True)
        return analyze_email(subject, getattr(parsed, "body", ""), parsed.headers.get("From"))
    except Exception:
        pass
    with open(filepath, "rb") as stream:
        message = BytesParser(policy=policy.default).parse(stream)
    body, body_is_html = _payload_text(message)
    return analyze_email(message.get("Subject", ""), body, message.get("From"), body_is_html=body_is_html)
