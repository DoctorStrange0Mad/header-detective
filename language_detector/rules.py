"""Deterministic, explainable linguistic threat rules."""

from __future__ import annotations

import re


_RULES = {
    "urgency": (0.15, "medium", ["urgent", "immediately", "act now", "action required", "within (?:an? )?\\d+ hours?", "today only", "final warning", "time sensitive", "respond immediately"]),
    "financial_request": (0.20, "high", ["wire transfer", "bank transfer", "transfer funds", "send money", "payment required", "make a payment", "gift cards?", "purchase gift cards?", "invoice payment", "account number", "beneficiary"]),
    "credential_harvesting": (0.20, "high", ["verify your account", "verify your identity", "confirm your password", "reset your password", "enter your password", "login immediately", "update your credentials", "account verification"]),
    "authority_impersonation": (0.15, "low", ["\\bCEO\\b", "\\bCFO\\b", "\\bdirector\\b", "\\badministrator\\b", "bank manager", "\\bgovernment\\b", "tax department", "security team", "HR department"]),
    "threat_or_pressure": (0.15, "high", ["account will be suspended", "account will be closed", "legal action", "\\bpenalty\\b", "failure to comply", "access will be revoked", "service termination"]),
    "secrecy": (0.10, "high", ["keep this confidential", "do not tell anyone", "don't tell anyone", "do not discuss this", "keep this private", "confidential request"]),
    "reward_or_lure": (0.05, "medium", ["you have won", "\\bprize\\b", "\\breward\\b", "\\bbonus\\b", "\\blottery\\b", "\\brefund\\b", "claim your reward"]),
    "suspicious_action": (0.05, "low", ["click here", "\\bclick\\b", "\\bverify\\b", "\\bdownload\\b", "open attachment", "\\benable\\b", "\\btransfer\\b", "\\bpay\\b", "\\bpurchase\\b", "\\breply\\b", "\\bconfirm\\b"]),
}


def _severity_for(category: str, base: str, categories: set[str]) -> str:
    if category == "authority_impersonation" and len(categories) > 1:
        return "medium"
    return base


def analyze_rules(text: str) -> tuple[list[dict], float, list[str]]:
    """Return matched evidence, capped score, and transparent summaries."""
    indicators: list[dict] = []
    categories: set[str] = set()
    matches_by_category: dict[str, list[str]] = {}
    for category, (_, severity, patterns) in _RULES.items():
        phrases: list[str] = []
        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                phrase = match.group(0)
                if phrase.lower() not in {p.lower() for p in phrases}:
                    phrases.append(phrase)
        if phrases:
            categories.add(category)
            matches_by_category[category] = phrases

    score = sum(_RULES[category][0] for category in categories if category != "suspicious_action")
    if "suspicious_action" in categories and len(categories) > 1:
        score += _RULES["suspicious_action"][0]

    combinations = [
        ({"authority_impersonation", "financial_request"}, "authority + financial request", 0.10),
        ({"authority_impersonation", "urgency"}, "authority + urgency", 0.05),
        ({"authority_impersonation", "secrecy"}, "authority + secrecy", 0.08),
        ({"urgency", "financial_request"}, "urgency + financial request", 0.08),
        ({"credential_harvesting", "urgency"}, "credential request + urgency", 0.08),
        ({"credential_harvesting", "threat_or_pressure"}, "credential request + threat", 0.08),
        ({"authority_impersonation", "secrecy", "financial_request"}, "authority + secrecy + financial request", 0.12),
    ]
    for required, phrase, bonus in combinations:
        if required.issubset(categories):
            indicators.append({"category": "social_engineering_combination", "phrase": phrase, "severity": "high"})
            score += bonus

    for category in sorted(categories):
        _, base_severity, _ = _RULES[category]
        for phrase in matches_by_category[category]:
            indicators.append({"category": category, "phrase": phrase, "severity": _severity_for(category, base_severity, categories)})

    summary = [f"{entry['category'].replace('_', ' ').title()} detected" for entry in indicators if entry["category"] != "suspicious_action"]
    return indicators, min(1.0, round(score, 4)), summary
