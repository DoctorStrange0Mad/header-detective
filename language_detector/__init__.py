"""Language Detective: local NLP evidence for phishing-email analysis."""

from .detector import analyze_email, analyze_eml

__all__ = ["analyze_email", "analyze_eml"]
