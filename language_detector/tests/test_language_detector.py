import unittest
from unittest.mock import patch

from language_detector.detector import analyze_email, analyze_eml
from language_detector.ner import extract_entities


class LanguageDetectorTests(unittest.TestCase):
    def setUp(self):
        # Rule/EML tests must stay offline and deterministic. A separate manual
        # integration check exercises the cached Hugging Face model.
        self.classifier = patch(
            "language_detector.detector.classify",
            return_value={"name": "dima806/phishing-email-detection", "label": "PHISHING EMAIL", "phishing_probability": 0.0, "score": 1.0, "available": True},
        )
        self.classifier.start()

    def tearDown(self):
        self.classifier.stop()

    def test_obvious_phishing_and_social_engineering(self):
        result = analyze_email("URGENT: CEO request", "Keep this confidential. Buy gift cards and send the codes immediately.")
        analysis = result["language_analysis"]
        categories = {entry["category"] for entry in analysis["indicators"]}
        self.assertIn("urgency", categories)
        self.assertIn("financial_request", categories)
        self.assertIn("secrecy", categories)
        self.assertGreaterEqual(analysis["rule_score"], 0.5)

    def test_legitimate_payment_is_not_high_from_authority_alone(self):
        result = analyze_email("Invoice approved", "The CEO approved the monthly invoice payment through the normal procurement portal.")
        # Authority + routine payment remains below high-risk without pressure,
        # secrecy, urgency, or credential language.
        self.assertLess(result["language_analysis"]["rule_score"], 0.5)

    def test_credential_and_threat(self):
        result = analyze_email("Account verification", "Verify your account immediately or your account will be suspended. Enter your password.")
        categories = {entry["category"] for entry in result["language_analysis"]["indicators"]}
        self.assertTrue({"credential_harvesting", "threat_or_pressure", "urgency"}.issubset(categories))

    def test_required_social_engineering_cases(self):
        cases = {
            "BEC executive impersonation": ("CEO request", "Reply immediately and keep this confidential.", "authority_impersonation"),
            "financial fraud": ("Payment", "Please make a wire transfer to this beneficiary today.", "financial_request"),
            "urgency": ("Action required", "Respond immediately within 1 hour.", "urgency"),
            "reward lure": ("You won", "Claim your reward today only.", "reward_or_lure"),
            "suspicious action": ("Notice", "Click here to download the document.", "suspicious_action"),
        }
        for name, (subject, body, expected) in cases.items():
            with self.subTest(name=name):
                result = analyze_email(subject, body)
                categories = {item["category"] for item in result["language_analysis"]["indicators"]}
                self.assertIn(expected, categories)

    def test_html_email(self):
        result = analyze_email("", "<p>Action required: <b>click here</b> to verify your account.</p>", body_is_html=True)
        phrases = [entry["phrase"].lower() for entry in result["language_analysis"]["indicators"]]
        self.assertIn("click here", phrases)

    def test_empty_fields_are_safe(self):
        result = analyze_email(None, None)
        self.assertIn("Email subject and body were empty.", result["language_analysis"]["warnings"])

    def test_model_failure_falls_back_to_rules(self):
        with patch("language_detector.detector.classify", return_value={"name": "dima806/phishing-email-detection", "label": None, "phishing_probability": None, "score": None, "available": False, "warning": "ML model unavailable: test"}):
            result = analyze_email("Urgent", "Wire transfer immediately")
        analysis = result["language_analysis"]
        self.assertEqual(analysis["language_threat_score"], analysis["rule_score"])
        self.assertFalse(analysis["model"]["available"])

    def test_eml_extraction(self):
        from tempfile import NamedTemporaryFile
        raw = b"From: x@example.com\nSubject: Verify now\nContent-Type: text/html\n\n<p>Verify your account immediately</p>"
        with NamedTemporaryFile(suffix=".eml", delete=False) as file:
            file.write(raw)
            file.flush()
            path = file.name
        try:
            result = analyze_eml(path)
        finally:
            import os
            os.unlink(path)
        self.assertTrue(result["language_analysis"]["indicators"])

    def test_ner_entities_when_spacy_model_is_available(self):
        entities, warnings = extract_entities("John Smith from Acme Corp requested $500 in Mumbai on 12 May 2026.")
        self.assertEqual(warnings, [])
        self.assertIn("John Smith", entities["persons"])
        self.assertIn("Acme Corp", entities["organizations"])
        self.assertTrue(any("500" in item for item in entities["money"]))

    def test_api_route_uses_the_language_contract(self):
        from fastapi.testclient import TestClient
        import api
        payload = {"language_analysis": {"model": {"name": "dima806/phishing-email-detection", "label": None, "phishing_probability": None, "score": None, "available": False}, "rule_score": 0.0, "language_threat_score": 0.0, "classification": "low_risk", "indicators": [], "entities": {"persons": [], "organizations": [], "money": [], "dates": [], "locations": []}, "summary": [], "warnings": []}}
        with patch("api.analyze_eml", return_value=payload):
            response = TestClient(api.app).post("/analyze-language", files={"file": ("test.eml", b"Subject: test\n\nbody", "message/rfc822")})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), payload)


if __name__ == "__main__":
    unittest.main()
