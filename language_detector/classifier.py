"""CPU-safe singleton for the selected local Hugging Face classifier."""

from __future__ import annotations

from functools import lru_cache

MODEL_NAME = "dima806/phishing-email-detection"


def _phishing_label(id2label: dict) -> tuple[int, str]:
    """Determine the phishing class from descriptive model metadata, never ID alone."""
    normalized = {int(key): str(value) for key, value in id2label.items()}
    matches = [(index, label) for index, label in normalized.items() if any(word in label.lower() for word in ("phish", "malicious", "fraud", "spam"))]
    if len(matches) != 1:
        raise ValueError(f"Unable to identify phishing label from config.id2label={normalized!r}")
    return matches[0]


@lru_cache(maxsize=1)
def _load_model():
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()
    phishing_id, phishing_name = _phishing_label(model.config.id2label)
    return torch, tokenizer, model, phishing_id, phishing_name


def classify(text: str) -> dict:
    result = {"name": MODEL_NAME, "label": None, "phishing_probability": None, "score": None, "available": False}
    try:
        torch, tokenizer, model, phishing_id, _ = _load_model()
        inputs = tokenizer(text, truncation=True, max_length=512, return_tensors="pt")
        with torch.inference_mode():
            probabilities = torch.softmax(model(**inputs).logits, dim=-1)[0].tolist()
        predicted_id = int(max(range(len(probabilities)), key=probabilities.__getitem__))
        labels = {int(key): str(value) for key, value in model.config.id2label.items()}
        probability = float(probabilities[phishing_id])
        result.update({"label": labels.get(predicted_id, str(predicted_id)), "phishing_probability": round(min(1.0, max(0.0, probability)), 6), "score": round(float(probabilities[predicted_id]), 6), "available": True})
        return result
    except Exception as exc:
        result["warning"] = f"ML model unavailable: {type(exc).__name__}: {exc}"
        return result
