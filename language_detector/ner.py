"""Cached spaCy named-entity extraction with a safe unavailable path."""

from __future__ import annotations

from functools import lru_cache


EMPTY_ENTITIES = {"persons": [], "organizations": [], "money": [], "dates": [], "locations": []}


@lru_cache(maxsize=1)
def _get_nlp():
    import spacy
    return spacy.load("en_core_web_sm")


def extract_entities(text: str) -> tuple[dict, list[str]]:
    entities = {key: [] for key in EMPTY_ENTITIES}
    try:
        doc = _get_nlp()(text)
    except Exception as exc:
        return entities, [f"spaCy NER unavailable: {type(exc).__name__}"]
    mapping = {"PERSON": "persons", "ORG": "organizations", "MONEY": "money", "DATE": "dates", "GPE": "locations"}
    for ent in doc.ents:
        destination = mapping.get(ent.label_)
        if destination and ent.text not in entities[destination]:
            entities[destination].append(ent.text)
    return entities, []
