# vectorstore/vectorizer.py
from sentence_transformers import SentenceTransformer
import numpy as np

MODEL_NAME = "all-MiniLM-L6-v2"
model = SentenceTransformer(MODEL_NAME)

def embed_text(texts):
    """Embed a list of texts using SentenceTransformer."""
    if not texts:
        return []
    return model.encode(texts, show_progress_bar=False)

def embed_single(text):
    return embed_text([text])[0]
