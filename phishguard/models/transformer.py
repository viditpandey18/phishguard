"""Fine-tuned transformer text classifier (optional; needs torch + transformers).

Recommended base models (see training/train_transformer.py):
  * ``xlm-roberta-base``   - strong multilingual incl. Hindi; handles Hinglish ok
  * ``google/muril-base-cased`` - trained on Indian languages + transliterated text
  * ``distilbert-base-multilingual-cased`` - smaller/faster, lower accuracy

Explanations use gradient x input saliency over tokens - cheaper than SHAP
for transformers and adequate for "which words drove this" UX.
"""

from __future__ import annotations

from pathlib import Path


class TransformerTextModel:
    name = "transformer"

    def __init__(self, model_dir: Path, max_length: int = 256) -> None:
        import torch  # noqa: F401 - imported lazily so the base install stays light
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        # local_files_only: never download weights at serving time
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir, local_files_only=True)
        self.model.eval()
        self.max_length = max_length
        self.version = Path(model_dir).name

    def predict_proba(self, text: str) -> float:
        enc = self.tokenizer(text, truncation=True, max_length=self.max_length, return_tensors="pt")
        with self.torch.no_grad():
            logits = self.model(**enc).logits
        return float(self.torch.softmax(logits, dim=-1)[0, 1])

    def explain(self, text: str, top_k: int = 5) -> list[tuple[str, float]]:
        enc = self.tokenizer(text, truncation=True, max_length=self.max_length, return_tensors="pt")
        embeds = self.model.get_input_embeddings()(enc["input_ids"]).detach().requires_grad_(True)
        out = self.model(inputs_embeds=embeds, attention_mask=enc["attention_mask"]).logits
        (out[0, 1] - out[0, 0]).backward()
        scores = (embeds.grad * embeds).sum(-1)[0].tolist()
        tokens = self.tokenizer.convert_ids_to_tokens(enc["input_ids"][0])
        pairs = [(t, s) for t, s in zip(tokens, scores) if t not in self.tokenizer.all_special_tokens]
        return sorted(pairs, key=lambda kv: -kv[1])[:top_k]
