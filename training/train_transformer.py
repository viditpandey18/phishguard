"""Fine-tune a multilingual transformer for scam/phishing text classification.

    pip install -e .[transformer]
    python training/train_transformer.py --base xlm-roberta-base --epochs 3
    PG_TEXT_MODEL=transformer PG_TRANSFORMER_MODEL_DIR=phishguard/models/artifacts/transformer uvicorn ...

Model choice trade-offs:
  * xlm-roberta-base (278M): best default for English + Hindi; Hinglish OK.
  * google/muril-base-cased (237M): trained on 17 Indian languages incl.
    transliterated text -> usually best on Hinglish; weaker on English email.
  * distilbert-base-multilingual-cased (134M): ~2x faster on CPU, lower recall.
For CPU serving, export to ONNX + int8 quantisation (roadmap) for ~4x speed-up.

Training notes: class-weighted loss for imbalance; early stopping on
validation PR-AUC (not accuracy); fixed seed; max_length 256 covers >95% of
SMS and email bodies after truncation.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np

from common import ARTIFACTS, fmt_metrics, load_splits, record_text, write_report
from phishguard.eval.metrics import average_precision, full_report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="xlm-roberta-base")
    ap.add_argument("--epochs", type=float, default=3)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--out", type=Path, default=ARTIFACTS / "transformer")
    args = ap.parse_args()

    import torch
    from datasets import Dataset
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer, EarlyStoppingCallback, Trainer,
                              TrainingArguments, set_seed)

    set_seed(42)
    splits = load_splits()
    data = {}
    for s, rows in splits.items():
        rows = [r for r in rows if r["input_type"] in ("text", "email")]
        data[s] = Dataset.from_dict({"text": [record_text(r) for r in rows], "label": [r["label"] for r in rows]})

    tok = AutoTokenizer.from_pretrained(args.base)
    enc = {s: d.map(lambda b: tok(b["text"], truncation=True, max_length=args.max_length), batched=True)
           for s, d in data.items()}
    model = AutoModelForSequenceClassification.from_pretrained(args.base, num_labels=2)

    y = np.array(data["train"]["label"])
    weights = torch.tensor([len(y) / (2 * max(1, (y == 0).sum())), len(y) / (2 * max(1, (y == 1).sum()))],
                           dtype=torch.float)

    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            loss = torch.nn.functional.cross_entropy(out.logits, labels, weight=weights.to(out.logits.device))
            return (loss, out) if return_outputs else loss

    def metrics(p):
        probs = torch.softmax(torch.tensor(p.predictions), -1)[:, 1].numpy()
        return {"pr_auc": average_precision(p.label_ids, probs)}

    targs = TrainingArguments(
        output_dir=str(args.out / "checkpoints"), num_train_epochs=args.epochs, learning_rate=args.lr,
        per_device_train_batch_size=args.batch, per_device_eval_batch_size=args.batch * 2,
        eval_strategy="epoch", save_strategy="epoch", load_best_model_at_end=True,
        metric_for_best_model="pr_auc", greater_is_better=True, weight_decay=0.01, warmup_ratio=0.06,
        logging_steps=50, report_to=[], seed=42)
    trainer = WeightedTrainer(model=model, args=targs, train_dataset=enc["train"], eval_dataset=enc["val"],
                              tokenizer=tok, compute_metrics=metrics,
                              callbacks=[EarlyStoppingCallback(early_stopping_patience=2)])
    trainer.train()

    pred = trainer.predict(enc["test"])
    probs = torch.softmax(torch.tensor(pred.predictions), -1)[:, 1].numpy()
    rep = full_report(np.array(data["test"]["label"]), probs)
    print(f"[transformer test] {fmt_metrics(rep)}")
    trainer.save_model(str(args.out))
    tok.save_pretrained(str(args.out))
    write_report("transformer", {"base": args.base, "test": rep})


if __name__ == "__main__":
    main()
