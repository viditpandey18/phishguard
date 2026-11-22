PY ?= python

.PHONY: install dev test lint run demo-train data train evaluate docker

install:      ## runtime deps
	$(PY) -m pip install -e .
dev:          ## runtime + test deps
	$(PY) -m pip install -e .[dev]
test:
	$(PY) -m pytest
lint:
	$(PY) -m ruff check phishguard tests training data
run:
	uvicorn phishguard.api.main:app --reload --port 8000
demo-train:   ## plumbing check on the tiny seed set (NOT a usable model)
	$(PY) data/prepare.py --sources seed
	$(PY) training/train_text_baseline.py --epochs 150
	$(PY) training/train_ensemble.py
	$(PY) training/evaluate.py
data:         ## download + prepare open datasets (read licences first!)
	$(PY) data/download.py sms_spam spamassassin nazario tranco openphish
	$(PY) data/prepare.py --sources seed sms_spam spamassassin nazario tranco openphish
train:
	$(PY) training/train_text_baseline.py --compare-sklearn
	$(PY) training/train_ensemble.py --compare-gbm
evaluate:
	$(PY) training/evaluate.py
docker:
	docker compose up --build
