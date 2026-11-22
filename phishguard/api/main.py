"""FastAPI service.

Run:  uvicorn phishguard.api.main:app --host 0.0.0.0 --port 8000
Docs: http://localhost:8000/docs (disabled when PG_ENVIRONMENT=prod)
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from pathlib import Path

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from phishguard import __version__
from phishguard.analyzer import Analyzer
from phishguard.api.security import (
    SECURITY_HEADERS,
    UI_CSP,
    BodySizeLimitMiddleware,
    TokenBucketLimiter,
    check_api_key,
    client_key,
)
from phishguard.config import Settings, get_settings
from phishguard.logging_utils import configure_logging, redact
from phishguard.sanitize import InputTooLargeError
from phishguard.schemas import (
    FeedbackRequest,
    FeedbackResponse,
    ScanAutoRequest,
    ScanEmailRequest,
    ScanResponse,
    ScanTextRequest,
    ScanURLRequest,
)

log = logging.getLogger("phishguard.api")
STATIC_DIR = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None, analyzer: Analyzer | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.analyzer = analyzer or Analyzer(settings)
        log.info("phishguard started", extra={"version": __version__,
                                              "text_model": getattr(app.state.analyzer.text_model, "name", None),
                                              "network_intel": settings.enable_network_intel,
                                              "active_probing": settings.enable_active_probing})
        yield

    prod = settings.environment == "prod"
    app = FastAPI(title="PhishGuard", version=__version__, lifespan=lifespan,
                  description="Defensive detection of scam messages, phishing emails and phishing URLs.",
                  docs_url=None if prod else "/docs", redoc_url=None, openapi_url=None if prod else "/openapi.json")
    app.state.settings = settings
    app.state.limiter = TokenBucketLimiter(settings.rate_limit_per_minute, settings.rate_limit_burst)

    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    if settings.cors_origin_list:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_methods=["GET", "POST"],
                           allow_headers=["content-type", "x-api-key"], allow_credentials=False)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if request.url.path.startswith("/ui"):
            response.headers["Content-Security-Policy"] = UI_CSP
        return response

    # Built-in web UI (plain HTML/JS, no extra dependencies). Disable with PG_ENABLE_WEB_UI=false.
    if settings.enable_web_ui:
        app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")

        @app.get("/", include_in_schema=False)
        def root() -> RedirectResponse:
            return RedirectResponse("/ui/")

    # ---------------------------------------------------------------- deps
    def guard(request: Request) -> Analyzer:
        check_api_key(request, settings.api_key_set)
        allowed, retry = app.state.limiter.allow(client_key(request, settings.trust_proxy_headers))
        if not allowed:
            raise HTTPException(status_code=429, detail="rate limit exceeded",
                                headers={"Retry-After": str(max(1, int(retry + 0.5)))})
        return request.app.state.analyzer

    def run(an: Analyzer, content: str | bytes, input_type: str) -> ScanResponse:
        try:
            return an.analyze(content, input_type)
        except InputTooLargeError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from None

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # never leak internals / content
        log.error("unhandled error", extra={"path": request.url.path, "error": type(exc).__name__})
        return JSONResponse(status_code=500, content={"detail": "internal error"})

    # ---------------------------------------------------------------- routes
    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/v1/info")
    def info(request: Request) -> dict:
        an: Analyzer = request.app.state.analyzer
        return {
            "version": __version__,
            "ensemble": an.scorer.version,
            "text_model": getattr(an.text_model, "name", None),
            "calibrated": an.scorer.calibrator is not None,
            "thresholds": {"suspicious": an.scorer.t_susp, "malicious": an.scorer.t_mal},
            "intel_providers": [p.name for p in an.providers if p.available()],
            "stores_content": settings.store_content,
        }

    # Sync handlers: FastAPI runs them in a threadpool, so CPU-bound analysis
    # does not block the event loop.
    @app.post("/v1/scan", response_model=ScanResponse)
    def scan(req: ScanAutoRequest, an: Analyzer = Depends(guard)) -> ScanResponse:
        return run(an, req.content, req.input_type)

    @app.post("/v1/scan/text", response_model=ScanResponse)
    def scan_text(req: ScanTextRequest, an: Analyzer = Depends(guard)) -> ScanResponse:
        return run(an, req.text, "text")

    @app.post("/v1/scan/url", response_model=ScanResponse)
    def scan_url(req: ScanURLRequest, an: Analyzer = Depends(guard)) -> ScanResponse:
        return run(an, req.url, "url")

    @app.post("/v1/scan/email", response_model=ScanResponse)
    def scan_email(req: ScanEmailRequest, an: Analyzer = Depends(guard)) -> ScanResponse:
        return run(an, req.raw, "email")

    @app.post("/v1/scan/email/upload", response_model=ScanResponse)
    def scan_email_upload(file: UploadFile = File(...), an: Analyzer = Depends(guard)) -> ScanResponse:
        data = file.file.read(settings.max_email_bytes + 1)
        if len(data) > settings.max_email_bytes:
            raise HTTPException(status_code=413, detail="email too large")
        return run(an, data, "email")

    @app.post("/v1/feedback", response_model=FeedbackResponse)
    def feedback(req: FeedbackRequest, request: Request, an: Analyzer = Depends(guard)) -> FeedbackResponse:
        """Collects label corrections for active learning. Stores *features only*
        (signal vector + model score), never the message, unless PG_STORE_CONTENT=true."""
        cached = an.feature_cache.get(req.scan_id)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(), "scan_id": req.scan_id, "correct_label": req.correct_label,
            "predicted": cached.get("label") if cached else None, "input_type": cached.get("input_type") if cached else None,
            "features": cached.get("features") if cached else None, "model_prob": cached.get("model_prob") if cached else None,
            "comment": redact(req.comment) if req.comment else None,
        }
        path = settings.feedback_file
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return FeedbackResponse(accepted=True, stored_features=cached is not None)

    return app


app = create_app()
