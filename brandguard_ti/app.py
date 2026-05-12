from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.analyzer import AnalysisInput, BrandGuardAnalyzer

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUTS_DIR = BASE_DIR / "outputs"

app = FastAPI(title="BrandGuard Threat Intel Demo", version="4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.mount("/samples", StaticFiles(directory=SAMPLES_DIR), name="samples")
app.mount("/outputs", StaticFiles(directory=OUTPUTS_DIR), name="outputs")

INDEX_HTML = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
analyzer = BrandGuardAnalyzer()

_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _job_view(job_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        return {
            "job_id": job_id,
            "status": job["status"],
            "progress": job["progress"],
            "message": job["message"],
            "result": job.get("result"),
            "error": job.get("error"),
        }


def _update_job(job_id: str, **fields: Any) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.update(fields)


def _run_job(job_id: str, payload: AnalysisInput, logo_blobs: list[bytes]) -> None:
    try:
        _update_job(job_id, status="running", progress=6, message="Capturing the webpage")

        def progress(pct: int, message: str) -> None:
            _update_job(job_id, progress=pct, message=message)

        result = analyzer.analyze(payload, reference_logos=logo_blobs or None, progress=progress)
        _update_job(job_id, status="done", progress=100, message="Analysis complete", result=result)
    except Exception as exc:  # pragma: no cover - job runner
        _update_job(job_id, status="error", progress=100, message="Analysis failed", error=str(exc))


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/meta")
def meta() -> dict[str, object]:
    return {
        "name": "BrandGuard Threat Intel Demo",
        "capabilities": [
            "passive URL inspection",
            "phishing heuristics",
            "trademark and brand impersonation scoring",
            "public threat-intel enrichment",
            "hosting and ASN attribution",
            "progressive job updates",
        ],
        "extensibility": [
            "brand profiles via JSON",
            "new detectors without UI changes",
            "more intel providers can be added later",
        ],
    }


@app.post("/api/analyze/start")
async def analyze_start(
    url: str = Form(...),
    brand_name: str = Form(""),
    official_domain: str = Form(""),
    max_images: int = Form(5),
    timeout_ms: int = Form(12000),
    logo_files: list[UploadFile] | None = File(default=None),
):
    target_url = url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="URL is required")

    logo_blobs: list[bytes] = []
    if logo_files:
        for item in logo_files:
            try:
                logo_blobs.append(await item.read())
            except Exception:
                continue

    job_id = uuid.uuid4().hex
    payload = AnalysisInput(
        url=target_url,
        brand_name=brand_name.strip(),
        official_domain=official_domain.strip(),
        max_images=max(1, min(int(max_images), 10)),
        timeout_ms=max(5000, min(int(timeout_ms), 12000)),
    )
    with _jobs_lock:
        _jobs[job_id] = {
            "status": "queued",
            "progress": 0,
            "message": "Queued for analysis",
            "result": None,
            "error": None,
        }
    thread = threading.Thread(target=_run_job, args=(job_id, payload, logo_blobs), daemon=True)
    thread.start()
    return JSONResponse({"job_id": job_id, "status_url": f"/api/analyze/status/{job_id}"})


@app.get("/api/analyze/status/{job_id}")
def analyze_status(job_id: str):
    try:
        return JSONResponse(_job_view(job_id))
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")


@app.post("/api/analyze")
async def analyze_compatibility(
    url: str = Form(...),
    brand_name: str = Form(""),
    official_domain: str = Form(""),
    max_images: int = Form(5),
    timeout_ms: int = Form(12000),
    logo_files: list[UploadFile] | None = File(default=None),
):
    target_url = url.strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="URL is required")

    logo_blobs: list[bytes] = []
    if logo_files:
        for item in logo_files:
            try:
                logo_blobs.append(await item.read())
            except Exception:
                continue

    result = analyzer.analyze(
        AnalysisInput(
            url=target_url,
            brand_name=brand_name.strip(),
            official_domain=official_domain.strip(),
            max_images=max(1, min(int(max_images), 10)),
            timeout_ms=max(5000, min(int(timeout_ms), 12000)),
        ),
        reference_logos=logo_blobs or None,
    )
    return JSONResponse(result)


@app.get("/sample/{name}")
def sample(name: str):
    p = SAMPLES_DIR / f"{name}.html"
    if not p.exists():
        raise HTTPException(status_code=404, detail="Sample not found")
    return FileResponse(p)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
