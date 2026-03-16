from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import uvicorn

from detector.models import AnalysisResult
from detector.service import analyze

from .storage import get_analysis, init_db, list_analyses, save_analysis
from .validators import validate_url
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))


BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Phishing Detector API", version="1.0.0")


# CORS: restringe por padrão; pode ser ajustado conforme necessidade
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


class AnalyzeRequest(BaseModel):
    url: str


class AnalysisSummary(BaseModel):
    id: int
    url: str
    risk_score: int
    risk_level: str
    created_at: str


templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult)
def analyze_url(payload: AnalyzeRequest) -> AnalysisResult:
    url = validate_url(payload.url)
    result = analyze(url)
    save_analysis(result)
    return result


@app.get("/history", response_model=List[AnalysisSummary])
def get_history(limit: int = 20, offset: int = 0) -> List[AnalysisSummary]:
    items = list_analyses(limit=limit, offset=offset)
    return [AnalysisSummary(**item) for item in items]


@app.get("/history/{analysis_id}", response_model=AnalysisResult)
def get_history_item(analysis_id: int) -> AnalysisResult:
    result = get_analysis(analysis_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found.",
        )
    return result

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)