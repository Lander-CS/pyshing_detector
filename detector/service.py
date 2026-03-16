from __future__ import annotations

from datetime import datetime
from typing import Iterable, List

from pydantic import HttpUrl

from .domain_analyzer import analyze_domain_indicators
from .html_analyzer import analyze_html
from .url_analyzer import analyze_url
from .typosquat_detector import detect_typosquatting_indicators

from .models import (
    AnalysisResult,
    Indicator,
    IndicatorCategory,
    RiskLevel,
    Severity,
)


RISK_WEIGHTS = {
    IndicatorCategory.URL_KEYWORD: 1,
    IndicatorCategory.URL_STRUCTURE: 1,
    IndicatorCategory.DOMAIN_MISSING: 2,
    IndicatorCategory.DOMAIN_METADATA: 1,
    IndicatorCategory.HTML_ISSUE: 1,
    IndicatorCategory.BRAND: 4,
    IndicatorCategory.TYPOSQUAT: 5,
    IndicatorCategory.OTHER: 0,
}


def _calculate_risk(indicators: Iterable[Indicator]) -> int:
    score = 0
    for indicator in indicators:
        score += RISK_WEIGHTS.get(indicator.category, 0)
    return min(score, 10)


def _classify_risk_level(score: int) -> RiskLevel:
    if score <= 2:
        return RiskLevel.LOW
    if 3 <= score <= 5:
        return RiskLevel.MEDIUM
    if 6 <= score <= 8:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def analyze(url: str | HttpUrl) -> AnalysisResult:
    """
    Executa toda a análise de phishing para a URL informada e
    retorna um AnalysisResult estruturado.
    """
    url_str = str(url)

    indicators: List[Indicator] = []

    # URL analysis
    indicators.extend(analyze_url(url_str))

    # Domain analysis
    indicators.extend(analyze_domain_indicators(url_str))

    # HTML analysis
    indicators.extend(analyze_html(url_str))

    # Typosquatting analysis
    indicators.extend(detect_typosquatting_indicators(url_str))

    risk_score = _calculate_risk(indicators)
    risk_level = _classify_risk_level(risk_score)

    return AnalysisResult(
        url=url_str,
        indicators=indicators,
        risk_score=risk_score,
        risk_level=risk_level,
        created_at=datetime.utcnow(),
    )

