"""
Простейший ML‑сервис для предиктивного анализа URL.

Поддерживает загрузку весов из JSON (после обучения скриптом scripts/train_url_ml.py).
Если файл не задан или не найден — используется встроенная линейная заглушка.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List
from urllib.parse import urlparse
import json
import math
import os

# Порядок признаков для совместимости с экспортом из train_url_ml.py
FEATURE_NAMES: List[str] = [
    "url_len",
    "domain_len",
    "digit_count",
    "subdomain_depth",
    "susp_kw_count",
    "external_flag",
    "heur_score",
]


@dataclass
class UrlMlResult:
    ml_score: float  # 0.0–1.0, чем выше — тем опаснее
    label: str       # 'safe' | 'suspicious' | 'malicious'


class UrlRiskMlModel:
    """
    ML‑модель для оценки риска URL.
    Загружает веса из JSON (URL_ML_MODEL_PATH), иначе использует встроенные коэффициенты.
    """

    _DEFAULT_WEIGHTS = {
        "url_len": 0.015,
        "domain_len": 0.0,
        "digit_count": 0.4,
        "subdomain_depth": 0.3,
        "susp_kw_count": 0.6,
        "external_flag": 1.2,
        "heur_score": 0.8,
    }
    _DEFAULT_BIAS = -2.0
    _THRESHOLD_SUSPICIOUS = 0.5
    _THRESHOLD_MALICIOUS = 0.8

    def __init__(self) -> None:
        self._weights: Dict[str, float] = dict(self._DEFAULT_WEIGHTS)
        self._bias = self._DEFAULT_BIAS
        self._threshold_suspicious = self._THRESHOLD_SUSPICIOUS
        self._threshold_malicious = self._THRESHOLD_MALICIOUS
        self._model_path: str | None = None
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        path = os.getenv("URL_ML_MODEL_PATH") or (Path(__file__).parent / "data" / "url_ml_model.json")
        path = Path(path)
        if not path.is_file():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._weights = dict(data.get("weights", self._DEFAULT_WEIGHTS))
            self._bias = float(data.get("bias", self._DEFAULT_BIAS))
            self._threshold_suspicious = float(data.get("threshold_suspicious", self._THRESHOLD_SUSPICIOUS))
            self._threshold_malicious = float(data.get("threshold_malicious", self._THRESHOLD_MALICIOUS))
            self._model_path = str(path)
        except Exception:
            pass

    def _sigmoid(self, x: float) -> float:
        try:
            return 1.0 / (1.0 + math.exp(-x))
        except OverflowError:
            return 0.0 if x < 0 else 1.0

    def _extract_features(
        self,
        url: str,
        domain: str,
        external_result: Dict[str, Any] | None,
        heuristic_result: Dict[str, Any] | None,
    ) -> Dict[str, float]:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        full = (url or "").lower()

        url_len = min(len(url or ""), 3000)
        domain_len = min(len(domain or ""), 255)
        digit_count = sum(ch.isdigit() for ch in domain or "")
        subdomain_depth = (domain or "").count(".")

        suspicious_keywords = [
            "login",
            "signin",
            "verify",
            "secure",
            "account",
            "update",
            "billing",
            "support",
            "bank",
            "wallet",
            "crypto",
        ]
        susp_kw_count = 0
        for kw in suspicious_keywords:
            if kw in full:
                susp_kw_count += 1

        # Внешние API / TI
        external_flag = 0.0
        if external_result:
            if external_result.get("safe") is False or external_result.get("threat_type"):
                external_flag = 1.0

        # Признаки из уже посчитанной эвристики (если есть)
        heur_score = 0.0
        if heuristic_result:
            try:
                heur_score = float(heuristic_result.get("riskScore") or 0.0)
            except Exception:
                heur_score = 0.0

        return {
            "url_len": float(url_len),
            "domain_len": float(domain_len),
            "digit_count": float(digit_count),
            "subdomain_depth": float(subdomain_depth),
            "susp_kw_count": float(susp_kw_count),
            "external_flag": external_flag,
            "heur_score": heur_score / 100.0,  # нормализуем до 0–1
        }

    def evaluate(
        self,
        url: str,
        domain: str,
        external_result: Dict[str, Any] | None,
        heuristic_result: Dict[str, Any] | None,
    ) -> UrlMlResult:
        """
        Основной метод: возвращает ml_score и текстовую метку.
        """
        feats = self._extract_features(url, domain, external_result, heuristic_result)

        # Нормализация как при обучении
        url_len_norm = (feats["url_len"] / 200.0) if feats["url_len"] else 0.0
        z = self._bias
        z += self._weights.get("url_len", 0.0) * url_len_norm
        z += self._weights.get("domain_len", 0.0) * (feats["domain_len"] / 100.0)
        z += self._weights.get("digit_count", 0.0) * feats["digit_count"]
        z += self._weights.get("subdomain_depth", 0.0) * feats["subdomain_depth"]
        z += self._weights.get("susp_kw_count", 0.0) * feats["susp_kw_count"]
        z += self._weights.get("external_flag", 0.0) * feats["external_flag"]
        z += self._weights.get("heur_score", 0.0) * feats["heur_score"]

        score = float(self._sigmoid(z))

        if score >= self._threshold_malicious:
            label = "malicious"
        elif score >= self._threshold_suspicious:
            label = "suspicious"
        else:
            label = "safe"

        return UrlMlResult(ml_score=score, label=label)

