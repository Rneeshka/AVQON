#!/usr/bin/env python3
"""
Обучение ML-модели для оценки риска URL (фишинг / безопасный).

Использование:
  pip install pandas scikit-learn
  # CSV: url, label (0=safe, 1=phishing или safe/phishing/malicious)
  python scripts/train_url_ml.py --data train.csv --output app/data/url_ml_model.json

Опционально для LightGBM (лучшая точность):
  pip install lightgbm
  python scripts/train_url_ml.py --data train.csv --output app/data/url_ml_model.json --model lightgbm
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

# Добавляем корень проекта в path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import pandas as pd
    import numpy as np
except ImportError:
    print("Установите: pip install pandas numpy")
    sys.exit(1)

FEATURE_NAMES = [
    "url_len",
    "domain_len",
    "digit_count",
    "subdomain_depth",
    "susp_kw_count",
    "external_flag",
    "heur_score",
]
SUSP_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "billing", "support", "bank", "wallet", "crypto",
]


def extract_features_row(url: str) -> dict:
    """Извлечение признаков из URL (без external/heuristic)."""
    try:
        parsed = urlparse(url)
        domain = (parsed.netloc or "").lower()
        full = (url or "").lower()
    except Exception:
        domain = ""
        full = (url or "").lower()
    url_len = min(len(url or ""), 3000)
    domain_len = min(len(domain), 255)
    digit_count = sum(ch.isdigit() for ch in domain)
    subdomain_depth = domain.count(".")
    susp_kw_count = sum(1 for kw in SUSP_KEYWORDS if kw in full)
    external_flag = 0.0
    heur_score = 0.0
    return {
        "url_len": url_len / 200.0,
        "domain_len": domain_len / 100.0,
        "digit_count": float(digit_count),
        "subdomain_depth": float(subdomain_depth),
        "susp_kw_count": float(susp_kw_count),
        "external_flag": external_flag,
        "heur_score": heur_score,
    }


def main():
    parser = argparse.ArgumentParser(description="Train URL risk ML model")
    parser.add_argument("--data", required=True, help="CSV with columns: url, label (0/1 or safe/phishing)")
    parser.add_argument("--output", default="app/data/url_ml_model.json", help="Output JSON path")
    parser.add_argument("--model", choices=["logistic", "lightgbm"], default="logistic")
    args = parser.parse_args()

    data_path = Path(args.data)
    if not data_path.is_file():
        print(f"File not found: {data_path}")
        sys.exit(1)

    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        print("CSV must have columns: url, label")
        sys.exit(1)

    # Нормализация меток: 0 = safe, 1 = phishing/malicious
    def norm_label(v):
        if isinstance(v, (int, float)):
            return 1 if v else 0
        s = str(v).strip().lower()
        if s in ("1", "phishing", "malicious", "bad", "unsafe"):
            return 1
        return 0

    df["y"] = df["label"].apply(norm_label)
    X_list = []
    for url in df["url"].astype(str):
        f = extract_features_row(url)
        X_list.append([f[k] for k in FEATURE_NAMES])
    X = np.array(X_list, dtype=np.float64)
    y = np.array(df["y"].tolist())

    if args.model == "lightgbm":
        try:
            import lightgbm as lgb
        except ImportError:
            print("LightGBM not installed, falling back to logistic. pip install lightgbm")
            args.model = "logistic"
    if args.model == "lightgbm":
        import lightgbm as lgb
        model = lgb.LGBMClassifier(n_estimators=100, max_depth=5, random_state=42, verbosity=-1)
        model.fit(X, y)
        # Экспорт: используем веса как линейную аппроксимацию (средние по деревьям)
        imp = model.feature_importances_
        imp = imp / (imp.sum() or 1e-9) * 10
        bias = -5.0
        weights = {name: float(imp[i]) for i, name in enumerate(FEATURE_NAMES)}
    else:
        from sklearn.linear_model import LogisticRegression
        model = LogisticRegression(max_iter=500, random_state=42)
        model.fit(X, y)
        coef = model.coef_[0]
        bias = float(model.intercept_[0])
        weights = {name: float(coef[i]) for i, name in enumerate(FEATURE_NAMES)}

    out = {
        "bias": bias,
        "weights": weights,
        "threshold_suspicious": 0.5,
        "threshold_malicious": 0.8,
        "feature_names": FEATURE_NAMES,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"Model saved to {out_path}")


if __name__ == "__main__":
    main()
