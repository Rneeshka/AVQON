import os
from pathlib import Path

from app.ml_url_model import UrlRiskMlModel
from app.external_apis.whoisxml import WhoisXMLClient
from app.ssl_info import get_ssl_info
from app.external_apis.urlscan import URLScanClient


def test_ml_model_default_evaluate():
    model = UrlRiskMlModel()
    res = model.evaluate(
        url="https://example.com/login",
        domain="example.com",
        external_result=None,
        heuristic_result={"riskScore": 50},
    )
    assert 0.0 <= res.ml_score <= 1.0
    assert res.label in {"safe", "suspicious", "malicious"}


def test_ml_model_load_from_json_tmp(tmp_path):
    model_path = tmp_path / "url_ml_model.json"
    model_path.write_text(
        '{"
bias": -1.0, "weights": {"url_len": 0.0, "domain_len": 0.0, "digit_count": 1.0, '
        '"subdomain_depth": 0.0, "susp_kw_count": 0.0, "external_flag": 0.0, "heur_score": 0.0}, '
        '"threshold_suspicious": 0.3, "threshold_malicious": 0.7}',
        encoding="utf-8",
    )
    os.environ["URL_ML_MODEL_PATH"] = str(model_path)
    try:
        model = UrlRiskMlModel()
        res = model.evaluate(
            url="https://ex4mpl3.com/",
            domain="ex4mpl3.com",
            external_result=None,
            heuristic_result=None,
        )
        assert 0.0 <= res.ml_score <= 1.0
    finally:
        os.environ.pop("URL_ML_MODEL_PATH", None)


def test_whois_client_disabled_without_key():
    client = WhoisXMLClient()
    assert not client.enabled


def test_urlscan_client_disabled_without_key():
    client = URLScanClient()
    assert not client.enabled


def test_ssl_info_empty_hostname():
    import asyncio

    async def _run():
        res = await get_ssl_info("")
        assert res.get("ssl_issuer") is None

    asyncio.run(_run())

