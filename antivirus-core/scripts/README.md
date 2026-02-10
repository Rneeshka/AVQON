## Скрипты для ML и датасетов URL

### 1. Сбор датасета

- **PhishTank + OpenPhish + безопасные URL**  
  Скрипт: `scripts/build_ml_dataset.py`  
  Результат: CSV `url,label` (0 = safe, 1 = phishing).

Примеры:

```bash
cd antivirus-core
python scripts/build_ml_dataset.py --output scripts/url_ml_train.csv
python scripts/build_ml_dataset.py --output train.csv --safe-urls my_safe_list.txt \
  --max-phish 5000 --max-openphish 2000
```

Есть также примерный маленький датасет:  
`scripts/sample_url_dataset.csv` — подходит для быстрой проверки пайплайна.

### 2. Обучение ML-модели

Скрипт: `scripts/train_url_ml.py`  
Ожидает CSV с колонками `url,label` (0/1 или строки safe/phishing/malicious).

```bash
cd antivirus-core
pip install pandas scikit-learn  # для логистической регрессии

# Обучение на собранном датасете
python scripts/train_url_ml.py --data scripts/url_ml_train.csv \
  --output app/data/url_ml_model.json

# С LightGBM (по желанию)
pip install lightgbm
python scripts/train_url_ml.py --data scripts/url_ml_train.csv \
  --output app/data/url_ml_model.json --model lightgbm
```

Модель сохраняется в `app/data/url_ml_model.json`.  
Бэкенд (`UrlRiskMlModel`) автоматически подхватит этот файл при старте.
Можно переопределить путь через переменную окружения `URL_ML_MODEL_PATH`.

### 3. Включение URLScan.io

Интеграция URLScan.io уже реализована в бэкенде (`external_apis/urlscan.py`, менеджер API).  
Чтобы её включить:

1. Получить API‑ключ на `https://urlscan.io`.
2. В `antivirus-core/app/env.env` добавить строку:

```env
URLSCAN_API_KEY=ваш_ключ
```

3. Перезапустить бэкенд.

При отсутствии ключа URLScan просто не вызывается (остальные TI‑источники продолжают работать).

