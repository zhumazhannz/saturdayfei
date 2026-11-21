# Детектор DGA (`dga_detector.py`) — Жумажанов Н

Компонент «Детектор DGA» из раздела 2.2 отчёта. Принимает домены (или `dns_events` от парсера), отдаёт `domain_scores`.

## Подключение в конвейер (для `main.py`)

```python
from dga_detector import DGADetector, load_list

det = DGADetector.load("models/dga_rf.joblib",
                       whitelist=load_list("data/whitelist.txt"),
                       blacklist=load_list("data/blacklist.txt"))
domain_scores = det.score_dns_events(dns_events)   # dns_events — DataFrame с колонкой query
```

`domain_scores`: `domain, sld, features (dict), dga_score (0–1), source (whitelist/blacklist/model), reasons (list)`.
`reasons` — объяснение для отчёта: какие признаки вышли за 5/95 перцентиль легитимных доменов.

## Структура

```
dga_detector.py               модуль + CLI (train / eval / score)
models/dga_rf.joblib          обученная модель (UMUDGA + Tranco)
data/umudga/*.txt             UMUDGA, 50 семейств DGA + legit, по 10 000 доменов
data/umudga_train.csv / test  выборки 80/20 (domain,label,family)
data/whitelist.txt            Tranco top-10 000
data/blacklist.txt            399 000 доменов UMUDGA, не вошедших в выборки (нет утечки в метрики)
data/words.txt                словарь ~9 500 английских слов
tools/build_umudga_dataset.py сборка выборок
tools/lofo.py                 проверка на неизвестных семействах
results/                      результаты экспериментов
tests/                        тесты
```

## Воспроизведение

```
python tools/build_umudga_dataset.py --tranco top-1m.csv   # top-1m.csv с https://tranco-list.eu
python dga_detector.py train --data data/umudga_train.csv
python dga_detector.py eval  --data data/umudga_test.csv --whitelist data/whitelist.txt
python tools/lofo.py
python tests/test_dga_detector.py
```

Результаты и текст для отчёта — в `ОТЧЁТ_DGA.md`.
