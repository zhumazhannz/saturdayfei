# 10. Заново обучить детектор DGA

Данные UMUDGA уже лежат в `dga/data/umudga/`. Нужен список Tranco: скачать https://tranco-list.eu/top-1m.csv.zip и распаковать `top-1m.csv` в папку `dga/data/`.

```
python dga/tools/build_umudga_dataset.py --tranco dga/data/top-1m.csv
```
```
python dga/dga_detector.py train --data dga/data/umudga_train.csv
```
```
python dga/dga_detector.py eval --data dga/data/umudga_test.csv --whitelist dga/data/whitelist.txt
```

Проверка на неизвестных семействах (~20 минут):
```
python dga/tools/lofo.py
```

Проверить один домен:
```
python dga/dga_detector.py score --whitelist dga/data/whitelist.txt google.com xjw8qpl2zkq.net
```
