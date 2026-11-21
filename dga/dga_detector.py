"""
dga_detector.py — модуль детектирования DGA-доменов (Студент 3).

Вход:  список доменов или DataFrame dns_events (колонка `query`) от pcap_parser.py.
Выход: DataFrame domain_scores с колонками
        domain, sld, features (dict), dga_score (0–1), source, reasons

source:
    whitelist — домен в белом списке (Tranco), score = 0
    blacklist — домен в чёрном списке известных DGA, score = 1
    model     — оценка Random Forest по лексическим признакам

CLI:
    python dga_detector.py train --data data/train.csv --model models/dga_rf.joblib
    python dga_detector.py eval  --data data/test.csv  --model models/dga_rf.joblib
    python dga_detector.py score --model models/dga_rf.joblib google.com xjw8qpl2zk.net
"""
from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score

HERE = Path(__file__).resolve().parent
DEFAULT_WORDS = HERE / "data" / "words.txt"

VOWELS = set("aeiouy")
CONSONANTS = set("bcdfghjklmnpqrstvwxz")

# Двухуровневые публичные суффиксы (упрощённо, без внешней зависимости tldextract)
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "com.kz", "org.kz", "gov.kz", "edu.kz", "net.kz", "com.ru", "org.ru",
    "com.br", "com.cn", "net.cn", "org.cn", "co.jp", "ne.jp", "co.kr",
    "co.in", "com.tr", "com.ua", "com.mx", "co.za", "com.sg", "com.hk",
}
COMMON_TLDS = {
    "com", "net", "org", "ru", "kz", "de", "uk", "info", "io", "edu", "gov",
    "br", "jp", "cn", "fr", "it", "nl", "pl", "in", "au", "es", "ca", "us",
    "co", "tv", "me", "app", "dev", "eu", "ua", "tr", "ch", "se", "kr",
}

# Сервисы динамического DNS: ими пользуются DGA-семейства (corebot, symmi, kraken) — [8]
DYNDNS_SUFFIXES = {
    "ddns.net", "mooo.com", "dyndns.org", "dyndns.com", "no-ip.org", "no-ip.com",
    "no-ip.biz", "no-ip.info", "noip.me", "hopto.org", "zapto.org", "sytes.net",
    "duckdns.org", "dynu.net", "freeddns.org", "servebeer.com", "serveftp.com",
    "myftp.org", "redirectme.net", "chickenkiller.com", "afraid.org", "dnsdojo.com",
    "dynv6.net", "3utilities.com", "bounceme.net", "ddnsking.com", "gotdns.ch",
    "changeip.com", "dyn-ip24.de", "homeip.net", "kozow.com", "strangled.net",
    "us.to", "ignorelist.com", "crabdance.com", "twilightparadox.com", "uk.to",
}

FEATURE_NAMES = [
    "length",            # длина метки SLD
    "entropy",           # энтропия Шеннона
    "digit_ratio",       # доля цифр
    "vowel_ratio",       # доля гласных среди букв
    "max_consonant_run", # макс. серия согласных
    "bigram_logprob",    # средняя лог-вероятность биграмм по легитимным доменам
    "dict_ratio",        # доля символов, покрытых словарными словами
    "num_words",         # число словарных слов в метке
    "avg_word_len",      # средняя длина найденного слова
    "hyphen_count",      # число дефисов (словарные DGA вида word-word)
    "trigram_logprob",   # средняя лог-вероятность триграмм по легитимным доменам
    "num_labels",        # число меток (поддоменов) во всём имени
    "rare_tld",          # 1, если TLD не из списка частых
]

# Как признак «подозрителен»: направление сравнения с перцентилем легитимных доменов
SUSPICIOUS_DIRECTION = {
    "length": "high", "entropy": "high", "digit_ratio": "high",
    "vowel_ratio": "low", "max_consonant_run": "high",
    "bigram_logprob": "low", "trigram_logprob": "low", "dict_ratio": "low",
    "num_labels": "high", "hyphen_count": "high",
}


# ---------------------------------------------------------------- нормализация
def normalize(domain: str) -> str:
    d = str(domain).strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def split_domain(domain: str) -> tuple[str, str, str]:
    """Возвращает (registered_domain, sld, tld). sld — метка, которую оцениваем."""
    parts = [p for p in normalize(domain).split(".") if p]
    if len(parts) == 0:
        return "", "", ""
    if len(parts) == 1:
        return parts[0], parts[0], ""
    last2 = ".".join(parts[-2:])
    # Динамический DNS: имя выбирает клиент (в т.ч. бот), поэтому оцениваем поддомен,
    # а «зарегистрированным доменом» считаем sub.ddns.net — белый список ddns.net его не спасёт.
    if last2 in DYNDNS_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:]), parts[-3], last2
    if last2 in MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:]), parts[-3], last2
    return last2, parts[-2], parts[-1]


# ---------------------------------------------------------------- признаки
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def max_consonant_run(s: str) -> int:
    best = cur = 0
    for ch in s:
        cur = cur + 1 if ch in CONSONANTS else 0
        best = max(best, cur)
    return best


def load_words(path: Path = DEFAULT_WORDS) -> set[str]:
    if not Path(path).exists():
        return set()
    text = Path(path).read_text(encoding="utf-8")
    return {w for w in text.split() if len(w) >= 3}


def segment(s: str, words: set[str], max_len: int = 15) -> tuple[int, int]:
    """Оптимальная сегментация (динамическое программирование):
    максимум символов, покрытых словарными словами, при равенстве — минимум слов.
    Возвращает (покрыто_символов, число_слов). Дефисы и цифры считаются разделителями."""
    n = len(s)
    best = [(0, 0)] * (n + 1)  # (covered, -words) — сравниваем лексикографически
    for i in range(1, n + 1):
        cand = best[i - 1]
        for L in range(3, min(max_len, i) + 1):
            if s[i - L:i] in words:
                c, w = best[i - L]
                cand = max(cand, (c + L, w - 1))
        best[i] = cand
    return best[n][0], -best[n][1]


def dict_ratio(s: str, words: set[str]) -> float:
    if not s or not words:
        return 0.0
    return segment(s, words)[0] / len(s)


class BigramModel:
    """Лог-вероятности n-грамм символов (по умолчанию биграмм), обученные на легитимных доменах."""

    def __init__(self, n: int = 2):
        self.n = n
        self.logp: dict[str, float] = {}
        self.unseen = -12.0

    def fit(self, labels) -> "BigramModel":
        counts = Counter()
        n = self.n
        for s in labels:
            s = f"^{s}$"
            counts.update(s[i:i + n] for i in range(len(s) - n + 1))
        total = sum(counts.values()) or 1
        self.logp = {bg: math.log(c / total) for bg, c in counts.items()}
        self.unseen = math.log(0.5 / total)
        return self

    def score(self, s: str) -> float:
        s = f"^{s}$"
        n = self.n
        grams = [s[i:i + n] for i in range(max(len(s) - n + 1, 1))]
        return float(np.mean([self.logp.get(g, self.unseen) for g in grams]))


def extract_features(domain: str, bigram: BigramModel, words: set[str],
                     trigram: BigramModel | None = None) -> dict:
    d = normalize(domain)
    _, sld, tld = split_domain(d)
    letters = [c for c in sld if c.isalpha()]
    covered, nwords = segment(sld, words) if words else (0, 0)
    return {
        "length": len(sld),
        "entropy": round(shannon_entropy(sld), 4),
        "digit_ratio": round(sum(c.isdigit() for c in sld) / max(len(sld), 1), 4),
        "vowel_ratio": round(sum(c in VOWELS for c in letters) / max(len(letters), 1), 4),
        "max_consonant_run": max_consonant_run(sld),
        "bigram_logprob": round(bigram.score(sld), 4),
        "dict_ratio": round(covered / max(len(sld), 1), 4),
        "num_words": nwords,
        "avg_word_len": round(covered / nwords, 4) if nwords else 0.0,
        "hyphen_count": sld.count("-"),
        "trigram_logprob": round(trigram.score(sld), 4) if trigram else 0.0,
        "num_labels": d.count(".") + 1 if d else 0,
        "rare_tld": int(tld.split(".")[-1] not in COMMON_TLDS) if tld else 1,
    }


def load_list(path) -> set[str]:
    """Читает список доменов: по одному на строку или CSV 'rank,domain' (Tranco)."""
    if path is None or not Path(path).exists():
        return set()
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.add(normalize(line.split(",")[-1]))
    return out


# ---------------------------------------------------------------- детектор
class DGADetector:
    def __init__(self, whitelist: set[str] | None = None,
                 blacklist: set[str] | None = None,
                 words: set[str] | None = None,
                 threshold: float = 0.5):
        self.whitelist = whitelist or set()
        self.blacklist = blacklist or set()
        self.words = words if words is not None else load_words()
        self.threshold = threshold
        self.bigram = BigramModel(2)
        self.trigram = BigramModel(3)
        self.model: RandomForestClassifier | None = None
        self.legit_percentiles: dict[str, tuple[float, float]] = {}

    # --- обучение
    def fit(self, domains, labels) -> "DGADetector":
        domains = [normalize(d) for d in domains]
        labels = np.asarray(labels, dtype=int)
        legit_slds = [split_domain(d)[1] for d, y in zip(domains, labels) if y == 0]
        self.bigram.fit(legit_slds)
        self.trigram.fit(legit_slds)
        X = self._matrix(domains)
        self.model = RandomForestClassifier(
            n_estimators=100, max_depth=18, min_samples_leaf=5,
            n_jobs=-1, random_state=42, class_weight="balanced",
        ).fit(X, labels)
        legit = X[labels == 0]
        self.legit_percentiles = {
            f: (float(np.percentile(legit[:, i], 5)), float(np.percentile(legit[:, i], 95)))
            for i, f in enumerate(FEATURE_NAMES)
        }
        return self

    def _matrix(self, domains) -> np.ndarray:
        rows = [extract_features(d, self.bigram, self.words, self.trigram) for d in domains]
        return np.array([[r[f] for f in FEATURE_NAMES] for r in rows], dtype=float)

    # --- объяснение вердикта для отчёта
    def _reasons(self, feats: dict) -> list[str]:
        out = []
        for f, direction in SUSPICIOUS_DIRECTION.items():
            lo, hi = self.legit_percentiles.get(f, (None, None))
            if lo is None:
                continue
            v = feats[f]
            if direction == "high" and v > hi:
                out.append(f"{f}={v} > p95 легитимных ({hi:.2f})")
            elif direction == "low" and v < lo:
                out.append(f"{f}={v} < p5 легитимных ({lo:.2f})")
        if feats["rare_tld"]:
            out.append("редкий TLD")
        if not out:
            out.append("сочетание признаков (модель); каждый по отдельности в норме — "
                       "возможен словарный DGA, нужна поведенческая проверка")
        return out

    # --- оценка
    def score(self, domains) -> pd.DataFrame:
        """Главная функция модуля: домены → DataFrame domain_scores."""
        if self.model is None:
            raise RuntimeError("Модель не обучена: вызовите fit() или DGADetector.load()")
        uniq = list(dict.fromkeys(normalize(d) for d in domains if str(d).strip()))
        if not uniq:
            return pd.DataFrame(columns=["domain", "sld", "features", "dga_score", "source", "reasons"])
        X = self._matrix(uniq)
        proba = self.model.predict_proba(X)[:, 1]
        records = []
        for d, x, p in zip(uniq, X, proba):
            reg, sld, _ = split_domain(d)
            feats = dict(zip(FEATURE_NAMES, x.tolist()))
            if reg in self.whitelist or d in self.whitelist:
                score, source, reasons = 0.0, "whitelist", ["в белом списке"]
            elif reg in self.blacklist or d in self.blacklist:
                score, source, reasons = 1.0, "blacklist", ["в чёрном списке DGA"]
            else:
                score, source = round(float(p), 4), "model"
                reasons = self._reasons(feats) if p >= self.threshold else []
            records.append({"domain": d, "sld": sld, "features": feats,
                            "dga_score": score, "source": source, "reasons": reasons})
        return pd.DataFrame(records).sort_values("dga_score", ascending=False, ignore_index=True)

    def score_dns_events(self, dns_events: pd.DataFrame) -> pd.DataFrame:
        """Удобная обёртка для конвейера: берёт уникальные query из dns_events парсера."""
        return self.score(dns_events["query"].dropna().unique())

    def predict(self, domains) -> np.ndarray:
        df = self.score(domains).set_index("domain")
        return np.array([int(df.loc[normalize(d), "dga_score"] >= self.threshold) for d in domains])

    def feature_importances(self) -> pd.Series:
        return pd.Series(self.model.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)

    # --- сохранение
    def save(self, path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "bigram": self.bigram, "trigram": self.trigram, "words": self.words,
                     "legit_percentiles": self.legit_percentiles,
                     "threshold": self.threshold}, path, compress=3)

    @classmethod
    def load(cls, path, whitelist=None, blacklist=None) -> "DGADetector":
        b = joblib.load(path)
        det = cls(whitelist=whitelist, blacklist=blacklist, threshold=b["threshold"])
        det.model, det.bigram, det.legit_percentiles = b["model"], b["bigram"], b["legit_percentiles"]
        det.trigram = b.get("trigram")
        det.words = b.get("words", det.words)
        return det


# ---------------------------------------------------------------- базовая линия
def entropy_baseline(domains, threshold: float = 3.0) -> np.ndarray:
    """Простейший детектор для сравнения: энтропия SLD выше порога → DGA."""
    return np.array([int(shannon_entropy(split_domain(d)[1]) > threshold) for d in domains])


def metrics(y_true, y_pred) -> dict:
    return {"precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1": round(f1_score(y_true, y_pred, zero_division=0), 4)}


# ---------------------------------------------------------------- CLI
def _cli(argv=None):
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Детектор DGA-доменов")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="обучить модель на CSV domain,label")
    t.add_argument("--data", required=True)
    t.add_argument("--model", default=str(HERE / "models" / "dga_rf.joblib"))

    e = sub.add_parser("eval", help="метрики на тестовом CSV domain,label[,family]")
    e.add_argument("--data", required=True)
    e.add_argument("--model", default=str(HERE / "models" / "dga_rf.joblib"))
    e.add_argument("--whitelist", help="дополнительно посчитать метрики с белым списком")

    s = sub.add_parser("score", help="оценить домены")
    s.add_argument("domains", nargs="*")
    s.add_argument("--file", help="файл с доменами, по одному на строку")
    s.add_argument("--model", default=str(HERE / "models" / "dga_rf.joblib"))
    s.add_argument("--whitelist")
    s.add_argument("--blacklist")

    a = ap.parse_args(argv)

    if a.cmd == "train":
        df = pd.read_csv(a.data)
        det = DGADetector().fit(df["domain"], df["label"])
        det.save(a.model)
        print(f"Обучено на {len(df)} доменах ({int(df['label'].sum())} DGA). Модель: {a.model}")
        print("Важность признаков:\n" + det.feature_importances().round(3).to_string())

    elif a.cmd == "eval":
        import time
        from sklearn.metrics import roc_auc_score
        df = pd.read_csv(a.data)
        det = DGADetector.load(a.model)
        y = df["label"].to_numpy()
        t0 = time.perf_counter()
        scores = det.score(df["domain"]).set_index("domain")["dga_score"]
        dt = time.perf_counter() - t0
        s = df["domain"].map(lambda d: scores[normalize(d)]).to_numpy()
        pred = (s >= det.threshold).astype(int)
        fpr = lambda p: round(float(p[y == 0].mean()), 4)
        base = entropy_baseline(df["domain"])
        print(f"Тест: {len(df)} доменов ({int(y.sum())} DGA), скорость: {len(df) / dt:,.0f} доменов/с")
        print("Random Forest:      ", metrics(y, pred), "FPR", fpr(pred), "ROC-AUC", round(roc_auc_score(y, s), 4))
        print("Порог энтропии 3.0: ", metrics(y, base), "FPR", fpr(base))
        if a.whitelist:
            det.whitelist = load_list(a.whitelist)
            sw = det.score(df["domain"]).set_index("domain")["dga_score"]
            pw = (df["domain"].map(lambda d: sw[normalize(d)]).to_numpy() >= det.threshold).astype(int)
            print("RF + белый список:  ", metrics(y, pw), "FPR", fpr(pw))
        if "family" in df.columns:
            df["pred"] = pred
            print("\nПо семействам (доля, помеченная как DGA):")
            print(df.groupby("family")["pred"].mean().round(4).to_string())

    elif a.cmd == "score":
        domains = list(a.domains)
        if a.file:
            domains += [l.strip() for l in open(a.file, encoding="utf-8") if l.strip()]
        det = DGADetector.load(a.model, load_list(a.whitelist), load_list(a.blacklist))
        out = det.score(domains)
        with pd.option_context("display.max_colwidth", 90, "display.width", 200):
            print(out[["domain", "dga_score", "source", "reasons"]].to_string(index=False))


if __name__ == "__main__":
    # запускаем через импорт, чтобы модель сохранялась со ссылкой на dga_detector.BigramModel, а не на __main__
    sys.path.insert(0, str(HERE))
    import dga_detector
    dga_detector._cli()
