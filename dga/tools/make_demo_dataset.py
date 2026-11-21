"""
Демо-датасет для разработки детектора, пока нет UMUDGA.

Легитимные домены: Tranco top-1M (https://tranco-list.eu), ранги ПОСЛЕ белого списка,
чтобы модель проверялась на доменах, которые белый список не спасает.
DGA-домены: синтетические генераторы, имитирующие стили реальных семейств
(случайные буквы, hex-хэши, «произносимые» слоги, словарные склейки).

ВНИМАНИЕ: для отчёта и защиты метрики нужно считать на UMUDGA / DGArchive,
синтетика — только чтобы код работал и было с чем сравнивать.

python tools/make_demo_dataset.py --tranco path/to/top-1m.csv
"""
import argparse
import hashlib
import random
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent.parent
TLDS = ["com", "net", "org", "info", "biz", "ru", "ws", "cc", "cn", "top", "xyz"]
LETTERS = "abcdefghijklmnopqrstuvwxyz"
CONS, VOWS = "bcdfghjklmnprstvwxz", "aeiou"


def gen_random_alpha(r):      # стиль Conficker / Ramnit
    return "".join(r.choice(LETTERS) for _ in range(r.randint(6, 15))) + "." + r.choice(TLDS)


def gen_random_alnum(r):      # стиль Necurs / Murofet
    return "".join(r.choice(LETTERS + "0123456789") for _ in range(r.randint(8, 24))) + "." + r.choice(TLDS)


def gen_hex(r):               # стиль Bamital / Dyre (хэш от даты+соли)
    h = hashlib.md5(str(r.random()).encode()).hexdigest()
    return h[: r.choice([16, 20, 32])] + "." + r.choice(TLDS)


def gen_pronounceable(r):     # стиль Kraken / Pykspa (слоги согласная+гласная)
    n = r.randint(3, 6)
    return "".join(r.choice(CONS) + r.choice(VOWS) for _ in range(n)) + "." + r.choice(TLDS)


def gen_dictionary(r, words): # стиль Suppobox / Matsnu (склейка слов)
    return "".join(r.choice(words) for _ in range(r.choice([2, 2, 3]))) + "." + r.choice(["com", "net", "org"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", required=True, help="top-1m.csv из tranco-list.eu")
    ap.add_argument("--whitelist-size", type=int, default=10000)
    ap.add_argument("--n", type=int, default=40000, help="доменов каждого класса")
    ap.add_argument("--out", default=str(HERE / "data"))
    sys.stdout.reconfigure(encoding="utf-8")
    a = ap.parse_args()
    r = random.Random(42)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    tr = pd.read_csv(a.tranco, header=None, names=["rank", "domain"])
    tr[tr["rank"] <= a.whitelist_size]["domain"].to_csv(out / "whitelist.txt", index=False, header=False)
    legit = tr[tr["rank"] > a.whitelist_size].sample(a.n, random_state=42)["domain"].tolist()

    words = (HERE / "data" / "words.txt").read_text(encoding="utf-8").split()
    gens = {
        "random_alpha": gen_random_alpha, "random_alnum": gen_random_alnum,
        "hex": gen_hex, "pronounceable": gen_pronounceable,
        "dictionary": lambda rr: gen_dictionary(rr, words),
    }
    per = a.n // len(gens)
    dga = [(g(r), fam) for fam, g in gens.items() for _ in range(per)]

    df = pd.DataFrame(
        [(d, 0, "legit") for d in legit] + [(d, 1, fam) for d, fam in dga],
        columns=["domain", "label", "family"],
    ).drop_duplicates("domain").sample(frac=1, random_state=42)
    cut = int(len(df) * 0.8)
    df.iloc[:cut].to_csv(out / "train.csv", index=False)
    df.iloc[cut:].to_csv(out / "test.csv", index=False)
    print(f"train: {cut}, test: {len(df) - cut}, whitelist: {a.whitelist_size} → {out}")


if __name__ == "__main__":
    main()
