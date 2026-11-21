"""
Сборка датасета для экспериментов из UMUDGA [8], [9] и Tranco.

UMUDGA (Mendeley Data, doi 10.17632/y8ph45msv8.1): папка «Fully Qualified Domain Names/<семейство>/list/10000.txt»,
скачанная в data/umudga/<семейство>.txt (50 семейств DGA + legit).

Легитимные домены: legit из UMUDGA (топ Alexa) + случайная выборка Tranco с рангами > размера белого списка,
чтобы в тесте были «непопулярные» сайты, которые белый список не спасает.

Выход:
  data/umudga_train.csv, data/umudga_test.csv   — domain,label,family (стратификация по семейству, 80/20)
  data/blacklist.txt                            — домены UMUDGA, НЕ попавшие в train/test (нет утечки в метрики)
  data/whitelist.txt                            — Tranco top-N

python tools/build_umudga_dataset.py --tranco path/to/top-1m.csv
"""
import argparse
import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

HERE = Path(__file__).resolve().parent.parent


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", required=True)
    ap.add_argument("--umudga", default=str(HERE / "data" / "umudga"))
    ap.add_argument("--per-family", type=int, default=2000, help="доменов на семейство DGA")
    ap.add_argument("--whitelist-size", type=int, default=10000)
    ap.add_argument("--out", default=str(HERE / "data"))
    a = ap.parse_args()
    out = Path(a.out)

    dga_parts, rest = [], []
    for f in sorted(Path(a.umudga).glob("*.txt")):
        if f.stem == "legit":
            continue
        doms = pd.Series([l.strip().lower() for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]).drop_duplicates()
        take = doms.sample(min(a.per_family, len(doms)), random_state=42)
        dga_parts.append(pd.DataFrame({"domain": take, "label": 1, "family": f.stem}))
        rest.append(doms[~doms.isin(take)])
    dga = pd.concat(dga_parts)

    tr = pd.read_csv(a.tranco, header=None, names=["rank", "domain"])
    tr[tr["rank"] <= a.whitelist_size]["domain"].to_csv(out / "whitelist.txt", index=False, header=False)
    umu_legit = [l.strip().lower() for l in (Path(a.umudga) / "legit.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    n_tranco = len(dga) - len(umu_legit)
    tranco_legit = tr[tr["rank"] > a.whitelist_size].sample(n_tranco, random_state=42)["domain"].str.lower()
    legit = pd.concat([
        pd.DataFrame({"domain": umu_legit, "label": 0, "family": "legit_umudga"}),
        pd.DataFrame({"domain": tranco_legit, "label": 0, "family": "legit_tranco"}),
    ])

    df = pd.concat([legit, dga]).drop_duplicates("domain", keep=False)  # убираем домены, попавшие в оба класса
    train, test = train_test_split(df, test_size=0.2, stratify=df["family"], random_state=42)
    train.to_csv(out / "umudga_train.csv", index=False)
    test.to_csv(out / "umudga_test.csv", index=False)

    bl = pd.concat(rest).drop_duplicates()
    bl = bl[~bl.isin(df["domain"])]
    bl.to_csv(out / "blacklist.txt", index=False, header=False)

    print(f"Семейств DGA: {dga['family'].nunique()}, DGA: {len(dga)}, легитимных: {len(legit)}")
    print(f"train: {len(train)}, test: {len(test)}, blacklist: {len(bl)}, whitelist: {a.whitelist_size}")


if __name__ == "__main__":
    main()
