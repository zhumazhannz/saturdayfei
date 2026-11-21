"""
Leave-one-family-out: насколько детектор ловит семейство DGA, которого НЕ было в обучении
(имитация нового, ещё неизвестного вредоноса).

Для каждого из 50 семейств: обучаем на остальных 49 + легитимных, меряем recall на исключённом.
Результат: results/lofo.csv и сводка в консоли.

python tools/lofo.py
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from dga_detector import DGADetector  # noqa: E402


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    train = pd.read_csv(HERE / "data" / "umudga_train.csv")
    test = pd.read_csv(HERE / "data" / "umudga_test.csv")
    families = sorted(f for f in train["family"].unique() if not f.startswith("legit"))
    rows = []
    for i, fam in enumerate(families, 1):
        tr = train[train["family"] != fam]
        det = DGADetector().fit(tr["domain"], tr["label"])
        held = pd.concat([train[train["family"] == fam], test[test["family"] == fam]])
        s = det.score(held["domain"]).set_index("domain")["dga_score"]
        recall_unseen = float((s >= det.threshold).mean())
        rows.append({"family": fam, "recall_unseen": round(recall_unseen, 4), "n": len(held)})
        print(f"[{i}/{len(families)}] {fam:14s} recall на новом семействе = {recall_unseen:.3f}", flush=True)
    out = pd.DataFrame(rows).sort_values("recall_unseen")
    (HERE / "results").mkdir(exist_ok=True)
    out.to_csv(HERE / "results" / "lofo.csv", index=False)
    print(f"\nСредний recall на неизвестных семействах: {out['recall_unseen'].mean():.3f}")
    print(f"Медиана: {out['recall_unseen'].median():.3f}; ≥0.9: {(out['recall_unseen'] >= 0.9).sum()} из {len(out)};"
          f" <0.5: {(out['recall_unseen'] < 0.5).sum()}")


if __name__ == "__main__":
    main()
