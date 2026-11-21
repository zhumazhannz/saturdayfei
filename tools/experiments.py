"""
Эксперименты Этапа 4 (Студент 5, Макушев К).

E1. 50 сценариев «офис 10 чистых хостов + 1 бот», по одному на каждое семейство UMUDGA.
    Метрики по хостам: обнаружение ботов (recall), ложные тревоги на чистых (FPR),
    сравнение: только DGA / только поведение / гибрид / базовый порог энтропии.
E2. «Тихий» бот: 2 пачки по 10 доменов, маячок раз в 5 мин с джиттером 50 % — 12 семейств разных типов.
E3. Скорость на большом дампе (100 хостов, 60 минут).
E4. Реальные дампы Stratosphere (pcaps/real).

python tools/experiments.py   → results/experiments.json, results/experiments.md
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dga"))
sys.path.insert(0, str(ROOT / "tools"))

from dga_detector import shannon_entropy, split_domain  # noqa: E402
from main import get_detector, run  # noqa: E402
from make_scenario import make_scenario, pools  # noqa: E402

OUT = ROOT / "results"
TMP = ROOT / "pcaps" / "experiments"
THR_INFECTED, THR_FLAG = 0.60, 0.35
QUIET_FAMILIES = ["necurs", "cryptolocker", "ramnit", "dyre", "kraken_v1", "pykspa", "gozi_gpl",
                  "matsnu", "suppobox_1", "suppobox_2", "nymaim", "pizd"]
DICT_FAMILIES = {"matsnu", "suppobox_1", "suppobox_2", "suppobox_3", "pizd", "nymaim", "gozi_gpl", "gozi_luther",
                 "gozi_nasa", "gozi_rfc4343", "vawtrak_v3"}


def entropy_baseline_host(dns: pd.DataFrame, wl: set, ip: str, k: int = 5) -> int:
    """Базовая линия: хост «заражён», если запросил ≥ k разных доменов не из белого списка с энтропией > 3,0."""
    q = dns.loc[dns["src_ip"] == ip, "query"].unique()
    n = sum(1 for d in q if split_domain(d)[0] not in wl and shannon_entropy(split_domain(d)[1]) > 3.0)
    return int(n >= k)


def host_rows(res, truth, wl, scenario, family_kind):
    rows = []
    fmap = {f["src_ip"]: f for f in res["findings"]}
    for ip, t in truth.items():
        f = fmap.get(ip)
        if f is None:
            continue
        dga, beh = f["dga_component"], f["behavior_component"]
        rows.append({
            "scenario": scenario, "ip": ip, "label": t["label"], "family": t["family"] or "",
            "kind": family_kind if t["label"] == "infected" else ("updater" if t["family"] == "updater" else "clean"),
            "risk": f["risk"], "dga": dga, "beh": beh,
            "risk_dga_only": 0.8 * dga, "risk_beh_only": 0.9 * beh,
            "baseline": entropy_baseline_host(res["dns"], wl, ip),
        })
    return rows


def metrics(df: pd.DataFrame, col: str, thr: float) -> dict:
    pos, neg = df[df["label"] == "infected"], df[df["label"] == "clean"]
    tp = int((pos[col] >= thr).sum())
    fp = int((neg[col] >= thr).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / len(pos) if len(pos) else 0.0
    return {"recall": round(rec, 4), "fpr": round(fp / len(neg), 4) if len(neg) else 0.0,
            "precision": round(prec, 4), "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "tp": tp, "fp": fp, "n_pos": len(pos), "n_neg": len(neg)}


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    OUT.mkdir(exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)
    det = get_detector(blacklist=None)          # без чёрного списка: проверяем модель, а не память
    wl = det.whitelist
    fams = sorted(pools()["dga"].keys())
    results: dict = {}

    # ---------------- E1
    rows = []
    t0 = time.perf_counter()
    for i, fam in enumerate(fams):
        p = TMP / f"e1_{fam}.pcap"
        make_scenario(p, [fam], n_benign=10, dur=1800, seed=100 + i)
        truth = json.loads(Path(str(p) + ".truth.json").read_text(encoding="utf-8"))
        res = run(str(p), det)
        rows += host_rows(res, truth, wl, f"e1_{fam}", "dictionary" if fam in DICT_FAMILIES else "random")
        bot = [r for r in rows if r["scenario"] == f"e1_{fam}" and r["label"] == "infected"][0]
        print(f"[E1 {i + 1}/{len(fams)}] {fam:14s} риск бота {bot['risk']:.2f} (DGA {bot['dga']:.2f}, поведение {bot['beh']:.2f})", flush=True)
    e1 = pd.DataFrame(rows)
    e1.to_csv(OUT / "e1_hosts.csv", index=False)
    clean_only = e1[e1["kind"] != "updater"]
    results["E1"] = {
        "scenarios": len(fams), "seconds": round(time.perf_counter() - t0, 1),
        "hybrid_infected": metrics(clean_only, "risk", THR_INFECTED),
        "hybrid_flagged": metrics(clean_only, "risk", THR_FLAG),
        "dga_only": metrics(clean_only, "risk_dga_only", THR_INFECTED),
        "behavior_only": metrics(clean_only, "risk_beh_only", THR_INFECTED),
        "entropy_baseline": metrics(clean_only, "baseline", 1),
        "updater": {"n": int((e1["kind"] == "updater").sum()),
                    "flagged": int((e1.loc[e1["kind"] == "updater", "risk"] >= THR_FLAG).sum()),
                    "infected": int((e1.loc[e1["kind"] == "updater", "risk"] >= THR_INFECTED).sum()),
                    "mean_risk": round(float(e1.loc[e1["kind"] == "updater", "risk"].mean()), 3)},
        "clean_risk_p95": round(float(clean_only.loc[clean_only["label"] == "clean", "risk"].quantile(0.95)), 3),
        "by_kind": {k: metrics(pd.concat([g, clean_only[clean_only["label"] == "clean"]]), "risk", THR_INFECTED)["recall"]
                    for k, g in clean_only[clean_only["label"] == "infected"].groupby("kind")},
        "bot_risk_by_family": e1[e1["label"] == "infected"].set_index("family")[["risk", "dga", "beh"]].round(3).to_dict("index"),
    }

    # ---------------- E2
    rows2 = []
    for i, fam in enumerate(QUIET_FAMILIES):
        p = TMP / f"e2_{fam}.pcap"
        make_scenario(p, [fam], n_benign=10, dur=1800, seed=500 + i, updater=False,
                      per_burst=10, bursts=2, beacon=300, jitter=0.5, fallback=False)
        truth = json.loads(Path(str(p) + ".truth.json").read_text(encoding="utf-8"))
        res = run(str(p), det)
        rows2 += host_rows(res, truth, wl, f"e2_{fam}", "dictionary" if fam in DICT_FAMILIES else "random")
        bot = [r for r in rows2 if r["scenario"] == f"e2_{fam}" and r["label"] == "infected"][0]
        print(f"[E2 {i + 1}/{len(QUIET_FAMILIES)}] тихий {fam:12s} риск {bot['risk']:.2f} (DGA {bot['dga']:.2f}, поведение {bot['beh']:.2f})", flush=True)
    e2 = pd.DataFrame(rows2)
    e2.to_csv(OUT / "e2_hosts.csv", index=False)
    results["E2"] = {
        "hybrid_infected": metrics(e2, "risk", THR_INFECTED),
        "hybrid_flagged": metrics(e2, "risk", THR_FLAG),
        "dga_only": metrics(e2, "risk_dga_only", THR_INFECTED),
        "behavior_only": metrics(e2, "risk_beh_only", THR_INFECTED),
        "bot_risk_by_family": e2[e2["label"] == "infected"].set_index("family")[["risk", "dga", "beh"]].round(3).to_dict("index"),
    }

    # ---------------- E3
    p = TMP / "e3_big.pcap"
    gen = make_scenario(p, ["necurs", "matsnu", "ramnit", "suppobox_1", "dyre"], n_benign=100, dur=3600, seed=900)
    res = run(str(p), det)
    tm = res["timings"]
    results["E3"] = {"packets": gen["packets"], "size_mb": round(p.stat().st_size / 1e6, 1),
                     "hosts": len(res["findings"]), "dns_queries": len(res["dns"]), "domains": len(res["domain_scores"]),
                     "timings": {k: round(v, 2) for k, v in tm.items()},
                     "packets_per_sec": round(gen["packets"] / tm["total"]),
                     "parse_packets_per_sec": round(gen["packets"] / tm["parse"])}
    truth = json.loads(Path(str(p) + ".truth.json").read_text(encoding="utf-8"))
    big = pd.DataFrame(host_rows(res, truth, wl, "e3", ""))
    results["E3"]["detection"] = metrics(big[big["kind"] != "updater"], "risk", THR_INFECTED)
    print(f"[E3] {gen['packets']} пакетов за {tm['total']:.1f} с → {results['E3']['packets_per_sec']} пакетов/с", flush=True)

    # ---------------- E4
    results["E4"] = {}
    for p in sorted((ROOT / "pcaps" / "real").glob("*.pcap")):
        res = run(str(p), det)
        results["E4"][p.name] = [{"ip": f["src_ip"], "risk": f["risk"], "verdict": f["verdict_label"],
                                  "evidence": f["evidence"][:4]} for f in res["findings"]]
    (OUT / "experiments.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in results["E1"].items() if k != "bot_risk_by_family"}, ensure_ascii=False, indent=1))
    print(json.dumps({k: v for k, v in results["E2"].items() if k != "bot_risk_by_family"}, ensure_ascii=False, indent=1))
    print(json.dumps(results["E3"], ensure_ascii=False))


if __name__ == "__main__":
    main()
