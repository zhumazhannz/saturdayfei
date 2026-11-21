"""
main.py — оркестратор модуля анализа PCAP (Студент 1, Басыбек М).

    python main.py --pcap capture.pcap --out report.html [--json findings.json]

Конвейер (раздел 2.2):
  pcap_parser → (dga_detector ∥ behavior_analyzer) → fusion → report_generator
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "dga"))

import pandas as pd  # noqa: E402

from behavior_analyzer import analyze  # noqa: E402
from dga_detector import DGADetector, load_list  # noqa: E402
from fusion import combine  # noqa: E402
from pcap_parser import parse_pcap  # noqa: E402
from report_generator import render  # noqa: E402

DEFAULT_MODEL = ROOT / "dga" / "models" / "dga_rf.joblib"
DEFAULT_WL = ROOT / "dga" / "data" / "whitelist.txt"
DEFAULT_BL = ROOT / "dga" / "data" / "blacklist.txt"

_DETECTOR = None


def get_detector(model=DEFAULT_MODEL, whitelist=DEFAULT_WL, blacklist=DEFAULT_BL) -> DGADetector:
    global _DETECTOR
    if _DETECTOR is None:
        _DETECTOR = DGADetector.load(model, load_list(whitelist), load_list(blacklist) if blacklist else set())
    return _DETECTOR


def run(pcap: str, detector: DGADetector | None = None) -> dict:
    """Полный прогон одного файла. Возвращает всё, что нужно отчёту и экспериментам."""
    det = detector or get_detector()
    timings = {}
    t = time.perf_counter()
    dns, conns, st = parse_pcap(pcap)
    timings["parse"] = time.perf_counter() - t

    t = time.perf_counter()
    domains = dns["query"].dropna().unique() if not dns.empty else []
    domain_scores = det.score(domains) if len(domains) else pd.DataFrame(
        columns=["domain", "sld", "features", "dga_score", "source", "reasons"])
    timings["dga"] = time.perf_counter() - t

    t = time.perf_counter()
    host_scores = analyze(dns, conns)
    timings["behavior"] = time.perf_counter() - t

    t = time.perf_counter()
    findings = combine(domain_scores, host_scores, dns)
    timings["fusion"] = time.perf_counter() - t
    timings["total"] = sum(timings.values())

    return {"pcap": str(pcap), "stats": st, "dns": dns, "conns": conns, "domain_scores": domain_scores,
            "host_scores": host_scores, "findings": findings, "timings": timings}


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Анализ PCAP: ботнеты и DGA")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", default="report.html")
    ap.add_argument("--json", help="сохранить findings в JSON")
    ap.add_argument("--no-blacklist", action="store_true", help="не использовать чёрный список")
    a = ap.parse_args(argv)

    det = get_detector(blacklist=None if a.no_blacklist else DEFAULT_BL)
    res = run(a.pcap, det)
    st, tm = res["stats"], res["timings"]
    Path(a.out).write_text(render(res), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(res["findings"], ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print(f"{Path(a.pcap).name}: {st.packets} пакетов, {len(res['dns'])} DNS-запросов, "
          f"{len(res['conns'])} соединений, {len(res['findings'])} хостов — {tm['total']:.2f} с")
    for f in res["findings"]:
        if f["verdict"] != "clean":
            print(f"  [{f['verdict_label']}] {f['src_ip']}  риск {f['risk']:.2f}  "
                  f"(DGA {f['dga_component']:.2f}, поведение {f['behavior_component']:.2f})")
            for e in f["evidence"][:4]:
                print(f"      - {e}")
    print(f"Отчёт: {a.out}")


if __name__ == "__main__":
    main()
