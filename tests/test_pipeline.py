"""Сквозные тесты конвейера: python tests/test_pipeline.py"""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dga"))
sys.path.insert(0, str(ROOT / "tools"))

import pandas as pd  # noqa: E402

from behavior_analyzer import analyze, ramp  # noqa: E402
from main import get_detector, run  # noqa: E402
from make_scenario import make_scenario  # noqa: E402
from pcap_parser import parse_pcap  # noqa: E402
from report_generator import render  # noqa: E402

TMP = Path(tempfile.mkdtemp())


def test_ramp():
    assert ramp(0.05, 0.1, 0.5) == 0 and ramp(0.6, 0.1, 0.5) == 1
    assert ramp(0.05, 0.35, 0.10) == 1  # обратная шкала для CV


def test_parser_on_scenario():
    p = TMP / "s.pcap"
    gen = make_scenario(p, ["necurs"], n_benign=3, dur=600, seed=3)
    dns, conns, st = parse_pcap(str(p))
    assert st.packets == gen["packets"]
    assert {"timestamp", "src_ip", "query", "rcode", "answers"} <= set(dns.columns)
    assert (dns["rcode"] == "NXDOMAIN").sum() > 50
    assert conns["had_dns_lookup"].any()


def test_bot_detected_and_report():
    p = TMP / "s2.pcap"
    make_scenario(p, ["ramnit"], n_benign=4, dur=900, seed=5, updater=False)
    truth = json.loads(Path(str(p) + ".truth.json").read_text(encoding="utf-8"))
    res = run(str(p), get_detector(blacklist=None))
    by_ip = {f["src_ip"]: f for f in res["findings"]}
    for ip, t in truth.items():
        if t["label"] == "infected":
            assert by_ip[ip]["verdict"] == "infected", by_ip[ip]
            assert any(m["id"] == "T1568.002" for m in by_ip[ip]["mitre_techniques"])
        else:
            assert by_ip[ip]["verdict"] == "clean", by_ip[ip]
    html = render(res)
    assert "<title>" in html and "Вероятно заражён" in html


def test_empty_inputs():
    hs = analyze(pd.DataFrame(columns=["timestamp", "src_ip", "query", "rcode", "pkt_no"]),
                 pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "dst_port", "proto", "packets", "had_dns_lookup"]))
    assert hs.empty


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
