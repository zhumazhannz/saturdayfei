"""Тесты детектора DGA. Запуск: python -m pytest tests  (или python tests/test_dga_detector.py)"""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dga_detector as dd  # noqa: E402

LEGIT = ["google.com", "wikipedia.org", "kaspi.kz", "weather.com", "bbc.co.uk",
         "github.com", "mail.ru", "booking.com", "openai.com", "egov.kz"] * 20
DGA = ["xjw8qpl2zkq.net", "qwzkrtplmv.info", "a8f3c91d0e7b44aa.biz", "zxcvbnmlkj.ru",
       "kdjfhgqwptz.ws", "plmoknijbuhv.cc", "9d8f7a6s5d4f.top", "vbnqwrtzxp.org",
       "hhqwzxprtk.com", "mnbvcxzlkjhg.net"] * 20


def test_split_domain():
    assert dd.split_domain("WWW.Mail.Google.COM.") == ("google.com", "google", "com")
    assert dd.split_domain("shop.bbc.co.uk") == ("bbc.co.uk", "bbc", "co.uk")
    assert dd.split_domain("kaspi.com.kz")[1] == "kaspi"
    # динамический DNS: оцениваем поддомен, а не «ddns»
    assert dd.split_domain("xoeffegeduu.ddns.net") == ("xoeffegeduu.ddns.net", "xoeffegeduu", "ddns.net")


def test_dyndns_not_whitelisted():
    det = _trained()
    det.whitelist = {"ddns.net"}
    out = det.score(["xoeffegeduu.ddns.net"]).iloc[0]
    assert out["source"] == "model"


def test_segment():
    words = {"wedding", "muscle", "animal", "forget"}
    assert dd.segment("animalforget", words) == (12, 2)
    assert dd.segment("xqzk", words) == (0, 0)


def test_entropy():
    assert dd.shannon_entropy("aaaa") == 0
    assert abs(dd.shannon_entropy("abcd") - 2.0) < 1e-9


def test_dict_ratio():
    words = {"water", "fire", "cloud"}
    assert dd.dict_ratio("waterfire", words) == 1.0
    assert dd.dict_ratio("xqzkw", words) == 0.0


def _trained():
    return dd.DGADetector(whitelist={"github.com"}, blacklist={"evil-dga.net"}).fit(
        LEGIT + DGA, [0] * len(LEGIT) + [1] * len(DGA))


def test_output_format_and_sources():
    det = _trained()
    out = det.score(["github.com", "api.github.com", "evil-dga.net", "qzkxwrtpl.info", "github.com"])
    assert list(out.columns) == ["domain", "sld", "features", "dga_score", "source", "reasons"]
    assert len(out) == 4  # дубликаты убраны
    src = dict(zip(out["domain"], out["source"]))
    assert src["api.github.com"] == "whitelist"
    assert src["evil-dga.net"] == "blacklist"
    assert src["qzkxwrtpl.info"] == "model"
    assert out["dga_score"].between(0, 1).all()


def test_dns_events_and_save_load(tmp_path=None):
    det = _trained()
    path = Path(tmp_path or Path(__file__).parent) / "_tmp_model.joblib"
    det.save(path)
    det2 = dd.DGADetector.load(path)
    path.unlink()
    events = pd.DataFrame({"query": ["kaspi.kz", "qzkxwrtpl.info", None, "kaspi.kz"]})
    out = det2.score_dns_events(events)
    assert set(out["domain"]) == {"kaspi.kz", "qzkxwrtpl.info"}
    assert out.set_index("domain").loc["qzkxwrtpl.info", "dga_score"] > \
        out.set_index("domain").loc["kaspi.kz", "dga_score"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
