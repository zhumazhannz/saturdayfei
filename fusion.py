"""
fusion.py — блок объединения (раздел 2.1, «Объединение»).

Вход:  domain_scores (детектор DGA), host_scores (анализ поведения), dns_events, conn_events.
Выход: findings — список словарей (→ JSON), один на внутренний хост:
       src_ip, risk (0–1), verdict, dga_component, behavior_component, top_domains,
       evidence (номера пакетов), mitre_techniques
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from behavior_analyzer import ramp
from dga_detector import split_domain

WEIGHTS = {"dga": 0.8, "behavior": 0.9}  # риск = 1 − (1 − 0,8·DGA)(1 − 0,9·поведение)
VERDICTS = [(0.60, "infected", "Вероятно заражён"), (0.35, "suspicious", "Подозрительный"), (0.0, "clean", "Чистый")]
DGA_SUSPICIOUS = 0.5           # порог dga_score, с которого домен считается подозрительным
DGA_COUNT_RAMP = (2, 12)       # «вес улик» (см. ниже), при котором DGA-оценка хоста становится полной
RESOLVED_WEIGHT = 0.25         # подозрительный, но существующий домен — слабая улика (DGA-боты в основном получают NXDOMAIN)
TOP_DOMAINS = 10


def verdict(risk: float) -> tuple[str, str]:
    for thr, code, label in VERDICTS:
        if risk >= thr:
            return code, label
    return "clean", "Чистый"


def _mitre(dga_comp, beh_row) -> list[dict]:
    out = []
    if dga_comp >= 0.5:
        out.append({"id": "T1568.002", "name": "Dynamic Resolution: Domain Generation Algorithms"})
    comp = beh_row.get("components", {}) if beh_row is not None else {}
    if comp.get("beacon", 0) >= 0.5:
        tgt = str(beh_row.get("beacon_target") or "")
        port = tgt.rsplit(":", 1)[-1] if ":" in tgt else ""
        if port == "53":
            out.append({"id": "T1071.004", "name": "Application Layer Protocol: DNS"})
        elif port in ("80", "443", "8080", "8443"):
            out.append({"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"})
        else:
            out.append({"id": "T1071", "name": "Application Layer Protocol (периодический C2)"})
    if comp.get("no_dns", 0) >= 0.5:
        out.append({"id": "T1008", "name": "Fallback Channels (IP без DNS)"})
    if comp.get("scan", 0) >= 0.5:
        out.append({"id": "T1046", "name": "Network Service Discovery (сканирование)"})
    if comp.get("ports", 0) >= 0.5:
        out.append({"id": "T1571", "name": "Non-Standard Port"})
    return out


def combine(domain_scores: pd.DataFrame, host_scores: pd.DataFrame,
            dns_events: pd.DataFrame, weights: dict | None = None) -> list[dict]:
    w = weights or WEIGHTS
    # подозрительные домены всех хостов — одной таблицей (быстро даже на сотнях тысяч запросов)
    by_host: dict[str, list[dict]] = {}
    n_domains: dict[str, int] = {}
    if not dns_events.empty and not domain_scores.empty:
        n_domains = dns_events.groupby("src_ip")["query"].nunique().to_dict()
        ds = domain_scores.set_index("domain")
        susp_ds = ds[(ds["dga_score"] >= DGA_SUSPICIOUS) & (ds["source"] != "whitelist")]
        q = dns_events[dns_events["query"].isin(susp_ds.index)]
        for (ip, name), g in q.groupby(["src_ip", "query"]):
            r = susp_ds.loc[name]
            by_host.setdefault(ip, []).append({
                "domain": name, "registered": split_domain(name)[0], "dga_score": float(r["dga_score"]),
                "source": r["source"], "reasons": list(r["reasons"]), "queries": len(g),
                "rcode": g["rcode"].mode().iat[0],
                "packets": sorted(set(g["pkt_no"].tolist() + g["resp_pkt_no"].dropna().astype(int).tolist()))[:6],
                "first_seen": float(g["timestamp"].min()),
            })
    findings = []
    for _, h in host_scores.iterrows():
        ip = h["src_ip"]
        susp = sorted(by_host.get(ip, []), key=lambda d: (-d["dga_score"], d["domain"]))
        # один зарегистрированный домен = одна улика (cdn.site.com и site.com — одно и то же);
        # NXDOMAIN весит 1, домен, который реально существует, — RESOLVED_WEIGHT
        regs: dict[str, float] = {}
        for d in susp:
            wgt = 1.0 if d["rcode"] == "NXDOMAIN" else RESOLVED_WEIGHT
            regs[d["registered"]] = max(regs.get(d["registered"], 0.0), wgt)
        n_eff = sum(regs.values())
        top_mean = float(np.mean([d["dga_score"] for d in susp[:TOP_DOMAINS]])) if susp else 0.0
        dga_comp = ramp(n_eff, *DGA_COUNT_RAMP) * top_mean
        if any(d["source"] == "blacklist" for d in susp):
            dga_comp = max(dga_comp, 0.9)
        beh = float(h["behavior_score"])
        risk = round(1.0 - (1.0 - w["dga"] * dga_comp) * (1.0 - w["behavior"] * beh), 4)
        code, label = verdict(risk)
        hrow = h.to_dict()
        evidence = list(h["evidence"])
        if susp:
            nx = sum(1 for d in susp if d["rcode"] == "NXDOMAIN")
            evidence.insert(0, f"{len(susp)} доменов похожи на DGA (из них {nx} — NXDOMAIN)")
        findings.append({
            "src_ip": ip, "risk": risk, "verdict": code, "verdict_label": label,
            "dga_component": round(dga_comp, 4), "behavior_component": round(beh, 4),
            "behavior": {k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in hrow.items()
                         if k not in ("src_ip", "evidence")},
            "n_domains": int(n_domains.get(ip, 0)), "n_suspicious_domains": len(susp), "dga_evidence_weight": round(n_eff, 2),
            "top_domains": susp[:TOP_DOMAINS],
            "evidence": evidence,
            "mitre_techniques": _mitre(dga_comp, hrow),
        })
    findings.sort(key=lambda f: -f["risk"])
    return findings
