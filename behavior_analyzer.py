"""
behavior_analyzer.py — модуль анализа ботнет-активности (Студент 4, Нурсоветов А).

Вход:  dns_events и conn_events от pcap_parser.py.
Выход: DataFrame host_scores — одна строка на внутренний IP:
       src_ip, window, n_queries, unique_domains, nxdomain_ratio, nx_unique, beacon_cv, beacon_period,
       beacon_target, beacon_count, no_dns_conns, rare_port_conns, behavior_score (0–1), evidence

Признаки (таблица из 2.1):
  * доля ответов NXDOMAIN — бот перебирает список DGA, большинство доменов не зарегистрировано [16];
  * число уникальных доменов (в «худшем» окне) — всплеск при переборе;
  * регулярность интервалов (коэффициент вариации CV) — маячки к C2 периодичны [17], [18];
  * соединения с IP без предшествующего DNS-запроса — жёстко заданный резервный C2;
  * нестандартные порты.

  * сканирование — попытки соединиться с десятками внешних IP без ответа (распространение червя, Mirai).

Оценка — прозрачная: каждый признак переводится в 0–1 линейной «рампой» между порогами
«норма» и «точно аномально», затем объединяется «шумным ИЛИ» с весами WEIGHTS. Пороги и веса — в THRESHOLDS / WEIGHTS,
их подбирают на валидационных данных (Этап 4).
"""
from __future__ import annotations

import ipaddress

import numpy as np
import pandas as pd

WINDOW_SECONDS = 300  # скользящее окно для всплесков DNS

THRESHOLDS = {                    # (норма, точно аномально)
    "nxdomain_ratio": (0.10, 0.50),
    "nx_unique": (5, 40),          # уникальных NXDOMAIN-доменов в худшем окне
    "unique_domains": (60, 250),   # уникальных доменов в худшем окне
    "beacon_cv": (0.35, 0.10),     # чем меньше CV — тем регулярнее (обратная шкала)
    "no_dns_conns": (2, 10),       # внешних IP без DNS
    "rare_port_conns": (3, 20),
    "scan_targets": (15, 80),      # внешних IP с безответными попытками соединения (сканирование)
}
# Максимальный вклад каждого признака. Объединение — «шумное ИЛИ»: score = 1 − Π(1 − w·c).
# Один сильный признак уже даёт заметный риск, совпадение нескольких — усиливает его.
WEIGHTS = {"nxdomain": 0.70, "burst": 0.50, "beacon": 0.60, "no_dns": 0.40, "ports": 0.20, "scan": 0.75}

MIN_QUERIES = 10       # меньше запросов — долю NXDOMAIN не считаем надёжной
MIN_BEACON_EVENTS = 6  # минимум повторов, чтобы говорить о периодичности
PERIODIC_BENIGN_PORTS = {123}  # NTP периодичен по природе — не маячок C2 (ср. [18])
COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389, 5222, 8080, 8443}


def ramp(x: float, lo: float, hi: float) -> float:
    """Линейно 0 → 1 между lo и hi (работает и для обратной шкалы, когда hi < lo)."""
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return 0.0
    if hi == lo:
        return float(x >= hi)
    return float(np.clip((x - lo) / (hi - lo), 0.0, 1.0))


def is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return (a.is_private or a.is_link_local) and not a.is_unspecified and not a.is_multicast
    except ValueError:
        return False


def _beacon(times: np.ndarray) -> tuple[float, float, int]:
    """CV и период интервалов между событиями. Медиана-устойчивая версия:
    отбрасываем 10 % самых длинных пауз (бот мог «спать»)."""
    times = np.sort(times)
    if len(times) < MIN_BEACON_EVENTS:
        return np.nan, np.nan, len(times)
    d = np.diff(times)
    d = d[d > 1.0]  # повторы одного запроса в пределах секунды — не маячок
    if len(d) < MIN_BEACON_EVENTS - 1:
        return np.nan, np.nan, len(times)
    d = np.sort(d)[: max(int(len(d) * 0.9), MIN_BEACON_EVENTS - 1)]
    mean = d.mean()
    return float(d.std() / mean) if mean > 0 else np.nan, float(np.median(d)), len(times)


def analyze(dns_events: pd.DataFrame, conn_events: pd.DataFrame,
            window: int = WINDOW_SECONDS) -> pd.DataFrame:
    hosts = set()
    if not dns_events.empty:
        hosts |= {h for h in dns_events["src_ip"].unique() if is_internal(h)}
    if not conn_events.empty:
        hosts |= {h for h in conn_events["src_ip"].unique() if is_internal(h)}
    rows = []
    for h in sorted(hosts):
        d = dns_events[dns_events["src_ip"] == h] if not dns_events.empty else dns_events
        c = conn_events[conn_events["src_ip"] == h] if not conn_events.empty else conn_events
        rows.append(_host_row(h, d, c, window))
    cols = ["src_ip", "window", "n_queries", "unique_domains", "nxdomain_ratio", "nx_unique", "beacon_cv",
            "beacon_period", "beacon_target", "beacon_count", "no_dns_conns", "rare_port_conns", "scan_targets",
            "behavior_score", "components", "evidence"]
    return pd.DataFrame(rows, columns=cols).sort_values("behavior_score", ascending=False, ignore_index=True)


def _host_row(h, d, c, window) -> dict:
    ev: list[str] = []
    n_q = len(d)
    # --- NXDOMAIN и всплески в худшем окне
    nx = d[d["rcode"] == "NXDOMAIN"] if n_q else d
    nx_ratio = len(nx) / n_q if n_q >= MIN_QUERIES else np.nan
    worst_w, uniq_w, nxu_w = None, 0, 0
    if n_q:
        win = ((d["timestamp"] - d["timestamp"].min()) // window).astype(int)
        for w, g in d.groupby(win):
            u = g["query"].nunique()
            nu = g.loc[g["rcode"] == "NXDOMAIN", "query"].nunique()
            if (nu, u) > (nxu_w, uniq_w):
                worst_w, uniq_w, nxu_w = int(w), u, nu
    # --- маячки: по каждому внешнему (dst_ip, port) и по каждому домену берём самый регулярный
    best = (np.nan, np.nan, None, 0)
    cands = []
    if not c.empty:
        ext = c[~c["dst_ip"].map(is_internal)]
        for (ip, port), g in ext.groupby(["dst_ip", "dst_port"]):
            if port in PERIODIC_BENIGN_PORTS:
                continue
            cands.append((f"{ip}:{port}", g["timestamp"].to_numpy()))
    if n_q:
        for q, g in d.groupby("query"):
            cands.append((q, g["timestamp"].to_numpy()))
    for target, times in cands:
        cv, period, cnt = _beacon(times)
        if not np.isnan(cv) and (np.isnan(best[0]) or cv < best[0]):
            best = (cv, period, target, cnt)
    # --- соединения без DNS и редкие порты
    no_dns = rare = scan = 0
    if not c.empty:
        ext = c[~c["dst_ip"].map(is_internal)]
        no_dns_df = ext[~ext["had_dns_lookup"]]
        no_dns = no_dns_df["dst_ip"].nunique()
        rare_df = ext[~ext["dst_port"].isin(COMMON_PORTS)]
        rare = len(rare_df)
        tcp = ext[ext["proto"] == "tcp"]
        scan = tcp.loc[tcp["packets"] <= 2, "dst_ip"].nunique()  # SYN без ответа / сразу RST
    # --- оценки
    comp = {
        "nxdomain": ramp(nx_ratio, *THRESHOLDS["nxdomain_ratio"]),
        "burst": max(ramp(nxu_w, *THRESHOLDS["nx_unique"]), ramp(uniq_w, *THRESHOLDS["unique_domains"])),
        "beacon": ramp(best[0], *THRESHOLDS["beacon_cv"]),
        "no_dns": ramp(no_dns, *THRESHOLDS["no_dns_conns"]),
        "ports": ramp(rare, *THRESHOLDS["rare_port_conns"]),
        "scan": ramp(scan, *THRESHOLDS["scan_targets"]),
    }
    score = 1.0 - float(np.prod([1.0 - WEIGHTS[k] * v for k, v in comp.items()]))
    if comp["nxdomain"] > 0:
        ev.append(f"NXDOMAIN {len(nx)} из {n_q} запросов ({nx_ratio:.0%})")
    if comp["burst"] > 0:
        ev.append(f"всплеск: {nxu_w} уникальных несуществующих доменов за {window // 60} мин (окно №{worst_w})")
    if comp["beacon"] > 0:
        ev.append(f"маячок к {best[2]}: {best[3]} обращений каждые ~{best[1]:.0f} с (CV {best[0]:.2f})")
    if comp["no_dns"] > 0:
        ev.append(f"соединения с {no_dns} внешними IP без DNS-запроса")
    if comp["ports"] > 0:
        ev.append(f"{rare} соединений на нестандартные порты")
    if comp["scan"] > 0:
        tops = c[c["packets"] <= 2]["dst_port"].value_counts().head(3).index.tolist() if not c.empty else []
        ev.append(f"сканирование: безответные попытки соединения с {scan} внешними IP (порты {', '.join(map(str, tops))})")
    return {
        "src_ip": h, "window": worst_w, "n_queries": n_q, "unique_domains": int(uniq_w),
        "nxdomain_ratio": None if np.isnan(nx_ratio) else round(nx_ratio, 4), "nx_unique": int(nxu_w),
        "beacon_cv": None if np.isnan(best[0]) else round(best[0], 4),
        "beacon_period": None if np.isnan(best[1]) else round(best[1], 1),
        "beacon_target": best[2], "beacon_count": best[3],
        "no_dns_conns": int(no_dns), "rare_port_conns": int(rare), "scan_targets": int(scan),
        "behavior_score": round(score, 4), "components": {k: round(v, 3) for k, v in comp.items()},
        "evidence": ev,
    }


if __name__ == "__main__":
    import sys
    from pcap_parser import parse_pcap
    sys.stdout.reconfigure(encoding="utf-8")
    dns, conns, _ = parse_pcap(sys.argv[1])
    hs = analyze(dns, conns)
    with pd.option_context("display.max_colwidth", 120, "display.width", 250):
        print(hs[["src_ip", "n_queries", "nxdomain_ratio", "beacon_cv", "no_dns_conns", "behavior_score", "evidence"]]
              .to_string(index=False))
