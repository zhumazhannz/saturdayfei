"""
Генератор размеченных сценариев PCAP (Студент 5, эксперименты).

Строит запись трафика «офисной сети» с известной разметкой: какие хосты чистые, какие заражены.
  * чистые хосты — посещают сайты (домены Tranco/UMUDGA-legit из ТЕСТОВОЙ выборки, не участвовавшие в обучении),
    изредка ошибаются в адресе (NXDOMAIN), синхронизируют время (NTP); один «апдейтер» периодически
    проверяет обновления — легитимная периодичность, ловушка для детектора маячков [18];
  * бот DGA — пачками перебирает домены своего семейства (UMUDGA, тестовая выборка), почти все NXDOMAIN;
    1–2 домена «зарегистрированы» и ведут на C2, дальше — периодические маячки к C2 c джиттером
    и попытка соединиться с жёстко заданным резервным IP без DNS.

python tools/make_scenario.py --out pcaps/demo/office.pcap --bots necurs matsnu --benign 12
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import struct
from pathlib import Path

import dpkt
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
TEST_CSV = ROOT / "dga" / "data" / "umudga_test.csv"
TRANCO_WL = ROOT / "dga" / "data" / "whitelist.txt"
START = 1763700000.0  # 2025-11-21 04:40 UTC
DNS_SERVER = "192.168.10.1"
GATEWAY_MAC = b"\x00\x1a\x2b\x3c\x4d\x01"

_pools: dict = {}


def pools():
    if not _pools:
        t = pd.read_csv(TEST_CSV)
        _pools["legit_tail"] = t[t["label"] == 0]["domain"].tolist()
        _pools["dga"] = {f: g["domain"].tolist() for f, g in t[t["label"] == 1].groupby("family")}
        _pools["popular"] = [l.strip() for l in open(TRANCO_WL, encoding="utf-8") if l.strip()][:3000]
    return _pools


class Writer:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.w = dpkt.pcap.Writer(self.f, linktype=dpkt.pcap.DLT_EN10MB)
        self.pkts: list[tuple[float, bytes]] = []

    def add(self, ts, src, dst, l4, proto):
        ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=64, data=l4)
        ip.len = len(ip)
        mac = lambda a: b"\x02\x00" + socket.inet_aton(a)
        eth = dpkt.ethernet.Ethernet(src=mac(src) if src.startswith("192.168.") else GATEWAY_MAC,
                                     dst=mac(dst) if dst.startswith("192.168.") else GATEWAY_MAC,
                                     type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
        self.pkts.append((ts, bytes(eth)))

    def close(self):
        self.pkts.sort(key=lambda x: x[0])
        for ts, b in self.pkts:
            self.w.writepkt(b, ts)
        self.f.close()
        return len(self.pkts)


class Net:
    def __init__(self, w: Writer, rnd: random.Random):
        self.w, self.r = w, rnd
        self.dns_id = 1
        self.ip_of: dict[str, str] = {}

    def public_ip(self, name):
        if name not in self.ip_of:
            self.ip_of[name] = f"{self.r.randint(23, 216)}.{self.r.randint(0, 255)}.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}"
        return self.ip_of[name]

    def dns(self, ts, host, name, exists=True, ip=None):
        self.dns_id = (self.dns_id + 1) % 65535
        sport = self.r.randint(49152, 65000)
        q = dpkt.dns.DNS(id=self.dns_id, qr=dpkt.dns.DNS_Q, rd=1, qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A)])
        self.w.add(ts, host, DNS_SERVER, dpkt.udp.UDP(sport=sport, dport=53, data=bytes(q)), dpkt.ip.IP_PROTO_UDP)
        an = []
        if exists:
            ip = ip or self.public_ip(name)
            an = [dpkt.dns.DNS.RR(name=name, type=dpkt.dns.DNS_A, cls=1, ttl=300, ip=socket.inet_aton(ip))]
        a = dpkt.dns.DNS(id=self.dns_id, qr=dpkt.dns.DNS_R, rd=1, ra=1, qd=q.qd, an=an,
                         rcode=dpkt.dns.DNS_RCODE_NOERR if exists else dpkt.dns.DNS_RCODE_NXDOMAIN)
        self.w.add(ts + self.r.uniform(0.005, 0.06), DNS_SERVER, host,
                   dpkt.udp.UDP(sport=53, dport=sport, data=bytes(a)), dpkt.ip.IP_PROTO_UDP)
        return ip if exists else None

    def tcp(self, ts, host, dst, dport, nbytes=1200, answered=True):
        sport = self.r.randint(49152, 65000)
        S = lambda t, a, b, sp, dp, fl, data=b"": self.w.add(
            t, a, b, dpkt.tcp.TCP(sport=sp, dport=dp, flags=fl, seq=1, ack=1, data=data), dpkt.ip.IP_PROTO_TCP)
        S(ts, host, dst, sport, dport, dpkt.tcp.TH_SYN)
        if not answered:
            return
        rtt = self.r.uniform(0.01, 0.12)
        S(ts + rtt, dst, host, dport, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
        S(ts + rtt * 1.1, host, dst, sport, dport, dpkt.tcp.TH_ACK)
        S(ts + rtt * 1.2, host, dst, sport, dport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"\x16" * min(nbytes, 1400))
        S(ts + rtt * 2.2, dst, host, dport, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, b"\x17" * min(nbytes * 3, 1400))
        S(ts + rtt * 3, host, dst, sport, dport, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK)

    def ntp(self, ts, host):
        ip = self.public_ip("pool.ntp.org")
        self.w.add(ts, host, ip, dpkt.udp.UDP(sport=123, dport=123, data=b"\x23" + b"\x00" * 47), dpkt.ip.IP_PROTO_UDP)


def benign_host(net: Net, host, dur, rnd, updater=False):
    p = pools()
    t = rnd.uniform(0, 60)
    while t < dur:
        site = rnd.choice(p["popular"]) if rnd.random() < 0.7 else rnd.choice(p["legit_tail"])
        names = [site] + ([f"cdn.{site}", f"static.{site}"][: rnd.randint(0, 2)])
        for n in names:
            ip = net.dns(START + t, host, n)
            net.tcp(START + t + 0.08, host, ip, 443, rnd.randint(400, 1400))
            t += rnd.uniform(0.05, 0.4)
        if rnd.random() < 0.02:  # опечатка в адресе
            typo = site[:-5] + rnd.choice("qxz") + site[-5:]
            net.dns(START + t, host, typo, exists=False)
        t += rnd.expovariate(1 / 25)  # пауза между сайтами ~25 с
    for k in range(int(dur // 64)):
        net.ntp(START + k * 64 + rnd.uniform(0, 2), host)
    if updater:  # легитимная периодичность: проверка обновлений каждые 300 с
        ip = None
        for k in range(int(dur // 300)):
            ts = START + 20 + k * 300 + rnd.uniform(-3, 3)
            ip = net.dns(ts, host, "update.example-av.com")
            net.tcp(ts + 0.05, host, ip, 443, 300)


def dga_bot(net: Net, host, family, dur, rnd, per_burst=60, bursts=4, beacon=60, jitter=0.15, fallback=True):
    """Бот DGA: пачки запросов + маячки к C2 + резервный IP без DNS."""
    doms = list(pools()["dga"][family])
    rnd.shuffle(doms)
    c2_ip = f"{rnd.randint(45, 200)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(2, 250)}"
    c2_found_at, i = None, 0
    for b in range(bursts):
        t = 30 + b * (dur - 60) / bursts
        live_k = rnd.randint(int(per_burst * 0.6), per_burst - 1) if b == 0 else -1  # один «зарегистрированный»
        for k in range(per_burst):
            d = doms[i % len(doms)]
            i += 1
            if k == live_k:
                net.dns(START + t, host, d, exists=True, ip=c2_ip)
                c2_found_at = c2_found_at or t
            else:
                net.dns(START + t, host, d, exists=False)
            t += rnd.uniform(0.05, 0.6)
    if c2_found_at is not None:
        t = c2_found_at + 2
        while t < dur:
            net.tcp(START + t, host, c2_ip, 443, rnd.randint(200, 400))
            t += beacon * (1 + rnd.uniform(-jitter, jitter))
    if fallback:
        hard = f"{rnd.randint(80, 190)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(2, 250)}"
        for k in range(3):
            net.tcp(START + 10 + k * 400, host, hard, 8443, 300, answered=False)
    # бот — это ещё и обычный компьютер пользователя
    benign_part = rnd.random() < 0.5
    if benign_part:
        benign_host(net, host, dur * 0.5, rnd)
    return {"c2_ip": c2_ip}


def make_scenario(out, bots: list[str], n_benign=12, dur=1800, seed=1, updater=True, **bot_kw) -> dict:
    rnd = random.Random(seed)
    w = Writer(out)
    net = Net(w, rnd)
    truth = {}
    hosts = [f"192.168.10.{i}" for i in range(20, 20 + n_benign + len(bots))]
    rnd.shuffle(hosts)
    for k in range(n_benign):
        benign_host(net, hosts[k], dur, rnd, updater=(updater and k == 0))
        truth[hosts[k]] = {"label": "clean", "family": "updater" if (updater and k == 0) else None}
    for j, fam in enumerate(bots):
        h = hosts[n_benign + j]
        info = dga_bot(net, h, fam, dur, rnd, **bot_kw)
        truth[h] = {"label": "infected", "family": fam, **info}
    n = w.close()
    Path(str(out) + ".truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"packets": n, "truth": truth}


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--bots", nargs="*", default=["necurs", "matsnu"])
    ap.add_argument("--benign", type=int, default=12)
    ap.add_argument("--minutes", type=int, default=30)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    r = make_scenario(a.out, a.bots, a.benign, a.minutes * 60, a.seed)
    print(f"{a.out}: {r['packets']} пакетов")
    for h, t in sorted(r["truth"].items()):
        print(f"  {h:15s} {t['label']:9s} {t['family'] or ''}")
