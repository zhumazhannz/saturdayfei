"""
pcap_parser.py — модуль парсинга PCAP (Студент 2, Солтанбек Б).

Единственный компонент, который читает сырой трафик. Остальные работают с таблицами:

dns_events:  timestamp, pkt_no, src_ip, dns_server, query, qtype, rcode, answers, ttl
             (одна строка на DNS-запрос; rcode: NOERROR / NXDOMAIN / SERVFAIL / ... / NORESPONSE)
conn_events: timestamp, pkt_no, src_ip, dst_ip, dst_port, proto, packets, bytes, duration, had_dns_lookup
             (одна строка на соединение; had_dns_lookup — был ли dst_ip в DNS-ответе ДО соединения)

Поддерживается pcap и pcapng; канальный уровень Ethernet, Linux SLL, Raw IP, Loopback; IPv4/IPv6; DNS по UDP и TCP.

python pcap_parser.py capture.pcap      → печатает сводку
"""
from __future__ import annotations

import hashlib
import ipaddress
import socket
import sys
import time
from dataclasses import dataclass, field

import dpkt
import pandas as pd

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
DEDUP_WINDOW = 1.0         # секунд: одинаковые кадры в этом окне — копии одного пакета
FLOW_IDLE_TIMEOUT = 60.0  # секунд тишины — и следующий пакет считается новым соединением


def ip_str(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6 if len(raw) == 16 else socket.AF_INET, raw)


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local or a.is_loopback
    except ValueError:
        return False


@dataclass
class ParseStats:
    packets: int = 0
    ip_packets: int = 0
    dns_packets: int = 0
    duplicates: int = 0
    skipped: int = 0
    start: float | None = None
    end: float | None = None
    seconds: float = 0.0
    linktype: int = 0
    errors: list = field(default_factory=list)


def _open(f):
    try:
        return dpkt.pcap.Reader(f)
    except ValueError:
        f.seek(0)
        return dpkt.pcapng.Reader(f)


def _ip_layer(buf: bytes, linktype: int):
    if linktype == dpkt.pcap.DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype in (113, 276):  # Linux cooked SLL / SLL2
        sll = dpkt.sll.SLL(buf) if linktype == 113 else dpkt.sll2.SLL2(buf)
        return sll.data if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype in (0, 108):    # BSD loopback
        lo = dpkt.loopback.Loopback(buf)
        return lo.data if isinstance(lo.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype in (12, 14, 101, 228, 229):  # raw IP
        v = buf[0] >> 4
        return dpkt.ip.IP(buf) if v == 4 else dpkt.ip6.IP6(buf) if v == 6 else None
    raise ValueError(f"Неподдерживаемый тип канала (linktype {linktype})")


def _parse_dns(payload: bytes, over_tcp: bool):
    if over_tcp:
        if len(payload) < 2:
            return None
        payload = payload[2:2 + int.from_bytes(payload[:2], "big")]
    try:
        return dpkt.dns.DNS(payload)
    except (dpkt.UnpackError, IndexError, ValueError):
        return None


def parse_pcap(path: str, dedup: bool = True) -> tuple[pd.DataFrame, pd.DataFrame, ParseStats]:
    """dedup: отбрасывать побайтно одинаковые кадры, пришедшие в пределах DEDUP_WINDOW секунд.
    Windows pktmon записывает каждый пакет на нескольких уровнях стека (до ~9 копий),
    Wireshark с нескольких интерфейсов — тоже. Номера пакетов остаются исходными (как в Wireshark)."""
    st = ParseStats()
    recent: dict[bytes, float] = {}
    t0 = time.perf_counter()
    pending: dict[tuple, dict] = {}   # (клиент, txid, qname) → событие запроса
    dns_rows: list[dict] = []
    flows: dict[tuple, dict] = {}     # (src, dst, dport, proto) → текущее соединение
    conn_rows: list[dict] = []
    resolved: dict[str, float] = {}   # ip → время первого DNS-ответа с этим ip

    with open(path, "rb") as f:
        rd = _open(f)
        st.linktype = rd.datalink()
        for ts, buf in rd:
            st.packets += 1
            n = st.packets
            st.start = ts if st.start is None else st.start
            st.end = ts
            if dedup:
                h = hashlib.blake2b(buf, digest_size=12).digest()
                prev = recent.get(h)
                recent[h] = ts
                if prev is not None and ts - prev <= DEDUP_WINDOW:
                    st.duplicates += 1
                    continue
                if len(recent) > 200_000:  # чистим старые записи, чтобы не расти бесконечно
                    recent = {k: v for k, v in recent.items() if ts - v <= DEDUP_WINDOW}
            try:
                ip = _ip_layer(buf, st.linktype)
            except Exception as e:  # битый кадр — пропускаем, но не падаем
                st.skipped += 1
                if len(st.errors) < 5:
                    st.errors.append(f"пакет {n}: {e}")
                continue
            if ip is None:
                st.skipped += 1
                continue
            st.ip_packets += 1
            l4 = ip.data
            if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                continue
            src, dst = ip_str(ip.src), ip_str(ip.dst)
            proto = "tcp" if isinstance(l4, dpkt.tcp.TCP) else "udp"
            sport, dport = l4.sport, l4.dport

            # ---------- DNS
            if 53 in (sport, dport):  # mDNS (5353) — это не резолвинг, его не берём
                payload = bytes(l4.data)
                dns = _parse_dns(payload, proto == "tcp") if payload else None
                if dns is None or not dns.qd:
                    continue
                st.dns_packets += 1
                q = dns.qd[0]
                qname = q.name.lower().rstrip(".")
                if dns.qr == dpkt.dns.DNS_Q:
                    key = (src, dns.id, qname)
                    ev = {"timestamp": ts, "pkt_no": n, "src_ip": src, "dns_server": dst,
                          "query": qname, "qtype": QTYPES.get(q.type, str(q.type)),
                          "rcode": "NORESPONSE", "answers": [], "ttl": None, "resp_pkt_no": None}
                    pending[key] = ev
                    dns_rows.append(ev)
                else:
                    answers, ttl = [], None
                    for rr in dns.an:
                        if rr.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA):
                            a = ip_str(rr.ip if rr.type == dpkt.dns.DNS_A else rr.ip6)
                            answers.append(a)
                            resolved.setdefault(a, ts)
                            ttl = rr.ttl if ttl is None else min(ttl, rr.ttl)
                    key = (dst, dns.id, qname)
                    ev = pending.pop(key, None)
                    if ev is None:  # ответ без запроса в дампе (захват начался посередине)
                        ev = {"timestamp": ts, "pkt_no": n, "src_ip": dst, "dns_server": src,
                              "query": qname, "qtype": QTYPES.get(q.type, str(q.type)),
                              "rcode": None, "answers": [], "ttl": None, "resp_pkt_no": None}
                        dns_rows.append(ev)
                    ev["rcode"] = RCODES.get(dns.rcode, str(dns.rcode))
                    ev["answers"] = answers
                    ev["ttl"] = ttl
                    ev["resp_pkt_no"] = n
                continue

            # ---------- соединения (не DNS)
            if sport == 5353 or dport == 5353 or _is_noise_dst(dst):
                continue
            size = len(buf)
            if proto == "tcp":
                syn = bool(l4.flags & dpkt.tcp.TH_SYN) and not (l4.flags & dpkt.tcp.TH_ACK)
                key = (src, dst, dport, proto)
                rkey = (dst, src, sport, proto)
                if syn:
                    _start_flow(flows, conn_rows, key, ts, n, resolved)
                elif key in flows:
                    _touch(flows[key], ts, size)
                    continue
                elif rkey in flows:
                    _touch(flows[rkey], ts, size)
                    continue
                else:
                    continue  # середина соединения, начатого до захвата
                _touch(flows[key], ts, size)
            else:
                key = (src, dst, dport, proto)
                rkey = (dst, src, sport, proto)
                if rkey in flows and ts - flows[rkey]["_last"] <= FLOW_IDLE_TIMEOUT:
                    _touch(flows[rkey], ts, size)
                    continue
                fl = flows.get(key)
                if fl is None or ts - fl["_last"] > FLOW_IDLE_TIMEOUT:
                    _start_flow(flows, conn_rows, key, ts, n, resolved)
                _touch(flows[key], ts, size)

    st.seconds = time.perf_counter() - t0
    dns_df = pd.DataFrame(dns_rows, columns=["timestamp", "pkt_no", "src_ip", "dns_server", "query", "qtype",
                                             "rcode", "answers", "ttl", "resp_pkt_no"])
    conn_df = pd.DataFrame([{k: v for k, v in r.items() if not k.startswith("_")} for r in conn_rows],
                           columns=["timestamp", "pkt_no", "src_ip", "dst_ip", "dst_port", "proto",
                                    "packets", "bytes", "duration", "had_dns_lookup"])
    if not dns_df.empty:
        dns_df["rcode"] = dns_df["rcode"].fillna("NORESPONSE")
    return dns_df, conn_df, st


def _is_noise_dst(ip: str) -> bool:
    """Широковещательные и multicast-адреса (DHCP, SSDP, mDNS) — не соединения хоста."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_multicast or a.is_unspecified or ip.endswith(".255")
    except ValueError:
        return True


def _start_flow(flows, rows, key, ts, n, resolved):
    src, dst, dport, proto = key
    r = {"timestamp": ts, "pkt_no": n, "src_ip": src, "dst_ip": dst, "dst_port": dport, "proto": proto,
         "packets": 0, "bytes": 0, "duration": 0.0,
         "had_dns_lookup": dst in resolved and resolved[dst] <= ts, "_last": ts}
    flows[key] = r
    rows.append(r)


def _touch(fl, ts, size):
    fl["packets"] += 1
    fl["bytes"] += size
    fl["duration"] = round(ts - fl["timestamp"], 3)
    fl["_last"] = ts


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    dns, conns, st = parse_pcap(sys.argv[1])
    print(f"Пакетов: {st.packets} (дублей убрано: {st.duplicates}), IP: {st.ip_packets}, DNS: {st.dns_packets}, пропущено: {st.skipped}, "
          f"разбор: {st.seconds:.2f} с ({st.packets / max(st.seconds, 1e-9):,.0f} пакетов/с)")
    print(f"DNS-запросов: {len(dns)}, соединений: {len(conns)}")
    if not dns.empty:
        print(dns["rcode"].value_counts().to_string())
        print(dns.head(10)[["src_ip", "query", "rcode", "answers"]].to_string(index=False))
    if not conns.empty:
        print(conns.head(10).to_string(index=False))
