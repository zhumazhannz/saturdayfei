"""
report_generator.py — генератор HTML-отчёта (Студент 1).

Простой документ: итог простыми словами, таблица компьютеров, подробности по подозрительным.
Один файл без внешних зависимостей, открывается в любом браузере и печатается.
"""
from __future__ import annotations

import datetime as dt
import html
from pathlib import Path

E = html.escape

CSS = """
body { font-family: Arial, Helvetica, sans-serif; font-size: 16px; line-height: 1.5;
       color: #222; background: #fff; margin: 0; }
.page { max-width: 900px; margin: 0 auto; padding: 32px 20px 48px; }
h1 { font-size: 26px; margin: 0 0 6px; }
h2 { font-size: 20px; margin: 36px 0 10px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
h3 { font-size: 17px; margin: 24px 0 8px; }
p { margin: 8px 0; }
.meta { color: #555; font-size: 14px; }
.summary { border: 1px solid #ccc; padding: 12px 16px; margin: 16px 0; background: #fafafa; }
.summary p { margin: 6px 0; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 15px; }
th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f0f0f0; font-weight: bold; }
.tbl { overflow-x: auto; }
.red { color: #b00020; font-weight: bold; }
.orange { color: #a15c00; font-weight: bold; }
.green { color: #1e7b34; font-weight: bold; }
.code { font-family: Consolas, "Courier New", monospace; font-size: 14px; }
ul { margin: 6px 0; padding-left: 22px; }
li { margin: 3px 0; }
.small { font-size: 13px; color: #666; }
@media (prefers-color-scheme: dark) {
  body { color: #e6e6e6; background: #1b1b1b; }
  .meta, .small { color: #aaa; }
  h2, th, td, .summary { border-color: #444; }
  th { background: #2a2a2a; }
  .summary { background: #232323; }
  .red { color: #ff7b7b; } .orange { color: #f0b35a; } .green { color: #7bd88f; }
}
"""

VERDICT_CLASS = {"infected": "red", "suspicious": "orange", "clean": "green"}


def _ts(t) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC") if t else "—"


def _dur(sec) -> str:
    sec = float(sec or 0)
    if sec < 60:
        return f"{sec:.0f} с"
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    return f"{h} ч {m} мин" if h else f"{m} мин {s} с"


def _num(x) -> str:
    return f"{int(x):,}".replace(",", " ")


def plain_reasons(f: dict) -> list[str]:
    """Причины вердикта простыми словами (без терминов)."""
    b = f["behavior"]
    c = b.get("components") or {}
    out = []
    if f["dga_component"] >= 0.3:
        nx = sum(1 for d in f["top_domains"] if d["rcode"] == "NXDOMAIN")
        out.append(f"обращался к {f['n_suspicious_domains']} адресам сайтов, похожим на случайно придуманные "
                   f"вирусом (DGA)" + (", большинство из них не существует" if nx >= len(f["top_domains"]) / 2 else ""))
    if c.get("nxdomain", 0) > 0 and b.get("nxdomain_ratio") is not None:
        out.append(f"{b['nxdomain_ratio']:.0%} его запросов — к несуществующим сайтам")
    if c.get("beacon", 0) >= 0.3 and b.get("beacon_period"):
        out.append(f"регулярно, примерно каждые {b['beacon_period']:.0f} с, связывался с одним и тем же адресом "
                   f"({b['beacon_target']}) — так бот выходит на связь со своим сервером")
    if c.get("no_dns", 0) > 0:
        out.append(f"соединялся с {b['no_dns_conns']} адресами в интернете напрямую, без запроса имени сайта")
    if c.get("scan", 0) >= 0.3:
        out.append(f"пытался подключиться к {b['scan_targets']} адресам, которые не ответили (похоже на сканирование)")
    if c.get("ports", 0) > 0:
        out.append("использовал необычные сетевые порты")
    return out


def _sentence(f: dict) -> str:
    r = plain_reasons(f)
    if not r:
        return "заметной подозрительной активности нет."
    return "; ".join(r) + "."


def render(res: dict) -> str:
    st, dns, conns = res["stats"], res["dns"], res["conns"]
    findings, tm = res["findings"], res["timings"]
    name = Path(res["pcap"]).name
    inf = [f for f in findings if f["verdict"] == "infected"]
    sus = [f for f in findings if f["verdict"] == "suspicious"]
    cln = [f for f in findings if f["verdict"] == "clean"]
    p = []
    p.append('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width,initial-scale=1">'
             f'<title>Отчёт: {E(name)}</title><style>{CSS}</style></head><body><div class="page">')

    # ---- шапка
    p.append(f'<h1>Отчёт анализа сетевого трафика</h1>'
             f'<p class="meta">Файл: <span class="code">{E(name)}</span> · запись от {_ts(st.start)}, '
             f'длительность {_dur((st.end or 0) - (st.start or 0))} · пакетов: {_num(st.packets)} · '
             f'компьютеров: {len(findings)} · анализ занял {tm["total"]:.1f} с</p>')

    # ---- итог простыми словами
    p.append('<div class="summary">')
    p.append(f'<p><b>Итог.</b> Проверено компьютеров: {len(findings)}. '
             f'<span class="red">Вероятно заражены: {len(inf)}</span>, '
             f'<span class="orange">подозрительные: {len(sus)}</span>, '
             f'<span class="green">чистые: {len(cln)}</span>.</p>')
    if not inf and not sus:
        p.append('<p>Признаков заражения не найдено.</p>')
    for f in inf:
        p.append(f'<p><span class="code">{E(f["src_ip"])}</span> — <span class="red">вероятно заражён</span>: '
                 f'{E(_sentence(f))}</p>')
    for f in sus:
        p.append(f'<p><span class="code">{E(f["src_ip"])}</span> — <span class="orange">подозрительный</span>: '
                 f'{E(_sentence(f))} Такое поведение бывает и у обычных программ (торрент-клиент, '
                 f'проверка обновлений), поэтому нужна проверка человеком.</p>')
    p.append('</div>')

    # ---- все компьютеры
    rows = []
    for f in findings:
        cls = VERDICT_CLASS[f["verdict"]]
        why = plain_reasons(f)
        rows.append(f'<tr><td class="code">{E(f["src_ip"])}</td><td class="{cls}">{E(f["verdict_label"])}</td>'
                    f'<td>{f["risk"]:.2f}</td><td>{E(why[0]) if why else "—"}</td></tr>')
    p.append('<h2>Все компьютеры</h2><div class="tbl"><table><tr><th>Адрес</th><th>Вердикт</th><th>Риск (0–1)</th>'
             f'<th>Главная причина</th></tr>{"".join(rows)}</table></div>')

    # ---- подробности
    flagged = inf + sus
    if flagged:
        p.append('<h2>Подробности</h2>')
    for f in flagged:
        cls = VERDICT_CLASS[f["verdict"]]
        p.append(f'<h3><span class="code">{E(f["src_ip"])}</span> — <span class="{cls}">{E(f["verdict_label"])}</span>, '
                 f'риск {f["risk"]:.2f}</h3>')
        p.append('<p>Что заметила программа:</p><ul>' + "".join(f"<li>{E(e)}</li>" for e in f["evidence"]) + '</ul>')
        p.append(f'<p>Вклад в риск: имена сайтов (DGA) — {f["dga_component"]:.2f}, поведение — {f["behavior_component"]:.2f}.</p>')
        if f["top_domains"]:
            drows = "".join(
                f'<tr><td class="code">{E(d["domain"])}</td><td>{d["dga_score"]:.2f}</td>'
                f'<td>{"не существует" if d["rcode"] == "NXDOMAIN" else ("существует" if d["rcode"] == "NOERROR" else E(d["rcode"]))}</td>'
                f'<td class="code">{", ".join(str(n) for n in d["packets"])}</td></tr>' for d in f["top_domains"])
            p.append(f'<p>Подозрительные адреса сайтов (показано {len(f["top_domains"])} из {f["n_suspicious_domains"]}):</p>'
                     '<div class="tbl"><table><tr><th>Адрес</th><th>Похожесть на DGA (0–1)</th><th>Сайт</th>'
                     f'<th>Номера пакетов</th></tr>{drows}</table></div>')
        if f["mitre_techniques"]:
            p.append('<p class="small">Техники по справочнику MITRE ATT&amp;CK: '
                     + "; ".join(f'{E(m["id"])} ({E(m["name"])})' for m in f["mitre_techniques"]) + '</p>')

    # ---- как читать
    p.append('<h2>Как читать отчёт</h2><ul>'
             '<li><b>Риск</b> — число от 0 до 1. От 0,6 — «вероятно заражён», от 0,35 — «подозрительный», ниже — «чистый».</li>'
             '<li><b>DGA</b> — способ, которым вирусы каждый день придумывают новые случайные адреса своих серверов '
             '(например, <span class="code">xjw8qpl2zkq.net</span>). Большинство таких адресов не существует.</li>'
             '<li><b>Номера пакетов</b> совпадают с номерами в Wireshark: по ним любую улику можно открыть и проверить.</li>'
             f'<li>Всего в записи: {_num(len(dns))} запросов имён сайтов (DNS) и {_num(len(conns))} соединений.</li></ul>')
    p.append(f'<p class="small">Модуль анализа сетевых дампов для выявления ботнетов и DGA · МУИТ · '
             f'отчёт создан {dt.datetime.now().strftime("%d.%m.%Y %H:%M")}</p>')
    p.append('</div></body></html>')
    return "".join(p)
