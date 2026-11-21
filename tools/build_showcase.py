"""
Собирает страницу-витрину проекта showcase/index.html из результатов экспериментов
и кладёт рядом настоящие отчёты программы (showcase/reports/*.html).

python tools/build_showcase.py
"""
from __future__ import annotations

import html
import json
import shutil
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dga"))
from main import get_detector, run  # noqa: E402
from report_generator import render  # noqa: E402

E = html.escape
OUT = ROOT / "showcase"


def pct(x, d=0):
    return f"{x * 100:.{d}f} %".replace(".", ",")


def num(x):
    return f"{int(x):,}".replace(",", " ")


def dec(x, d=3):
    return f"{x:.{d}f}".replace(".", ",")


# ------------------------------------------------------------------ графики (встроенный SVG)
def dot_plot(df: pd.DataFrame) -> str:
    """Recall по семействам: «семейство было в обучении» vs «новое семейство (LOFO)»."""
    df = df.sort_values(["lofo", "test"], ascending=True)
    rowh, top, left, right = 17, 34, 118, 46
    W = 640
    H = top + rowh * len(df) + 30
    pw = W - left - right
    x = lambda v: left + pw * v
    o = [f'<svg viewBox="0 0 {W} {H}" width="100%" style="max-width:{W}px;min-width:420px" role="img" '
         f'aria-label="Доля обнаруженных доменов по 50 семействам DGA">']
    for t in (0, .25, .5, .75, 1):
        o.append(f'<line x1="{x(t):.1f}" x2="{x(t):.1f}" y1="{top - 6}" y2="{H - 26}" stroke="var(--grid)"/>'
                 f'<text x="{x(t):.1f}" y="{H - 10}" text-anchor="middle" class="tick">{int(t * 100)} %</text>')
    for i, (_, r) in enumerate(df.iterrows()):
        y = top + i * rowh + rowh / 2
        a, b = sorted((r["test"], r["lofo"]))
        o.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" class="lab">{E(r["family"])}</text>'
                 f'<line x1="{x(a):.1f}" x2="{x(b):.1f}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--grid-strong)" stroke-width="2"/>'
                 f'<g class="hit"><title>{E(r["family"])}: в обучении было — {pct(r["test"])}, '
                 f'новое семейство — {pct(r["lofo"])}</title>'
                 f'<rect x="{left}" y="{y - rowh / 2:.1f}" width="{pw}" height="{rowh}" fill="transparent"/>'
                 f'<circle cx="{x(r["lofo"]):.1f}" cy="{y:.1f}" r="4.5" fill="var(--s2)" stroke="var(--surface)" stroke-width="2"/>'
                 f'<circle cx="{x(r["test"]):.1f}" cy="{y:.1f}" r="4.5" fill="var(--s1)" stroke="var(--surface)" stroke-width="2"/></g>')
    o.append("</svg>")
    return "".join(o)


def hbars(items: list[tuple[str, float, str]], thr: float | None = None, thr_label: str = "",
          fmt=pct, label_w=150, aria="") -> str:
    """Горизонтальные полосы одной серии. items: (подпись, значение 0–1, подсказка)."""
    rowh, top, W = 30, 10, 640
    right = 70
    H = top + rowh * len(items) + (34 if thr is not None else 24)
    pw = W - label_w - right
    x = lambda v: label_w + pw * v
    o = [f'<svg viewBox="0 0 {W} {H}" width="100%" style="max-width:{W}px;min-width:420px" role="img" aria-label="{E(aria)}">']
    for t in (0, .5, 1):
        o.append(f'<line x1="{x(t):.1f}" x2="{x(t):.1f}" y1="{top - 4}" y2="{top + rowh * len(items)}" stroke="var(--grid)"/>')
    for i, (lab, v, tip) in enumerate(items):
        y = top + i * rowh
        w = max(pw * v, 0)
        o.append(f'<g class="hit"><title>{E(tip)}</title>'
                 f'<text x="{label_w - 10}" y="{y + rowh / 2 + 4:.1f}" text-anchor="end" class="lab">{E(lab)}</text>'
                 f'<path d="M{x(0)},{y + 6} h{max(w - 4, 0):.1f} a4,4 0 0 1 4,4 v{rowh - 20} a4,4 0 0 1 -4,4 h{-max(w - 4, 0):.1f} z" '
                 f'fill="var(--s1)"/><text x="{x(v) + 8:.1f}" y="{y + rowh / 2 + 4:.1f}" class="val">{E(fmt(v))}</text></g>')
    if thr is not None:
        o.append(f'<line x1="{x(thr):.1f}" x2="{x(thr):.1f}" y1="{top - 4}" y2="{top + rowh * len(items) + 4}" '
                 f'stroke="var(--crit)" stroke-dasharray="4 3" stroke-width="1.5"/>'
                 f'<text x="{x(thr):.1f}" y="{H - 8}" text-anchor="middle" class="tick">{E(thr_label)}</text>')
    else:
        for t in (0, .5, 1):
            o.append(f'<text x="{x(t):.1f}" y="{H - 6}" text-anchor="middle" class="tick">{int(t * 100)} %</text>')
    o.append("</svg>")
    return "".join(o)


CSS = """
/* Компоновка: витрина продукта — шапка с главными цифрами, конвейер, демонстрация, доказательства, ограничения */
:root{
  --bg:#f3f5f7; --surface:#ffffff; --ink:#14202b; --muted:#566473; --line:#d9e0e6; --soft:#edf1f4;
  --accent:#1d5f8a; --grid:#e6ebef; --grid-strong:#c3ccd4;
  --s1:#2a78d6; --s2:#eb6834;
  --crit:#d03b3b; --crit-ink:#b0302d; --crit-soft:#f9e3e2;
  --warn-ink:#94600c; --warn-soft:#f8ecd6; --good-ink:#21703f; --good-soft:#e0f1e6;
  --code-bg:#14202b; --code-ink:#e8eef3;
  --f-text:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --f-head:"IBM Plex Sans Condensed","IBM Plex Sans",system-ui,"Segoe UI",sans-serif;
  --f-mono:"IBM Plex Mono",ui-monospace,"Cascadia Mono",Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0d1217; --surface:#151c23; --ink:#e3e9ee; --muted:#95a3b0; --line:#27323c; --soft:#1b242d;
  --accent:#6aa8d4; --grid:#222c35; --grid-strong:#3a4652;
  --s1:#3987e5; --s2:#d95926;
  --crit:#d03b3b; --crit-ink:#f08880; --crit-soft:#3a1d1c;
  --warn-ink:#e7b15a; --warn-soft:#342715; --good-ink:#73c897; --good-soft:#142e1f;
  --code-bg:#0a0e12; --code-ink:#dfe7ee; color-scheme:dark}}
:root[data-theme="dark"]{
  --bg:#0d1217; --surface:#151c23; --ink:#e3e9ee; --muted:#95a3b0; --line:#27323c; --soft:#1b242d;
  --accent:#6aa8d4; --grid:#222c35; --grid-strong:#3a4652;
  --s1:#3987e5; --s2:#d95926;
  --crit:#d03b3b; --crit-ink:#f08880; --crit-soft:#3a1d1c;
  --warn-ink:#e7b15a; --warn-soft:#342715; --good-ink:#73c897; --good-soft:#142e1f;
  --code-bg:#0a0e12; --code-ink:#dfe7ee; color-scheme:dark}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font:16px/1.6 var(--f-text);margin:0}
.wrap{max-width:1040px;margin:0 auto;padding-block:36px 72px;
  padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));
  display:grid;gap:56px}
h1,h2,h3{font-family:var(--f-head);text-wrap:balance;margin:0;line-height:1.15}
h1{font-size:clamp(32px,6vw,50px);font-weight:600;letter-spacing:-.01em}
h2{font-size:clamp(23px,3.4vw,30px);font-weight:600}
h3{font-size:18px;font-weight:600}
p{margin:0;max-width:68ch}
a{color:var(--accent)}
a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.eyebrow{font:500 12px/1.2 var(--f-mono);letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.mono{font-family:var(--f-mono);font-size:.92em}
.muted{color:var(--muted)}
section{display:grid;gap:18px;min-width:0}
.hero{display:grid;gap:18px}
.lede{font-size:19px;color:var(--muted)}
pre.cmd{margin:0;background:var(--code-bg);color:var(--code-ink);border-radius:10px;padding:14px 16px;
  font:14px/1.5 var(--f-mono);overflow-x:auto}
pre.cmd .p{color:#7fa7c6}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;display:grid;gap:6px;align-content:start}
.stat b{font:600 34px/1 var(--f-mono);font-variant-numeric:tabular-nums;letter-spacing:-.02em}
.stat span{font-size:14px;color:var(--muted)}
.pipe{display:grid;grid-template-columns:1fr auto 1.25fr auto 1fr auto 1fr;gap:10px;align-items:stretch}
.pipe .arrow{align-self:center;color:var(--muted);font:18px var(--f-mono)}
.branch{display:grid;gap:10px}
.stage{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px;display:grid;gap:6px;align-content:start;min-width:0}
.stage .who{font-size:13px;color:var(--accent);font-weight:600}
.stage p{font-size:14px;color:var(--muted)}
.stage code{font:12.5px/1.45 var(--f-mono);color:var(--ink);background:var(--soft);border-radius:6px;padding:6px 8px;display:block;overflow-wrap:anywhere}
@media (max-width:820px){.pipe{grid-template-columns:1fr}.pipe .arrow{transform:rotate(90deg);justify-self:center}}
.tablebox{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
th{font:500 12px/1.3 var(--f-mono);letter-spacing:.05em;text-transform:uppercase;color:var(--muted);background:var(--soft);white-space:nowrap}
tr:last-child td{border-bottom:0}
td.num{font-family:var(--f-mono);font-variant-numeric:tabular-nums;white-space:nowrap}
tr.hl td{background:var(--soft);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-weight:600;font-size:13px;white-space:nowrap}
.pill i{width:8px;height:8px;border-radius:50%;background:currentColor;display:inline-block}
.pill.infected{background:var(--crit-soft);color:var(--crit-ink)}
.pill.suspicious{background:var(--warn-soft);color:var(--warn-ink)}
.pill.clean{background:var(--good-soft);color:var(--good-ink)}
.ok{color:var(--good-ink);font-weight:600} .bad{color:var(--crit-ink);font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px;display:grid;gap:10px;align-content:start;min-width:0}
.card .go{font-weight:600;text-decoration:none;display:inline-flex;gap:6px}
.card .go:hover{text-decoration:underline}
.figure{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;display:grid;gap:10px;min-width:0}
.figure .svgbox{overflow-x:auto}
.legend{display:flex;flex-wrap:wrap;gap:16px;font-size:13.5px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{width:10px;height:10px;border-radius:50%;display:inline-block}
svg text{font-family:var(--f-mono)}
svg .lab{font-size:11.5px;fill:var(--ink)}
svg .val{font-size:12px;fill:var(--ink);font-weight:600}
svg .tick{font-size:11px;fill:var(--muted)}
svg .hit:hover circle,svg .hit:hover path{filter:brightness(1.12)}
details{font-size:14px}
summary{cursor:pointer;color:var(--accent);font-weight:600}
summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
ul.lim{margin:0;padding-left:20px;display:grid;gap:8px;max-width:75ch}
footer{font-size:13.5px;color:var(--muted);border-top:1px solid var(--line);padding-top:16px;display:grid;gap:4px}
@media (prefers-reduced-motion:no-preference){.stat,.stage,.card{transition:border-color .15s}.card:hover{border-color:var(--accent)}}
"""


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    OUT.mkdir(exist_ok=True)
    (OUT / "reports").mkdir(exist_ok=True)
    R = json.loads((ROOT / "results" / "experiments.json").read_text(encoding="utf-8"))
    e1, e2, e3 = R["E1"], R["E2"], R["E3"]

    # --- живые отчёты программы
    det = get_detector(blacklist=None)
    demo = run(str(ROOT / "pcaps" / "demo" / "office.pcap"), det)
    (OUT / "reports" / "office.html").write_text(render(demo), encoding="utf-8")
    real = run(str(ROOT / "pcaps" / "real" / "test7-malicious.pcap"), get_detector())
    (OUT / "reports" / "test7.html").write_text(render(real), encoding="utf-8")
    truth = json.loads((ROOT / "pcaps" / "demo" / "office.pcap.truth.json").read_text(encoding="utf-8"))

    # --- детектор DGA: per-family
    ev = (ROOT / "dga" / "results" / "eval_umudga.txt").read_text(encoding="utf-8")
    fam_test = {}
    on = False
    for line in ev.splitlines():
        if line.startswith("family"):
            on = True
            continue
        if on and line.strip():
            f, v = line.split()
            fam_test[f] = float(v)
    lofo = pd.read_csv(ROOT / "dga" / "results" / "lofo.csv")
    fam = lofo.rename(columns={"recall_unseen": "lofo"})
    fam["test"] = fam["family"].map(fam_test)
    legit_fpr = (fam_test.get("legit_tranco", 0) * 17919 + fam_test.get("legit_umudga", 0) * 1918) / (17919 + 1918)

    p = []
    p.append('<title>Анализатор ботнетов PCAP</title><meta name="claude:viewport-fit-sides" content="cover">'
             '<link rel="preconnect" href="https://fonts.googleapis.com">'
             '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600'
             '&family=IBM+Plex+Sans+Condensed:wght@600&family=IBM+Plex+Sans:wght@400;600&display=swap">'
             f'<style>{CSS}</style><main class="wrap">')
    # ---------------- шапка
    p.append('<header class="hero"><span class="eyebrow">Групповой проект МУИТ · сетевая криминалистика</span>'
             '<h1>Анализатор ботнетов PCAP</h1>'
             '<p class="lede">Программа получает запись сетевого трафика и показывает, какие компьютеры в сети заражены. '
             'Она ловит ботов по двум признакам сразу: по «придуманным» доменам (DGA) и по поведению — '
             'перебору несуществующих адресов, регулярным «маячкам» к серверу управления, сканированию.</p>'
             '<pre class="cmd"><span class="p">$</span> python main.py --pcap capture.pcap --out report.html</pre>'
             '<div class="stats">'
             f'<div class="stat"><b>{e1["hybrid_infected"]["tp"]} из {e1["hybrid_infected"]["n_pos"]}</b>'
             '<span>ботов найдено — по одному на каждое семейство DGA из набора UMUDGA</span></div>'
             f'<div class="stat"><b>{e1["hybrid_infected"]["fp"]} из {e1["hybrid_infected"]["n_neg"]}</b>'
             '<span>чистых компьютеров ошибочно названы заражёнными</span></div>'
             '<div class="stat"><b>0,916</b><span>F1 детектора DGA на 39 837 доменах (порог энтропии — 0,689)</span></div>'
             f'<div class="stat"><b>{num(e3["packets_per_sec"])}</b><span>пакетов в секунду на обычном ноутбуке, без GPU</span></div>'
             '</div></header>')
    # ---------------- конвейер
    p.append('<section><span class="eyebrow">Устройство</span><h2>Как программа работает</h2>'
             '<p class="muted">Пять модулей, у каждого свой автор. Сырой трафик читает только парсер, '
             'остальные работают с таблицами, поэтому две ветви анализа независимы.</p><div class="pipe">'
             '<div class="stage"><span class="eyebrow">Шаг 1</span><h3>Парсер PCAP</h3><span class="who">Солтанбек Б</span>'
             '<p>Читает pcap/pcapng, собирает DNS-запросы с ответами и соединения.</p>'
             '<code>dns_events, conn_events</code></div><span class="arrow">→</span>'
             '<div class="branch">'
             '<div class="stage"><span class="eyebrow">Шаг 2а</span><h3>Детектор DGA</h3><span class="who">Жумажанов Н</span>'
             '<p>13 признаков имени домена и Random Forest. Объясняет, какой признак выдал домен.</p>'
             '<code>domain → dga_score 0–1</code></div>'
             '<div class="stage"><span class="eyebrow">Шаг 2б</span><h3>Анализ поведения</h3><span class="who">Нурсоветов А</span>'
             '<p>Доля NXDOMAIN, всплески запросов, маячки к C2, IP без DNS, сканирование.</p>'
             '<code>host → behavior_score 0–1</code></div></div><span class="arrow">→</span>'
             '<div class="stage"><span class="eyebrow">Шаг 3</span><h3>Объединение</h3><span class="who">Басыбек М</span>'
             '<p>Любая сильная улика поднимает риск, совпадение двух усиливает его.</p>'
             '<code>риск = 1 − (1 − 0,8·DGA)(1 − 0,9·поведение)</code></div><span class="arrow">→</span>'
             '<div class="stage"><span class="eyebrow">Шаг 4</span><h3>Отчёт</h3><span class="who">Басыбек М</span>'
             '<p>HTML для эксперта: вердикты, улики, номера пакетов для Wireshark, техники MITRE ATT&amp;CK.</p>'
             '<code>report.html, findings.json</code></div></div></section>')
    # ---------------- демонстрация
    fmap = {f["src_ip"]: f for f in demo["findings"]}
    order = sorted(truth, key=lambda ip: -fmap[ip]["risk"])
    rows = []
    for ip in order:
        t, f = truth[ip], fmap[ip]
        who = f'бот <span class="mono">{E(t["family"] or "")}</span>' if t["label"] == "infected" else "обычный пользователь"
        if t.get("family") == "updater":
            who = "программа, проверяющая обновления раз в 5 минут"
        right = (t["label"] == "infected") == (f["verdict"] == "infected")
        rows.append(f'<tr><td class="num">{E(ip)}</td><td>{who}</td>'
                    f'<td><span class="pill {f["verdict"]}"><i></i>{E(f["verdict_label"])}</span></td>'
                    f'<td class="num">{dec(f["risk"], 2)}</td>'
                    f'<td>{E(f["evidence"][0]) if f["evidence"] and f["verdict"] != "clean" else "—"}</td></tr>')
    st = demo["stats"]
    p.append('<section><span class="eyebrow">Демонстрация</span><h2>Офисная сеть с двумя ботами</h2>'
             f'<p class="muted">Получасовая запись сети из {len(truth)} компьютеров ({num(st.packets)} пакетов). Мы заранее знаем, '
             'кто заражён: бот necurs (случайные домены) и бот matsnu (склейки слов). Программа видит только трафик. '
             f'Анализ занял {dec(demo["timings"]["total"], 1)} с.</p>'
             '<div class="tablebox"><table><thead><tr><th>Компьютер</th><th>Кто это на самом деле</th><th>Вердикт программы</th>'
             f'<th>Риск</th><th>Главная улика</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
             '<div class="cards">'
             '<div class="card"><span class="eyebrow">Отчёт программы</span><h3>office.pcap</h3>'
             '<p class="muted">Итог простыми словами, улики по каждому боту, подозрительные домены с номерами пакетов.</p>'
             '<a class="go" href="reports/office.html">Открыть отчёт →</a></div>'
             '<div class="card"><span class="eyebrow">Реальный вредоносный трафик</span><h3>test7-malicious.pcap</h3>'
             '<p class="muted">Запись из открытого набора Stratosphere Lab (авторы CTU-13). Заражённое IoT-устройство '
             'сканирует Telnet на сотнях адресов. Программа помечает его как вероятно заражённое.</p>'
             '<a class="go" href="reports/test7.html">Открыть отчёт →</a></div></div></section>')
    # ---------------- детектор DGA
    p.append('<section><span class="eyebrow">Модуль 2а</span><h2>Насколько хорошо детектор узнаёт DGA-домены</h2>'
             '<p class="muted">Обучение на 159 тыс. доменов: 50 семейств вредоносов из UMUDGA и нормальные сайты из Tranco. '
             'Проверка на 39 837 доменах, которых модель не видела.</p>'
             '<div class="tablebox"><table><thead><tr><th>Метод</th><th>Precision</th><th>Recall</th><th>F1</th>'
             '<th>Ложные срабатывания</th></tr></thead><tbody>'
             '<tr><td>Порог энтропии H &gt; 3,0 (базовый метод)</td><td class="num">0,684</td><td class="num">0,694</td>'
             '<td class="num">0,689</td><td class="num">32,3 %</td></tr>'
             '<tr class="hl"><td>Наш Random Forest, 13 признаков</td><td class="num">0,925</td><td class="num">0,908</td>'
             f'<td class="num">0,916</td><td class="num">{pct(legit_fpr, 1)}</td></tr></tbody></table></div>'
             '<div class="figure"><h3>Доля пойманных доменов по семействам</h3>'
             '<p class="muted" style="font-size:14px">Синяя точка — семейство было в обучении. Оранжевая — модель обучали без него '
             '(как будто появился новый вирус). Случайные домены узнаются даже у новых вирусов. Склейки слов '
             '(suppobox, matsnu, pizd) — нет.</p>'
             '<div class="legend"><span><i style="background:var(--s1)"></i>семейство было в обучении</span>'
             '<span><i style="background:var(--s2)"></i>новое семейство (leave-one-family-out)</span></div>'
             f'<div class="svgbox">{dot_plot(fam)}</div>'
             '<details><summary>Таблица значений</summary><div class="tablebox" style="margin-top:8px"><table><thead><tr>'
             '<th>Семейство</th><th>В обучении было</th><th>Новое семейство</th></tr></thead><tbody>'
             + "".join(f'<tr><td class="mono">{E(r.family)}</td><td class="num">{pct(r.test)}</td><td class="num">{pct(r.lofo)}</td></tr>'
                       for r in fam.sort_values("lofo").itertuples())
             + '</tbody></table></div></details></div></section>')
    # ---------------- эксперименты
    meth = [("Только детектор DGA", e2["dga_only"]["recall"]), ("Только поведение", e2["behavior_only"]["recall"]),
            ("Гибрид (наш модуль)", e2["hybrid_infected"]["recall"])]
    quiet = sorted(e2["bot_risk_by_family"].items(), key=lambda kv: kv[1]["risk"])
    p.append('<section><span class="eyebrow">Этап 4 · эксперименты</span><h2>Всё вместе: находит ли программа заражённые компьютеры</h2>'
             '<p class="muted">Для каждого из 50 семейств собрана отдельная запись: 10 обычных компьютеров, '
             'программа-апдейтер и один бот. Ботов проверяли по доменам, которых детектор не видел при обучении, '
             'чёрный список отключён.</p>'
             '<div class="tablebox"><table><thead><tr><th>Метод (50 сценариев)</th><th>Найдено ботов</th>'
             '<th>Ложные тревоги на 450 чистых</th><th>F1</th></tr></thead><tbody>'
             f'<tr><td>Базовый: ≥ 5 доменов с энтропией &gt; 3,0</td><td class="num">{e1["entropy_baseline"]["tp"]} / 50</td>'
             f'<td class="num bad">{e1["entropy_baseline"]["fp"]} ({pct(e1["entropy_baseline"]["fpr"])})</td><td class="num">{dec(e1["entropy_baseline"]["f1"])}</td></tr>'
             f'<tr><td>Только детектор DGA</td><td class="num">{e1["dga_only"]["tp"]} / 50</td><td class="num">{e1["dga_only"]["fp"]}</td>'
             f'<td class="num">{dec(e1["dga_only"]["f1"])}</td></tr>'
             f'<tr><td>Только поведение</td><td class="num">{e1["behavior_only"]["tp"]} / 50</td><td class="num">{e1["behavior_only"]["fp"]}</td>'
             f'<td class="num">{dec(e1["behavior_only"]["f1"])}</td></tr>'
             f'<tr class="hl"><td>Гибрид (наш модуль)</td><td class="num">{e1["hybrid_infected"]["tp"]} / 50</td>'
             f'<td class="num ok">{e1["hybrid_infected"]["fp"]}</td><td class="num">{dec(e1["hybrid_infected"]["f1"])}</td></tr>'
             '</tbody></table></div>'
             f'<p class="muted">Апдейтер ни разу не назван заражённым: во всех {e1["updater"]["n"]} сценариях он получил вердикт '
             '«подозрительный». Регулярные обращения бывают и у честных программ, поэтому решение по нему остаётся за аналитиком.</p>'
             '<div class="two">'
             '<div class="figure"><h3>«Тихий» бот: какая доля найдена</h3>'
             '<p class="muted" style="font-size:14px">12 ботов шлют всего 20 запросов за полчаса и выходят на связь раз в 5 минут '
             'с разбросом ±50 %. Поодиночке ветви анализа пропускают многих, вместе — почти никого.</p>'
             f'<div class="svgbox">{hbars([(m, v, f"{m}: найдено {pct(v)}") for m, v in meth], aria="Доля найденных тихих ботов по методам", label_w=170)}</div></div>'
             '<div class="figure"><h3>Риск каждого «тихого» бота</h3>'
             '<p class="muted" style="font-size:14px">Пунктир — порог «вероятно заражён» (0,6). suppobox_2 склеивает два '
             'частых слова и остаётся «подозрительным».</p>'
             f'<div class="svgbox">{hbars([(f, v["risk"], f"{f}: риск {dec(v["risk"], 2)}") for f, v in quiet], thr=0.6, thr_label="порог 0,6", fmt=lambda v: dec(v, 2), aria="Риск тихих ботов", label_w=110)}</div></div>'
             '</div>'
             '<div class="stats">'
             f'<div class="stat"><b>{dec(e3["timings"]["total"], 1)} с</b><span>на запись в {dec(e3["size_mb"], 1)} МБ: '
             f'{num(e3["packets"])} пакетов, {e3["hosts"]} компьютеров, час трафика</span></div>'
             f'<div class="stat"><b>{e3["detection"]["tp"]} из {e3["detection"]["n_pos"]}</b><span>ботов найдено в этой большой '
             f'сети, ложных тревог — {e3["detection"]["fp"]} из {e3["detection"]["n_neg"]}</span></div>'
             f'<div class="stat"><b>{num(e3["parse_packets_per_sec"])}</b><span>пакетов в секунду разбирает парсер</span></div>'
             '</div></section>')
    # ---------------- ограничения
    p.append('<section><span class="eyebrow">Честно о слабых местах</span><h2>Ограничения</h2><ul class="lim">'
             '<li><b>Словарные DGA.</b> Домены вроде <span class="mono">weakgrow.net</span> по имени неотличимы от обычных. '
             'Такого бота выдаёт только поведение: перебор несуществующих доменов и маячки.</li>'
             '<li><b>Обычный трафик в сценариях искусственный.</b> Домены настоящие (Tranco, UMUDGA), а расписание посещений '
             'сгенерировано. На реальной сети с тысячами пользователей пороги нужно перенастроить.</li>'
             '<li><b>Зашифрованный DNS</b> (DoH/DoT) прячет имена доменов: остаются только признаки соединений.</li>'
             '<li><b>Сервер CTU-13 был недоступен</b>, поэтому из реального вредоносного трафика проверены две небольшие записи Stratosphere. '
             'В них нет DGA, но есть сканирование, и его программа нашла.</li></ul></section>')
    p.append('<footer><span>Разработка автоматизированного модуля анализа сетевых дампов (PCAP) для выявления ботнет-активности и DGA.</span>'
             '<span>Басыбек М · Солтанбек Б · Жумажанов Н · Нурсоветов А · Макушев К — International Information Technology University</span>'
             '<span>Данные: UMUDGA (Zago и др., 2020), Tranco Top-1M, Stratosphere Lab.</span></footer></main>')
    (OUT / "index.html").write_text("".join(p), encoding="utf-8")
    print("showcase/index.html готов")


if __name__ == "__main__":
    main()
