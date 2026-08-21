"""Testes sem rede: rodam sempre, em qualquer maquina, em segundos."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.db import connect, save_scan, scans_for
from funnel_recon.osint.rdap import _parse_iso
from funnel_recon.osint.runner import normalize_targets
from funnel_recon.report import _correlate
from funnel_recon.schema import ScanResult
from funnel_recon.signals import is_meta_host, looks_like_redirector, scan_text

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


# --- erro 4 da secao 4: dominio do Meta nunca e alvo ------------------------
check("meta transparency", is_meta_host("transparency.meta.com"), True)
check("meta cdn", is_meta_host("scontent-gru1.xx.fbcdn.net"), True)
check("meta insta", is_meta_host("instagram.com"), True)
check("alvo real", is_meta_host("cantinhoprivado.shop"), False)
# Guarda contra falso positivo por sufixo: "notmeta.com" nao e do Meta.
check("sufixo falso", is_meta_host("notmeta.com"), False)

# --- erro 1 da secao 4: a URL util tem PATH --------------------------------
check("redirector real", looks_like_redirector(
    "https://cantinhoprivado.shop/l/ab68b001?fbclid=IwcGRvZ"), True)
check("raiz nao e redirector", looks_like_redirector("https://cantinhoprivado.shop/"), False)

# --- sinais ----------------------------------------------------------------
check("telegram", "telegram_link" in scan_text("acesse https://t.me/+abc123"), True)
check("pixel", "fb_pixel" in scan_text("fbq('init', '123456789012')"), True)
check("kclickid nao vira binom", scan_text("kclickid=9"), ["tracker_keitaro"])
check("texto limpo", scan_text("loja de roupas femininas"), [])

# --- normalizacao de alvos -------------------------------------------------
check("url vira host", normalize_targets(["https://cantinhoprivado.shop/l/x?fbclid=1"]),
      ["cantinhoprivado.shop"])
check("www removido", normalize_targets(["www.exemplo.shop"]), ["exemplo.shop"])
check("meta filtrado na entrada", normalize_targets(
    ["transparency.meta.com", "alvo.shop"]), ["alvo.shop"])
check("dedup", normalize_targets(["a.shop", "https://a.shop/x", "www.a.shop"]), ["a.shop"])

# --- datas: o bug que reportou idade falsa de 10 anos ----------------------
check("rdap iso", str(_parse_iso("2026-03-17T03:04:32.0Z").date()), "2026-03-17")
check("data simples", str(_parse_iso("2026-03-17").date()), "2026-03-17")
check("lixo vira None", _parse_iso("nao e data"), None)
check("vazio vira None", _parse_iso(None), None)

# --- correlacao: mesmo par de NS = mesmo operador --------------------------
ns = "ns_pair:aldo.ns.cloudflare.com,evangeline.ns.cloudflare.com"
corr = _correlate({
    "a.shop": [ScanResult(target="a.shop", stage="osint", source="rdap", signals=[ns])],
    "b.shop": [ScanResult(target="b.shop", stage="osint", source="rdap", signals=[ns])],
})
check("correlacao detectada", any("MESMO PAR DE NAMESERVERS" in c for c in corr), True)
solo = _correlate({
    "a.shop": [ScanResult(target="a.shop", stage="osint", source="rdap", signals=[ns])],
    "b.shop": [ScanResult(target="b.shop", stage="osint", source="rdap",
                          signals=["ns_pair:outro.ns.com"])],
})
check("sem correlacao falsa", any("MESMO PAR" in c for c in solo), False)

# --- persistencia: listas e dict voltam intactos ---------------------------
conn = connect(":memory:")
save_scan(conn, ScanResult(target="t.shop", stage="osint", source="rdap",
                           signals=["a", "b"], raw={"k": [1, 2]}))
row = scans_for(conn, "t.shop")[0]
check("signals persistidos", row["signals"], '["a", "b"]')
check("raw persistido", row["raw"], '{"k": [1, 2]}')

# --- caminhos arquivados: a pista quando o anuncio nao entrega o caminho ----
# O indice do Wayback guarda URL malformada raspada de dentro de pagina. Sem
# filtro, medido em iana.org, saem 1.153 "caminhos" e as primeiras 12 linhas
# sao todas lixo. O filtro e o que torna a secao utilizavel.
from funnel_recon.osint.wayback import archived_paths

LINHAS = [
    ["20240101", "https://alvo.site/quiz", "200", "text/html"],
    ["20240102", "https://alvo.site/quiz", "200", "text/html"],
    ["20240103", "https://alvo.site/vsl", "200", "text/html"],
    ["20240104", "https://alvo.site/", "200", "text/html"],          # raiz
    ["20240105", "https://alvo.site/sumiu", "404", "text/html"],     # ja nao existia
    ["20240106", "https://alvo.site/erro", "503", "text/html"],
    ["20240107", "https://alvo.site/&gt", "200", "text/html"],       # entidade HTML
    ["20240108", "https://alvo.site/%0A%0A", "200", "text/html"],    # lixo de parser
    ["20240109", "https://alvo.site/.28", "200", "text/html"],       # segmento com ponto
    ["20240110", "https://alvo.site/_js/app", "200", "text/html"],   # underscore inicial
    ["20240111", "https://alvo.site/main.js", "200", "application/javascript"],
    ["20240112", "https://alvo.site/logo.png", "200", "image/png"],
    ["20240113", "https://alvo.site/" + "a" * 90, "200", "text/html"],  # longo demais
    ["20240114", "https://alvo.site/api/track/abc-123", "200", "text/html"],
]
caminhos = archived_paths(LINHAS)
check("mais visto primeiro", caminhos[0], ("/quiz", 2))
check("so rota de verdade sobra",
      sorted(c for c, _ in caminhos), ["/api/track/abc-123", "/quiz", "/vsl"])
check("raiz nao entra", [c for c, _ in caminhos if c == "/"], [])
check("nada quebra com lista vazia", archived_paths([]), [])
check("linha malformada nao quebra", archived_paths([[], ["x"], None or ["a", "b"]]), [])

# Empate: o caminho mais curto vem primeiro, por ser mais provavel que seja
# rota de verdade e nao permalink profundo.
empate = archived_paths([["1", "https://x.site/a/b/c/d", "200"],
                         ["2", "https://x.site/quiz", "200"]])
check("desempate por tamanho", empate[0][0], "/quiz")

# --- despejo: o cloaker manda o recusado pro site real de outra pessoa ------
# Caso real: achadaspremium.shop jogou todas as personas humanas em cwc.edu
# (Central Wyoming College) e sensualdesireart.site/quiz jogou num site de
# tarot. Sem marcar isso, o app dizia "money page" sobre uma faculdade.
from funnel_recon.probe.engine import Probe, to_scan_results
from funnel_recon.signals import bounced_offsite, is_funnel_value, scan_text

check("despejo em terceiro", bounced_offsite("https://www.cwc.edu/x", "https://alvo.shop/l/a"),
      "www.cwc.edu")
check("ficou em casa", bounced_offsite("https://alvo.shop/ok", "https://alvo.shop/l/a"), "")
check("subdominio do alvo nao e despejo",
      bounced_offsite("https://app.alvo.site/x", "https://massagem.alvo.site/quiz"), "")
check("t.me e funil, nao despejo",
      bounced_offsite("https://t.me/canal", "https://alvo.shop/l/a"), "")
check("wa.me e funil", bounced_offsite("https://wa.me/5511999", "https://alvo.shop/l/a"), "")
check("sem final_url", bounced_offsite("", "https://alvo.shop/l/a"), "")

# `\b\w{3,32}bot\b` casava com qualquer palavra terminada em "bot".
check("chatbot/robot nao sao funil",
      scan_text("our chatbot, the robot lab and prof. Abbot"), [])
check("handle com contexto conta",
      "telegram_bot" in scan_text("fale no t.me/CantinhoPrivadoBot"), True)
check("arroba tambem conta", "telegram_bot" in scan_text("chama @MeuFunilBot"), True)

# Pixel do Facebook existe em toda loja: nao pode ser prova de money page.
check("pixel nao e valor de funil", is_funnel_value("meta_pixel:123456789012"), False)
check("telegram e valor de funil", is_funnel_value("telegram:canal"), True)
check("handle de bot e valor de funil", is_funnel_value("bot_handle:MeuBot"), True)

ALVO = "https://alvo.shop/l/abc"
despejadas = [Probe(persona=f"p{i}", ok=True, status=200, body_sha=f"sha{i}",
                    final_url="https://www.cwc.edu/international/",
                    signals=["fb_pixel", "js_redirect"],
                    values=["meta_pixel:288528425319413"]) for i in range(4)]
res = to_scan_results(ALVO, despejadas, "probe", None)
check("pixel sozinho nao vira money", {r.verdict for r in res}, {"white"})
check("despejo fica registrado",
      all(any(s.startswith("bounced_offsite:www.cwc.edu") for s in r.signals) for r in res), True)

# Mas funil de verdade continua sendo money, despejo ou nao.
com_funil = Probe(persona="bot", ok=True, status=200, body_sha="x",
                  final_url=ALVO, signals=["telegram_bot"],
                  values=["telegram:universitygirlsclubbot"])
res2 = to_scan_results(ALVO, despejadas + [com_funil], "probe", None)
check("handle real ainda e money",
      [r.verdict for r in res2 if r.source == "bot"], ["money"])

# --- robustez do cloaker: le a matriz e da a nota, sem tentar burlar --------
from funnel_recon.probe.engine import robustness
from funnel_recon.schema import ScanResult

def _sr(persona, sha, verdict, sinais=None):
    return ScanResult(target="u", stage="probe", source=persona, body_sha=sha,
                      verdict=verdict, signals=sinais or [])

# Vazou pro crawler = fraco (nao vale caro).
fraco = robustness([
    _sr("facebookexternalhit", "aaa", "money", ["telegram:x"]),
    _sr("googlebot", "aaa", "money"),
    _sr("chrome-desktop-us", "bbb", "white"),
    _sr("safari-ios-us+fb", "bbb", "white"),
])
check("crawler recebeu oferta = fraco", fraco["grade"], "fraco")
check("marcou vazamento", fraco["leaked"], True)

# Todas as personas HTTP iguais, sem proxy = indeterminado (falta o IP).
indet = robustness([
    _sr("python-cru", "aaa", "white"),
    _sr("chrome-desktop-us", "aaa", "white"),
    _sr("fb-inapp-ios", "aaa", "white"),
])
check("tudo igual sem proxy = indeterminado", indet["grade"], "indeterminado")

# Com proxy: se a MESMA persona muda de pagina, o filtro e de IP = medio.
direto = [_sr("chrome-desktop-us", "aaa", "white"),
          _sr("fb-inapp-ios", "aaa", "white")]
via_proxy = [_sr("chrome-desktop-us", "bbb", "white"),
             _sr("fb-inapp-ios", "bbb", "white")]
medio = robustness(direto, via_proxy)
check("cede ao IP certo = medio", medio["grade"], "medio")
check("IP entrou como eixo", "IP/geo" in medio["axes_read"], True)

# Com proxy e MESMA pagina mesmo assim = forte (so JS abre).
forte = robustness(direto, [_sr("chrome-desktop-us", "aaa", "white"),
                            _sr("fb-inapp-ios", "aaa", "white")])
check("nem com IP certo muda = forte", forte["grade"], "forte")

# Dedup: mesma persona repetida (varias rodadas) nao infla vazamento.
dup = robustness([_sr("googlebot", "aaa", "white"),
                  _sr("googlebot", "bbb", "money", ["telegram:x"]),
                  _sr("chrome-desktop-us", "aaa", "white")])
check("dedup: fica a ultima da persona", dup["leaked"], True)

# --- normalizacao de proxy: aceita o que vier do painel ---------------------
# O usuario nao controla o formato que o provedor entrega. Colar o formato de
# painel (host:porta:user:senha) sem converter fazia o proxy ser ignorado em
# silencio -- a probe saia pelo IP de casa achando que estava no proxy.
from funnel_recon.probe.engine import normalize_proxy
check("formato de painel http", normalize_proxy("http://1.2.3.4:8000:u:p"),
      "http://u:p@1.2.3.4:8000")
check("sem esquema vira http", normalize_proxy("1.2.3.4:8000:u:p"),
      "http://u:p@1.2.3.4:8000")
check("ja no formato @ nao muda", normalize_proxy("http://u:p@1.2.3.4:8000"),
      "http://u:p@1.2.3.4:8000")
check("socks preserva esquema", normalize_proxy("socks5://u:p@h:1080"),
      "socks5://u:p@h:1080")
check("host:porta sem auth", normalize_proxy("1.2.3.4:8080"), "http://1.2.3.4:8080")
check("host nomeado do painel",
      normalize_proxy("us.prov.com:9000:user:pass"), "http://user:pass@us.prov.com:9000")
check("vazio vira None", normalize_proxy(""), None)
check("None vira None", normalize_proxy(None), None)

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print("todos os testes passaram")
