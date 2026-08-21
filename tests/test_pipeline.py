"""Teste de gabarito: reproduz a distribuicao real do caso Ana Alves e
verifica se a ferramenta chega sozinha na conclusao que a investigacao
manual levou tres frentes para alcancar.

Sem rede. Roda em segundos.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.collect.normalize import (domain_histogram, load_export,
                                            normalize_row, path_histogram,
                                            pick_probe_targets)
from funnel_recon.signals import apex_domain, cloaker_platform
from funnel_recon.probe.engine import Probe, preflight, to_scan_results
from funnel_recon.probe.personas import PERSONAS, candidates

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


FIXTURE = Path(__file__).parent / "fixtures" / "adlib_export.csv"
ads = load_export(FIXTURE)

# --- erro 4: ruido do Meta fora ---------------------------------------------
check("meta descartado", len(ads), 200)
check("nenhum host do meta", [a for a in ads if a.display_host and "meta" in a.display_host], [])

# --- histograma bate com o caso real ----------------------------------------
hist = domain_histogram(ads)
check("dominio dominante", hist[0][0], "achadaspremium.shop")
check("contagem white", hist[0][1], 132)
check("segundo funil", hist[1][0], "cantinhoprivado.shop")

# --- erro 6: dois funis paralelos NAO sao outlier ---------------------------
check("sem outlier falso", [h for h, _, o in hist if o], [])

# --- o achado que virou o jogo: a URL com /l/<hash> vem em primeiro ----------
targets = pick_probe_targets(ads, 3)
check("alvo 1 e o redirecionador", "/l/" in targets[0].full_url, True)
check("alvo 1 no segundo funil", targets[0].display_host, "cantinhoprivado.shop")
check("alvo 1 e o mais antigo", targets[0].start_date, "2026-03-19")

# --- o caminho, que e onde mora o valor -------------------------------------
# Caso real: 1.128 anuncios em /quiz e 65 em /sulamita, no mesmo host. A tela
# so mostrava o host, o usuario abriu a raiz e levou "Cannot GET /" -- que e o
# 404 padrao do Express. O caminho estava coletado o tempo todo.
frota = ([normalize_row({"ad_id": f"q{i}", "url": "https://alvo.site/quiz",
                         "host": "alvo.site"}) for i in range(20)]
         + [normalize_row({"ad_id": f"s{i}", "url": "https://alvo.site/sulamita",
                           "host": "alvo.site"}) for i in range(2)])
caminhos = path_histogram(frota)["alvo.site"]
check("caminho dominante primeiro", caminhos[0][0], "/quiz")
check("contagem do dominante", caminhos[0][2], 20)
check("caminho da cauda marcado", (caminhos[1][0], caminhos[1][3]), ("/sulamita", True))
check("dominante nao e variante", caminhos[0][3], False)

# Volumes parecidos sao funis SIMULTANEOS, nao variante -- mesma leitura que o
# histograma de dominios faz, e pelo mesmo motivo.
par = ([normalize_row({"ad_id": f"a{i}", "url": "https://x.site/ltpv",
                       "host": "x.site"}) for i in range(10)]
       + [normalize_row({"ad_id": f"b{i}", "url": "https://x.site/testab",
                         "host": "x.site"}) for i in range(8)])
check("volume parecido nao vira variante",
      [v for _, _, _, v in path_histogram(par)["x.site"]], [False, False])

# Com fbclid cada anuncio tem URL unica: agrupar pela URL inteira produziria
# mil linhas de tamanho 1 em vez de um caminho com mil.
com_fbclid = [normalize_row({"ad_id": f"f{i}", "host": "y.site",
                             "url": f"https://y.site/quiz?fbclid=Iw{i}"}) for i in range(5)]
grupo = path_histogram(com_fbclid)["y.site"]
check("agrupa por caminho, nao por URL", (grupo[0][0], grupo[0][2]), ("/quiz", 5))
check("guarda exemplo com fbclid", "fbclid" in grupo[0][1], True)
check("amostra nao marca variante",
      [v for _, _, _, v in path_histogram(frota, sample=True)["alvo.site"]], [False, False])

# --- apex: sem isto a busca por subdominio irmao nao acha nada --------------
check("sobe do subdominio pro apex",
      apex_domain("massagem.sensualdesireart.site"), "sensualdesireart.site")
check("apex ja e apex", apex_domain("achadaspremium.shop"), "achadaspremium.shop")
check("sufixo de dois rotulos", apex_domain("a.b.loja.com.br"), "loja.com.br")
check("aceita URL inteira", apex_domain("https://track.cloakby.com/api/x"), "cloakby.com")

# --- plataforma de cloaking se identificando --------------------------------
check("marca conhecida", cloaker_platform("track.cloakby.com"), ("CloakBy", True))
check("marca conhecida em outro TLD", cloaker_platform("app.cloakup.me"), ("CloakUp", True))
check("suspeita pelo nome nao vira fato", cloaker_platform("x.mycloaker.io"), ("mycloaker", False))
check("dominio comum nao e cloaker", cloaker_platform("massagem.alvo.site"), ("", False))

# --- amostra nao produz outlier ---------------------------------------------
# Coleta cortada por limite entrega os anuncios MAIS RECENTES, nao uma fatia
# aleatoria. Marcar "raro" ali inventa achado: o dominio de teste da operacao
# pode ser maioria na fatia, ou nao ter aparecido nela.
check("pagina inteira marca outlier", [h for h, _, o in hist if o], [])
amostra = domain_histogram(ads, sample=True)
check("amostra nunca marca outlier", [h for h, _, o in amostra if o], [])
check("amostra preserva as contagens", [(h, n) for h, n, _ in amostra],
      [(h, n) for h, n, _ in hist])

# Com um outlier real presente, a supressao tem que ser visivel de verdade --
# senao o teste acima passaria mesmo se `sample` nao fizesse nada.
muitos = [normalize_row({"ad_id": f"n{i}", "url": "https://white.shop/p", "host": "white.shop"})
          for i in range(20)]
muitos.append(normalize_row({"ad_id": "raro", "url": "https://raro.shop/l/x", "host": "raro.shop"}))
check("outlier aparece na pagina inteira",
      [h for h, _, o in domain_histogram(muitos) if o], ["raro.shop"])
check("e some na amostra",
      [h for h, _, o in domain_histogram(muitos, sample=True) if o], [])

# --- status de veiculacao manda na fila de alvos -----------------------------
# O export do caso Ana Alves e anterior a coleta de status: todo mundo None.
# O ranking nao pode mudar por isso -- "nao sei" nao e "encerrado".
check("export antigo nao inventa status", {a.is_active for a in ads}, {None})

# Com status, o encerrado passa na frente do ativo em tudo mais igual.
mesmo = dict(url="https://alvo.shop/l/h1?fbclid=Iw", host="alvo.shop", start_date="2026-01-01")
fila = pick_probe_targets([
    normalize_row({"ad_id": "no-ar", "is_active": "true", **mesmo}),
    normalize_row({"ad_id": "encerrado", "is_active": "false", **mesmo}),
    normalize_row({"ad_id": "sem-status", **mesmo}),
], 3)
check("encerrado primeiro", [a.ad_id for a in fila], ["encerrado", "sem-status", "no-ar"])
check("status normalizado de texto", fila[0].is_active, False)

# --- vazamento no corpo do anuncio ------------------------------------------
leaks = {l for a in ads for l in a.leaks}
check("telegram extraido", "telegram:+Kj9xQz2Lm" in leaks, True)
check("handle do bot extraido", "bot_handle:CantinhoPrivadoBot" in leaks, True)

# --- normalizacao de linha isolada ------------------------------------------
check("linha sem id vira None", normalize_row({"url": "https://x.shop/l/a"}), None)
check("host do meta vira None",
      normalize_row({"ad_id": "1", "host": "transparency.meta.com"}), None)

# --- erro 1: preflight pega a raiz antes de gastar requisicao ---------------
check("raiz detectada", "url_e_raiz" in preflight("https://x.shop/"), True)
check("url real passa", preflight("https://x.shop/l/ab68?fbclid=Iw"), [])
check("falta fbclid", preflight("https://x.shop/l/ab68"), ["sem_fbclid"])

# --- escadas de impersonate sem alvo morto ----------------------------------
try:
    import typing
    from curl_cffi.requests.impersonate import BrowserTypeLiteral
    validos = set(typing.get_args(BrowserTypeLiteral))
    mortos = [(p.name, c) for p in PERSONAS for c in candidates(p.impersonate)
              if c and c not in validos]
    check("nenhum alvo de impersonate morto", mortos, [])
except ImportError:
    pass

# --- veredito por persona ---------------------------------------------------
probes = [
    Probe(persona="a", ok=True, status=200, body_sha="AAA"),
    Probe(persona="b", ok=True, status=200, body_sha="AAA"),
    Probe(persona="c", ok=True, status=200, body_sha="BBB",
          values=["telegram:+abc"], signals=["telegram_link"]),
    Probe(persona="d", ok=True, status=403, body_sha="CCC", is_challenge=True),
    Probe(persona="e", ok=False, error="timeout"),
]
verdicts = {r.source: r.verdict for r in to_scan_results("u", probes, "probe", None)}
check("maioria = white", verdicts["a"], "white")
check("maioria = white (2)", verdicts["b"], "white")
check("divergente com funil = money", verdicts["c"], "money")
check("waf = challenge", verdicts["d"], "challenge")
check("falha = error", verdicts["e"], "error")

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print(f"gabarito reproduzido: {len(ads)} anuncios, alvo correto eleito automaticamente")
