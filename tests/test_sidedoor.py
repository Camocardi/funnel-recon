"""Testes das portas laterais [3b]. Sem rede: o cliente HTTP e dublado.

O que se testa e a logica de decisao -- quais portas tentar, quando o apex nao
faz sentido, ler o inventario do WordPress, e reconhecer a oferta -- nao o
httpx. As respostas simuladas reproduzem o caso real que originou o modulo:
apex WordPress aberto servindo a VSL, com o checkout no HTML.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon import sidedoor
from funnel_recon.signals import scan_values

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


# --- candidatos: apex so faz sentido a partir de subdominio -----------------
check("subdominio gera portas",
      sidedoor.candidates("https://massagem.alvo.site/quiz"),
      ["https://alvo.site/", "https://www.alvo.site/"])
check("apex nao tem apex por tras",
      sidedoor.candidates("https://alvo.site/quiz"), [])
# www.alvo.site TEM apex por tras (alvo.site), entao gerar as portas e certo.
check("www ainda tem o apex por tras",
      sidedoor.candidates("https://www.alvo.site/x"),
      ["https://alvo.site/", "https://www.alvo.site/"])


# --- extracao de oferta do HTML (o padrao do caso real) ---------------------
VSL = ('<html><head><title>main</title></head><body>'
       '<script>fbq("init","3248264035336938");</script>'
       '<script src="https://scripts.converteai.net/abc/players/def"></script>'
       '<a href="https://www.checkout-ds24.com/product/687041">Comprar</a>'
       '</body></html>')
valores = scan_values(VSL)
check("checkout extraido",
      any(v == "checkout:https://www.checkout-ds24.com/product/687041" for v in valores), True)
check("player de vsl extraido",
      any(v.startswith("vsl_player:https://scripts.converteai.net") for v in valores), True)


# --- rede dublada: apex WordPress com inventario e oferta -------------------
INDEX = ('<html><head><title>Lover\'s Trick</title>'
         '<link href="/wp-json/"></head><body>wp-content</body></html>')
# Sem content: forca o fetch por URL (caminho classico). O content embutido
# tem teste proprio mais abaixo.
WP_PAGES = json.dumps([
    {"link": "https://alvo.site/main/", "content": {"rendered": ""}},
    {"link": "https://alvo.site/main-es/", "content": {"rendered": ""}},
    {"link": "https://alvo.site/hello-world/", "content": {"rendered": ""}},
])
CORPOS = {
    "https://alvo.site/": ("text/html", INDEX),
    "https://alvo.site/wp-json/wp/v2/pages?per_page=100&_fields=link,content": ("application/json", WP_PAGES),
    "https://alvo.site/wp-json/wp/v2/posts?per_page=100&_fields=link,content": ("application/json", "[]"),
    "https://alvo.site/main/": ("text/html", VSL),
    "https://alvo.site/main-es/": ("text/html",
        '<title>main-es</title><a href="https://payment.x.site/checkout/1">pt</a>'),
    "https://alvo.site/hello-world/": ("text/html", "<title>Hello world!</title>nada aqui"),
}
pedidos = []


class RespFalsa:
    def __init__(self, url):
        self.url = url
        self._t, self._b = CORPOS.get(url, ("text/html", ""))
        self.status_code = 200 if url in CORPOS else 404
        self.headers = {"content-type": self._t}
        self.text = self._b


class ClientFalso:
    def __init__(self, **kw): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False
    async def get(self, url, **kw):
        pedidos.append(url)
        return RespFalsa(url)


sidedoor.client = lambda **kw: ClientFalso()
# Zera a pausa entre paginas sem recursao: guarda a original antes de trocar.
_dorme = asyncio.sleep
async def _sem_espera(*a, **k):
    await _dorme(0)
sidedoor.asyncio.sleep = _sem_espera

res = asyncio.run(sidedoor.probe_sidedoors("https://massagem.alvo.site/quiz"))
por_path = {r.source: r for r in res}

check("abriu apex e as 3 paginas do inventario", len(res), 4)
check("apex reconhecido", "sidedoor:/" in por_path, True)
check("achou a VSL em ingles", por_path["sidedoor:/main/"].verdict, "money")
check("checkout ds24 na VSL",
      any("checkout:https://www.checkout-ds24.com/product/687041" in s
          for s in por_path["sidedoor:/main/"].signals), True)
check("variante espanhola tambem e oferta", por_path["sidedoor:/main-es/"].verdict, "money")
check("hello-world nao e oferta", por_path["sidedoor:/hello-world/"].verdict, "unknown")
check("nao tentou www depois de achar indice no apex",
      "https://www.alvo.site/" in pedidos, False)
# O titulo vira sinal, para o relatorio nomear a pagina.
check("titulo capturado",
      any(s.startswith("sidedoor_title:Lover") for s in por_path["sidedoor:/"].signals), True)


# --- content.rendered da REST fura o gate de referer ------------------------
# Caso real: buscar /up1/ direto dava 400 (checa referer), mas o mesmo HTML
# saiu limpo pelo content.rendered da REST. Aqui a URL /up1/ NAO esta em CORPOS
# (fetch direto falharia), mas o content vem embutido no inventario.
pedidos.clear()
CK = "https://www.checkout-ds24.com/product/693074"
INV_COM_CONTENT = json.dumps([
    {"link": "https://alvo.site/up1/", "content": {"rendered":
        f'<vturb-smartplayer></vturb-smartplayer>'
        f'<script>https://cdn.converteai.net/81d625dd-b729-4291-9176-b1b5e1565068/v/x.m3u8</script>'
        f'<a href="{CK}">buy</a>'}},
])
CORPOS.clear()
CORPOS["https://alvo.site/"] = ("text/html", INDEX)  # WordPress
CORPOS["https://alvo.site/wp-json/wp/v2/pages?per_page=100&_fields=link,content"] = \
    ("application/json", INV_COM_CONTENT)
CORPOS["https://alvo.site/wp-json/wp/v2/posts?per_page=100&_fields=link,content"] = \
    ("application/json", "[]")
# repare: /up1/ NAO esta em CORPOS -- se o codigo tentasse buscar, daria 404.
res_ref = asyncio.run(sidedoor.probe_sidedoors("https://massagem.alvo.site/quiz"))
up1 = next((r for r in res_ref if r.source == "sidedoor:/up1/"), None)
check("achou a pagina gated pela REST", up1 is not None, True)
check("extraiu a oferta sem fetch direto", up1.verdict if up1 else None, "money")
check("nao tentou buscar a URL gated",
      "https://alvo.site/up1/" in pedidos, False)


# --- fallback: sem WordPress, cai no sitemap --------------------------------
pedidos.clear()
CORPOS2 = {
    "https://loja.site/": ("text/html", "<title>Loja</title>site comum sem cms"),
    "https://loja.site/sitemap.xml": ("application/xml",
        "<urlset><url><loc>https://loja.site/oferta/</loc></url></urlset>"),
    "https://loja.site/oferta/": ("text/html",
        '<title>Oferta</title><a href="https://hotmart.com/pay/x">quero</a>'),
}
CORPOS.clear(); CORPOS.update(CORPOS2)
res2 = asyncio.run(sidedoor.probe_sidedoors("https://vsl.loja.site/quiz"))
achou = {r.source: r.verdict for r in res2}
check("sitemap usado quando nao ha wordpress", "sidedoor:/oferta/" in achou, True)
check("oferta do sitemap reconhecida", achou.get("sidedoor:/oferta/"), "money")


# --- porta fechada nao quebra -----------------------------------------------
CORPOS.clear()  # tudo 404
res3 = asyncio.run(sidedoor.probe_sidedoors("https://x.morto.site/quiz"))
check("dominio morto devolve lista vazia sem levantar", res3, [])

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print("porta lateral ok")
