"""Portas laterais: chegar na oferta sem enfrentar o cloaker.

O probe [3] pergunta "consigo passar pelo filtro?". Quando a resposta e nao --
e contra filtro de IP ela e nao, porque nenhuma linha de codigo muda de qual
IP o pacote sai -- ainda sobra a pergunta que interessa: "existe outra porta?".

Quase sempre existe, e por um motivo estrutural: o operador poe o cloaker no
que o ANUNCIO aponta, nao no dominio inteiro. Protege
`massagem.alvo.site/quiz`, esquece `alvo.site`. Foi exatamente o caso real que
originou este modulo -- o apex servia a VSL aberta, com o checkout no HTML,
enquanto o subdominio despejava toda persona num site de tarot de terceiro.

Tres portas, da mais barata para a mais cara:

  1. APEX e www. Uma requisicao cada. E a que mais paga.
  2. Inventario do CMS. WordPress com `wp-json` aberto entrega a lista
     COMPLETA de paginas -- sem adivinhar path, sem forca bruta, sem barulho.
  3. sitemap.xml. Funciona fora do WordPress e tambem e material publicado
     pelo proprio site para ser lido.

Nada aqui e forca bruta de diretorio. Alem de ruidoso e de queimar o IP
residencial do usuario, seria adivinhacao quando o proprio site publica o
indice. Se estas tres portas falharem, a resposta honesta e proxy no pais-alvo
-- e o relatorio deve dizer isso, nao inventar uma quarta.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from .osint.http import client
from .schema import ScanResult
from .signals import apex_domain, registrable_host, scan_text, scan_values

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
WP_MARKERS = ("/wp-json", "wp-content", "wp-includes", "xmlrpc.php")
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# Teto de paginas a buscar do inventario. O objetivo e achar a oferta, nao
# espelhar o site: as paginas de venda estao sempre entre as primeiras.
MAX_PAGES = 12
MAX_BYTES = 1_500_000
TIMEOUT = 20.0


def candidates(target_url: str) -> list[str]:
    """Portas a tentar, em ordem de custo. Vazio se nao houver o que tentar.

    So faz sentido quando o alvo E um subdominio: se o anuncio ja aponta para
    o apex, nao existe apex "por tras" para tentar.
    """
    host = registrable_host(target_url)
    apex = apex_domain(host)
    if not apex or apex == host:
        return []
    return [f"https://{apex}/", f"https://www.{apex}/"]


async def _get(c, url: str) -> tuple[int, str, str]:
    """(status, url_final, corpo). Nunca levanta -- porta fechada e rotina."""
    try:
        r = await c.get(url)
        # json entra porque o inventario do WordPress vem por REST -- filtrar
        # so html/xml aqui fazia a lista de paginas voltar vazia em silencio,
        # e a pagina de venda em ingles ficava de fora do resultado.
        tipo = r.headers.get("content-type", "")
        corpo = r.text[:MAX_BYTES] if any(
            t in tipo for t in ("html", "xml", "json", "text/plain")) else ""
        return r.status_code, str(r.url), corpo
    except Exception:
        return 0, url, ""


def _titulo(corpo: str) -> str:
    m = TITLE_RE.search(corpo or "")
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def is_wordpress(corpo: str) -> bool:
    return any(m in (corpo or "") for m in WP_MARKERS)


async def wp_inventory(c, base: str) -> list[tuple[str, str]]:
    """(link, html_renderizado) de cada pagina publicada, pela REST do WordPress.

    Isto e conteudo que o proprio site publica para ser lido -- a diferenca
    entre ler um indice e arrombar portas, e mais completo que qualquer
    wordlist: devolve o que existe, nao o que alguem chutou.

    Pede `content` junto de `link` de proposito. O `content.rendered` traz o
    HTML da pagina JA MONTADO -- e isso PASSA POR CIMA do gate de referer que
    algumas dessas paginas de funil usam: buscar a URL direto devolvia 400,
    mas o mesmo conteudo sai limpo pela REST. Foi assim que o funil inteiro de
    upsells (up1/up2/up3) apareceu num caso real. Quando `content` vier vazio,
    o link fica para o fetch normal cuidar.
    """
    achados: list[tuple[str, str]] = []
    vistos: set[str] = set()
    for tipo in ("pages", "posts"):
        url = urljoin(base, f"/wp-json/wp/v2/{tipo}?per_page=100&_fields=link,content")
        status, _, corpo = await _get(c, url)
        if status != 200 or not corpo:
            continue
        try:
            import json
            for item in json.loads(corpo):
                link = item.get("link")
                if not link or link in vistos:
                    continue
                vistos.add(link)
                html = (item.get("content") or {}).get("rendered", "") \
                    if isinstance(item.get("content"), dict) else ""
                achados.append((link, html))
        except Exception:
            continue
    return achados


async def sitemap_inventory(c, base: str) -> list[tuple[str, str]]:
    """(url, "") do sitemap.xml. Sem HTML embutido: o sitemap so lista URLs,
    entao cada uma sera buscada depois -- por isso vem com corpo vazio, no
    mesmo formato de wp_inventory para o chamador nao precisar distinguir."""
    urls: list[str] = []
    status, _, corpo = await _get(c, urljoin(base, "/sitemap.xml"))
    if status != 200 or not corpo:
        return []
    locs = LOC_RE.findall(corpo)
    # Sitemap-indice aponta para outros sitemaps; abrir so o primeiro basta
    # para o proposito aqui e evita cascata de requisicoes.
    filhos = [u for u in locs if u.lower().endswith(".xml")][:1]
    urls += [u for u in locs if not u.lower().endswith(".xml")]
    for filho in filhos:
        st, _, corpo2 = await _get(c, filho)
        if st == 200 and corpo2:
            urls += [u for u in LOC_RE.findall(corpo2) if not u.lower().endswith(".xml")]
    return [(u, "") for u in urls]


async def probe_sidedoors(target_url: str, on_progress=None) -> list[ScanResult]:
    """Tenta as portas laterais e devolve o que cada uma serviu.

    Um resultado por pagina aberta. `verdict="money"` so quando a pagina
    carrega sinal de oferta de verdade (checkout, player de VSL, canal de
    funil) -- pagina institucional do apex nao conta.
    """
    def say(msg: str, **d):
        if on_progress:
            on_progress(msg, d)

    portas = candidates(target_url)
    if not portas:
        return []

    saida: list[ScanResult] = []
    vistos: set[str] = set()

    async with client(timeout=TIMEOUT) as c:
        # (url, html) -- html vem preenchido quando a REST do WordPress ja
        # entregou o conteudo renderizado; vazio quando so temos a URL.
        inventario: list[tuple[str, str]] = []
        for porta in portas:
            say("porta", url=porta)
            status, final, corpo = await _get(c, porta)
            if status != 200 or not corpo:
                continue
            saida.append(_resultado(target_url, porta, status, final, corpo))
            vistos.add(porta)

            if is_wordpress(corpo):
                say("cms", tipo="wordpress")
                inventario = await wp_inventory(c, porta)
            if not inventario:
                inventario = await sitemap_inventory(c, porta)
            if inventario:
                say("inventario", paginas=len(inventario))
                break  # uma porta que respondeu ja da o indice; nao repetir

        for url, html in inventario[:MAX_PAGES]:
            if url in vistos:
                continue
            vistos.add(url)
            # HTML da REST fura o gate de referer; so busca a URL quando nao veio.
            if html and (scan_values(html) or is_wordpress(html)):
                saida.append(_resultado(target_url, url, 200, url, html))
                continue
            status, final, corpo = await _get(c, url)
            if status == 200 and corpo:
                saida.append(_resultado(target_url, url, status, final, corpo))
            await asyncio.sleep(0.3)  # ritmo humano; nao e varredura

    say("fim", paginas=len(saida),
        com_oferta=sum(1 for r in saida if r.verdict == "money"))
    return saida


def _resultado(alvo: str, url: str, status: int, final: str, corpo: str) -> ScanResult:
    valores = scan_values(corpo)
    sinais = scan_text(corpo)
    tem_oferta = any(v.startswith(("checkout:", "vsl_player:", "telegram:",
                                   "whatsapp:", "bot_handle:")) for v in valores)
    titulo = _titulo(corpo)
    return ScanResult(
        target=alvo, stage="probe", source=f"sidedoor:{urlparse(url).path or '/'}",
        status=str(status), final_url=final,
        signals=sinais + valores + [f"sidedoor_url:{url}"]
                + ([f"sidedoor_title:{titulo}"] if titulo else []),
        verdict="money" if tem_oferta else "unknown",
        raw={"title": titulo, "body_len": len(corpo)},
    )
