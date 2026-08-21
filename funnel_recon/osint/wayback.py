"""Wayback Machine via CDX API -> o dominio existiu antes de ser descartavel?

Secao 3.1: a UI do Wayback deu timeout; a CDX API responde texto/JSON puro e
nao trava. Usamos `url=DOMINIO*` para pegar todos os caminhos ja arquivados --
e o caminho e o que interessa: um `/l/<hash>` arquivado entrega o formato do
redirecionador sem precisar coletar anuncio nenhum.
"""

from __future__ import annotations

import asyncio

import re
from urllib.parse import urlparse

import httpx

from ..schema import ScanResult
from ..signals import looks_like_redirector, scan_text
from .http import client

CDX = "https://web.archive.org/cdx/search/cdx"

# O indice do Wayback guarda URL malformada raspada de dentro de pagina:
# `/&gt`, `/%0A`, entidade HTML inteira virando caminho. Sem filtrar, a lista
# de "caminhos descobertos" sai dominada por lixo e nao serve de pista --
# medido em iana.org, onde as 12 primeiras linhas eram todas ruido.
#
# Rota de verdade e curta e usa alfabeto de rota. Perder um caminho exotico e
# barato; entregar 25 linhas de lixo faz a pessoa parar de olhar a secao.
# Cada segmento tem que COMECAR com alfanumerico: mata `/.28`, `/.The`,
# `/_js/` -- restos de parser, nao rota.
PLAUSIBLE_PATH = re.compile(
    r"^/[A-Za-z0-9][A-Za-z0-9._~\-]*(?:/[A-Za-z0-9][A-Za-z0-9._~\-]*)*/?$")
MAX_PATH_LEN = 80

# Asset nao e rota de funil. Um dominio arquivado tem centenas de .js/.png e
# eles afogariam as poucas linhas que interessam.
ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
             ".woff", ".woff2", ".ttf", ".eot", ".map", ".xml", ".txt",
             ".pdf", ".zip", ".mp4", ".webp", ".json")
LIMIT = 2000
# A CDX e lenta e derruba conexao sob carga; em teste real deu ReadTimeout na
# primeira tentativa e respondeu na segunda. Tentar de novo e mais barato que
# reportar lacuna falsa.
ATTEMPTS = 3
READ_TIMEOUT = 45.0


def archived_paths(rows: list) -> list[tuple[str, int]]:
    """Caminhos plausiveis extraidos das linhas da CDX, do mais visto ao menos.

    Responde "qual e o diretorio certo?" quando os anuncios nao entregam o
    caminho -- e a raiz de um app Node responde "Cannot GET /", entao nao ha
    o que adivinhar. O Wayback ja tinha a lista; faltava agregar e limpar.

    Medido em iana.org: sem filtro saem 1.153 "caminhos" e as 12 primeiras
    linhas sao todas lixo (`/&gt`, `/%0A`, entidade HTML virando rota). Com
    filtro sobram 65, todos rota de verdade.
    """
    caminhos: dict[str, int] = {}
    for row in rows:
        url = row[1] if len(row) > 1 else ""
        codigo = row[2] if len(row) > 2 else ""
        # 404 arquivado e caminho que ja nao existia -- ruido, nao pista.
        if codigo and str(codigo).startswith(("4", "5")):
            continue
        try:
            caminho = urlparse(url if "://" in url else "http://" + url).path or "/"
        except ValueError:
            continue
        if (caminho != "/" and len(caminho) <= MAX_PATH_LEN
                and not caminho.lower().endswith(ASSET_EXT)
                and PLAUSIBLE_PATH.match(caminho)):
            caminhos[caminho] = caminhos.get(caminho, 0) + 1

    # Desempate por tamanho: entre caminhos igualmente vistos, o mais curto e
    # o mais provavel de ser rota de verdade, e nao um permalink profundo.
    return sorted(caminhos.items(), key=lambda kv: (-kv[1], len(kv[0])))


async def run(domain: str) -> ScanResult:
    params = {
        "url": f"{domain}*",
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(LIMIT),
    }
    timeout = httpx.Timeout(READ_TIMEOUT, connect=10.0)
    last_err = None
    rows = None
    for attempt in range(ATTEMPTS):
        try:
            async with client(timeout=timeout) as c:
                r = await c.get(CDX, params=params)
                r.raise_for_status()
                rows = r.json() or []
            break
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < ATTEMPTS - 1:
                await asyncio.sleep(2 * (attempt + 1))
    if rows is None:
        return ScanResult(target=domain, stage="osint", source="wayback",
                          verdict="error",
                          error=f"{last_err} (apos {ATTEMPTS} tentativas)")

    # A primeira linha da CDX em modo json e o cabecalho das colunas.
    if rows and rows[0] and rows[0][0] == "timestamp":
        rows = rows[1:]

    if not rows:
        return ScanResult(
            target=domain, stage="osint", source="wayback",
            status="0 snapshots", verdict="unknown",
            signals=["no_wayback_snapshot"], raw={"snapshots": 0},
        )

    stamps = sorted(r[0] for r in rows if r and r[0])
    first, last = stamps[0], stamps[-1]

    signals = [
        f"wayback_snapshots:{len(rows)}",
        f"wayback_first:{first[:8]}",
        f"wayback_last:{last[:8]}",
    ]

    # Caminhos de redirecionador arquivados: o achado mais valioso daqui.
    redirectors = []
    for row in rows:
        url = row[1] if len(row) > 1 else ""
        if looks_like_redirector(url):
            redirectors.append(url)
            signals.append(f"archived_redirector:{url}")
        for s in scan_text(url):
            signals.append(f"in_archived_url:{s}")

    # Caminhos arquivados, do mais visto ao menos. Isto responde a pergunta
    # "qual e o diretorio certo?" quando os anuncios NAO entregam o caminho --
    # a raiz de um app Node responde "Cannot GET /" e nao ha o que adivinhar.
    # O Wayback ja tem a lista: o que faltava era agrega-la em vez de so olhar
    # o que parecia redirecionador.
    ordenados = archived_paths(rows)
    signals += [f"archived_path:{c}" for c, _ in ordenados[:25]]
    if ordenados:
        signals.append(f"archived_paths_total:{len(ordenados)}")

    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    return ScanResult(
        target=domain, stage="osint", source="wayback",
        status=f"{len(rows)} snapshots ({first[:8]}..{last[:8]}), "
               f"{len(ordenados)} caminhos",
        verdict="unknown", signals=signals[:160],
        raw={"count": len(rows), "first": first, "last": last,
             "redirectors": redirectors[:40],
             "paths": [{"caminho": c, "n": n} for c, n in ordenados[:60]],
             "sample": rows[:40]},
    )
