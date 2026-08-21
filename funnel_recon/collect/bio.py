"""O dominio que a PAGINA do anunciante declara -- invisivel na Biblioteca.

Descoberto perseguindo uma suspeita do usuario: "o link que a pessoa clica
pode nem ser o mesmo dominio". A Biblioteca so devolve `link_url`, o destino
do anuncio. Mas a pagina que veicula o anuncio tem um campo "site" proprio, e
ele aponta para OUTRO dominio -- que nenhum export da Biblioteca mostra.

O que apareceu num caso real: dez paginas clonadas da mesma persona ("Dr.
Selena _ Moore - Sexologist", cada uma numa cidade americana), cada uma com
seu dominio descartavel `drselena??moore.com`. Nenhum deles constava em
anuncio nenhum. Nao e um afiliado testando: e operacao com pagina e dominio
queimados em ciclo, e a bio e onde o ciclo aparece antes do anuncio.

O link da bio vem embrulhado no redirecionador do Meta, com assinatura:
`l.facebook.com/l.php?u=<destino>&h=<assinatura>`. Guardamos as duas coisas.
O destino alimenta a lista de dominios; a URL assinada e a unica forma de
entrar por um caminho que o Meta considera legitimo sem depender de um clique
em anuncio -- que e o sinal que nao se fabrica.

Exige sessao logada (o mesmo perfil da coleta): pagina do Meta nao abre a bio
para visitante anonimo.
"""

from __future__ import annotations

import asyncio
import re
import socket
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from ..paths import profile_dir

LPHP_RE = re.compile(r'https://l\.facebook\.com/l\.php\?[^"\'<>\s]+')
# Dominios do proprio Meta e ruido de boilerplate nunca sao o site do alvo.
IGNORAR = ("facebook.com", "fb.com", "instagram.com", "messenger.com",
           "whatsapp.com", "w3.org", "schema.org", "fbcdn.net", "fbsbx.com")


def extrair_links(html: str) -> list[tuple[str, str]]:
    """(destino, url_assinada) de cada link de saida no HTML da pagina.

    Puro, sem rede -- e por isso testavel. O HTML vem do navegador logado.
    """
    fora: list[tuple[str, str]] = []
    visto: set[str] = set()
    for assinada in LPHP_RE.findall((html or "").replace("&amp;", "&")):
        alvo = parse_qs(urlparse(assinada).query).get("u", [""])[0]
        if not alvo:
            continue
        destino = unquote(alvo)
        host = (urlparse(destino).hostname or "").lower()
        if not host or any(host == d or host.endswith("." + d) for d in IGNORAR):
            continue
        if host in visto:
            continue
        visto.add(host)
        fora.append((destino, assinada))
    return fora


def resolve(host: str) -> bool:
    """O dominio existe? Dominio de bio morto e a assinatura de ciclo ja
    encerrado -- e saber disso separa 'pista velha' de 'alvo atual'."""
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


async def bio_de_paginas(page_ids: list[str], on_progress=None,
                         max_paginas: int = 10,
                         profile_dir_arg: Path | None = None) -> list[dict]:
    """Abre cada pagina e devolve o que ela declara como site proprio."""
    from playwright.async_api import async_playwright

    def say(msg: str, **d):
        if on_progress:
            on_progress(msg, d)

    ids = [p for p in dict.fromkeys(page_ids) if p][:max_paginas]
    if not ids:
        return []

    achados: list[dict] = []
    perfil = Path(profile_dir_arg) if profile_dir_arg else profile_dir()
    async with async_playwright() as pw:
        ctx = await pw.chromium.launch_persistent_context(
            user_data_dir=str(perfil), headless=True,
            viewport={"width": 1380, "height": 900}, locale="pt-BR",
            args=["--disable-blink-features=AutomationControlled"])
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        for i, pid in enumerate(ids):
            say("pagina", i=i + 1, total=len(ids), page_id=pid)
            try:
                await page.goto(f"https://web.facebook.com/profile.php?id={pid}",
                                wait_until="domcontentloaded", timeout=40000)
                await asyncio.sleep(3)
                html = await page.content()
                nome = (await page.title()).split("|")[0].strip()[:60]
            except Exception as e:
                say("falhou", page_id=pid, erro=type(e).__name__)
                continue
            for destino, assinada in extrair_links(html):
                host = (urlparse(destino).hostname or "").lower()
                achados.append({"page_id": pid, "nome": nome, "url": destino,
                                "host": host, "assinada": assinada,
                                "resolve": resolve(host)})
                say("achou", page_id=pid, host=host)
        try:
            await ctx.close()
        except Exception:
            pass
    return achados
