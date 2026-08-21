"""Estagio [1] dentro do app: navegador controlado coletando a Biblioteca.

Substitui o passo manual "varra com a extensao e exporte o CSV". O app abre
uma janela do Chromium, voce faz login no Facebook UMA vez, e a sessao fica
guardada num perfil proprio. Das proximas vezes ele so abre e coleta.

Por que headed e nao headless: (a) voce precisa poder logar e resolver
checkpoint quando o Meta pedir; (b) headless tem marcas que o Meta detecta.
Ver a janela trabalhando tambem e o que torna o processo legivel para quem
nao e tecnico -- da pra acompanhar o que esta acontecendo.

Interceptamos a resposta de rede, nao o DOM: o DOM da Biblioteca e React com
classes ofuscadas que mudam a cada deploy, enquanto o payload GraphQL e
estavel e traz campos que a interface nem renderiza.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..paths import profile_dir
from .parse import extract_ads, merge_rec
GRAPHQL_MARKERS = ("/api/graphql", "/ads/library/async")

# Quantos ciclos de rolagem sem anuncio novo antes de considerar que acabou.
STAGNANT_LIMIT = 4
SCROLL_PAUSE = 1.6
MAX_SCROLLS = 400

# Tres freios independentes, porque uma pagina grande derrota cada um sozinho.
#
# Numa pagina de dropshipper com dezenas de milhares de anuncios ativos,
# STAGNANT_LIMIT nunca dispara -- sempre chega anuncio novo. A coleta ia ate
# MAX_SCROLLS, ~11 minutos, com o Chromium segurando um DOM que so cresce, ate
# a rolagem estourar o timeout do Playwright. E ai a excecao levava junto tudo
# que ja tinha sido coletado: o usuario esperava onze minutos por nada.
#
# MAX_ADS e o freio util: 2.000 anuncios ja descrevem a operacao de qualquer
# pagina. MAX_SECONDS e a rede de seguranca para quando a pagina fica lenta
# antes de chegar la.
MAX_ADS = 2000
MAX_SECONDS = 300.0


class NotLoggedIn(Exception):
    """A Biblioteca deslogada esconde metade dos campos -- inclusive a URL."""


def stop_reason(ads: int, elapsed: float, stagnant: int,
                max_ads: int = MAX_ADS, max_seconds: float = MAX_SECONDS) -> str | None:
    """Motivo para parar de rolar, ou None para continuar.

    Funcao pura de proposito: e a unica logica de decisao da coleta, e testa-la
    dentro do laco exigiria um Chromium e uma pagina do Facebook com 50.000
    anuncios. Aqui ela custa microssegundos.

    A ordem importa. `fim_da_lista` fica por ultimo porque so vale quando
    nenhum limite artificial mordeu antes: se pararmos no teto e chamarmos de
    fim da lista, o relatorio trata amostra como retrato completo.
    """
    if ads >= max_ads:
        return "teto_de_anuncios"
    if elapsed >= max_seconds:
        return "prazo_esgotado"
    if stagnant >= STAGNANT_LIMIT:
        return "fim_da_lista"
    return None


def with_all_statuses(url: str, status: str = "all") -> str:
    """Fixa o `active_status` da URL da Biblioteca.

    Por que `all` e o padrao: a Biblioteca abre em `active_status=active`, e
    so o que esta no ar hoje esconde metade do caso -- o brief (secao 6) manda
    coletar ativos E inativos, porque cloaker de campanha morta fica mal
    configurado e serve a money page pra qualquer um.

    Por que virou escolha: numa pagina com anos de historico o custo se
    inverte. Um alvo real trouxe 2.098 anuncios dos quais 1.995 estavam
    encerrados havia meses -- a rolagem inteira gasta no morto, e a VSL que se
    acha e a aposentada. Quando a pergunta e "o que esta rodando AGORA",
    `status="active"` respeita o filtro que o usuario montou na Biblioteca.

    Mexe so no que e do Meta e so no parametro de status: o resto da URL
    (`view_all_page_id`, `country`, `q`) e a busca que o usuario montou.
    """
    try:
        parts = urlparse(url)
    except ValueError:
        return url
    host = (parts.hostname or "").lower()
    if not (host == "facebook.com" or host.endswith(".facebook.com")):
        return url
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != "active_status"]
    query.append(("active_status", status))
    return urlunparse(parts._replace(query=urlencode(query)))


async def collect(
    library_url: str,
    on_progress: Callable[[str, dict], None] | None = None,
    max_scrolls: int = MAX_SCROLLS,
    max_ads: int = MAX_ADS,
    max_seconds: float = MAX_SECONDS,
    headless: bool = False,
    profile_dir_arg: Path | None = None,
    status: str = "all",
) -> list[dict]:
    from playwright.async_api import async_playwright

    def say(msg: str, **data):
        if on_progress:
            on_progress(msg, data)

    profile = Path(profile_dir_arg) if profile_dir_arg else profile_dir()
    profile.mkdir(parents=True, exist_ok=True)

    records: dict[str, dict] = {}
    payloads_seen = 0

    async with async_playwright() as pw:
        ctx = await pw.chromium.launch_persistent_context(
            user_data_dir=str(profile),
            headless=headless,
            viewport={"width": 1380, "height": 900},
            locale="pt-BR",
            args=["--disable-blink-features=AutomationControlled"],
        )
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()

        # Quanto esta coleta custa de internet, medido de verdade.
        #
        # A pergunta e pratica: rolar uma pagina grande da Biblioteca renderiza
        # o criativo de cada anuncio, e essa MIDIA domina o gasto -- o JSON do
        # GraphQL, que e o que a gente de fato quer, e a menor parte. Sem o
        # numero na mao nao da para dizer se cabe numa conexao limitada.
        #
        # `encodedDataLength` do CDP e o byte que passou no fio, ja comprimido
        # e ja com cache aplicado (recurso servido do disco nao conta) -- e por
        # isso que a medida vem daqui e nao de somar Content-Length.
        rede = {"bytes": 0, "requisicoes": 0, "por_tipo": {}}
        _tipos: dict[str, str] = {}
        cdp = await ctx.new_cdp_session(page)
        await cdp.send("Network.enable")

        def _viu_resposta(ev):
            _tipos[ev["requestId"]] = ev.get("type") or "Other"

        def _terminou(ev):
            n = ev.get("encodedDataLength") or 0
            rede["bytes"] += n
            rede["requisicoes"] += 1
            t = _tipos.pop(ev.get("requestId", ""), "Other")
            rede["por_tipo"][t] = rede["por_tipo"].get(t, 0) + n

        cdp.on("Network.responseReceived", _viu_resposta)
        cdp.on("Network.loadingFinished", _terminou)

        async def on_response(response):
            nonlocal payloads_seen
            if not any(m in response.url for m in GRAPHQL_MARKERS):
                return
            if len(records) >= max_ads:
                return  # teto atingido; parsear o resto so gasta CPU
            try:
                body = await response.text()
            except Exception:
                return  # resposta ja consumida ou binaria; ignorar
            payloads_seen += 1
            novos = 0
            for rec in extract_ads(body):
                prev = records.get(rec["ad_id"])
                if not prev:
                    records[rec["ad_id"]] = rec
                    novos += 1
                else:
                    merge_rec(prev, rec)
            if novos:
                say("coletando", ads=len(records), novos=novos)

        page.on("response", on_response)

        library_url = with_all_statuses(library_url, status)
        say("abrindo", url=library_url)
        await page.goto(library_url, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(3)

        if "/login" in page.url or "login.php" in page.url:
            await ctx.close()
            raise NotLoggedIn(
                "O Facebook pediu login. Rode de novo, faca login na janela que "
                "abrir e deixe a coleta seguir -- a sessao fica guardada e nas "
                "proximas vezes isso nao se repete."
            )

        say("rolando", ads=len(records))
        stagnant, last = 0, -1
        scrolls = 0
        motivo = "limite_de_rolagem"
        inicio = asyncio.get_running_loop().time()

        for i in range(max_scrolls):
            parar_por = stop_reason(
                len(records),
                asyncio.get_running_loop().time() - inicio,
                stagnant, max_ads, max_seconds)
            if parar_por:
                motivo = parar_por
                break
            scrolls = i + 1
            try:
                await page.mouse.wheel(0, 2600)
            except Exception as e:
                # Pagina grande demais trava o Playwright na rolagem. O que ja
                # esta em `records` e coleta legitima e sai daqui com a gente:
                # devolver 1.800 anuncios e um aviso vale infinitamente mais
                # que levantar excecao e devolver zero.
                motivo = "pagina_travou"
                say("rolagem_falhou", ads=len(records), erro=type(e).__name__)
                break
            await asyncio.sleep(SCROLL_PAUSE)
            if len(records) == last:
                stagnant += 1
            else:
                stagnant = 0
                last = len(records)
                say("rolando", ads=len(records), scrolls=scrolls,
                    mb=round(rede["bytes"] / 1_048_576, 1))

        # `fim_da_lista` e o unico desfecho que significa "vi a pagina inteira".
        # Todos os outros entregam uma AMOSTRA, e quem for tirar conclusao de
        # distribuicao depois precisa saber disso -- ver normalize.domain_histogram.
        parcial = motivo != "fim_da_lista"
        say("parcial" if parcial else "fim_da_lista",
            ads=len(records), scrolls=scrolls, motivo=motivo)

        try:
            await ctx.close()
        except Exception:
            pass  # fechar o navegador falhar nao pode custar a coleta

    if not records and payloads_seen == 0:
        raise RuntimeError(
            "Nenhuma resposta GraphQL capturada. O Meta provavelmente mudou a "
            "rota da Biblioteca; ajuste GRAPHQL_MARKERS em collect/browser.py."
        )
    say("rede", **rede, mb=round(rede["bytes"] / 1_048_576, 1),
        kb_por_anuncio=round(rede["bytes"] / max(len(records), 1) / 1024, 1))
    say("pronto", ads=len(records), payloads=payloads_seen)
    return list(records.values())
