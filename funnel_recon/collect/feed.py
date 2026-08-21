"""Estagio [1], segunda responsabilidade: capturar o criativo ENTREGUE no feed.

A Biblioteca mostra o criativo que foi aprovado. O feed mostra o que esta sendo
servido. Quando os dois diferem, e cloaking de criativo -- e nao ha atalho de
dado para descobrir isso, porque quem serve o arquivo e o proprio Meta. Ou voce
observa a entrega, ou nao sabe.

TRES COISAS QUE ESTE MODULO NAO CONSEGUE FAZER, e que precisam estar claras
antes de alguem confiar num resultado vazio:

1. Nao da para INVOCAR o anuncio de um anunciante. Voce rola o seu feed e pega
   o que o Meta resolveu te mostrar. Zero anuncios do alvo e o desfecho mais
   provavel numa primeira rodada, e isso NAO significa "nao ha cloaking" --
   significa "nao vi". O relatorio precisa dizer as duas coisas de forma
   diferente.

2. O que aparece no SEU feed foi escolhido para VOCE. Se o alvo segmenta outro
   pais, outra idade ou outro interesse, o anuncio nunca chega. Ai a resposta
   nao esta aqui: esta em conta/proxy no perfil certo, que e o estagio [4].

3. Criativo dinamico e montado na entrega. Duas pessoas veem versoes
   diferentes, ambas legitimas. Divergencia sozinha nao prova ma-fe.

Como aumentar a chance de o alvo aparecer: interagir com o nicho antes. Curtir,
comentar e passar tempo em conteudo do assunto treina o modelo de entrega e a
concorrencia do alvo passa a te perseguir. Isso e trabalho manual e humano, e
esta certo que seja -- e o mesmo motivo de o app rodar local.

A juncao com a Biblioteca e por PAGINA, nao por anuncio: ver parse_sponsored().
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable

from ..paths import profile_dir
from .browser import stop_reason
from .parse import collect_media, unwrap_facebook_link, walk

FEED_URL = "https://www.facebook.com/"

# O feed usa as mesmas rotas GraphQL da Biblioteca.
GRAPHQL_MARKERS = ("/api/graphql",)

# Marcadores de post patrocinado. O Meta ofusca isto com frequencia -- e parte
# do jogo dele que a pagina nao seja raspavel -- entao aceitamos varias
# grafias e tambem o rotulo em texto, que sobrevive a renomeacao de campo.
SPONSOR_FLAGS = ("is_sponsored", "isSponsored", "sponsored", "is_ad", "isAd")
SPONSOR_LABELS = ("sponsored", "patrocinado", "publicidad", "gesponsert")
LABEL_KEYS = ("sponsored_label", "sponsored_data", "ad_label", "label",
              "sponsored_tag", "subtitle_text")

PAGE_ID_KEYS = ("page_id", "pageID", "pageId", "actor_id", "owner_id", "id")
PAGE_NAME_KEYS = ("page_name", "pageName", "name", "actor_name")
AD_ID_KEYS = ("ad_id", "adID", "ad_archive_id", "adArchiveID")
URL_KEYS = ("link_url", "linkUrl", "url", "target_url")

SCROLL_PAUSE = 2.2
MAX_POSTS = 400
MAX_SECONDS = 240.0
MAX_SCROLLS = 300


class NotLoggedIn(Exception):
    """Sem sessao nao existe feed -- so a pagina de login."""


def _first(obj: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, dict) and isinstance(v.get("text"), str):
            return v["text"].strip()
    return ""


def _looks_sponsored(obj: dict) -> bool:
    """O objeto e um post patrocinado?

    Duas evidencias independentes de proposito. A flag booleana e limpa mas e
    renomeada a cada tantos deploys; o rotulo em texto e feio mas sobrevive,
    porque o Meta e obrigado por lei a exibir "Patrocinado" para o usuario.
    """
    for k in SPONSOR_FLAGS:
        if obj.get(k) is True:
            return True
    for k in LABEL_KEYS:
        v = obj.get(k)
        texto = v if isinstance(v, str) else (
            v.get("text") if isinstance(v, dict) and isinstance(v.get("text"), str) else "")
        if texto and any(rot in texto.lower() for rot in SPONSOR_LABELS):
            return True
    return False


def parse_sponsored(payload: str) -> list[dict]:
    """Payload cru do feed -> posts patrocinados com midia.

    A juncao com a Biblioteca e pelo `page_id`, nao pelo id do anuncio: o
    payload do feed frequentemente nao traz um id que exista na Biblioteca,
    mas quase sempre traz de quem e o post. E isso basta para a pergunta que
    interessa -- "este criativo entregue se parece com ALGUM que a pagina
    publicou?" -- porque um criativo entregue que nao lembra nenhum dos
    aprovados ja e a resposta, independente de qual anuncio ele seja.
    """
    achados: dict[str, dict] = {}
    chunks = payload.split("\n") if "\n" in payload else [payload]

    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk or chunk[0] not in "{[":
            continue
        try:
            data = json.loads(chunk)
        except (json.JSONDecodeError, ValueError):
            continue

        for obj in walk(data):
            if not _looks_sponsored(obj):
                continue
            media = collect_media(obj)
            if not media:
                continue  # sem criativo nao ha o que comparar
            page_id = _first(obj, PAGE_ID_KEYS)
            rec = {
                "page_id": page_id,
                "page_name": _first(obj, PAGE_NAME_KEYS),
                "ad_id": _first(obj, AD_ID_KEYS),
                "url": unwrap_facebook_link(_first(obj, URL_KEYS)),
                "media": media,
            }
            # Sem id de anuncio, a midia identifica o post. Dois posts com a
            # mesma midia sao o mesmo criativo entregue duas vezes.
            chave = rec["ad_id"] or f"{page_id}:{media[0]}"
            if chave not in achados:
                achados[chave] = rec
    return list(achados.values())


async def harvest(
    page_ids: set[str] | None = None,
    on_progress: Callable[[str, dict], None] | None = None,
    max_posts: int = MAX_POSTS,
    max_seconds: float = MAX_SECONDS,
    max_scrolls: int = MAX_SCROLLS,
    headless: bool = False,
    profile_dir_arg: Path | None = None,
) -> list[dict]:
    """Rola o feed e devolve os posts patrocinados vistos.

    `page_ids` nao filtra a coleta, so a contagem de progresso: guardar todo
    patrocinado custa nada e serve de linha de base -- "vi 80 anuncios e
    nenhum era do alvo" e uma frase muito mais util que "vi 0 anuncios".
    """
    from playwright.async_api import async_playwright

    def say(msg: str, **data):
        if on_progress:
            on_progress(msg, data)

    profile = Path(profile_dir_arg) if profile_dir_arg else profile_dir()
    profile.mkdir(parents=True, exist_ok=True)

    posts: dict[str, dict] = {}
    payloads_seen = 0
    alvo = page_ids or set()

    async with async_playwright() as pw:
        ctx = await pw.chromium.launch_persistent_context(
            user_data_dir=str(profile),
            headless=headless,
            viewport={"width": 1380, "height": 900},
            locale="pt-BR",
            args=["--disable-blink-features=AutomationControlled"],
        )
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()

        async def on_response(response):
            nonlocal payloads_seen
            if not any(m in response.url for m in GRAPHQL_MARKERS):
                return
            if len(posts) >= max_posts:
                return
            try:
                body = await response.text()
            except Exception:
                return
            payloads_seen += 1
            novos = 0
            for rec in parse_sponsored(body):
                chave = rec["ad_id"] or f"{rec['page_id']}:{rec['media'][0]}"
                if chave not in posts:
                    posts[chave] = rec
                    novos += 1
            if novos:
                say("patrocinados", total=len(posts), novos=novos,
                    do_alvo=sum(1 for p in posts.values() if p["page_id"] in alvo))

        page.on("response", on_response)

        say("abrindo", url=FEED_URL)
        await page.goto(FEED_URL, wait_until="domcontentloaded", timeout=60000)
        await asyncio.sleep(3)

        if "/login" in page.url or "login.php" in page.url:
            await ctx.close()
            raise NotLoggedIn(
                "O Facebook pediu login. Rode a coleta da Biblioteca primeiro "
                "para logar -- o perfil do navegador e o mesmo."
            )

        stagnant, last, scrolls = 0, -1, 0
        motivo = "limite_de_rolagem"
        inicio = asyncio.get_running_loop().time()

        for i in range(max_scrolls):
            # Mesmos tres freios da Biblioteca, e pelo mesmo motivo: o feed
            # tambem e infinito e nunca sinaliza "acabou".
            parar_por = stop_reason(
                len(posts), asyncio.get_running_loop().time() - inicio,
                stagnant, max_posts, max_seconds)
            if parar_por:
                motivo = {"teto_de_anuncios": "teto_de_posts"}.get(parar_por, parar_por)
                break
            scrolls = i + 1
            try:
                await page.mouse.wheel(0, 2200)
            except Exception as e:
                motivo = "pagina_travou"
                say("rolagem_falhou", total=len(posts), erro=type(e).__name__)
                break
            await asyncio.sleep(SCROLL_PAUSE)
            if len(posts) == last:
                stagnant += 1
            else:
                stagnant, last = 0, len(posts)
                say("rolando", total=len(posts), scrolls=scrolls)

        say("fim", total=len(posts), scrolls=scrolls, motivo=motivo,
            do_alvo=sum(1 for p in posts.values() if p["page_id"] in alvo))

        try:
            await ctx.close()
        except Exception:
            pass

    if not posts and payloads_seen == 0:
        raise RuntimeError(
            "Nenhuma resposta GraphQL capturada no feed. O Meta provavelmente "
            "mudou a rota; ajuste GRAPHQL_MARKERS em collect/feed.py."
        )
    return list(posts.values())
