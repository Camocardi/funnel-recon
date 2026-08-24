"""Estagio [5c]: comparador de criativo.

A outra metade do projeto. O cloaker de DESTINO esconde para onde o clique vai
e quem decide e o servidor do anunciante -- por isso o probe [3] existe. O
cloaker de CRIATIVO esconde o que o anuncio MOSTRA, e ai quem serve o arquivo
e o proprio Meta: nao ha o que sondar. A unica saida e comparar duas versoes do
mesmo criativo e medir se divergiram.

Tres comparacoes possiveis, com viabilidades bem diferentes (secao 5 do brief):

  Biblioteca x feed      cobre bait-and-switch e criativo dinamico, mas depende
                         de ver o anuncio entregue num feed real -- ver feed.py,
                         que e oportunista por natureza.
  Biblioteca x Biblioteca  o mesmo anuncio hasheado em coletas diferentes. Pega
      no tempo           bait-and-switch sozinho, sem feed nenhum, e e de graca:
                         basta ja termos gravado o hash antigo.
  asset de terceiro      quando a midia vem de dominio que nao e do Meta, o
                         arquivo pode ser cloakeado na origem -- ai recai no
                         probe [3] e nao neste modulo.

Por que pHash e nao sha256: recompressao, marca d'agua e resize mudam todo byte
sem mudar o que a pessoa ve. Hash criptografico diria "diferente" para todo
par e a ferramenta gritaria cloaking o tempo todo.

Por que a DCT esta escrita aqui em vez de `imagehash`: aquele pacote arrasta
numpy e scipy para fazer o que cabe em quarenta linhas sobre uma imagem de
32x32. O app ja pede para o usuario esperar uma instalacao na primeira
execucao; dobrar esse tempo por causa disto nao se paga.
"""

from __future__ import annotations

import asyncio
import math
from urllib.parse import urlparse

from .osint.http import client
from .schema import CreativeDiff

# 32x32 alimenta a DCT; ficamos com o bloco 8x8 de baixa frequencia, que e onde
# mora a estrutura da imagem. Detalhe fino e justamente o que a recompressao
# destroi -- descartar e o ponto.
DCT_N = 32
HASH_SIDE = 8

# Distancia de Hamming, em bits de 64. Os patamares NAO vieram do folclore de
# pHash; foram medidos (tests/test_creative.py refaz a medicao):
#
#   recompressao JPEG q90..q25, resize 1080->320, WEBP, blur leve ....... 0
#   marca d'agua num canto ............................................. 8
#   crop de 3% e reescala .............................................. 8
#   criativos genuinamente diferentes .................... 22 no minimo
#
# Dai SAME_MAX=10 (cobre marca d'agua e crop com folga) e DIFF_MIN=18 (abaixo
# do piso observado para imagens diferentes, tambem com folga). A faixa 11..17
# nao aparece em nenhum dos dois grupos medidos: cair ali significa que a
# medicao nao cobriu o caso, e a resposta honesta e `ambiguo`, nao um chute.
#
# Ressalva: as imagens da medicao sao sinteticas. Fotos reais diferentes podem
# chegar mais perto que 22 -- se aparecer falso "divergente" em campo, e este
# comentario que precisa ser refeito com assets de verdade, nao os limiares
# ajustados no olho.
SAME_MAX = 10
DIFF_MIN = 18

IMAGE_EXT = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp")

# Teto de download. Um criativo de imagem nao passa de alguns MB; o que passa
# e video, que este modulo nao hasheia de qualquer forma.
MAX_BYTES = 8 * 1024 * 1024

_COS = [[math.cos(math.pi / DCT_N * (x + 0.5) * u) for x in range(DCT_N)]
        for u in range(DCT_N)]


def _dct_2d_low(pixels: list[float]) -> list[float]:
    """Bloco 8x8 de baixa frequencia da DCT-II de uma imagem DCT_N x DCT_N.

    Separavel: primeiro as linhas, depois as colunas do resultado. So os 8
    primeiros coeficientes de cada eixo interessam, entao o laco para ali --
    calcular os 32 e jogar 24 fora seria 4x o trabalho por nada.
    """
    linhas = []
    for y in range(DCT_N):
        base = y * DCT_N
        linha = pixels[base:base + DCT_N]
        linhas.append([sum(linha[x] * _COS[u][x] for x in range(DCT_N))
                       for u in range(HASH_SIDE)])
    return [sum(linhas[y][u] * _COS[v][y] for y in range(DCT_N))
            for v in range(HASH_SIDE) for u in range(HASH_SIDE)]


def phash(data: bytes) -> str | None:
    """Hash perceptual de 64 bits, em hex. None se o byte nao for imagem.

    Devolver None em vez de levantar e proposital: um asset que expirou no CDN
    ou virou HTML de erro e ocorrencia rotineira aqui, nao excecao.
    """
    try:
        from io import BytesIO

        from PIL import Image

        img = Image.open(BytesIO(data))
        img = img.convert("L").resize((DCT_N, DCT_N), Image.Resampling.LANCZOS)
    except Exception:
        return None

    coef = _dct_2d_low([float(p) for p in img.getdata()])

    # O termo DC (coef[0]) e o brilho medio e e uma ordem de grandeza maior que
    # o resto: deixa-lo entrar na mediana puxaria o limiar para cima e boa
    # parte dos bits viraria zero.
    resto = sorted(coef[1:])
    mediana = (resto[31] + resto[32]) / 2

    bits = 0
    for i, c in enumerate(coef):
        if c > mediana:
            bits |= 1 << i
    return f"{bits:016x}"


def hamming(a: str | None, b: str | None) -> int | None:
    """Distancia em bits, ou None se faltar um dos lados."""
    if not a or not b:
        return None
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return None


def verdict(distance: int | None) -> str:
    """Tres estados, nao dois. `ambiguo` e resposta legitima."""
    if distance is None:
        return "sem_dado"
    if distance <= SAME_MAX:
        return "igual"
    if distance >= DIFF_MIN:
        return "divergente"
    return "ambiguo"


def hashable_asset(media: list[str]) -> str:
    """Qual dos assets do anuncio da para hashear.

    Para video o que sobra e a thumbnail (`video_preview_image_url`), e ela
    entra nesta lista como qualquer outra imagem. Comparar thumbnail nao pega
    troca de conteudo no meio do video -- esse limite esta no relatorio, nao
    escondido aqui. Baixar e decodificar o video inteiro custaria ordens de
    grandeza mais e exigiria ffmpeg.
    """
    for url in media or []:
        if not isinstance(url, str) or not url.startswith("http"):
            continue
        try:
            path = urlparse(url).path.lower()
        except ValueError:
            continue
        if path.endswith(IMAGE_EXT):
            return url
    return ""


async def fetch_asset(url: str, timeout: float = 20.0) -> bytes | None:
    """Baixa um asset de criativo, com teto de tamanho.

    URL de CDN do Meta e assinada e EXPIRA em horas. Por isso o hash tem que
    ser tirado na hora da coleta: guardar a URL para voltar depois nao
    funciona, e sem o hash de antes nao existe comparacao no tempo.
    """
    if not url:
        return None
    try:
        async with client(timeout=timeout) as c:
            async with c.stream("GET", url) as r:
                if r.status_code != 200:
                    return None
                tipo = r.headers.get("content-type", "")
                if tipo and not tipo.startswith("image/"):
                    return None
                buf = bytearray()
                async for pedaco in r.aiter_bytes():
                    buf += pedaco
                    if len(buf) > MAX_BYTES:
                        return None
                return bytes(buf)
    except Exception:
        return None


async def hash_asset(media: list[str]) -> str | None:
    """Atalho: escolhe o asset hasheavel, baixa e hasheia."""
    data = await fetch_asset(hashable_asset(media))
    return phash(data) if data else None


async def hash_e_salvar(media: list[str], destino) -> str | None:
    """Baixa o asset UMA vez, hasheia e grava a imagem em `destino`.

    Salva junto porque a URL expira: sem o arquivo agora, ver o criativo
    depois vira impossivel. Devolve o pHash como hash_asset.
    """
    from pathlib import Path

    url = hashable_asset(media)
    data = await fetch_asset(url)
    if not data:
        return None
    h = phash(data)
    if h and destino is not None:
        try:
            ext = ".png" if data[:8] == b"\x89PNG\r\n\x1a\n" else ".jpg"
            Path(destino).with_suffix(ext).write_bytes(data)
        except Exception:
            pass  # nao poder salvar a imagem nao invalida o hash
    return h


async def hash_many(items: list[tuple[str, list[str]]], concurrency: int = 6,
                    on_done=None, salvar_em=None, salvar_apenas=None) -> dict[str, str]:
    """{ad_id: pHash} para varios anuncios de uma vez.

    Concorrencia baixa de proposito. Sao requisicoes ao CDN do Meta a partir do
    IP residencial do usuario, que e o ativo mais caro do projeto -- disparar
    dezenas em paralelo e o tipo de padrao que rende bloqueio, e nao ha pressa
    aqui que justifique o risco.
    """
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, str] = {}

    async def um(ad_id: str, media: list[str]):
        # Hasheia todos; salva a imagem so de quem esta em `salvar_apenas`
        # (os criativos mais escalados). Assim o historico cobre tudo, mas o
        # disco so guarda o que vale ver.
        grava = salvar_em is not None and (salvar_apenas is None or ad_id in salvar_apenas)
        async with sem:
            if grava:
                h = await hash_e_salvar(media, salvar_em / str(ad_id))
            else:
                h = await hash_asset(media)
        if h:
            out[ad_id] = h
        if on_done:
            on_done(len(out))

    await asyncio.gather(*(um(i, m) for i, m in items))
    return out


def temporal_diffs(antes: dict[str, str], agora: dict[str, str]) -> list[CreativeDiff]:
    """Compara o mesmo anuncio entre duas coletas.

    E a deteccao de bait-and-switch que NAO depende de feed: aprovam um
    criativo limpo, depois editam o anuncio, e a Biblioteca passa a mostrar
    outra coisa no mesmo ad_id. Se ja tinhamos o hash antigo gravado, a troca
    aparece sozinha -- de graca, sem furar nada.

    So entra quem existe dos dois lados: anuncio novo nao tem com o que
    comparar, e isso e ausencia de dado, nao ausencia de troca.
    """
    saida: list[CreativeDiff] = []
    for ad_id, novo in agora.items():
        antigo = antes.get(ad_id)
        if not antigo:
            continue
        d = hamming(antigo, novo)
        v = verdict(d)
        saida.append(CreativeDiff(
            ad_id=ad_id, phash_lib=antigo, phash_feed=novo, distance=d,
            is_cloaked={"divergente": True, "igual": False}.get(v),
            kind="tempo",
        ))
    return saida


async def feed_diffs(posts: list[dict], lib_por_pagina: dict[str, list[str]],
                     on_done=None) -> list[CreativeDiff]:
    """Compara cada criativo entregue no feed com os da mesma pagina.

    Post de pagina que nao esta na base fica de fora: sem os criativos
    aprovados nao ha com o que comparar, e comparar contra a pagina errada
    produziria "divergente" para todo mundo.
    """
    alvo = [p for p in posts if p.get("page_id") in lib_por_pagina]
    if not alvo:
        return []

    chaves = [(p.get("ad_id") or f"{p['page_id']}:{i}", p.get("media") or [])
              for i, p in enumerate(alvo)]
    hashes = await hash_many(chaves, on_done=on_done)

    saida: list[CreativeDiff] = []
    for (chave, _), post in zip(chaves, alvo):
        h = hashes.get(chave)
        if not h:
            continue
        biblioteca = lib_por_pagina[post["page_id"]]
        d, comparados = nearest(h, biblioteca)
        if not comparados:
            continue
        # Qual criativo aprovado ficou mais perto -- e o par que a pessoa vai
        # querer abrir lado a lado para decidir com o olho.
        mais_perto = min(biblioteca, key=lambda x: hamming(h, x) if hamming(h, x) is not None else 99)
        v = verdict(d)
        saida.append(CreativeDiff(
            ad_id=chave, phash_lib=mais_perto, phash_feed=h, distance=d,
            is_cloaked={"divergente": True, "igual": False}.get(v),
            kind="feed",
        ))
    return saida


def nearest(feed_hash: str, lib_hashes: list[str]) -> tuple[int | None, int]:
    """Menor distancia entre um criativo do feed e os da Biblioteca da pagina.

    Comparar contra o conjunto todo, e nao contra um anuncio especifico, e o
    que torna a deteccao possivel: o payload do feed nem sempre traz o id de
    arquivo do anuncio, mas traz de qual PAGINA ele e. Se o criativo entregue
    nao se parece com NENHUM que a pagina publicou na Biblioteca, o que a
    Biblioteca mostra nao e o que esta no ar.
    """
    distancias = [d for h in lib_hashes if (d := hamming(feed_hash, h)) is not None]
    if not distancias:
        return None, 0
    return min(distancias), len(distancias)
