"""Extracao de anuncios a partir do payload GraphQL cru da Biblioteca.

Porte da logica que ja esta provada em `extension/adlib-harvester/content.js`.
Existir nas duas linguagens nao e duplicacao acidental: a extensao roda dentro
do Chrome do usuario e o coletor por navegador roda em Python, mas AMBOS
alimentam o mesmo `normalize.py`. A logica aqui e a que o app usa; a da
extensao fica como caminho alternativo.

Principio da secao 8: esta camada le JSON bruto e nao sabe nada de schema do
Meta. Quando o Meta mudar nomes de campo, o conserto e aqui e so aqui.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator
from urllib.parse import parse_qs, unquote, urlparse

MAX_DEPTH = 30
ID_KEYS = ("ad_archive_id", "adArchiveID", "adArchiveId", "archive_id")

# Campos que carregam a URL de destino. `link_url` e o que importa: e dele que
# sai a URL REAL com caminho e fbclid -- a que a interface nao mostra e que foi
# a descoberta decisiva da secao 3.4.
URL_KEYS = ("link_url", "linkUrl", "caption_link", "url")
PAGE_KEYS = ("page_name", "pageName")
CTA_KEYS = ("cta_text", "ctaText", "cta_type")
TITLE_KEYS = ("title", "link_description", "caption")
BODY_KEYS = ("body", "text")

# Status de veiculacao. O anuncio ENCERRADO e o alvo mais valioso da coleta:
# ninguem volta pra arrumar o filtro de uma campanha morta, entao e nele que o
# cloaker mais vaza a money page. Ver secao 6 do brief.
ACTIVE_KEYS = ("is_active", "isActive", "active")
END_KEYS = ("end_date", "endDate", "ad_delivery_stop_time")

# Mídia do criativo. Alimenta a trilha de criativo: se o asset vier de dominio
# de terceiro, ele volta a ser servido pelo anunciante -- e ai recai no probe.
MEDIA_KEYS = ("video_hd_url", "video_sd_url", "video_preview_image_url",
              "original_image_url", "resized_image_url", "image_url", "watermarked_video_sd_url")


def walk(node: Any, depth: int = 0) -> Iterator[dict]:
    """Percorre qualquer JSON e devolve todo dicionario encontrado."""
    if depth > MAX_DEPTH:
        return
    if isinstance(node, list):
        for item in node:
            yield from walk(item, depth + 1)
    elif isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value, depth + 1)


def find_id(obj: dict) -> str | None:
    for k in ID_KEYS:
        v = obj.get(k)
        if v is not None and len(str(v)) > 6:
            return str(v)
    return None


def unwrap_facebook_link(raw: str) -> str:
    """Desembrulha l.facebook.com/l.php?u=<destino>.

    O Meta envolve todo link de saida nesse redirecionador. Sem desembrulhar,
    todo anuncio parece apontar pra facebook.com e o histograma de dominios
    nao serve pra nada.
    """
    if not raw or not isinstance(raw, str):
        return ""
    url = raw.strip()
    for _ in range(3):
        try:
            p = urlparse(url)
        except ValueError:
            break
        host = (p.hostname or "").lower()
        if not (host == "facebook.com" or host.endswith(".facebook.com")):
            break
        if p.path.lower() != "/l.php":
            break
        target = parse_qs(p.query).get("u", [None])[0]
        if not target:
            break
        url = unquote(target)
    return url


def first_string(obj: dict, keys: tuple[str, ...]) -> str:
    """Primeiro valor de texto util entre as chaves dadas.

    O Meta as vezes manda `{"text": "..."}` em vez de string direta.
    """
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, dict) and isinstance(v.get("text"), str) and v["text"].strip():
            return v["text"].strip()
    return ""


def find_active(obj: dict, snap: dict) -> bool | None:
    """Status de veiculacao, ou None se o payload nao disse.

    Devolver False no lugar de None seria mentir: o parser nao sabe a
    diferenca entre "o Meta disse que acabou" e "o Meta nao mandou o campo",
    e quem ordena os alvos precisa dessa diferenca.
    """
    for src in (obj, snap):
        for k in ACTIVE_KEYS:
            v = src.get(k)
            if isinstance(v, bool):
                return v
            if isinstance(v, (int, float)) and v in (0, 1):
                return bool(v)
    return None


def merge_rec(prev: dict, rec: dict) -> None:
    """Funde um registro parcial no que ja temos, mantendo o mais rico.

    O mesmo anuncio chega em varios payloads, as vezes pela metade. Preencher
    so o que falta evita que uma versao pobre apague uma boa.

    `is_active` sai do laco generico porque o teste de verdade descartaria um
    False legitimo como se fosse ausencia -- e False e justamente o valor que
    interessa.
    """
    for k, v in rec.items():
        if k == "is_active":
            continue
        if v and not prev.get(k):
            prev[k] = v
    if prev.get("is_active") is None and rec.get("is_active") is not None:
        prev["is_active"] = rec["is_active"]


def to_date(v: Any) -> str:
    """O Meta manda ora epoch em segundos, ora string ISO."""
    if v in (None, ""):
        return ""
    try:
        n = int(v)
        if 1_000_000_000 < n < 4_000_000_000:
            from datetime import datetime, timezone
            return datetime.fromtimestamp(n, timezone.utc).date().isoformat()
    except (TypeError, ValueError):
        pass
    if isinstance(v, str) and re.match(r"^\d{4}-\d{2}-\d{2}", v):
        return v[:10]
    return ""


def collect_media(snap: dict) -> list[str]:
    """URLs de midia do criativo, incluindo as aninhadas em videos[]/images[]."""
    found: list[str] = []
    for obj in walk(snap):
        for k in MEDIA_KEYS:
            v = obj.get(k)
            if isinstance(v, str) and v.startswith("http") and v not in found:
                found.append(v)
    return found


def extract_ads(payload: str) -> list[dict]:
    """Payload cru -> lista de registros no formato que `normalize.py` consome.

    Respostas GraphQL do Meta as vezes vem como varios objetos JSON
    concatenados por quebra de linha, entao tentamos linha a linha.
    """
    out: dict[str, dict] = {}
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
            ad_id = find_id(obj)
            if not ad_id:
                continue
            snap = obj.get("snapshot") if isinstance(obj.get("snapshot"), dict) else obj
            media = collect_media(snap)
            rec = {
                "ad_id": ad_id,
                "url": unwrap_facebook_link(first_string(snap, URL_KEYS)),
                "page": first_string(snap, PAGE_KEYS),
                "page_id": str(obj.get("page_id") or snap.get("page_id") or ""),
                "cta": first_string(snap, CTA_KEYS),
                "title": first_string(snap, TITLE_KEYS),
                "body": first_string(snap, BODY_KEYS)[:400],
                "start": to_date(obj.get("start_date") or obj.get("startDate")
                                 or snap.get("start_date")),
                "is_active": find_active(obj, snap),
                "end": to_date(next((obj.get(k) or snap.get(k) for k in END_KEYS
                                     if obj.get(k) or snap.get(k)), None)),
                "creative_lib_url": media[0] if media else "",
                "media": media,
            }
            prev = out.get(ad_id)
            if not prev:
                out[ad_id] = rec
            else:
                merge_rec(prev, rec)
    return list(out.values())
