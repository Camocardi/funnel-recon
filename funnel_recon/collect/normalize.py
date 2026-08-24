"""Estagio [1], lado Python: le o export da extensao e produz Ad (secao 10).

Por que existe uma camada de traducao em vez de a extensao ja cuspir o schema
final: secao 8. O Meta muda o schema do GraphQL periodicamente e a extensao
quebra. Mantendo a extensao "burra" (captura e exporta o que viu) e o
mapeamento aqui, um deploy do Meta so exige mexer num lugar -- e este lugar
tem testes, enquanto a extensao so pode ser testada com o Facebook aberto.

A LICAO CENTRAL da secao 3.4 vive aqui: a coluna `url` do export carrega a URL
REAL, com path e fbclid, que a interface da Biblioteca nao mostra. E dela que
sai `full_url`, e e `full_url` -- nunca o dominio -- que vai para o probe.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..schema import Ad
from ..signals import is_meta_host, looks_like_redirector, registrable_host, scan_values

# Nomes possiveis para o mesmo campo. A extensao usa uns; a API oficial da Ad
# Library usa outros; um export futuro pode usar terceiros. Aceitar todos custa
# pouco e evita reescrever isto a cada fonte nova.
FIELD_ALIASES = {
    "ad_id": ["ad_id", "id", "adArchiveID", "ad_archive_id", "archive_id"],
    "page_id": ["page_id", "pageId", "page"],
    "start_date": ["start_date", "start", "startDate", "ad_delivery_start_time"],
    "is_active": ["is_active", "isActive", "active", "active_status", "status"],
    "end_date": ["end_date", "end", "endDate", "ad_delivery_stop_time"],
    "full_url": ["full_url", "url", "link_url", "linkUrl"],
    "display_host": ["display_host", "host", "caption"],
    "cta": ["cta", "cta_text", "ctaText", "cta_type"],
    "title": ["title", "link_description", "headline"],
    "body": ["body", "text", "ad_creative_body"],
    "creative_lib_url": ["creative_lib_url", "video_url", "image_url", "creative"],
    "creative_feed_url": ["creative_feed_url"],
}


def _pick(row: dict, field: str) -> str:
    for key in FIELD_ALIASES.get(field, [field]):
        v = row.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, (int, float)):
            return str(v)
    return ""


TRUTHY = {"true", "1", "yes", "y", "sim", "active", "ativo", "veiculando"}
FALSY = {"false", "0", "no", "n", "nao", "n\u00e3o", "inactive", "inativo", "encerrado"}


def _pick_bool(row: dict, field: str) -> bool | None:
    """Como `_pick`, mas tri-estado: True, False ou None.

    None tem que sobreviver ate o fim. Se virasse False, todo export antigo --
    que nem tinha o campo -- passaria a se declarar encerrado e furaria a fila
    de alvos do probe.
    """
    for key in FIELD_ALIASES.get(field, [field]):
        v = row.get(key)
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)) and v in (0, 1):
            return bool(v)
        if isinstance(v, str) and v.strip():
            s = v.strip().lower()
            if s in TRUTHY:
                return True
            if s in FALSY:
                return False
    return None


def _split_leaks(row: dict) -> list[str]:
    v = row.get("leaks")
    if isinstance(v, list):
        return [str(x) for x in v if x]
    if isinstance(v, str) and v.strip():
        # O CSV da extensao junta com " | "
        return [p.strip() for p in v.split("|") if p.strip()]
    return []


def normalize_row(row: dict) -> Ad | None:
    """Uma linha do export -> um Ad. Devolve None se a linha for ruido."""
    ad_id = _pick(row, "ad_id")
    if not ad_id:
        return None

    full_url = _pick(row, "full_url")
    host = registrable_host(_pick(row, "display_host") or full_url)
    host = host[4:] if host.startswith("www.") else host

    # Erro 4 da secao 4: link interno do Meta nao e destino de anuncio.
    # A extensao ja filtra no fallback de DOM, mas um export antigo pode
    # trazer ruido -- e um export de outra fonte certamente traz.
    if host and is_meta_host(host):
        return None

    leaks = _split_leaks(row)
    # Varre tambem os textos: um handle de bot que escapou pro corpo do anuncio
    # e o achado mais barato que existe -- nao precisa furar cloaker nenhum.
    blob = " ".join(str(row.get(k, "")) for k in ("title", "body", "cta", "url"))
    for v in scan_values(blob):
        if v not in leaks:
            leaks.append(v)

    return Ad(
        ad_id=str(ad_id),
        page_id=_pick(row, "page_id") or None,
        start_date=_pick(row, "start_date") or None,
        is_active=_pick_bool(row, "is_active"),
        end_date=_pick(row, "end_date") or None,
        display_host=host or None,
        full_url=full_url or None,
        cta=_pick(row, "cta") or None,
        title=_pick(row, "title") or None,
        body=(_pick(row, "body") or None),
        leaks=leaks,
        creative_lib_url=_pick(row, "creative_lib_url") or None,
        creative_feed_url=_pick(row, "creative_feed_url") or None,
        asset_hosts=sorted({
            h for h in (registrable_host(_pick(row, k))
                        for k in ("creative_lib_url", "creative_feed_url"))
            if h and not is_meta_host(h)
        }),
        collation_count=row.get("collation_count"),
        collation_id=row.get("collation_id"),
    )


def load_export(path: str | Path) -> list[Ad]:
    """Le CSV ou JSON exportado pela extensao."""
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")

    if path.suffix.lower() == ".json" or text.lstrip()[:1] in "[{":
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("ads", data.get("results", []))
    else:
        rows = list(csv.DictReader(text.splitlines()))

    ads: list[Ad] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        ad = normalize_row(row)
        if ad and ad.ad_id not in seen:
            seen.add(ad.ad_id)
            ads.append(ad)
    return ads


def domain_histogram(ads: list[Ad], sample: bool = False) -> list[tuple[str, int, bool]]:
    """(host, quantidade, e_outlier), do mais comum ao menos.

    O dominio dominante e a white page -- conhecida, sem valor. O achado esta
    na cauda: variante de teste, campanha velha, cloaker mal configurado.

    Erro 5 da secao 4: com pouco dado, TUDO parece outlier. Por isso o piso de
    volume minimo -- abaixo dele nao marcamos nada.

    `sample=True` diz que a coleta foi cortada por limite (pagina grande demais)
    e desliga a marcacao. Nao e cautela exagerada: "raro" so tem sentido contra
    o conjunto inteiro, e a Biblioteca entrega os mais recentes primeiro. Numa
    fatia dos 2.000 mais novos de uma pagina de 50.000, o dominio raro da
    operacao pode ser maioria -- ou nao ter aparecido nenhuma vez. Marcar
    outlier ali e inventar um achado, que e pior que nao ter achado nenhum.
    """
    counts: dict[str, int] = {}
    for ad in ads:
        if ad.display_host:
            counts[ad.display_host] = counts.get(ad.display_host, 0) + 1
    total = sum(counts.values())
    threshold = max(2, int(total * 0.05))
    return sorted(
        ((h, n, not sample and total > 8 and n <= threshold) for h, n in counts.items()),
        key=lambda t: -t[1],
    )


# Um caminho com menos da metade do volume do principal e VARIANTE do mesmo
# funil (teste, campanha antiga, publico separado). Com volume parecido sao
# funis simultaneos -- a mesma leitura que domain_histogram faz para dominios,
# e pelo mesmo motivo: chamar de variante o que e operacao paralela faz o
# usuario ignorar metade do alvo.
VARIANT_RATIO = 0.5


def path_histogram(ads: list[Ad], sample: bool = False
                   ) -> dict[str, list[tuple[str, str, int, bool]]]:
    """{host: [(caminho, url_exemplo, quantidade, e_variante)]}, do maior ao menor.

    A licao central da secao 3.4 mora aqui, e ela e sobre a TELA, nao sobre a
    coleta: o valor esta no caminho, nao no dominio. Uma tela que so mostra
    `alvo.site` faz a pessoa abrir a raiz -- que num app Node responde
    "Cannot GET /" -- enquanto os 1.128 anuncios diziam `/quiz` o tempo todo.
    Aconteceu exatamente assim na primeira analise real.

    Agrupa por CAMINHO e nao pela URL inteira: quando ha `fbclid`, cada anuncio
    tem uma URL unica e o histograma viraria uma lista de mil linhas de tamanho
    1. Guarda uma URL de exemplo COMPLETA junto, porque e ela -- com fbclid --
    que o probe precisa receber.
    """
    por_host: dict[str, dict[str, dict]] = {}
    for ad in ads:
        if not ad.full_url or not ad.display_host:
            continue
        try:
            caminho = urlparse(ad.full_url).path or "/"
        except ValueError:
            continue
        slot = por_host.setdefault(ad.display_host, {}).setdefault(
            caminho, {"n": 0, "url": ad.full_url})
        slot["n"] += 1
        # Preferir um exemplo COM fbclid: e o que o probe quer.
        if "fbclid" in (ad.full_url or "") and "fbclid" not in slot["url"]:
            slot["url"] = ad.full_url

    saida: dict[str, list[tuple[str, str, int, bool]]] = {}
    for host, caminhos in por_host.items():
        ordenado = sorted(caminhos.items(), key=lambda kv: -kv[1]["n"])
        topo = ordenado[0][1]["n"]
        saida[host] = [
            (caminho, d["url"], d["n"],
             (not sample) and len(ordenado) > 1 and d["n"] < topo * VARIANT_RATIO)
            for caminho, d in ordenado
        ]
    return saida


def pick_probe_targets(ads: list[Ad], limit: int = 5, sample: bool = False) -> list[Ad]:
    """Quais anuncios vale sondar primeiro.

    Prioridade, do brief:
      1. quem tem URL com CAMINHO de redirecionador (`/l/<hash>`) -- e a URL
         real, a que o probe precisa;
      2. quem esta em dominio outlier (cauda, nao white page);
      3. ENCERRADO antes de ativo -- campanha morta costuma ter cloaker mal
         configurado, servindo a money page pra qualquer um;
      4. mais antigo primeiro, pelo mesmo motivo.

    O item 3 era so o 4 ate a coleta passar a trazer `is_active`: a data de
    inicio era um palpite do que hoje da pra saber direto. Anuncio sem status
    (None) fica no meio -- nao ganha a prioridade do encerrado nem leva a
    despriorizacao do ativo, porque nao sabemos qual dos dois ele e.
    """
    # Em amostra nao ha outlier calculavel (ver domain_histogram): o criterio 2
    # simplesmente sai do desempate, e os outros tres decidem sozinhos.
    outliers = {h for h, _, is_out in domain_histogram(ads, sample=sample) if is_out}

    def score(ad: Ad) -> tuple:
        return (
            0 if (ad.full_url and looks_like_redirector(ad.full_url)) else 1,
            0 if ad.display_host in outliers else 1,
            0 if (ad.full_url and "fbclid" in (urlparse(ad.full_url).query or "")) else 1,
            {False: 0, None: 1, True: 2}[ad.is_active],
            ad.start_date or "9999",
        )

    # Uma URL por alvo. Sem isto, `limit=2` podia devolver dois anuncios com a
    # MESMA url (o mesmo criativo replicado dezenas de vezes e o normal), o
    # chamador deduplicava depois, e metade do orcamento de sondagem sumia --
    # numa coleta com quatro destinos distintos, so um era sondado.
    vistos: set[str] = set()
    fora: list[Ad] = []
    for a in sorted([a for a in ads if a.full_url], key=score):
        if a.full_url in vistos:
            continue
        vistos.add(a.full_url)
        fora.append(a)
        if len(fora) >= limit:
            break
    return fora
