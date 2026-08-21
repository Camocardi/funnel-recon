"""Contrato de dados entre modulos (secao 10 do brief).

Todo modulo le e escreve estas estruturas. Mudanca aqui e mudanca de
contrato: mexa com cuidado.

Duas extensoes deliberadas ao schema do brief, ambas por necessidade real:

1. `ScanResult.target` e `ad_id` opcional. O brief chaveia scan_result por
   ad_id, mas o OSINT roda sobre um DOMINIO que pode nem estar ligado a um
   anuncio ainda (voce digita o dominio na mao). `target` diz o que foi
   testado; `ad_id` liga ao anuncio quando essa ligacao existir.

2. `ScanResult.raw`. Secao 8 manda separar captura burra de parsing, para
   consertar num lugar so quando a fonte mudar de formato. Guardar o payload
   bruto permite reparsear scans antigos sem refazer a rede.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal, Optional

# "criativo" e achado da trilha de criativo, nao da de destino: o funil
# continua desconhecido, mas o anuncio mostra hoje algo diferente do que
# mostrava antes. Misturar com "money" apagaria essa distincao.
Verdict = Literal["white", "money", "challenge", "criativo", "error", "unknown"]
Stage = Literal["collect", "osint", "probe", "probe_proxy", "browser", "creative"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Ad:
    """Um anuncio como coletado da Biblioteca (estagio [1])."""

    ad_id: str
    page_id: Optional[str] = None
    start_date: Optional[str] = None
    # Tri-estado de proposito: None e "a fonte nao disse", que NAO e o mesmo
    # que False. Anuncio encerrado e alvo prioritario (secao 6) -- um export
    # antigo, que nao trazia o campo, nao pode se passar por encerrado.
    is_active: Optional[bool] = None
    end_date: Optional[str] = None
    countries: list[str] = field(default_factory=list)
    display_host: Optional[str] = None
    # A URL REAL, com path + fbclid. A licao central da secao 3.4: o valor
    # esta aqui, nao no dominio raiz. Nunca sondar a raiz quando isto existe.
    full_url: Optional[str] = None
    cta: Optional[str] = None
    title: Optional[str] = None
    body: Optional[str] = None
    leaks: list[str] = field(default_factory=list)
    creative_lib_url: Optional[str] = None
    creative_feed_url: Optional[str] = None
    # pHash do criativo da Biblioteca, tirado NA HORA da coleta. URL de CDN do
    # Meta e assinada e expira em horas, entao guardar so a URL nao permite
    # voltar depois: sem o hash gravado agora, nao existe comparacao no tempo.
    creative_phash: Optional[str] = None
    asset_hosts: list[str] = field(default_factory=list)
    ts: str = field(default_factory=now_iso)


@dataclass
class ScanResult:
    """Uma tentativa de estagio contra um alvo. Uma linha por tentativa."""

    target: str
    stage: Stage
    source: str  # persona/proxy no probe; nome da fonte no OSINT
    ad_id: Optional[str] = None
    status: Optional[str] = None
    body_sha: Optional[str] = None
    final_url: Optional[str] = None
    signals: list[str] = field(default_factory=list)
    verdict: Verdict = "unknown"
    error: Optional[str] = None
    raw: Optional[dict[str, Any]] = None
    ts: str = field(default_factory=now_iso)


@dataclass
class CreativeDiff:
    """Divergencia entre duas versoes do mesmo criativo (estagio [5c]).

    `kind` diz quais duas versoes foram comparadas, porque as conclusoes sao
    diferentes:

      "feed"   Biblioteca x o que foi entregue num feed real. Pega bait-and-
               switch e criativo dinamico, mas depende de ver o anuncio rodando.
      "tempo"  o mesmo anuncio da Biblioteca em duas coletas. Pega bait-and-
               switch sozinho, sem feed. Aqui `phash_lib` e a versao ANTIGA e
               `phash_feed` a nova -- os nomes vem do schema da secao 10 do
               brief, que so previa a comparacao com feed.

    `is_cloaked` e tri-estado: None quando a distancia caiu na faixa ambigua
    dos limiares, que e resposta legitima e nao ausencia de resultado.
    """

    ad_id: str
    phash_lib: Optional[str] = None
    phash_feed: Optional[str] = None
    distance: Optional[int] = None
    is_cloaked: Optional[bool] = None
    kind: str = "feed"
    ts: str = field(default_factory=now_iso)


def to_json(obj: Any) -> str:
    return json.dumps(asdict(obj), ensure_ascii=False, default=str)
