"""A identidade de VSL de uma money page, e os IRMAOS do mesmo operador.

Nasceu de um caso concreto. A money page nao aparece na Biblioteca -- o Meta
so publica o link do cloaker. Mas UMA money page na mao (vinda de um grupo,
de um clique real, do que for) revela a CONTA do operador no converteai/VTurb
(`vsl_account`), e essa conta e a mesma em todas as VSLs dele.

Com a conta em maos, dois caminhos de correlacao acham as outras ofertas dele:

  1. o proprio banco -- toda money page ja radiografada que carrega a mesma
     conta e do mesmo dono, mesmo com dominio, produto e idioma diferentes;
  2. o IP do servidor + vizinhos de host -- operador reusa infra, e os
     dominios irmaos costumam morar no mesmo lugar.

Confirmado: `thesidetrack.site` (disfuncao, ES) e `thehealthvantage.site`
(bicarbonato/emagrecimento, EN) sao dominios, produtos e idiomas diferentes --
e a MESMA conta 6e3ae2f6-ad64-483b-9bc5-bafc50ec8005.

Nada aqui toca em filtro de cloaker. A money page abre pela porta da frente
(o JS-wall atrasa, nao filtra por conteudo); o resto e OSINT de infraestrutura.
"""

from __future__ import annotations

import re
import socket

from .page import from_url
from .signals import apex_domain

# A CONTA e o UUID logo apos o dominio do converteai; o VIDEO e o ObjectId no
# CDN. So a conta liga operador -- o video diferencia ofertas do mesmo dono.
ACCOUNT_RE = re.compile(
    r"converteai\.net/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
    re.I)


def account_de_fingerprint(fp: dict) -> str:
    """Extrai a conta da radiografia de uma money page, ou ""."""
    contas = fp.get("accounts") or []
    if contas:
        return contas[0].lower()
    # fallback: alguns sinais trazem a URL inteira do player
    for v in fp.get("players", []) or []:
        m = ACCOUNT_RE.search(v)
        if m:
            return m.group(1).lower()
    return ""


async def identidade(url: str) -> dict:
    """Radiografa a money page e devolve conta, video, checkout e host."""
    fp = await from_url(url)
    return {
        "url": url,
        "titulo": fp.get("title", ""),
        "account": account_de_fingerprint(fp),
        "videos": fp.get("video", []),
        "players": fp.get("player_ids", []),
        "checkouts": fp.get("checkouts", []),
        "host": apex_domain(url),
        "bounced": fp.get("bounced", False),
        "final_url": fp.get("final_url", url),
    }


def irmaos_no_banco(conn, account: str) -> list[dict]:
    """Toda money page ja gravada que carrega a MESMA conta de VSL.

    Le `scan_result.signals`, onde `vsl_account:<uuid>` fica guardado desde a
    radiografia. Cada alvo distinto aparece uma vez, com o que se sabe dele.
    """
    if not account:
        return []
    import json
    account = account.lower()
    achados: dict[str, dict] = {}
    for row in conn.execute(
            "SELECT target, final_url, signals, ts FROM scan_result "
            "WHERE signals LIKE ? ORDER BY ts", (f"%vsl_account:{account}%",)):
        try:
            sinais = json.loads(row["signals"] or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        if not any(s == f"vsl_account:{account}" for s in sinais):
            continue
        alvo = row["final_url"] or row["target"]
        if alvo in achados:
            continue
        achados[alvo] = {
            "url": alvo,
            "videos": sorted({s.split(":", 1)[1] for s in sinais
                              if s.startswith("vsl_video:")}),
            "checkouts": sorted({s.split(":", 1)[1] for s in sinais
                                 if s.startswith("checkout:")}),
            "visto_em": row["ts"][:10] if row["ts"] else "",
        }
    return list(achados.values())


def ip_do_host(host: str) -> list[str]:
    """IPs A/AAAA do host. Vizinhos de host sao a outra via de correlacao."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    return sorted({i[4][0] for i in infos})
