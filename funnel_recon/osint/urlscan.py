"""urlscan.io -> alguem ja capturou este dominio?

Secao 3.1: no caso real deu 0 scans, o que ja e informacao -- dominio
descartavel, recem-criado, ninguem viu antes. Quando HA scan, e o melhor
retorno de todo o OSINT: vem screenshot da pagina e a cadeia de redirect
inteira, ou seja, alguem ja pagou o custo de clicar por voce.

Chave opcional em URLSCAN_API_KEY sobe o limite de requisicoes.
"""

from __future__ import annotations

import os

from ..schema import ScanResult
from ..signals import registrable_host, scan_text
from .http import client

SEARCH = "https://urlscan.io/api/v1/search/"
RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
MAX_DETAIL = 3  # detalhar so os scans mais recentes: cada um e uma requisicao


def _headers() -> dict:
    key = os.getenv("URLSCAN_API_KEY", "").strip()
    return {"API-Key": key} if key else {}


async def _detail(c, uuid: str) -> dict:
    r = await c.get(RESULT.format(uuid=uuid))
    r.raise_for_status()
    d = r.json()
    page = d.get("page") or {}
    lists = d.get("lists") or {}
    return {
        "uuid": uuid,
        "final_url": page.get("url"),
        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
        "ip": page.get("ip"),
        "asn": page.get("asn"),
        "asnname": page.get("asnname"),
        "country": page.get("country"),
        "server": page.get("server"),
        "domains": (lists.get("domains") or [])[:60],
        "urls": (lists.get("urls") or [])[:200],
    }


async def run(domain: str) -> ScanResult:
    try:
        async with client(headers={**_headers()}) as c:
            r = await c.get(SEARCH, params={"q": f'domain:"{domain}"', "size": 100})
            r.raise_for_status()
            results = (r.json() or {}).get("results", [])

            details = []
            for item in results[:MAX_DETAIL]:
                uuid = (item.get("task") or {}).get("uuid") or item.get("_id")
                if not uuid:
                    continue
                try:
                    details.append(await _detail(c, uuid))
                except Exception as e:
                    details.append({"uuid": uuid, "error": f"{type(e).__name__}: {e}"})
    except Exception as e:
        return ScanResult(target=domain, stage="osint", source="urlscan",
                          verdict="error", error=f"{type(e).__name__}: {e}")

    if not results:
        # Zero scans e um achado, nao uma falha: ninguem capturou este dominio.
        return ScanResult(
            target=domain, stage="osint", source="urlscan",
            status="0 scans", verdict="unknown",
            signals=["no_public_scan"],
            raw={"results": 0},
        )

    signals = [f"urlscan_scans:{len(results)}"]
    final_url = None
    # Todo host de terceiro contatado pela pagina e candidato a asset externo
    # de criativo ou a hop de tracker -- ambos alimentam o probe [3].
    third_party = set()
    for d in details:
        if d.get("error"):
            continue
        final_url = final_url or d.get("final_url")
        if d.get("final_url"):
            signals.append(f"urlscan_final_url:{d['final_url']}")
        if d.get("asnname"):
            signals.append(f"urlscan_asn:{d['asnname']}")
        if d.get("country"):
            signals.append(f"urlscan_country:{d['country']}")
        signals.append(f"urlscan_screenshot:{d['screenshot']}")
        for u in d.get("urls", []):
            for s in scan_text(u):
                signals.append(f"in_scanned_url:{s}")
        for h in d.get("domains", []):
            h = registrable_host(h)
            if h and h != domain and not h.endswith("." + domain):
                third_party.add(h)
    signals += [f"third_party_host:{h}" for h in sorted(third_party)]

    seen: set[str] = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    return ScanResult(
        target=domain, stage="osint", source="urlscan",
        status=f"{len(results)} scans", final_url=final_url,
        verdict="unknown", signals=signals,
        raw={"count": len(results), "details": details},
    )
