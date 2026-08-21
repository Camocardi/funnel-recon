"""Orquestra as fontes de OSINT [2].

Regra da secao 12: uma fonte falhar nao pode derrubar as outras. Por isso
`return_exceptions=True` e conversao de qualquer excecao em ScanResult de erro
-- o relatorio sempre sai, com a lacuna marcada em vez de omitida.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

from ..schema import ScanResult
from ..signals import is_meta_host, registrable_host
from . import crtsh, rdap, urlscan, wayback

SOURCES: dict[str, Callable[[str], Awaitable[ScanResult]]] = {
    "urlscan": urlscan.run,
    "crtsh": crtsh.run,
    "wayback": wayback.run,
    "rdap": rdap.run,
}


def normalize_targets(raw: list[str]) -> list[str]:
    """Aceita dominio ou URL; devolve hosts unicos, sem dominios do Meta.

    Erro 4 da secao 4: dominio do Meta nunca e alvo. Filtrar na entrada evita
    gastar requisicao e sujar o relatorio.
    """
    out: list[str] = []
    for item in raw:
        host = registrable_host(item)
        host = host[4:] if host.startswith("www.") else host
        if not host or is_meta_host(host) or host in out:
            continue
        out.append(host)
    return out


async def osint_domain(domain: str, sources: list[str] | None = None) -> list[ScanResult]:
    chosen = sources or list(SOURCES)
    tasks = [SOURCES[name](domain) for name in chosen]
    done = await asyncio.gather(*tasks, return_exceptions=True)

    results: list[ScanResult] = []
    for name, res in zip(chosen, done):
        if isinstance(res, BaseException):
            results.append(ScanResult(
                target=domain, stage="osint", source=name,
                verdict="error", error=f"{type(res).__name__}: {res}",
            ))
        else:
            results.append(res)
    return results


async def osint_many(domains: list[str], sources: list[str] | None = None,
                     concurrency: int = 4) -> dict[str, list[ScanResult]]:
    """Varios dominios em paralelo, com teto para nao levar rate limit."""
    sem = asyncio.Semaphore(concurrency)

    async def one(d: str):
        async with sem:
            return d, await osint_domain(d, sources)

    pairs = await asyncio.gather(*(one(d) for d in domains))
    return dict(pairs)
