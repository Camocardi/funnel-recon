"""crt.sh -> subdominios via Certificate Transparency.

Secao 3.1: crt.sh caiu com 502 durante a investigacao. Por isso duas coisas:
usar `?output=json` (mais estavel que a UI) e ter CertSpotter como fallback
automatico. Uma fonte fora nao pode derrubar a resposta.

Valor: um subdominio revelador (`pay.`, `checkout.`, `bot.`) as vezes entrega
o funil sem precisar sondar nada.
"""

from __future__ import annotations

from ..schema import ScanResult
from ..signals import apex_domain, is_meta_host
from .http import client

CRTSH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"

# Subdominios que sugerem infraestrutura de funil, nao loja generica.
REVEALING = ("pay", "checkout", "cart", "bot", "tg", "telegram", "wa", "zap",
             "go", "link", "track", "click", "api", "admin", "painel", "app")


def _clean(names, apex: str) -> set[str]:
    out = set()
    for n in names or []:
        n = (n or "").strip().lower().lstrip("*.").rstrip(".")
        if not n or is_meta_host(n):
            continue
        if n == apex or n.endswith("." + apex):
            out.add(n)
    return out


async def _try_crtsh(domain: str) -> tuple[set[str], list[dict]]:
    async with client() as c:
        r = await c.get(CRTSH, params={"q": f"%.{domain}", "output": "json"})
        r.raise_for_status()
        rows = r.json()
    names: set[str] = set()
    for row in rows:
        for n in (row.get("name_value") or "").splitlines():
            names |= _clean([n], domain)
        names |= _clean([row.get("common_name")], domain)
    return names, rows[:50]


async def _try_certspotter(domain: str) -> tuple[set[str], list[dict]]:
    async with client() as c:
        r = await c.get(CERTSPOTTER, params={
            "domain": domain, "include_subdomains": "true", "expand": "dns_names",
        })
        r.raise_for_status()
        rows = r.json()
    names: set[str] = set()
    for row in rows:
        names |= _clean(row.get("dns_names"), domain)
    return names, rows[:50]


async def run(domain: str) -> ScanResult:
    """Enumera subdominios do APEX, nao do host recebido.

    O alvo que chega aqui costuma ja ser um subdominio -- o anuncio aponta
    para `massagem.alvo.site`, nao para `alvo.site`. Consultar o host como
    veio pede `%.massagem.alvo.site` ao Certificate Transparency, que devolve
    ele mesmo e nada mais. Na primeira analise real foi exatamente isso: o
    `app.` e o `track.` da mesma operacao existiam e ficaram invisiveis.

    Subindo para o apex, os IRMAOS aparecem -- e irmao de subdominio e o pivo
    mais barato que existe para achar o resto da operacao.
    """
    apex = apex_domain(domain)
    used, names, rows, err = "crtsh", set(), [], None
    try:
        names, rows = await _try_crtsh(apex)
    except Exception as e:
        first = f"crtsh: {type(e).__name__}: {e}"
        try:
            used = "certspotter"
            names, rows = await _try_certspotter(apex)
        except Exception as e2:
            return ScanResult(
                target=domain, stage="osint", source="crtsh",
                verdict="error", error=f"{first} | certspotter: {type(e2).__name__}: {e2}",
            )

    subs = sorted(names)
    signals = [f"subdomain:{s}" for s in subs]
    signals += [f"revealing_subdomain:{s}" for s in subs
                if s != domain and s.split(".")[0] in REVEALING]
    # Irmao = existe no apex e NAO e o host que os anuncios usam. E a lista
    # que interessa: infraestrutura da operacao que nenhum anuncio revelou.
    irmaos = [s for s in subs if s != domain and s != apex]
    signals += [f"sibling_subdomain:{s}" for s in irmaos]
    if apex != domain:
        signals.append(f"apex:{apex}")
    return ScanResult(
        target=domain, stage="osint", source=used,
        status=f"{len(subs)} subdominios em {apex}",
        verdict="unknown" if subs else "white",
        signals=signals,
        raw={"provider": used, "apex": apex, "subdomains": subs,
             "siblings": irmaos, "sample": rows},
        error=err,
    )
