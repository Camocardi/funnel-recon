"""RDAP + DNS -> idade do dominio e para onde ele aponta.

POR QUE RDAP E NAO WHOIS: a ICANN aposentou o WHOIS em 01/05/2026 na
transicao para RDAP. O binario `whois` ainda responde, mas para muitos TLDs
devolve o registro do PROPRIO TLD em vez do dominio -- em teste real,
`whois cantinhoprivado.shop` retornou "created: 2016-05-05", que e a data de
criacao do registro .shop pela GMO, nao do dominio. Idade errada e pior que
idade ausente: viraria um "dominio antigo, provavelmente legitimo" falso.

RDAP e JSON estruturado, sem parsing de texto livre. `whois` fica so como
fallback, e com guarda contra registro de TLD.

Sinal central (secao 3.1): a IDADE. Dominio de semanas com anuncio ativo e
descartavel por construcao -- evidencia de operacao de cloaking.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from ..schema import ScanResult
from .http import client

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
# Calibrado com o caso real: os dois dominios da investigacao tinham 131 e 156
# dias e eram infra descartavel. Um corte em 120 os teria deixado passar.
YOUNG_DAYS = 180
VERY_YOUNG_DAYS = 30

# Fallback de whois: so aceitamos a data se a resposta for do DOMINIO.
# Registro de TLD se denuncia por linhas como "organisation:" sem "Domain Name:".
WHOIS_CREATED = re.compile(
    r"^\s*(?:creation date|created|registered on|registration time)\s*:\s*(.+)$", re.I | re.M
)
WHOIS_IS_DOMAIN = re.compile(r"^\s*domain name\s*:", re.I | re.M)


def _parse_iso(raw: str | None):
    if not raw:
        return None
    s = raw.strip().rstrip(".").replace("Z", "+00:00")
    for attempt in (s, s[:19], s[:10]):
        try:
            d = datetime.fromisoformat(attempt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(s[:len(datetime.now().strftime(fmt))], fmt).replace(
                tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


async def _sh(cmd: list[str], timeout: float = 15.0) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except FileNotFoundError:
        return ""
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return ""
    return out.decode("utf-8", "replace")


async def _rdap(domain: str) -> dict:
    async with client(headers={"Accept": "application/rdap+json"}) as c:
        r = await c.get(RDAP_BOOTSTRAP.format(domain=domain))
        if r.status_code == 404:
            return {"_notfound": True}
        r.raise_for_status()
        return r.json()


def _registrar(data: dict) -> str | None:
    for ent in data.get("entities") or []:
        if "registrar" not in (ent.get("roles") or []):
            continue
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                return str(item[3])
        if ent.get("handle"):
            return str(ent["handle"])
    return None


async def run(domain: str) -> ScanResult:
    rdap_data: dict = {}
    rdap_err = None
    try:
        rdap_data = await _rdap(domain)
    except Exception as e:
        rdap_err = f"{type(e).__name__}: {e}"

    a_rec, ns_rec, mx_rec = await asyncio.gather(
        _sh(["dig", "+short", domain, "A"]),
        _sh(["dig", "+short", domain, "NS"]),
        _sh(["dig", "+short", domain, "MX"]),
    )

    signals: list[str] = []
    ips = [l.strip() for l in a_rec.splitlines() if l.strip() and not l.startswith(";")]
    nss = sorted({l.strip().rstrip(".").lower() for l in ns_rec.splitlines() if l.strip()})
    mxs = [l.strip() for l in mx_rec.splitlines() if l.strip()]

    if not ips:
        signals.append("no_dns_a_record")
    signals += [f"ip:{i}" for i in ips]
    signals += [f"ns:{n}" for n in nss]
    if nss:
        # O par de NS e assinatura de CONTA no Cloudflare (e em varios DNS
        # gerenciados): dominios com o mesmo par saem da mesma conta. E o
        # pivo mais barato para achar os outros dominios do mesmo operador.
        signals.append("ns_pair:" + ",".join(nss))
    if any("cloudflare" in n for n in nss):
        signals.append("behind_cloudflare")
    if not mxs:
        signals.append("no_mx_record")

    created_raw, source_used, registrar, statuses = None, None, None, []

    if rdap_data.get("_notfound"):
        signals.append("rdap_not_found")
    elif rdap_data:
        for ev in rdap_data.get("events") or []:
            if ev.get("eventAction") == "registration":
                created_raw, source_used = ev.get("eventDate"), "rdap"
            elif ev.get("eventAction") == "last changed":
                signals.append(f"last_changed:{str(ev.get('eventDate'))[:10]}")
        registrar = _registrar(rdap_data)
        statuses = rdap_data.get("status") or []
        for st in statuses:
            signals.append(f"status:{st}")
        if not rdap_data.get("nameservers") and not ips:
            signals.append("no_nameservers")

    if not created_raw:
        whois_txt = await _sh(["whois", domain])
        m = WHOIS_CREATED.search(whois_txt or "")
        # Guarda: sem "Domain Name:" a resposta e do registro do TLD, nao do
        # dominio. Descartamos em vez de reportar idade falsa.
        if m and WHOIS_IS_DOMAIN.search(whois_txt or ""):
            created_raw, source_used = m.group(1).strip(), "whois"
        elif m:
            signals.append("whois_returned_tld_record")
        elif not (whois_txt or "").strip():
            signals.append("whois_unavailable")

    age_days = None
    created = _parse_iso(created_raw)
    if created:
        age_days = (datetime.now(timezone.utc) - created).days
        signals.append(f"domain_created:{created.date()}")
        signals.append(f"domain_age_days:{age_days}")
        if age_days < VERY_YOUNG_DAYS:
            signals.append(f"very_young_domain:{age_days}d")
        if age_days < YOUNG_DAYS:
            signals.append(f"young_domain:{age_days}d")
    else:
        signals.append("domain_age_unknown")

    if registrar:
        signals.append(f"registrar:{registrar}")

    status = (f"idade {age_days}d (via {source_used})" if age_days is not None
              else "idade desconhecida")

    return ScanResult(
        target=domain, stage="osint", source="rdap",
        status=status, verdict="unknown", signals=signals,
        error=rdap_err if not rdap_data else None,
        raw={"ips": ips, "ns": nss, "mx": mxs, "created": created_raw,
             "created_source": source_used, "age_days": age_days,
             "registrar": registrar, "rdap_status": statuses},
    )
