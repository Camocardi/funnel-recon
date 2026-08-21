"""Descoberta de origem: furar o cloaker que roda na BORDA, nao no servidor.

Ha dois lugares onde um cloaker decide: no servidor de origem (PHP/plugin, como
o caso Hostinger/LiteSpeed que nos travou) ou na BORDA -- um Worker do
Cloudflare, uma regra de CDN. Contra origem nao ha bypass de rede: a decisao e
tomada no unico lugar por onde a resposta sai. Contra borda, ha: o servidor
real atras do CDN muitas vezes serve a money page SEM protecao nenhuma, porque
o dono confiou a filtragem inteira ao edge. Baste falar com a origem direto.

O problema e achar o IP de origem quando o dominio so aponta para o CDN. O
caminho mais barato e barulho zero: IRMAOS mal configurados. O operador poe
`alvo.com` atras do Cloudflare mas deixa `mail.alvo.com`, `cpanel.alvo.com`,
`ftp.alvo.com` apontando direto para o servidor -- servicos que nao passam pelo
proxy. Um desses entrega o IP real, e ai um GET no IP com `Host: alvo.com` pula
a borda inteira.

Isto NAO e forca bruta nem exploit: e ler A records publicos e comparar com
faixas de CDN conhecidas. O que nao resolve, nao resolve -- e o relatorio diz
qual dos dois cloakers e, que ja vale por si: "esta na borda, tente a origem"
x "esta no servidor, so proxy no pais-alvo".
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

# Faixas do Cloudflare (o CDN dominante nessas operacoes; publicadas em
# cloudflare.com/ips). Um IP aqui e do proxy, nao do servidor real. A lista e
# estavel; se o Cloudflare adicionar faixa, o pior caso e classificar uma
# origem nova como "desconhecida" -- nunca o contrario.
CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CLOUDFLARE_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# Outros CDNs comuns -- so o suficiente para nao chamar de origem um IP que
# tambem e proxy. Faixa parcial de proposito: a duvida vira "desconhecido",
# que o relatorio trata como candidato a origem a conferir, nao como fato.
OTHER_CDN_V4 = {
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "Sucuri": ["192.124.249.0/24", "185.93.228.0/22"],
    "Akamai": ["23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10"],
}

# Subdominios que classicamente escapam do proxy e apontam para a origem.
# Servico de e-mail, painel e FTP raramente entram no Cloudflare -- eles
# precisam do IP real.
ORIGIN_HINTS = ("mail", "webmail", "cpanel", "whm", "ftp", "sftp", "direct",
                "origin", "server", "host", "smtp", "mx", "ns1", "ns2",
                "dev", "staging", "test", "old", "api", "cdn-origin")

_CF = [ipaddress.ip_network(c) for c in CLOUDFLARE_V4 + CLOUDFLARE_V6]
_OTHER = {name: [ipaddress.ip_network(c) for c in cidrs]
          for name, cidrs in OTHER_CDN_V4.items()}


# CDN reconhecido pelo CN do certificado. Quando o teste manual de origem
# conecta, o certificado entrega quem e o dono do IP -- e um `*.b-cdn.net`
# prova que aquele "candidato a origem" era so mais uma camada de CDN
# (BunnyCDN), nao o servidor real. Caso real: thekingmanuscript tinha
# Cloudflare no apex e BunnyCDN no www; nenhuma origem vazou.
CDN_CERT_CN = {
    "b-cdn.net": "BunnyCDN",
    "cloudfront.net": "CloudFront",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "cloudflare.com": "Cloudflare",
    "cloudflaressl.com": "Cloudflare",
    "akamai": "Akamai",
    "akamaiedge.net": "Akamai",
    "edgekey.net": "Akamai",
    "sucuri.net": "Sucuri",
    "stackpathcdn.com": "StackPath",
    "cdn77": "CDN77",
    "gcorelabs": "Gcore",
    "gcdn.co": "Gcore",
}


def cdn_from_cert_cn(cn: str) -> str:
    """Nome do CDN dono de um certificado, ou "" se nao for CDN conhecido.

    Passe o CN/SAN que o `curl -v` mostra (ex.: `*.b-cdn.net`). Se casar, o
    IP testado NAO e a origem -- e outra borda, e a caca continua.
    """
    c = (cn or "").lower().lstrip("*.").strip()
    for marca, nome in CDN_CERT_CN.items():
        if marca in c:
            return nome
    return ""


def classify_ip(ip: str) -> str:
    """"Cloudflare", nome de outro CDN, ou "" (provavel origem)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if any(addr in net for net in _CF):
        return "Cloudflare"
    for name, nets in _OTHER.items():
        if any(addr in net for net in nets):
            return name
    return ""


def is_origin_ip(ip: str) -> bool:
    """IP que NAO e de CDN conhecido -- candidato a servidor real."""
    return bool(ip) and not classify_ip(ip)


async def resolve(host: str) -> list[str]:
    """A/AAAA de um host. Lista vazia em vez de excecao: host morto e rotina."""
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def rank_origin_candidates(por_host: dict[str, list[str]], apex: str) -> list[dict]:
    """{host: [ip]} -> candidatos a origem, do mais promissor ao menos.

    Prioridade:
      1. IP fora de CDN que aparece num subdominio-dica (mail/cpanel/ftp...):
         e o padrao classico de origem vazada.
      2. Qualquer IP fora de CDN visto em algum host da operacao.
    Um IP so entra uma vez, com a lista de onde apareceu -- se o mesmo IP surge
    no apex E no mail, a confianca sobe.
    """
    por_ip: dict[str, dict] = {}
    for host, ips in por_host.items():
        rotulo = host.split(".")[0] if host != apex else "@"
        dica = any(host.split(".")[0] == h for h in ORIGIN_HINTS)
        for ip in ips:
            if not is_origin_ip(ip):
                continue
            slot = por_ip.setdefault(ip, {"ip": ip, "hosts": [], "from_hint": False})
            if host not in slot["hosts"]:
                slot["hosts"].append(host)
            slot["from_hint"] = slot["from_hint"] or dica
    return sorted(por_ip.values(),
                  key=lambda d: (not d["from_hint"], -len(d["hosts"]), d["ip"]))


async def discover(apex: str, subdomains: list[str]) -> dict:
    """Radiografia de origem de um dominio.

    `apex` e o registravel; `subdomains` sai do crt.sh (estagio [2]). Resolve
    todos, classifica cada IP e devolve o veredito: esta na borda (ha origem a
    tentar) ou nao da para separar (provavel cloaking no servidor).
    """
    alvos = sorted({apex, f"www.{apex}", *subdomains})
    # Acrescenta as dicas classicas mesmo que o crt.sh nao as tenha listado:
    # custam uma resolucao cada e sao onde a origem mais vaza.
    alvos = sorted(set(alvos) | {f"{h}.{apex}" for h in ORIGIN_HINTS})

    resolucoes = await asyncio.gather(*(resolve(h) for h in alvos))
    por_host = {h: ips for h, ips in zip(alvos, resolucoes) if ips}

    todos_ips = {ip for ips in por_host.values() for ip in ips}
    cdn = {ip: classify_ip(ip) for ip in todos_ips if classify_ip(ip)}
    candidatos = rank_origin_candidates(por_host, apex)

    apex_ips = por_host.get(apex, [])
    apex_atras_de_cdn = any(classify_ip(ip) for ip in apex_ips)

    return {
        "apex": apex,
        "hosts_resolvidos": len(por_host),
        "cdn": sorted(set(cdn.values())),
        "apex_atras_de_cdn": apex_atras_de_cdn,
        "origin_candidates": candidatos,
        "por_host": por_host,
    }
