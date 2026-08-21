"""Testes da descoberta de origem [3c]. Parte pura, sem rede.

O que se testa: classificar um IP como CDN ou origem, e ranquear candidatos a
origem. A resolucao DNS e o request sao integracao e ficam de fora -- aqui e a
logica que decide "borda x servidor final", que e o veredito que vale.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.origin import classify_ip, is_origin_ip, rank_origin_candidates

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


# --- classificacao ----------------------------------------------------------
check("cloudflare 104.16", classify_ip("104.16.132.229"), "Cloudflare")
check("cloudflare 172.64", classify_ip("172.67.1.1"), "Cloudflare")
check("cloudflare v6", classify_ip("2606:4700::1"), "Cloudflare")
check("fastly", classify_ip("151.101.1.1"), "Fastly")
check("hostinger e origem", classify_ip("77.37.42.234"), "")
check("google dns nao e cdn nosso", classify_ip("8.8.8.8"), "")
check("lixo nao quebra", classify_ip("nao-e-ip"), "")

check("origem = fora de cdn", is_origin_ip("77.37.42.234"), True)
check("cloudflare nao e origem", is_origin_ip("104.16.132.229"), False)
check("vazio nao e origem", is_origin_ip(""), False)

# --- ranqueamento -----------------------------------------------------------
# A dica (mail/cpanel/ftp) sobe na frente: e o padrao classico de origem vazada.
por_host = {
    "alvo.com": ["104.16.1.1"],                 # so cloudflare no apex
    "www.alvo.com": ["104.16.1.2"],             # idem
    "ftp.alvo.com": ["45.9.1.7"],               # DICA -> origem
    "cpanel.alvo.com": ["45.9.1.7"],            # mesma origem, reforca
    "shop.alvo.com": ["88.8.8.8"],              # origem sem dica
}
cands = rank_origin_candidates(por_host, "alvo.com")
check("so ips fora de cdn viram candidato", sorted(c["ip"] for c in cands),
      ["45.9.1.7", "88.8.8.8"])
check("dica vem primeiro", cands[0]["ip"], "45.9.1.7")
check("dica marcada", cands[0]["from_hint"], True)
check("candidato de dica junta os hosts", sorted(cands[0]["hosts"]),
      ["cpanel.alvo.com", "ftp.alvo.com"])
check("origem sem dica vem depois", cands[1]["ip"], "88.8.8.8")
check("origem sem dica nao e marcada", cands[1]["from_hint"], False)

# Apex 100% Cloudflare sem vazamento = nada a caçar.
so_cf = rank_origin_candidates({"alvo.com": ["104.16.1.1"],
                                "www.alvo.com": ["172.67.2.2"]}, "alvo.com")
check("cloudflare puro nao gera candidato", so_cf, [])

# --- CDN reconhecido pelo certificado ---------------------------------------
# Caso real: o "candidato a origem" do thekingmanuscript apresentou cert
# *.b-cdn.net -- era BunnyCDN, outra borda, nao o servidor real.
from funnel_recon.origin import cdn_from_cert_cn
check("bunnycdn pelo cert", cdn_from_cert_cn("*.b-cdn.net"), "BunnyCDN")
check("cloudfront pelo cert", cdn_from_cert_cn("*.cloudfront.net"), "CloudFront")
check("sucuri pelo cert", cdn_from_cert_cn("CN=*.sucuri.net"), "Sucuri")
check("dominio real nao e cdn", cdn_from_cert_cn("loja-real.com"), "")
check("vazio nao quebra", cdn_from_cert_cn(""), "")

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print("origem ok")
