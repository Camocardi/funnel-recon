"""Dominio declarado na bio da pagina do anunciante. Sem rede.

A Biblioteca so entrega `link_url`, o destino do anuncio. A pagina tem um
campo "site" proprio apontando para OUTRO dominio -- num caso real, dez
paginas clonadas da mesma persona, cada uma com seu dominio descartavel, e
nenhum deles constava em anuncio nenhum.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.collect.bio import extrair_links

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


def _lphp(destino_codificado, h="AUBt_XYZ"):
    return f'<a href="https://l.facebook.com/l.php?u={destino_codificado}&amp;h={h}">x</a>'


# O caso real, com o `&amp;` que vem do HTML do Meta.
html = _lphp("http%3A%2F%2Fdrselenacfmoore.com%2F")
links = extrair_links(html)
check("acha o destino", [d for d, _ in links], ["http://drselenacfmoore.com/"])
check("guarda a URL assinada", "h=AUBt_XYZ" in links[0][1], True)

# Ruido de boilerplate e link para o proprio Meta nunca sao o site do alvo.
ruido = (_lphp("https%3A%2F%2Fwww.w3.org%2F1999%2Fxhtml")
         + _lphp("https%3A%2F%2Fwww.instagram.com%2Falguem")
         + _lphp("https%3A%2F%2Fpt-br.facebook.com%2Fpolicies"))
check("filtra ruido e dominios do proprio Meta", extrair_links(ruido), [])

# Um dominio por pagina: o mesmo link repetido no HTML nao vira dois achados.
check("nao duplica o mesmo host",
      len(extrair_links(html + html)), 1)

# Subdominio de dominio ignorado tambem sai.
check("subdominio do Meta tambem e ignorado",
      extrair_links(_lphp("https%3A%2F%2Fweb.facebook.com%2Fx")), [])

check("html vazio nao quebra", extrair_links(""), [])
check("html sem link nao quebra", extrair_links("<p>nada</p>"), [])

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("bio de pagina ok")
