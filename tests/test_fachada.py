"""Anuncio-fachada: criativo generico escondendo o funil real. Sem rede.

Caso real que o usuario viu: pagina "Dr. Selena Moore - Sexologist" rodando
dezenas de "Mini Projector - $4.99" e UM anuncio apontando para o dominio de
intimidade. Os projetores sao isca de revisao; o funil real e a minoria.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.fachada import analisar
from funnel_recon.schema import Ad

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


# Caso Selena Moore: 18 iscas de projetor + 1 funil real de intimidade.
ads = [Ad(ad_id=f"p{i}", body="Mini Projector - $4.99 Free shipping")
       for i in range(18)]
ads.append(Ad(ad_id="real", body="{{product.brand}}",
              display_host="drselenaxmooresexologistintimacy.com",
              full_url="http://drselenaxmooresexologistintimacy.com/"))
r = analisar(ads)
check("detecta a fachada", bool(r), True)
check("conta as iscas", r["iscas"], 18)
check("aponta quem foge", r["fogem"], 1)
check("revela o destino real",
      r["destinos_reais"][0]["host"], "drselenaxmooresexologistintimacy.com")

# Pagina normal (sem isca dominante) nao dispara.
normais = [Ad(ad_id=f"n{i}", body="Guia de saude intima", display_host="x.site")
           for i in range(10)]
check("pagina normal nao vira fachada", analisar(normais), {})

# Poucos anuncios: nao ha padrao para julgar.
check("amostra minima nao dispara", analisar(ads[:2]), {})

# Iscas sem ninguem fugindo: nao ha alvo a revelar.
so_isca = [Ad(ad_id=f"p{i}", body="Smart Watch $9.99 free shipping")
           for i in range(8)]
check("so isca, sem alvo, nao dispara", analisar(so_isca), {})

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("fachada ok")
