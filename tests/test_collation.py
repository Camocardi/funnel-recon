"""Criativo pulverizado em copias. Sem rede.

Verificacao de criativo que nao depende da money page: o Meta agrupa copias do
mesmo criativo por collation_id e conta em collation_count. Caso real: um
operador com um criativo em 51 copias e outro em 47.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.collation import resumo
from funnel_recon.schema import Ad

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


def ad(ad_id, cid, cc, host="alvo.shop", ativo=True, ini=None, fim=None):
    return Ad(ad_id=ad_id, collation_id=cid, collation_count=cc, display_host=host,
              is_active=ativo, start_date=ini, end_date=fim)


ads = [
    ad("a1", "C51", 51), ad("a2", "C51", 51), ad("a3", "C51", 51),
    ad("b1", "C47", 47), ad("b2", "C47", 47),
    ad("s1", "C1", 1),          # copia unica: nao e pulverizacao
    ad("n1", None, None),        # sem collation: export antigo
]
r = resumo(ads)
check("dois grupos pulverizados", len(r), 2)
check("ordenado do maior", [g["declarado"] for g in r], [51, 47])
check("conta as copias vistas", r[0]["vistos"], 3)
check("declarado vem do Meta", r[0]["declarado"], 51)
check("host agrupado", r[0]["hosts"], ["alvo.shop"])
check("copia unica fica de fora",
      all(g["collation_id"] != "C1" for g in r), True)
check("sem collation nao quebra",
      resumo([ad("x", None, None)]), [])

# --- ativo/inativo e datas por grupo (o pedido: "40 copias mas inativo") ----
grupos = resumo([
    ad("m1", "MORTO", 40, ativo=False, ini="2026-07-01", fim="2026-07-20"),
    ad("m2", "MORTO", 40, ativo=False, ini="2026-07-05", fim="2026-07-25"),
    ad("v1", "VIVO", 30, ativo=True, ini="2026-08-20", fim="2026-08-24"),
])
morto = next(g for g in grupos if g["collation_id"] == "MORTO")
vivo = next(g for g in grupos if g["collation_id"] == "VIVO")
check("grupo so inativo e sinalizado", morto["so_inativos"], True)
check("conta inativos", morto["inativos"], 2)
check("faixa de datas do grupo morto", (morto["inicio"], morto["fim"]),
      ("2026-07-01", "2026-07-25"))
check("grupo com ativo nao e so_inativos", vivo["so_inativos"], False)
check("conta ativos", vivo["ativos"], 1)

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("collation ok")
