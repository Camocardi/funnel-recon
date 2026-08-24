"""Pulverizacao de criativo: um criativo rodando em muitas copias.

Verificacao de criativo que NAO depende da money page -- so da Biblioteca, que
nunca e cloakeada. Foi o pedido central: mesmo quando o cloaker (The White
Rabbit) bloqueia o destino, isto continua visivel.

O Meta agrupa copias do mesmo criativo por `collation_id` e informa quantas
sao em `collation_count`. Um `collation_count` alto e tecnica de escapar de
revisao: pulveriza-se o criativo em dezenas de ad_ids; derrubam um, seguem os
outros. Confirmado num caso real: um operador com um criativo em 51 copias e
outro em 47.

Nao acusa "bait-and-switch de imagem" (isso exige ver o destino). Acusa o
PADRAO OPERACIONAL de quem escala assim -- e esse padrao vaza na propria
Biblioteca.
"""

from __future__ import annotations


def resumo(ads: list) -> list[dict]:
    """Grupos de criativo pulverizado, do maior para o menor.

    Um grupo por `collation_id`, com quantas copias o Meta contou e quantas a
    coleta viu. Sem collation_id (export antigo, criativo unico) fica de fora.
    """
    grupos: dict[str, dict] = {}
    for a in ads:
        cid = getattr(a, "collation_id", None)
        cc = getattr(a, "collation_count", None)
        if not cid or not cc or cc < 2:
            continue
        g = grupos.setdefault(cid, {
            "collation_id": cid, "declarado": cc, "vistos": 0,
            "hosts": set(), "exemplo": a.ad_id})
        g["vistos"] += 1
        if getattr(a, "display_host", None):
            g["hosts"].add(a.display_host)
    saida = []
    for g in grupos.values():
        g["hosts"] = sorted(g["hosts"])
        saida.append(g)
    return sorted(saida, key=lambda g: -g["declarado"])
