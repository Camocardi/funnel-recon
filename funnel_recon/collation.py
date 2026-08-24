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


def representantes(ads: list, limite: int = 12) -> list:
    """UM anuncio por grupo de criativo, dos mais escalados, ate `limite`.

    Cada grupo de collation e um criativo em N copias -- salvar as N e
    desperdicio de espaco e de olho. Guarda-se um representante de cada, e so
    dos grupos maiores: mais copias = criativo mais validado, que e o que
    interessa. Fora de grupo (collation_count 1 ou ausente) nao entra: nao ha
    o que "ver escalado" ali.
    """
    por_grupo: dict[str, list] = {}
    for a in ads:
        cid = getattr(a, "collation_id", None)
        cc = getattr(a, "collation_count", None) or 0
        if cid and cc >= 2:
            por_grupo.setdefault(cid, []).append(a)
    ordenados = sorted(por_grupo.values(),
                       key=lambda g: -(getattr(g[0], "collation_count", 0) or 0))
    return [g[0] for g in ordenados[:limite]]


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
            "ativos": 0, "inativos": 0, "hosts": set(),
            "inicio": None, "fim": None, "exemplo": a.ad_id})
        g["vistos"] += 1
        if getattr(a, "is_active", None) is True:
            g["ativos"] += 1
        elif getattr(a, "is_active", None) is False:
            g["inativos"] += 1
        if getattr(a, "display_host", None):
            g["hosts"].add(a.display_host)
        # faixa de datas do grupo: quando comecou e quando o ultimo saiu do ar.
        ini = getattr(a, "start_date", None)
        fim = getattr(a, "end_date", None)
        if ini and (g["inicio"] is None or ini < g["inicio"]):
            g["inicio"] = ini
        if fim and (g["fim"] is None or fim > g["fim"]):
            g["fim"] = fim
    saida = []
    for g in grupos.values():
        g["hosts"] = sorted(g["hosts"])
        # so_inativos: o criativo foi escalado mas ja saiu todo do ar -- rodou
        # e morreu. Diferente de ativo, que e o que esta convertendo agora.
        g["so_inativos"] = g["ativos"] == 0 and g["inativos"] > 0
        saida.append(g)
    return sorted(saida, key=lambda g: -g["declarado"])
