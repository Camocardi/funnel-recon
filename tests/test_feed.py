"""Testes do coletor de feed e da comparacao Biblioteca x entrega. Sem rede.

O download de asset e substituido por um duble: o que precisa ser testado aqui
e o RECONHECIMENTO do post patrocinado e o casamento com a pagina certa, nao o
httpx -- esse caminho ja e exercitado em test_creative.py.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon import creative
from funnel_recon.collect.feed import parse_sponsored
from funnel_recon.report import render_feed

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


def contem(name, texto, trecho):
    if trecho.lower() not in texto.lower():
        failures.append(f"{name}: nao achei {trecho!r} no relatorio")


IMG = "https://scontent.xx.fbcdn.net/v/t45/123_n.jpg?stp=abc"
IMG2 = "https://scontent.xx.fbcdn.net/v/t45/999_n.jpg?stp=xyz"

# --- reconhecimento de patrocinado ------------------------------------------
# Duas evidencias independentes, porque o Meta renomeia campo mas e obrigado a
# mostrar o rotulo "Patrocinado" na tela.
por_flag = json.dumps({"feed": [{
    "is_sponsored": True, "page_id": "555", "page_name": "Loja X",
    "image_url": IMG, "link_url": "https://alvo.shop/l/a?fbclid=Iw"}]})
por_rotulo = json.dumps({"feed": [{
    "sponsored_label": {"text": "Patrocinado"}, "page_id": "777",
    "page_name": "Loja Y", "original_image_url": IMG2}]})

a = parse_sponsored(por_flag)
check("achou pela flag", len(a), 1)
check("page_id extraido", a[0]["page_id"], "555")
check("midia extraida", a[0]["media"], [IMG])
check("url desembrulhada", a[0]["url"], "https://alvo.shop/l/a?fbclid=Iw")
check("achou pelo rotulo em texto", len(parse_sponsored(por_rotulo)), 1)

# Post organico NAO pode entrar: contaminaria a comparacao com criativo que
# nem e anuncio.
organico = json.dumps({"feed": [{"page_id": "555", "image_url": IMG,
                                 "message": "bom dia"}]})
check("organico ignorado", parse_sponsored(organico), [])
# Patrocinado sem midia nao tem o que comparar.
check("patrocinado sem midia ignorado", parse_sponsored(json.dumps(
    {"feed": [{"is_sponsored": True, "page_id": "555"}]})), [])
check("lixo nao quebra", parse_sponsored("nao e json"), [])
check("vazio", parse_sponsored(""), [])
# `sponsored: False` e uma flag presente e negativa -- nao pode contar.
check("flag negativa nao conta", parse_sponsored(json.dumps(
    {"feed": [{"is_sponsored": False, "page_id": "5", "image_url": IMG}]})), [])

# O mesmo post chega em varios payloads; a midia identifica quando nao ha id.
check("dedup entre payloads", len(parse_sponsored(por_flag + "\n" + por_flag)), 1)

# --- comparacao com a Biblioteca --------------------------------------------
# Duble: devolve um hash conhecido por chave, sem tocar na rede.
IGUAL = "ffffffffffffffff"
PERTO = "ffffffffffffff00"   # 8 bits de diferenca -> mesma imagem
LONGE = "0000000000000000"   # 64 bits -> criativo trocado

posts = [
    {"page_id": "555", "ad_id": "ad_confere", "media": [IMG]},
    {"page_id": "555", "ad_id": "ad_trocado", "media": [IMG2]},
    {"page_id": "999", "ad_id": "ad_de_outra_pagina", "media": [IMG]},
    {"page_id": "555", "ad_id": "ad_sem_hash", "media": [IMG]},
]
FALSOS = {"ad_confere": PERTO, "ad_trocado": LONGE, "ad_de_outra_pagina": LONGE}


async def hash_falso(items, concurrency=6, on_done=None):
    return {chave: FALSOS[chave] for chave, _ in items if chave in FALSOS}


real, creative.hash_many = creative.hash_many, hash_falso
try:
    diffs = asyncio.run(creative.feed_diffs(posts, {"555": [IGUAL]}))
finally:
    creative.hash_many = real

por_id = {d.ad_id: d for d in diffs}
check("pagina de fora nao entra", "ad_de_outra_pagina" in por_id, False)
check("sem hash nao vira diff", "ad_sem_hash" in por_id, False)
check("comparou os dois da pagina", sorted(por_id), ["ad_confere", "ad_trocado"])
check("criativo que confere", por_id["ad_confere"].is_cloaked, False)
check("criativo trocado", por_id["ad_trocado"].is_cloaked, True)
check("distancia registrada", por_id["ad_trocado"].distance, 64)
check("guarda o aprovado mais parecido", por_id["ad_trocado"].phash_lib, IGUAL)
check("marcado como comparacao de feed", por_id["ad_confere"].kind, "feed")
check("sem biblioteca nao compara", asyncio.run(creative.feed_diffs(posts, {})), [])

# --- o relatorio nao pode confundir "nada visto" com "nada errado" ----------
vazio = render_feed([], [], {"555": [IGUAL]})
contem("feed vazio explica que nao houve medicao", vazio, "nao houve medicao")

so_outros = render_feed([{"page_id": "999", "page_name": "Outra"}], [], {"555": [IGUAL]})
contem("alvo ausente e avisado", so_outros, "NAO E RESULTADO NEGATIVO")
contem("diz como aumentar a chance", so_outros, "interaja com conteudo do nicho")

com_troca = render_feed(posts, diffs, {"555": [IGUAL]})
contem("divergencia aparece", com_troca, "DIVERGEM")
contem("mostra o anuncio trocado", com_troca, "ad_trocado")
contem("nao acusa sozinho", com_troca, "criativo dinamico")

tudo_ok = render_feed(posts[:1], [d for d in diffs if d.is_cloaked is False],
                      {"555": [IGUAL]})
contem("confere e dito com escopo", tudo_ok, "continua sem medicao")

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print("feed ok")
