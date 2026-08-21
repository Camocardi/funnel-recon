"""Testes do comparador de criativo [5c]. Sem rede.

Este arquivo REFAZ a medicao que fixou SAME_MAX e DIFF_MIN em creative.py, em
vez de so checar os valores. A diferenca importa: se um dia a DCT, o resize ou
a versao do Pillow mudarem o comportamento do hash, um teste de valor fixo
passaria igual e os limiares ficariam calibrados para um mundo que nao existe
mais. Aqui a medicao roda de novo a cada execucao e falha se a separacao entre
"mesma imagem" e "imagem diferente" encolher.
"""

import random
import sys
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image, ImageDraw, ImageFilter

from funnel_recon import db
from funnel_recon.collect.normalize import normalize_row
from funnel_recon.creative import (DIFF_MIN, SAME_MAX, hamming, hashable_asset,
                                   nearest, phash, temporal_diffs, verdict)
from funnel_recon.orchestrate import _escolher_criativos

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


def check_max(name, got, teto):
    if got is None or got > teto:
        failures.append(f"{name}: {got} passou do teto {teto}")


def criativo(seed: int, w: int = 1080, h: int = 1080) -> Image.Image:
    """Imagem sintetica no espirito de um criativo de anuncio.

    Sintetica de proposito: um fixture binario de criativo real seria pesado,
    envelheceria e traria material de terceiro pro repositorio.
    """
    r = random.Random(seed)
    img = Image.new("RGB", (w, h), (r.randrange(200, 256),
                                    r.randrange(200, 256),
                                    r.randrange(200, 256)))
    d = ImageDraw.Draw(img)
    for _ in range(6):
        x, y = r.randrange(0, w - 200), r.randrange(0, h - 200)
        d.rectangle((x, y, x + r.randrange(80, 300), y + r.randrange(80, 300)),
                    fill=(r.randrange(256), r.randrange(256), r.randrange(256)))
    d.ellipse((w * 0.2, h * 0.2, w * 0.8, h * 0.8), outline=(0, 0, 0), width=14)
    d.text((40, h - 60), f"OFERTA {seed}", fill=(0, 0, 0))
    return img


def raw(img: Image.Image, fmt: str = "PNG", **kw) -> bytes:
    buf = BytesIO()
    img.save(buf, fmt, **kw)
    return buf.getvalue()


orig = criativo(1)
h0 = phash(raw(orig))
check("hash tem 64 bits em hex", len(h0), 16)
check("hash e estavel", phash(raw(orig)), h0)

# --- o que um CDN faz com a imagem NAO pode contar como criativo trocado -----
# Este e o motivo de existir pHash aqui: sha256 daria "diferente" em todos.
mesma = {
    "JPEG q90": raw(orig, "JPEG", quality=90),
    "JPEG q25": raw(orig, "JPEG", quality=25),
    "resize 1080->320": raw(orig.resize((320, 320))),
    "resize + JPEG q60": raw(orig.resize((600, 600)), "JPEG", quality=60),
    "WEBP q70": raw(orig, "WEBP", quality=70),
    "blur leve": raw(orig.filter(ImageFilter.GaussianBlur(1.4))),
}
marca = orig.copy()
ImageDraw.Draw(marca).rectangle((0, 0, 300, 70), fill=(255, 255, 255))
mesma["marca d'agua"] = raw(marca)
mesma["crop de 3%"] = raw(orig.crop((30, 30, 1050, 1050)).resize((1080, 1080)))

for nome, data in mesma.items():
    d = hamming(h0, phash(data))
    check_max(f"mesma imagem / {nome}", d, SAME_MAX)
    check(f"veredito de {nome}", verdict(d), "igual")

# --- criativo trocado tem que cair do outro lado da faixa -------------------
distintos = [hamming(h0, phash(raw(criativo(s)))) for s in range(2, 12)]
if min(distintos) < DIFF_MIN:
    failures.append(f"criativos distintos chegaram a {min(distintos)}, "
                    f"abaixo de DIFF_MIN={DIFF_MIN}")
check("todo criativo distinto e divergente",
      {verdict(d) for d in distintos}, {"divergente"})

# A separacao entre os dois grupos e o que sustenta os limiares. Se encolher,
# e a medicao que precisa ser refeita -- nao os limiares apertados no olho.
pior_igual = max(hamming(h0, phash(d)) for d in mesma.values())
if min(distintos) - pior_igual < 8:
    failures.append(f"folga de so {min(distintos) - pior_igual} bits entre "
                    f"mesma imagem ({pior_igual}) e imagem diferente ({min(distintos)})")

# --- degradacao: nada disto pode levantar excecao ---------------------------
check("bytes que nao sao imagem", phash(b"isto nao e uma imagem"), None)
check("bytes vazios", phash(b""), None)
check("hash faltando de um lado", hamming(h0, None), None)
check("hash invalido nao explode", hamming(h0, "zzzz"), None)
check("sem dado tem veredito proprio", verdict(None), "sem_dado")

# --- escolha do asset -------------------------------------------------------
# Anuncio de video: o hasheavel e a thumbnail, nao o .mp4.
check("prefere a imagem ao video", hashable_asset(
    ["https://cdn.fb/v.mp4?x=1", "https://cdn.fb/thumb.jpg?stp=abc"]),
    "https://cdn.fb/thumb.jpg?stp=abc")
check("query string nao confunde a extensao", hashable_asset(
    ["https://cdn.fb/a.png?_nc_cat=1&oh=2"]), "https://cdn.fb/a.png?_nc_cat=1&oh=2")
check("so video nao tem o que hashear", hashable_asset(["https://cdn.fb/v.mp4"]), "")
check("lista vazia", hashable_asset([]), "")
check("lixo na lista", hashable_asset([None, 42, "nao-e-url"]), "")

# --- comparacao contra o conjunto da pagina ---------------------------------
# O payload do feed nem sempre traz o id do anuncio, mas traz a pagina. Se o
# criativo entregue nao se parece com NENHUM que a pagina publicou, o que a
# Biblioteca mostra nao e o que esta no ar.
lib = [phash(raw(criativo(s))) for s in (2, 3, 4)]
check("criativo do feed reconhecido", nearest(lib[1], lib)[0], 0)
check("comparou contra os tres", nearest(lib[1], lib)[1], 3)
d, n = nearest(h0, lib)
check("criativo estranho a pagina e divergente", verdict(d), "divergente")
check("sem biblioteca nao ha comparacao", nearest(h0, []), (None, 0))
check("hash invalido na biblioteca e ignorado", nearest(lib[0], [None, "", lib[0]]),
      (0, 1))

# --- bait-and-switch sem feed: o mesmo anuncio em duas coletas --------------
h_igual = phash(raw(orig, "JPEG", quality=40))   # so recomprimido
h_outro = phash(raw(criativo(9)))                # criativo trocado

diffs = {d.ad_id: d for d in temporal_diffs(
    {"trocou": h0, "manteve": h0, "sumiu": h0},
    {"trocou": h_outro, "manteve": h_igual, "novo": h0},
)}
check("so compara quem existe dos dois lados", sorted(diffs), ["manteve", "trocou"])
check("troca de criativo detectada", diffs["trocou"].is_cloaked, True)
check("recompressao nao e troca", diffs["manteve"].is_cloaked, False)
check("guarda a versao antiga", diffs["trocou"].phash_lib, h0)
check("guarda a versao nova", diffs["trocou"].phash_feed, h_outro)
check("marcado como comparacao no tempo", diffs["trocou"].kind, "tempo")
check("sem historico nao inventa diff", temporal_diffs({}, {"x": h0}), [])

# --- quem ganha o download do criativo --------------------------------------
# Anuncio com hash gravado vem primeiro: so ele permite comparar no tempo.
frota = [normalize_row({"ad_id": f"a{i}", "url": f"https://x.shop/p{i}", "host": "x.shop"})
         for i in range(10)]
frota.append(normalize_row({"ad_id": "alvo", "url": "https://x.shop/l/h?fbclid=Iw",
                            "host": "x.shop"}))
escolha = _escolher_criativos(frota, {"a7", "a9"}, limite=4)
check("historico primeiro", [a.ad_id for a in escolha[:2]], ["a7", "a9"])
check("depois a fila do probe", escolha[2].ad_id, "alvo")
check("respeita o limite", len(escolha), 4)
check("sem historico ainda escolhe", len(_escolher_criativos(frota, set(), limite=3)), 3)
check("nao duplica", len({a.ad_id for a in _escolher_criativos(frota, {"a1"}, limite=11)}), 11)

# --- ida e volta no banco ---------------------------------------------------
import tempfile
with tempfile.TemporaryDirectory() as tmp:
    caminho = Path(tmp) / "t.db"
    conn = db.connect(caminho)
    a = normalize_row({"ad_id": "gravado", "url": "https://x.shop/p", "host": "x.shop"})
    a.creative_phash = h0
    db.save_ad(conn, a)
    db.save_ad(conn, normalize_row({"ad_id": "sem_hash", "url": "https://x.shop/p",
                                    "host": "x.shop"}))
    check("le o hash gravado", db.creative_hashes(conn, ["gravado", "sem_hash"]), {"gravado": h0})
    check("id desconhecido nao aparece", db.creative_hashes(conn, ["nunca_visto"]), {})
    check("lista vazia nao consulta", db.creative_hashes(conn, []), {})
    db.save_creative_diff(conn, temporal_diffs({"gravado": h0}, {"gravado": h_outro})[0])
    linha = conn.execute("SELECT kind, is_cloaked, distance FROM creative_diff").fetchone()
    check("diff persistido com o tipo", linha["kind"], "tempo")
    check("divergencia persistida", linha["is_cloaked"], 1)

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print(f"criativo ok — mesma imagem ate {pior_igual} bits, "
      f"criativo trocado a partir de {min(distintos)}")
