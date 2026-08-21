"""Testes da radiografia de pagina [5c]. Sem rede.

O nucleo e a pergunta que travou uma investigacao real: a VSL que a pessoa com
acesso ve e a mesma que ja temos, ou uma nova? Quem responde e o par
(video, produto) -- o video diferencia a VSL, o produto identifica a oferta.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.page import compare, fingerprint

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


# Os tres identificadores do converteai/VTurb sao coisas diferentes, e
# confundi-los ja custou um diagnostico errado: a CONTA e a mesma em todas as
# VSLs do operador, entao comparar por ela responde "mesma VSL" para dois
# videos diferentes do mesmo dono. O layout real das URLs:
#   scripts.converteai.net/<conta>/players/<player>/v4/player.js
#   cdn.converteai.net/<conta>/<video>/main.m3u8
# A conta e UUID com hifens; o player e o video sao ObjectId de 24 hex. Os
# valores abaixo saem de um player.js de producao -- formato inventado ja
# escondeu um bug aqui (regex de video que so casava UUID nunca casava nada).
CONTA = "81d625dd-b729-4291-9176-b1b5e1565068"
PLAYER_A = "68ef0f38821710ceb6f1272d"
VID_A = "6a2f12e2d33ef46eda9d9122"
VID_B = "99999999aaaabbbbcccc0000"

VSL = f'''<html><head><title>main</title></head><body>
<script>fbq("init","3248264035336938");</script>
<vturb-smartplayer id="vid-x">
<script src="https://scripts.converteai.net/{CONTA}/players/{PLAYER_A}/v4/player.js">
https://cdn.converteai.net/{CONTA}/{VID_A}/main.m3u8</script>
<a href="https://www.checkout-ds24.com/product/687041">Comprar $67</a>
</body></html>'''

fp = fingerprint(VSL, source="vsl")
check("titulo", fp["title"], "main")
check("video id extraido", fp["video"], [VID_A])
check("conta nao se confunde com o video", fp["accounts"], [CONTA])
check("player id extraido", fp["player_ids"], [PLAYER_A])
check("produto extraido", fp["product_ids"], ["687041"])
check("checkout limpo", fp["checkouts"], ["https://www.checkout-ds24.com/product/687041"])
check("pixel separado da identidade", fp["pixels"], ["3248264035336938"])

# Asset da Digistore (css/png) nao pode virar "checkout".
ASSET = ('<a href="https://digistore24.com/pb/file/x/assets/brand/color.css">x</a>'
         '<img src="https://www.digistore24.com/pb/img/merchant_1/product/a.png">')
check("asset nao e checkout", fingerprint(ASSET)["checkouts"], [])

# Pagina de despejo: sem oferta nenhuma.
DESPEJO = '<html><title>Tarot Reading</title><body>your daily reading</body></html>'
d = fingerprint(DESPEJO)
check("despejo nao tem video", d["video"], [])
check("despejo nao tem checkout", d["checkouts"], [])

# --- a comparacao, o coracao do modulo --------------------------------------
mesma = fingerprint(VSL)
check("mesmo html = mesma vsl", compare(fp, mesma)["veredito"], "mesma_vsl")

nova = fingerprint(VSL.replace(VID_A, VID_B))
c = compare(fp, nova)
check("video trocado, mesmo produto = oferta com video novo",
      c["veredito"], "mesma_oferta_video_novo")
check("aponta o video novo", c["video_so_em_b"], [VID_B])
check("confirma o produto comum", c["produto_comum"], ["687041"])

outra = fingerprint(VSL.replace(VID_A, VID_B).replace("687041", "111111"))
check("video e produto diferentes = outra oferta",
      compare(fp, outra)["veredito"], "oferta_diferente")

sem_video = fingerprint('<a href="https://www.checkout-ds24.com/product/687041">x</a>')
check("sem video dos dois lados, cai no produto",
      compare(sem_video, sem_video)["veredito"], "mesma_oferta")
check("nada em comum = indeterminado",
      compare(fingerprint("<i>nada</i>"), fp)["veredito"], "indeterminado")

# --- regressao: a mesma conta NAO pode virar "mesma VSL" --------------------
# Caso real (sensualdesireart.site): duas paginas do mesmo operador, players
# diferentes, sem m3u8 no HTML estatico. Comparar pela conta dizia "mesma
# VSL" e escondia que a oferta do anuncio era outra.
def _pag(player, produto):
    return (f'<script src="https://scripts.converteai.net/{CONTA}/players/'
            f'{player}/v4/player.js"></script>'
            f'<a href="https://www.checkout-ds24.com/product/{produto}">c</a>')

raiz = fingerprint(_pag("68ef0f38821710ceb6f1272d", "687041"))
main = fingerprint(_pag("6a2f12e8f1639bbd69b2944b", "687041"))
c2 = compare(raiz, main)
check("mesma conta, players diferentes = video novo, nao mesma vsl",
      c2["veredito"], "mesma_oferta_video_novo")
check("sem m3u8, a comparacao cai no player", c2["comparado_por"], "player")
check("a conta comum aparece como dado a parte", c2["conta_comum"], [CONTA])
check("com m3u8, a comparacao usa o video",
      compare(fp, fingerprint(VSL))["comparado_por"], "video")

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print("radiografia de pagina ok")
