"""VSL ja conhecida: achar a isca nao e achar o funil.

O caso real: o dominio raiz de sensualdesireart.site respondeu sem cloaker e
serviu uma VSL. O app deu "oferta encontrada" -- mas aquela VSL ja era sabida,
a antiga/saturada, exposta de proposito. A oferta do anuncio seguia fechada.

Roda num FUNNEL_RECON_HOME temporario: a lista de conhecidas do usuario nao
pode ser tocada por teste.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_tmp = tempfile.mkdtemp(prefix="funnelrecon-teste-")
os.environ["FUNNEL_RECON_HOME"] = _tmp

from funnel_recon import conhecidas  # noqa: E402  (depende do env acima)
from funnel_recon.orchestrate import Findings, _decide  # noqa: E402
from funnel_recon.schema import ScanResult  # noqa: E402
from funnel_recon.signals import scan_text, scan_values  # noqa: E402

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


CONTA = "81d625dd-b729-4291-9176-b1b5e1565068"
ISCA = "68ef0f38821710ceb6f1272d"
NOVA = "6a2f12e8f1639bbd69b2944b"


def _lateral(url, player, checkout):
    html = (f'<script src="https://scripts.converteai.net/{CONTA}/players/'
            f'{player}/v4/player.js"></script><a href="{checkout}">c</a>')
    return ScanResult(
        target="sensualdesireart.site", stage="probe", source="sidedoor:/",
        status="200", final_url=url, verdict="money",
        signals=scan_text(html) + scan_values(html) + [f"sidedoor_url:{url}"])


def _travado():
    return ScanResult(target="x", stage="probe", source="persona:desktop",
                      status="200", final_url="https://alvo/lp", verdict="white",
                      signals=[])


# --- a lista -----------------------------------------------------------------
check("lista comeca vazia", conhecidas.listar(), [])
conhecidas.marcar(ISCA, "antiga/saturada", "exposta no apex de proposito")
check("marcou", [i for i, _ in conhecidas.listar()], [ISCA])
check("id inedito nao consta", conhecidas.avaliar([NOVA]), {})
check("id conhecido consta",
      conhecidas.avaliar([ISCA])[ISCA]["rotulo"], "antiga/saturada")

# Marcar de novo troca o rotulo e PRESERVA a data: "desde quando eu sei disto".
antes = conhecidas.carregar()[ISCA]["marcada_em"]
conhecidas.marcar(ISCA, "outro rotulo")
check("remarcar preserva a data", conhecidas.carregar()[ISCA]["marcada_em"], antes)
conhecidas.marcar(ISCA, "antiga/saturada")

# A conta NUNCA entra: e a mesma em toda VSL do operador.
check("conta fica fora dos ids comparaveis",
      conhecidas.ids_de([f"vsl_account:{CONTA}", f"vsl_player_id:{ISCA}"]), [ISCA])

# --- o veredito --------------------------------------------------------------
isca = _lateral("https://sensualdesireart.site/", ISCA,
                "https://payment.loversecretguide.site/checkout/204194432")
nova = _lateral("https://sensualdesireart.site/main/", NOVA,
                "https://www.checkout-ds24.com/product/687041")

f = Findings()
f.probes = {"u": [_travado()]}
f.sidedoors = [isca]
_decide(f, None)
check("so VSL conhecida = isca, nao 'money'", f.verdict, "isca")
check("aponta o rotulo na manchete", "antiga/saturada" in f.headline, True)

f2 = Findings()
f2.probes = {"u": [_travado()]}
f2.sidedoors = [isca, nova]
_decide(f2, None)
check("uma inedita no meio volta a valer como achado", f2.verdict, "money")
check("a conhecida continua sinalizada", list(f2.vsls_conhecidas), [ISCA])

conhecidas.esquecer(ISCA)
f3 = Findings()
f3.probes = {"u": [_travado()]}
f3.sidedoors = [isca]
_decide(f3, None)
check("sem lista, o comportamento antigo permanece", f3.verdict, "money")

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("vsl conhecida ok")
