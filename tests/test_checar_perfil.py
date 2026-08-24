"""Checagem do proprio navegador contra os sinais do cloaker. Sem rede.

Os campos sao os que o captcha.min.js do The White Rabbit coleta. Isto NAO
engana filtro nenhum -- roda os mesmos testes no proprio navegador e aponta o
que o entregaria. Foi o que derrubou o usuario: headless e incoerencia geo.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.checar_perfil import avaliar

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


def ruins(dados, **kw):
    return {a["campo"] for a in avaliar(dados, **kw) if not a["ok"]}


REAL = {"webdriver": False, "plugins": 5, "inner": [1512, 820],
        "outer": [1512, 860], "hardwareConcurrency": 8,
        "timezone": "America/New_York", "language": "en-US",
        "referrer": "https://l.facebook.com/"}

check("perfil real coerente nao acusa nada",
      ruins(REAL, geo_pais="US", geo_timezone="America/New_York"), set())

check("webdriver=true e pego",
      "webdriver" in ruins({**REAL, "webdriver": True}), True)
check("zero plugins e pego",
      "plugins" in ruins({**REAL, "plugins": 0}), True)
check("outer zerado (headless) e pego",
      "janela" in ruins({**REAL, "outer": [0, 0]}), True)
check("fuso que nao bate com o IP e pego",
      "fuso x IP" in ruins({**REAL, "timezone": "America/Sao_Paulo"},
                           geo_timezone="America/New_York"), True)
check("idioma que destoa do pais e pego",
      "idioma x pais" in ruins({**REAL, "language": "pt-BR"}, geo_pais="US"), True)
check("sem referrer do Facebook e pego",
      "referrer" in ruins({**REAL, "referrer": ""}), True)

# Sem geo informada, nao inventa incoerencia de fuso/idioma.
check("sem geo, nao acusa fuso x IP",
      "fuso x IP" not in ruins(REAL), True)

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("checar perfil ok")
