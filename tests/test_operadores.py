"""Operadores conhecidos pela conta de VSL. Sem rede, home isolado."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["FUNNEL_RECON_HOME"] = tempfile.mkdtemp(prefix="funnelrecon-op-")

from funnel_recon import operadores as op  # noqa: E402

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


A = "81d625dd-b729-4291-9176-b1b5e1565068"
B = "6e3ae2f6-ad64-483b-9bc5-bafc50ec8005"

check("comeca vazio", op.listar(), [])
op.marcar(A, "loveinstinct", "PT/EN")
data1 = op.carregar()[A]["visto_em"]
op.marcar(A, "loveinstinct v2")
check("remarcar preserva a data", op.carregar()[A]["visto_em"], data1)

op.marcar(B, "healthvantage")
check("dois operadores", {a for a, _ in op.listar()}, {A, B})

check("extrai contas dos sinais",
      op.contas_em([f"vsl_account:{A}", "vsl_video:xyz", "checkout:z"]), [A])

vistos = op.reconhecer([B, "conta-nova-nunca-vista"])
check("reconhece o conhecido", list(vistos), [B])
check("nao inventa o desconhecido", "conta-nova-nunca-vista" in vistos, False)

check("esquecer remove", op.esquecer(A), True)
check("esquecer o que nao existe", op.esquecer("nada"), False)
check("sobra so o outro", [a for a, _ in op.listar()], [B])

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("operadores ok")
