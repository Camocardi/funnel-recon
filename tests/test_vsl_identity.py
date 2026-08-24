"""Identidade de VSL e correlacao de operador. Sem rede.

A money page nao aparece na Biblioteca, mas UMA na mao revela a conta do
operador no converteai -- e essa conta e a mesma em todas as VSLs dele. Caso
real: thesidetrack.site (ES, disfuncao) e thehealthvantage.site (EN,
bicarbonato) sao a MESMA conta 6e3ae2f6.
"""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.vsl_identity import account_de_fingerprint, irmaos_no_banco

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


CONTA = "6e3ae2f6-ad64-483b-9bc5-bafc50ec8005"

check("conta sai do campo accounts",
      account_de_fingerprint({"accounts": [CONTA]}), CONTA)
check("conta sai da URL do player quando accounts vazio",
      account_de_fingerprint(
          {"accounts": [],
           "players": [f"https://scripts.converteai.net/{CONTA}/players/abc/v4/player.js"]}),
      CONTA)
check("sem conta devolve vazio", account_de_fingerprint({}), "")

# --- correlacao pelo banco ---------------------------------------------------
import json  # noqa: E402

conn = sqlite3.connect(":memory:")
conn.row_factory = sqlite3.Row
conn.execute("CREATE TABLE scan_result (target TEXT, final_url TEXT, "
             "signals TEXT, ts TEXT)")


def grava(url, conta, video, checkout=None):
    sinais = [f"vsl_account:{conta}", f"vsl_video:{video}"]
    if checkout:
        sinais.append(f"checkout:{checkout}")
    conn.execute("INSERT INTO scan_result VALUES (?,?,?,?)",
                 (url, url, json.dumps(sinais), "2026-08-24T00:00:00"))


grava("https://thesidetrack.site/upsells/vsl-ht/", CONTA, "68acd108def35b4ab941b94e")
grava("https://thehealthvantage.site/", CONTA, "69e81b696ef5029c0c533aff",
      "https://jellylean.pay.clickbank.net/x")
# Outro operador -- conta diferente, NAO pode aparecer.
grava("https://outrooperador.site/", "11111111-2222-3333-4444-555555555555", "aaa")
conn.commit()

irmaos = irmaos_no_banco(conn, CONTA)
hosts = sorted(x["url"] for x in irmaos)
check("acha as duas paginas da mesma conta", len(irmaos), 2)
check("nao mistura operador de outra conta",
      all("outrooperador" not in x["url"] for x in irmaos), True)
check("traz o video de cada uma",
      sorted(v for x in irmaos for v in x["videos"]),
      ["68acd108def35b4ab941b94e", "69e81b696ef5029c0c533aff"])
check("traz o checkout quando existe",
      [x["checkouts"] for x in irmaos if x["checkouts"]],
      [["https://jellylean.pay.clickbank.net/x"]])
check("conta vazia nao retorna nada", irmaos_no_banco(conn, ""), [])

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("identidade de vsl ok")
