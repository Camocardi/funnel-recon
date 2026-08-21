"""Persona de navegador real [5]. Sem rede, sem abrir Chromium.

O que estes testes protegem e uma armadilha especifica: o navegador devolve o
DOM re-serializado, entao o hash dele nunca bate com o de uma persona HTTP.
Se ele votasse no baseline, o app anunciaria divergencia do cloaker em toda
rodada -- falso positivo no diagnostico mais importante do projeto.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.probe import engine
from funnel_recon.probe.engine import (Probe, e_navegador, probe_url,
                                       tem_conteudo, to_scan_results)
from funnel_recon.probe.navegador import _proxy_playwright, perfil_para

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


# --- proxy: o Chromium quer credencial em campo separado --------------------
check("http com credencial", _proxy_playwright("http://u:s@1.2.3.4:8080"),
      {"server": "http://1.2.3.4:8080", "username": "u", "password": "s"})
check("http sem credencial", _proxy_playwright("http://1.2.3.4:8080"),
      {"server": "http://1.2.3.4:8080"})
check("sem proxy", _proxy_playwright(None), None)

# SOCKS5 com senha nao funciona no Chromium. Falhar CALADO faria a sonda sair
# pelo IP de casa achando que estava no proxy -- o erro mais caro do projeto.
try:
    _proxy_playwright("socks5://u:s@1.2.3.4:1080")
    failures.append("socks5 com credencial: devia levantar ValueError")
except ValueError as e:
    check("socks5 avisa em vez de sair pelo IP de casa", "SOCKS5" in str(e), True)

# --- perfis ------------------------------------------------------------------
check("perfil da sonda e separado do que loga no Meta",
      perfil_para("probe") != perfil_para("fb"), True)
check("perfil 'nenhum' e sessao descartavel", perfil_para("nenhum"), None)

# --- o navegador nao vota no baseline ---------------------------------------
check("reconhece a persona de navegador", e_navegador("navegador:probe"), True)
check("persona HTTP nao e navegador", e_navegador("chrome-desktop-us"), False)


def _p(nome, sha, valores=()):
    return Probe(persona=nome, ok=True, status=200, body_sha=sha,
                 body_len=100, values=list(valores))


# Tres personas HTTP receberam a MESMA pagina (baseline claro) e o navegador,
# como sempre, um hash proprio. Isso nao pode virar "o cloaker respondeu
# diferente": o veredito das HTTP tem que continuar "white".
probes = [_p("python-cru", "aaa"), _p("chrome-desktop-us", "aaa"),
          _p("googlebot", "aaa"), _p("navegador:probe", "zzz")]
res = {r.source: r.verdict for r in to_scan_results("https://alvo/x", probes,
                                                    "probe", None)}
check("HTTP iguais continuam white", res["python-cru"], "white")
check("navegador nao arrasta ninguem para divergencia", res["googlebot"], "white")
check("navegador fica em unknown, sem fingir divergencia",
      res["navegador:probe"], "unknown")

# Se o navegador votasse, com so uma HTTP o baseline poderia virar o dele.
poucas = [_p("python-cru", "aaa"), _p("navegador:probe", "zzz")]
res2 = {r.source: r.verdict for r in to_scan_results("https://alvo/x", poucas,
                                                     "probe", None)}
check("com uma HTTP so, ela segue sendo o baseline", res2["python-cru"], "white")

# --- quando o navegador entra -----------------------------------------------
check("ha conteudo util", tem_conteudo([_p("x", "a")]), True)
check("so challenge nao e conteudo",
      tem_conteudo([Probe(persona="x", ok=True, status=200, is_challenge=True)]),
      False)
check("so erro nao e conteudo",
      tem_conteudo([Probe(persona="x", ok=False)]), False)

chamou = []
engine.run_persona = lambda url, p, proxy=None, timeout=25: _p(p.name, "aaa")
import funnel_recon.probe.navegador as nav
nav.run_navegador = lambda url, proxy=None, timeout=30000, perfil="probe": (
    chamou.append(perfil) or _p(f"navegador:{perfil}", "zzz"))

from funnel_recon.probe.personas import PERSONAS

uma = PERSONAS[:1]
probe_url("https://alvo/x", personas=uma, delay=0, navegador="nao")
check("navegador='nao' nao abre navegador", chamou, [])

probe_url("https://alvo/x", personas=uma, delay=0, navegador="auto")
check("auto NAO gasta navegador quando o HTTP ja trouxe pagina", chamou, [])

engine.run_persona = lambda url, p, proxy=None, timeout=25: Probe(
    persona=p.name, ok=True, status=200, is_challenge=True)
probe_url("https://alvo/x", personas=uma, delay=0, navegador="auto")
check("auto entra quando so veio parede de JS", chamou, ["probe"])

probe_url("https://alvo/x", personas=uma, delay=0, navegador="sempre",
          perfil="nenhum")
check("sempre entra de qualquer jeito", chamou, ["probe", "nenhum"])

# --- corpo ilegivel nao pode virar "white" ---------------------------------
# Caso real: o proxy devolveu Content-Encoding: gzip num corpo brotli. Status
# 200, corpo binario. Sem guarda, scan_text nao acha sinal, a persona vira
# "white" e o app conclui "recebeu a safe page" sobre algo que nunca foi lido.
from funnel_recon.probe.engine import _ilegivel  # noqa: E402

check("html normal e legivel",
      _ilegivel("<html><body><p>oferta aqui</p></body></html>"), False)
check("html com tab e quebra de linha segue legivel",
      _ilegivel("<html>\t\n  <body>ok</body>\n</html>"), False)
check("corpo vazio nao e ilegivel", _ilegivel(""), False)
check("binario e ilegivel", _ilegivel("\x00\x01\x02\ufffd" * 200), True)

if failures:
    print(f"FALHOU ({len(failures)}):")
    for x in failures:
        print("  -", x)
    raise SystemExit(1)
print("persona de navegador ok")
