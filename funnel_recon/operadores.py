"""Operadores conhecidos, identificados pela conta de VSL.

A conta do converteai/VTurb (`vsl_account`) e a mesma em todas as VSLs de um
operador -- muda dominio, produto, nicho, idioma; a conta nao. Isso a torna a
impressao digital mais duravel que ha.

O uso e chegar CEDO. A VSL que da para pegar de graca (apex aberto, porta
lateral) costuma ser a velha, ja saturada, deixada exposta de proposito. A que
vale e a que esta escalando AGORA, atras do cloaker. Nao da para furar o
cloaker -- mas da para reconhecer o operador no primeiro anuncio de uma
campanha nova, enquanto o apex ainda esta aberto e antes de saturar.

Este modulo guarda as contas ja vistas com um rotulo, e diz na hora se uma
coleta nova traz um operador conhecido.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .paths import data_dir


def _arquivo() -> Path:
    return data_dir() / "operadores.json"


def carregar() -> dict[str, dict]:
    p = _arquivo()
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return d if isinstance(d, dict) else {}


def _gravar(d: dict) -> None:
    _arquivo().write_text(json.dumps(d, indent=2, ensure_ascii=False),
                          encoding="utf-8")


def marcar(account: str, rotulo: str = "", nota: str = "") -> dict:
    """Registra uma conta como operador conhecido. Preserva a data original."""
    account = account.strip().lower()
    d = carregar()
    antes = d.get(account, {})
    d[account] = {
        "rotulo": rotulo or antes.get("rotulo", ""),
        "nota": nota or antes.get("nota", ""),
        "visto_em": antes.get("visto_em",
                              datetime.now(timezone.utc).isoformat(timespec="seconds")),
    }
    _gravar(d)
    return d[account]


def esquecer(account: str) -> bool:
    d = carregar()
    if d.pop(account.strip().lower(), None) is None:
        return False
    _gravar(d)
    return True


def listar() -> list[tuple[str, dict]]:
    return sorted(carregar().items(), key=lambda kv: kv[1].get("visto_em", ""))


def contas_em(signals) -> list[str]:
    """As contas de VSL presentes numa lista de sinais."""
    return sorted({s.split(":", 1)[1].lower() for s in (signals or [])
                   if s.startswith("vsl_account:")})


def reconhecer(accounts) -> dict[str, dict]:
    """Das contas dadas, quais ja sao operador conhecido -> o rotulo dele."""
    conhecidos = carregar()
    fora = {}
    for a in accounts:
        a = a.strip().lower()
        if a in conhecidos:
            fora[a] = conhecidos[a]
    return fora
