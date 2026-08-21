"""VSLs que ja conhecemos -- e por que isso decide um veredito.

O caso que originou o modulo: o dominio raiz de um alvo respondeu sem cloaker
e serviu uma VSL. A ferramenta comemorou ("oferta encontrada por porta
lateral"), mas o operador ja tinha sido investigado antes e aquela era a VSL
VELHA, a saturada -- deixada exposta de proposito. A oferta que o anuncio
entrega continuava atras do cloaker. Achar a isca e ser enganado, nao vencer.

Duas fontes respondem "isto ja e conhecido?", e as duas fazem falta:

  - a lista marcada a mao: o que o investigador aprendeu FORA da ferramenta
    (um concorrente que ele ja comprou, um id que veio de outra fonte). Sem
    isto o app so aprende depois de errar uma vez;
  - o historico do banco: todo id de VSL que qualquer analise anterior ja
    gravou. Sai de graca e cobre o que a ferramenta mesma viu.

O id comparado e o do PLAYER ou o do VIDEO -- nunca o da conta, que e igual em
todas as VSLs do mesmo dono. Ver signals.VALUE_PATTERNS.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .paths import data_dir


def _arquivo() -> Path:
    return data_dir() / "vsl_conhecidas.json"


def _agora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def carregar() -> dict[str, dict]:
    """Mapa id -> {rotulo, nota, marcada_em}. Arquivo corrompido nao derruba
    a analise: uma lista de anotacoes perdida vale menos que o resultado."""
    p = _arquivo()
    if not p.exists():
        return {}
    try:
        dados = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return dados if isinstance(dados, dict) else {}


def _gravar(dados: dict[str, dict]) -> None:
    _arquivo().write_text(json.dumps(dados, indent=2, ensure_ascii=False),
                          encoding="utf-8")


def marcar(vsl_id: str, rotulo: str = "conhecida", nota: str = "") -> dict:
    """Marca um id como ja conhecido. Marcar de novo atualiza o rotulo e
    preserva a data original -- 'desde quando eu sei disto' e o dado util."""
    vsl_id = vsl_id.strip().lower()
    dados = carregar()
    antes = dados.get(vsl_id, {})
    dados[vsl_id] = {
        "rotulo": rotulo,
        "nota": nota or antes.get("nota", ""),
        "marcada_em": antes.get("marcada_em", _agora()),
    }
    _gravar(dados)
    return dados[vsl_id]


def esquecer(vsl_id: str) -> bool:
    dados = carregar()
    if dados.pop(vsl_id.strip().lower(), None) is None:
        return False
    _gravar(dados)
    return True


def listar() -> list[tuple[str, dict]]:
    return sorted(carregar().items(), key=lambda kv: kv[1].get("marcada_em", ""))


def _historico(conn: sqlite3.Connection, ids: set[str]) -> dict[str, dict]:
    """Primeira vez que cada id apareceu em qualquer analise ja gravada."""
    if not ids:
        return {}
    achados: dict[str, dict] = {}
    for row in conn.execute(
            "SELECT target, signals, ts FROM scan_result "
            "WHERE signals LIKE '%vsl_%' ORDER BY ts"):
        try:
            sinais = json.loads(row["signals"] or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        for s in sinais:
            if not s.startswith(("vsl_video:", "vsl_player_id:")):
                continue
            valor = s.split(":", 1)[1].lower()
            if valor in ids and valor not in achados:
                achados[valor] = {"visto_em": row["ts"], "alvo": row["target"]}
    return achados


def avaliar(ids, conn: sqlite3.Connection | None = None) -> dict[str, dict]:
    """id -> como ele e conhecido, ou ausente se for inedito.

    A marcacao manual ganha do historico: ela carrega o julgamento do
    investigador ("esta e a saturada"), o historico so carrega uma data.
    """
    ids = {i.strip().lower() for i in ids if i}
    marcadas = carregar()
    hist = _historico(conn, ids - set(marcadas)) if conn is not None else {}
    fora: dict[str, dict] = {}
    for i in ids:
        if i in marcadas:
            fora[i] = {"fonte": "marcada", **marcadas[i]}
        elif i in hist:
            fora[i] = {"fonte": "historico", "rotulo": "ja vista antes", **hist[i]}
    return fora


def ids_de(signals) -> list[str]:
    """Os ids de VSL de uma lista de sinais. So o que discrimina: o id da
    CONTA (`vsl_account:`) fica de fora de proposito."""
    return sorted({s.split(":", 1)[1].lower() for s in (signals or [])
                   if s.startswith(("vsl_video:", "vsl_player_id:"))})
