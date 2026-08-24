"""Persistencia SQLite.

Motivo de existir (secao 8): anuncio comercial some da Biblioteca ao pausar e,
fora da UE, nao ha arquivo publico. O que nao for gravado no momento da coleta
se perde para sempre. Guardar tambem permite comparar campanhas ao longo do
tempo, coisa que a Biblioteca nao deixa fazer.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .paths import db_path
from .schema import Ad, CreativeDiff, ScanResult

# Fora da pasta do projeto: ver funnel_recon/paths.py. SQLite dentro de pasta
# sincronizada por nuvem pode corromper.
DEFAULT_DB = db_path()

SCHEMA = """
CREATE TABLE IF NOT EXISTS ad (
    ad_id             TEXT PRIMARY KEY,
    page_id           TEXT,
    start_date        TEXT,
    is_active         INTEGER,
    end_date          TEXT,
    countries         TEXT,
    display_host      TEXT,
    full_url          TEXT,
    cta               TEXT,
    title             TEXT,
    body              TEXT,
    leaks             TEXT,
    creative_lib_url  TEXT,
    creative_feed_url TEXT,
    creative_phash    TEXT,
    asset_hosts       TEXT,
    collation_count   INTEGER,
    collation_id      TEXT,
    ts                TEXT
);

CREATE TABLE IF NOT EXISTS scan_result (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    target    TEXT NOT NULL,
    stage     TEXT NOT NULL,
    source    TEXT NOT NULL,
    ad_id     TEXT,
    status    TEXT,
    body_sha  TEXT,
    final_url TEXT,
    signals   TEXT,
    verdict   TEXT,
    error     TEXT,
    raw       TEXT,
    ts        TEXT
);

CREATE TABLE IF NOT EXISTS creative_diff (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ad_id      TEXT NOT NULL,
    phash_lib  TEXT,
    phash_feed TEXT,
    distance   INTEGER,
    is_cloaked INTEGER,
    kind       TEXT,
    ts         TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_result(target);
CREATE INDEX IF NOT EXISTS idx_scan_stage  ON scan_result(stage);
CREATE INDEX IF NOT EXISTS idx_ad_host     ON ad(display_host);
"""

_JSON_FIELDS = {"countries", "leaks", "asset_hosts", "signals", "raw"}


# Colunas acrescentadas depois que ja havia banco em uso. `CREATE TABLE IF NOT
# EXISTS` nao altera tabela existente: sem isto, um banco antigo continuaria
# sem as colunas e todo INSERT quebraria. Cada anuncio nao gravado se perde
# para sempre (o Meta apaga ao pausar), entao recriar o banco nao e opcao.
MIGRATIONS = {
    "ad": (("is_active", "INTEGER"), ("end_date", "TEXT"),
           ("creative_phash", "TEXT"),
           ("collation_count", "INTEGER"), ("collation_id", "TEXT")),
    "creative_diff": (("kind", "TEXT"),),
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in MIGRATIONS.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, decl in columns:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    conn.commit()


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(path) if path is not None else db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def _encode(row: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in row.items():
        if k in _JSON_FIELDS:
            out[k] = json.dumps(v, ensure_ascii=False, default=str) if v is not None else None
        elif isinstance(v, bool):
            out[k] = int(v)
        else:
            out[k] = v
    return out


def _insert(conn: sqlite3.Connection, table: str, obj: Any, replace: bool = False) -> None:
    row = _encode(asdict(obj))
    cols = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    verb = "INSERT OR REPLACE" if replace else "INSERT"
    conn.execute(f"{verb} INTO {table} ({cols}) VALUES ({marks})", list(row.values()))


def save_ad(conn: sqlite3.Connection, ad: Ad) -> None:
    _insert(conn, "ad", ad, replace=True)
    conn.commit()


def save_scan(conn: sqlite3.Connection, result: ScanResult) -> None:
    _insert(conn, "scan_result", result)
    conn.commit()


def save_scans(conn: sqlite3.Connection, results: Iterable[ScanResult]) -> int:
    n = 0
    for r in results:
        _insert(conn, "scan_result", r)
        n += 1
    conn.commit()
    return n


def save_creative_diff(conn: sqlite3.Connection, diff: CreativeDiff) -> None:
    _insert(conn, "creative_diff", diff)
    conn.commit()


def creative_hashes(conn: sqlite3.Connection, ad_ids: Iterable[str]) -> dict[str, str]:
    """pHash gravado numa coleta ANTERIOR, por ad_id.

    Tem que ser lido antes de `save_ad`: a gravacao e INSERT OR REPLACE e
    apagaria justamente o valor antigo que serve de base de comparacao.
    """
    ids = [str(i) for i in ad_ids]
    if not ids:
        return {}
    out: dict[str, str] = {}
    # SQLite limita a quantidade de parametros; 2.000 anuncios passariam.
    for i in range(0, len(ids), 400):
        lote = ids[i:i + 400]
        marks = ",".join("?" for _ in lote)
        for r in conn.execute(
            f"SELECT ad_id, creative_phash FROM ad "
            f"WHERE creative_phash IS NOT NULL AND ad_id IN ({marks})", lote
        ):
            out[r["ad_id"]] = r["creative_phash"]
    return out


def creative_hashes_by_page(conn: sqlite3.Connection,
                            page_ids: Iterable[str] | None = None) -> dict[str, list[str]]:
    """{page_id: [pHash, ...]} do que a pagina publicou na Biblioteca.

    Agrupado por pagina porque e assim que a comparacao com o feed funciona:
    o post patrocinado nem sempre traz um id de anuncio que exista na
    Biblioteca, mas traz de quem ele e. Ver collect/feed.parse_sponsored.
    """
    q = ("SELECT page_id, creative_phash FROM ad "
         "WHERE creative_phash IS NOT NULL AND page_id IS NOT NULL AND page_id != ''")
    args: list[Any] = []
    if page_ids is not None:
        ids = [str(i) for i in page_ids]
        if not ids:
            return {}
        q += f" AND page_id IN ({','.join('?' for _ in ids)})"
        args = ids
    out: dict[str, list[str]] = {}
    for r in conn.execute(q, args):
        out.setdefault(r["page_id"], []).append(r["creative_phash"])
    return out


def scans_for(conn: sqlite3.Connection, target: str, stage: str | None = None) -> list[sqlite3.Row]:
    q = "SELECT * FROM scan_result WHERE target = ?"
    args: list[Any] = [target]
    if stage:
        q += " AND stage = ?"
        args.append(stage)
    return conn.execute(q + " ORDER BY ts DESC", args).fetchall()
