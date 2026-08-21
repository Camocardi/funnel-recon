"""Onde ficam os arquivos pesados e volateis.

NAO na pasta do projeto. O projeto vive em ~/Documents, que no Mac deste
usuario e sincronizado pelo iCloud Drive -- e isso causou um problema real:

  - o ambiente Python tem ~2.300 arquivos, e o iCloud tentava sincronizar
    todos, podendo descarregar e re-materializar arquivos sob demanda. O app
    demorava de forma imprevisivel para abrir, sem dar sinal nenhum;
  - o perfil do navegador tem milhares de arquivos que mudam a cada uso;
  - SQLite dentro de pasta sincronizada pode corromper: o sync copia o
    arquivo por baixo enquanto o banco esta escrevendo.

O CODIGO continua no Documents de proposito -- sao poucos arquivos, e ter
backup automatico dele e bom. Sai daqui so o que e pesado ou regeneravel.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "FunnelRecon"


def support_dir() -> Path:
    """Pasta de apoio, fora de qualquer sincronizacao de nuvem."""
    override = os.getenv("FUNNEL_RECON_HOME")
    if override:
        base = Path(override).expanduser()
    elif os.uname().sysname == "Darwin":
        base = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        base = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def data_dir() -> Path:
    d = support_dir() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path() -> Path:
    return data_dir() / "scans.db"


def profile_dir() -> Path:
    d = support_dir() / "browser_profile"
    d.mkdir(parents=True, exist_ok=True)
    return d


def venv_python() -> Path:
    return support_dir() / "venv" / "bin" / "python"


def log_path() -> Path:
    return data_dir() / "app.log"
