"""O proxy guardado uma vez, em vez de colado a cada comando.

Existe por um motivo medido, nao por conforto. Colar a string do provedor a
mao produziu, num unico dia: `socks5://` num endpoint que e HTTP (nove
SSLError seguidos), um usuario com duas letras trocadas (407 mudo), e o
`sessid` reescrito a cada visita ao painel -- que troca o IP de saida sem
avisar e destroi a comparacao entre rodadas.

Todos esses erros aparecem como "o alvo bloqueou", que e a conclusao errada
mais cara possivel: manda a pessoa comprar proxy melhor quando o problema era
uma letra.

Guardar valida ANTES: parseia, checa o esquema e, se pedido, faz uma consulta
real e mostra o IP/ASN de saida. O que falha, falha na hora de salvar -- com o
nome do erro -- e nao no meio de um diagnostico.
"""

from __future__ import annotations

import os
from pathlib import Path

from .paths import support_dir


def _arquivo() -> Path:
    return support_dir() / "proxy.txt"


def salvar(bruto: str) -> str:
    """Normaliza e grava. Devolve a forma normalizada."""
    from .probe.engine import normalize_proxy
    normalizado = normalize_proxy(bruto)
    if not normalizado:
        raise ValueError("string de proxy vazia ou irreconhecivel")
    p = _arquivo()
    p.write_text(normalizado + "\n", encoding="utf-8")
    # Credencial de proxy e segredo: so o dono le.
    os.chmod(p, 0o600)
    return normalizado


def carregar() -> str | None:
    p = _arquivo()
    if not p.exists():
        return None
    v = p.read_text(encoding="utf-8").strip()
    return v or None


def esquecer() -> bool:
    p = _arquivo()
    if not p.exists():
        return False
    p.unlink()
    return True


def mascarar(proxy: str) -> str:
    """Esconde a senha para poder imprimir sem vazar em log ou captura."""
    if not proxy or "@" not in proxy:
        return proxy or ""
    credencial, host = proxy.rsplit("@", 1)
    if ":" in credencial:
        usuario = credencial.rsplit(":", 1)[0]
        return f"{usuario}:****@{host}"
    return f"{credencial}@{host}"


def testar(proxy: str, timeout: int = 30) -> dict:
    """Consulta real pelo proxy. Devolve o que o alvo veria: IP, ASN, regiao.

    O ASN e o dado que decide: datacenter disfarcado de residencial aparece
    aqui, e e ele que o cloaker le antes de qualquer cabecalho.
    """
    import json

    from curl_cffi import requests

    r = requests.get("http://ipinfo.thordata.com",
                     proxies={"http": proxy, "https": proxy},
                     impersonate="chrome124", timeout=timeout)
    texto = (r.text or "").strip()
    if not texto.startswith("{"):
        raise RuntimeError(f"HTTP {r.status_code}: {texto[:120]}")
    return json.loads(texto)
