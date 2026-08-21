"""Cliente HTTP compartilhado pelas fontes de OSINT.

Nada de fingerprint aqui: estas sao APIs publicas de terceiros, nao o alvo.
Fingerprint (curl_cffi/JA3) e assunto do probe [3], que fala com o adversario.
"""

from __future__ import annotations

import httpx

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
DEFAULT_TIMEOUT = httpx.Timeout(25.0, connect=10.0)


def client(**kw) -> httpx.AsyncClient:
    kw.setdefault("timeout", DEFAULT_TIMEOUT)
    kw.setdefault("follow_redirects", True)
    kw.setdefault("headers", {"User-Agent": UA, "Accept": "application/json,text/plain,*/*"})
    return httpx.AsyncClient(**kw)
