"""Radiografia de uma pagina: extrai a identidade do funil de uma URL ou de um
arquivo HTML salvo.

Existe por um motivo concreto. A VSL que o alvo entrega ao trafego APROVADO
vive atras do cloaker de IP, e de um IP residencial errado nao ha como
alcanca-la -- nem este app, nem urlscan, nem bot nenhum passa. Mas quem tem
acesso legitimo (a conta certa, o pais certo) VE a pagina. Este modulo
transforma o que essa pessoa ve num dado que a ferramenta entende: ela salva a
pagina (Cmd+S -> "pagina completa") e passa o arquivo aqui.

Isto e o "clique humano no pais-alvo" que o brief (secao 6) previu como o
degrau final -- so que em vez de contratar um freelancer a US$20, e um amigo
com acesso mandando o HTML. A ferramenta faz o resto: identifica o video, o
checkout, os pixels e a oferta, e diz se e a mesma VSL que ja temos ou uma
nova.

Aceita URL tambem, para o caso comum de a pagina NAO ser cloakeada (o apex, o
checkout, uma pagina de obrigado). Se a URL for cloakeada, o proprio resultado
denuncia -- vem a pagina de despejo, nao a oferta -- e a saida e salvar o HTML
de quem tem acesso.
"""

from __future__ import annotations

import re
from pathlib import Path

from .osint.http import client
from .signals import registrable_host, scan_text, scan_values

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
MAX_BYTES = 4_000_000


def _title(html: str) -> str:
    m = TITLE_RE.search(html or "")
    return re.sub(r"\s+", " ", m.group(1)).strip()[:140] if m else ""


def fingerprint(html: str, source: str = "") -> dict:
    """Identidade do funil extraida de um HTML. Puro, sem rede.

    Separa o que IDENTIFICA a oferta (video, checkout, produto) do que so
    instrumenta (pixels), porque a pergunta util e "e a mesma VSL?", e quem
    responde isso e o par (video, checkout) -- nao o pixel, que muda por
    campanha sem a oferta mudar.
    """
    valores = scan_values(html)
    def _vals(prefixo):
        return sorted({v.split(":", 1)[1] for v in valores if v.startswith(prefixo)})

    # Um order form nao termina em asset. `/pb/img/.../product/a.png` casa o
    # padrao de checkout pelo `/product/`, mas e imagem -- fora.
    _ASSET = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".woff", ".woff2", ".ico", ".webp")
    checkouts = [c for c in _vals("checkout:")
                 if not c.lower().rstrip("\\]").endswith(_ASSET)]
    # ID do produto no checkout: o pivo mais duravel. Sobrevive a troca de
    # dominio da VSL, de video, de pixel -- e o mesmo produto sendo vendido.
    produtos = sorted({m.group(1) for c in checkouts
                       for m in [re.search(r"/product/(\d+)", c)] if m})

    return {
        "source": source,
        "title": _title(html),
        "video": _vals("vsl_video:"),
        "player_ids": _vals("vsl_player_id:"),
        "accounts": _vals("vsl_account:"),
        "players": _vals("vsl_player:"),
        "checkouts": checkouts,
        "product_ids": produtos,
        "funnels": _vals("telegram:") + _vals("whatsapp:") + _vals("bot_handle:"),
        "pixels": _vals("meta_pixel:"),
        "signals": scan_text(html),
        "bytes": len(html or ""),
    }


async def from_url(url: str) -> dict:
    """Baixa a URL e radiografa. O host final entra no resultado: se vier
    diferente do pedido, a pagina te redirecionou (possivel despejo)."""
    async with client() as c:
        r = await c.get(url)
        html = r.text[:MAX_BYTES]
        fp = fingerprint(html, source=url)
        fp["status"] = r.status_code
        fp["final_url"] = str(r.url)
        fp["bounced"] = registrable_host(str(r.url)) != registrable_host(url)
        return fp


def from_file(path: str | Path) -> dict:
    """Radiografa um HTML salvo -- o caminho de quem TEM acesso ao alvo."""
    p = Path(path)
    html = p.read_text(encoding="utf-8", errors="ignore")[:MAX_BYTES]
    return fingerprint(html, source=str(p))


def compare(a: dict, b: dict) -> dict:
    """Duas radiografias -> e a mesma VSL?

    O veredito sai do par (video, produto), nunca do pixel. Dois documentos
    com o mesmo video E o mesmo produto sao a mesma oferta ainda que o pixel
    ou o dominio tenham mudado; video diferente com o mesmo produto e a MESMA
    oferta com criativo novo -- exatamente o caso "e a VSL nova?".
    """
    # Discriminador: o uuid do video, quando os dois lados tem. O m3u8 e
    # montado pelo JS em tempo de execucao, entao HTML estatico muitas vezes
    # so traz a tag do player -- ai o id do player responde no lugar dele.
    va, vb = set(a.get("video", [])), set(b.get("video", []))
    base = "video"
    if not (va and vb):
        va, vb = set(a.get("player_ids", [])), set(b.get("player_ids", []))
        base = "player"
    pa, pb = set(a.get("product_ids", [])), set(b.get("product_ids", []))
    ca, cb = set(a.get("accounts", [])), set(b.get("accounts", []))

    if va and vb:
        if va & vb:
            veredito = "mesma_vsl"
        elif pa & pb:
            veredito = "mesma_oferta_video_novo"
        else:
            veredito = "oferta_diferente"
    elif pa & pb:
        veredito = "mesma_oferta"
    else:
        veredito = "indeterminado"

    return {
        "veredito": veredito,
        "comparado_por": base,
        "video_igual": sorted(va & vb),
        "video_so_em_a": sorted(va - vb),
        "video_so_em_b": sorted(vb - va),
        "produto_comum": sorted(pa & pb),
        # A conta do player nao entra no veredito: ela e a mesma em todas as
        # VSLs do operador. Sai como dado a parte -- e o que liga um dominio
        # novo ao mesmo dono.
        "conta_comum": sorted(ca & cb),
    }
