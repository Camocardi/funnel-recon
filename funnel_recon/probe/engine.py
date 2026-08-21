"""Estagio [3]: dispara a MESMA URL com varias personas e compara.

Isto NAO quebra cloaker. Cloaker de destino decide server-side, e a variavel
decisiva e o IP -- nenhuma linha de codigo muda de qual IP o pacote sai. O que
este modulo faz e DIAGNOSTICAR qual camada do filtro acordou:

  todas as respostas iguais  -> o filtro decidiu antes de olhar header/TLS.
                                E IP/ASN/geo. So proxy resolve.
  respostas diferentes       -> o filtro le header/TLS/referrer. Da pra ajustar,
                                e o par de controle que divergiu diz qual.

As guardas existem porque cada uma corresponde a um erro real da secao 4 do
brief -- sem elas o diagnostico sai confiante e errado.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..schema import ScanResult
from ..signals import bounced_offsite, is_funnel_value, scan_text, scan_values
from .personas import PERSONAS, Persona, candidates

try:
    from curl_cffi import requests as cffi
except ImportError:  # pragma: no cover
    cffi = None

CHALLENGE_MARKERS = re.compile(
    r"cloudflare|attention required|just a moment|checking your browser|"
    r"cf-ray|ddos-guard|please enable (?:js|javascript)", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class Probe:
    """Resultado cru de uma persona. Vira ScanResult depois da analise."""

    persona: str
    ok: bool = False
    status: int | None = None
    hops: list[str] = field(default_factory=list)
    final_url: str = ""
    title: str = ""
    body_sha: str = ""
    body_len: int = 0
    signals: list[str] = field(default_factory=list)
    values: list[str] = field(default_factory=list)
    is_challenge: bool = False
    error: str = ""


def preflight(url: str) -> list[str]:
    """Avisos ANTES de gastar requisicao.

    Erro 1 da secao 4 foi testar a raiz do dominio por varias rodadas sem
    perceber que a URL real, com path e fbclid, estava no CSV o tempo todo.
    Checar isso custa zero e economiza nove requisicoes e uma conclusao falsa.
    """
    warns: list[str] = []
    try:
        u = urlparse(url)
    except ValueError:
        return ["url_invalida"]
    if u.scheme not in ("http", "https"):
        warns.append("url_sem_esquema")
    if u.path in ("", "/"):
        warns.append("url_e_raiz")
    if "fbclid" not in (u.query or ""):
        warns.append("sem_fbclid")
    return warns


def _normalize(body: str) -> str:
    """Remove nonce/timestamp antes de hashear.

    Sem isto, duas respostas IDENTICAS geram hashes diferentes so porque o
    servidor embutiu um token novo -- e o diagnostico diria "as personas
    divergiram" quando nada divergiu.
    """
    norm = re.sub(r"[0-9a-f]{16,}|\d{10,}", "", body)
    return re.sub(r"\s+", " ", norm).strip()


def run_persona(url: str, p: Persona, proxy: str | None = None,
                timeout: int = 25) -> Probe:
    r = Probe(persona=p.name)
    if cffi is None:
        r.error = "curl_cffi nao instalado (pip install curl_cffi)"
        return r

    kwargs = {"headers": p.headers, "timeout": timeout,
              "allow_redirects": True, "max_redirects": 12}
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}

    resp = None
    for candidate in candidates(p.impersonate):
        attempt = dict(kwargs)
        if candidate:
            attempt["impersonate"] = candidate
        try:
            resp = cffi.get(url, **attempt)
            break
        except Exception as e:
            msg = str(e)
            r.error = f"{type(e).__name__}: {msg}"
            # So vale descer a escada se a falha foi o alvo nao existir nesta
            # versao. Timeout ou DNS nao melhoram trocando de fingerprint.
            if "impersonat" not in msg.lower():
                return r
    if resp is None:
        return r

    r.ok = True
    r.status = resp.status_code
    r.hops = [h.url for h in getattr(resp, "history", [])] + [resp.url]
    r.final_url = resp.url

    body = resp.text or ""
    r.body_len = len(body)
    r.body_sha = hashlib.sha256(
        _normalize(body).encode("utf-8", "replace")).hexdigest()[:12]

    m = TITLE_RE.search(body)
    r.title = re.sub(r"\s+", " ", m.group(1)).strip()[:90] if m else ""
    r.signals = scan_text(body)
    r.values = scan_values(body)

    # Guarda 3 da secao 4: desafio de WAF nao e resposta do cloaker.
    # Sao camadas diferentes e comparar as duas juntas polui o diagnostico.
    r.is_challenge = bool(
        r.status in (403, 503) and CHALLENGE_MARKERS.search(r.title + body[:4000]))
    return r


def normalize_proxy(raw: str | None) -> str | None:
    """Aceita o proxy em qualquer formato comum e devolve o que o curl entende.

    Provedores exportam de dois jeitos, e o usuario nao controla qual vem:
      - `user:senha@host:porta`  (o que o curl quer)
      - `host:porta:user:senha`  (colado do painel, separado so por `:`)
    Alem de com ou sem esquema (`http://`, `socks5://`). Normalizar aqui, num
    lugar so, evita o erro silencioso de colar o formato de painel e o proxy
    simplesmente nao ser aplicado -- a probe sairia pelo IP de casa achando
    que estava no proxy.
    """
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None

    scheme = "http"
    rest = raw
    if "://" in raw:
        scheme, rest = raw.split("://", 1)
    scheme = scheme.lower()

    # Ja no formato com credencial (user:senha@host:porta): so garante esquema.
    if "@" in rest:
        return f"{scheme}://{rest}"

    partes = rest.split(":")
    # host:porta:user:senha -> user:senha@host:porta
    if len(partes) == 4 and partes[1].isdigit():
        host, porta, user, senha = partes
        return f"{scheme}://{user}:{senha}@{host}:{porta}"
    # host:porta (sem auth) -> passa direto
    if len(partes) == 2:
        return f"{scheme}://{rest}"
    # qualquer outra coisa (IPv6, formato exotico): devolve com esquema e deixa
    # o curl decidir, em vez de adivinhar errado.
    return f"{scheme}://{rest}"


def probe_url(url: str, proxy: str | None = None, timeout: int = 25,
              personas: list[Persona] | None = None, delay: float = 0.4,
              on_progress=None) -> list[Probe]:
    """Roda as personas em SEQUENCIA.

    Sequencial de proposito: nove requisicoes simultaneas do mesmo IP e um
    burst, e burst e exatamente o padrao que WAF classifica como bot. O ganho
    de tempo nao compensa contaminar o proprio experimento.
    """
    proxy = normalize_proxy(proxy)
    out: list[Probe] = []
    chosen = personas or PERSONAS
    for i, p in enumerate(chosen):
        if on_progress:
            on_progress(i, len(chosen), p)
        out.append(run_persona(url, p, proxy, timeout))
        if delay and i < len(chosen) - 1:
            time.sleep(delay)
    return out


def to_scan_results(url: str, probes: list[Probe], stage: str,
                    proxy: str | None, ad_id: str | None = None) -> list[ScanResult]:
    """Converte para o contrato da secao 10, ja com veredito por persona."""
    content = [p for p in probes if p.ok and not p.is_challenge
               and p.status and p.status < 400]
    # Baseline = a pagina que a MAIORIA recebeu. Secao 6: essa e a white page.
    # Quem foge dela E tem sinal de funil e candidato a money page.
    counts: dict[str, int] = {}
    for p in content:
        counts[p.body_sha] = counts.get(p.body_sha, 0) + 1
    baseline = max(counts, key=counts.get) if counts else None

    results = []
    for p in probes:
        # Despejo: o cloaker manda quem falha no filtro para o site real de um
        # terceiro. Nos dados reais foi `cwc.edu` (uma faculdade) e um site de
        # tarot. Sem marcar isso, a divergencia entre personas parecia achado.
        fora = bounced_offsite(p.final_url, url)

        # `p.values` inclui `meta_pixel:`, que existe em toda loja do planeta.
        # Aceitar qualquer valor como prova fazia o app anunciar money page
        # sobre a pagina institucional de uma universidade.
        funil = [v for v in p.values if is_funnel_value(v)]

        if not p.ok:
            verdict = "error"
        elif p.is_challenge:
            verdict = "challenge"
        elif p.status and p.status >= 400:
            verdict = "error"
        elif funil or any(s in ("telegram_link", "telegram_scheme",
                                "whatsapp_link", "telegram_bot") for s in p.signals):
            verdict = "money"
        elif fora:
            # Terminou no site de outra pessoa e sem sinal de funil: isto e a
            # saida de rejeicao do cloaker, nao a money page.
            verdict = "white"
        elif baseline and p.body_sha != baseline:
            verdict = "unknown"  # divergiu, mas sem sinal de funil: so anota
        else:
            verdict = "white"

        sinais = p.signals + p.values
        if fora:
            sinais = sinais + [f"bounced_offsite:{fora}"]

        results.append(ScanResult(
            target=url, stage=stage, source=p.persona, ad_id=ad_id,
            status=str(p.status) if p.status else None,
            body_sha=p.body_sha or None, final_url=p.final_url or None,
            signals=sinais, verdict=verdict,
            error=p.error or None,
            raw={"hops": p.hops, "title": p.title, "body_len": p.body_len,
                 "proxy": proxy, "is_challenge": p.is_challenge},
        ))
    return results


# Pares de controle: duas personas que diferem em UMA variavel. Se o cloaker
# responde diferente para as duas, ele LE aquela variavel -- e cada variavel
# que ele le e um sinal a menos que voce precisa acertar para passar.
CONTROL_AXES = [
    ("chrome-desktop-us", "chrome-desktop-us+fb", "referrer", "HTTP"),
    ("fb-inapp-ios", "fb-inapp-ptbr", "idioma", "HTTP"),
    ("chrome-desktop-us+fb", "android-chrome-us+fb", "device", "HTTP"),
    ("python-cru", "chrome-desktop-us", "user-agent/TLS", "HTTP"),
]

# Personas que NAO sao humano nenhum: crawler e script. Se o cloaker entrega a
# oferta para um destes, ele nem tenta filtrar de verdade -- vazamento grave.
NON_HUMAN = {"python-cru", "facebookexternalhit", "googlebot"}


def robustness(results: list[ScanResult],
               proxy_results: list[ScanResult] | None = None) -> dict:
    """Avalia a robustez de um cloaker a partir da matriz de personas.

    Responde a pergunta do projeto -- "pagar por este cloaker vale a pena?" --
    sem tentar burlar nada: e leitura do que a matriz JA mostrou. Um cloaker
    que entrega a oferta para o googlebot, ou que divergiu por causa de um
    header, e um cloaker fraco. Um que serviu a MESMA pagina para tudo (mesmo
    com o IP certo via proxy) so cede a fingerprint de JS -- e forte.

    Nao devolve "como passar". Devolve "o que ele le e onde vaza", que e
    diagnostico de qualidade, nao receita de bypass.
    """
    # Uma persona por nome: o banco pode ter varias rodadas do mesmo alvo, e
    # contar a mesma persona tres vezes distorce vazamento e baseline. Fica a
    # ultima vista (a mais recente na ordem recebida).
    por_persona = {r.source: r for r in results if r.body_sha and r.verdict != "error"}
    content = list(por_persona.values())
    if not content:
        return {"grade": "sem_dado", "leaked": False, "axes_read": [],
                "leaks": [], "note": "Nenhuma resposta util para avaliar."}

    # Baseline = a pagina que a MAIORIA recebeu (a safe page).
    from collections import Counter
    contagem = Counter(r.body_sha for r in content)
    baseline = contagem.most_common(1)[0][0]

    # Vazamento: persona que recebeu money page (a oferta escapou para ela).
    leaks = [r.source for r in content if r.verdict == "money"]
    leak_non_human = [s for s in leaks if s in NON_HUMAN]

    # Quais eixos o cloaker LE (par de controle que divergiu).
    sha = {r.source: r.body_sha for r in content}
    axes_read = [what for a, b, what, _ in CONTROL_AXES
                 if a in sha and b in sha and sha[a] != sha[b]]

    # Se ha proxy: o IP e o eixo. Comparar a MESMA persona com e sem proxy
    # isola se o filtro e de IP.
    ip_is_axis = None
    if proxy_results:
        pc = {r.source: r.body_sha for r in proxy_results
              if r.body_sha and r.verdict != "error"}
        diffs = [s for s in sha if s in pc and sha[s] != pc[s]]
        ip_is_axis = bool(diffs)
        if ip_is_axis and "IP/geo" not in axes_read:
            axes_read.append("IP/geo")

    # Nota. Quanto mais eixos HTTP ele le e quanto menos vaza, mais forte --
    # ate o teto: se nem o IP certo (proxy) abre, so JS resolve.
    if leak_non_human:
        grade = "fraco"
        note = ("Entregou a oferta para crawler/script (" +
                ", ".join(leak_non_human) + "). Filtra de menos: nao vale caro.")
    elif leaks:
        grade = "fraco"
        note = ("A oferta vazou para persona HTTP (" + ", ".join(leaks) +
                "). Um sinal de rede basta para passar -- protecao rasa.")
    elif proxy_results and ip_is_axis is False:
        grade = "forte"
        note = ("Nem com o IP certo (proxy) a pagina mudou: o filtro e "
                "comportamental/JS, nao so IP. E o tier caro fazendo o servico.")
    elif proxy_results and ip_is_axis:
        grade = "medio"
        note = ("Cede ao IP certo: com proxy no pais-alvo a pagina muda. "
                "Sólido contra quem so troca header, mas IP resolve.")
    else:
        grade = "indeterminado"
        note = ("Todas as personas HTTP receberam a mesma pagina. Ou nao ha "
                "cloaker, ou o filtro e de IP -- rode de novo com --proxy para "
                "separar os dois.")

    return {
        "grade": grade,
        "leaked": bool(leaks),
        "leaks": leaks,
        "axes_read": axes_read,
        "ip_is_axis": ip_is_axis,
        "baseline_share": contagem[baseline] / len(content),
        "note": note,
    }
