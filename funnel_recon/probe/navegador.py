"""Persona de navegador real [5]: Chromium com perfil persistente.

Complementa as personas HTTP, nao as substitui. A divisao de trabalho:

  personas HTTP  -- baratas, nove por alvo, e o que DIAGNOSTICA a camada do
                    filtro (todas iguais = IP; divergiram = header/TLS).
  navegador      -- caro, uma por alvo, e o que passa por parede de JS:
                    Cloudflare "checking your browser", cloaker que so decide
                    depois de executar script, VSL que so monta o player no
                    runtime.

Duas coisas que o navegador NAO faz, e vale dizer alto porque a expectativa
contraria custa dinheiro em proxy:

  - cookie de facebook.com nao chega no site do anunciante. Cookie e por
    dominio; estar logado no Meta nao te credencia em dominio de terceiro.
    Quem decide no cloaker e IP/ASN/geo, e depois disso Referer e User-Agent;
  - por isso `perfil="fb"` nao "passa" cloaker nenhum. Ele existe para o caso
    especifico de sondar uma pagina DO PROPRIO Meta, e cobra um preco -- ver
    paths.probe_profile_dir.

O que o perfil persistente SIM resolve, e nao e pouco:

  - cookie do PROPRIO alvo, com destaque para o `cf_clearance` do Cloudflare:
    passou o challenge uma vez, as proximas visitas entram direto. Como esta
    persona so e chamada quando bateu parede de JS, este e o ganho principal;
  - perfil com quilometragem (historico, cache, localStorage) pontua melhor
    em anti-bot do que perfil recem-criado.

E cobra: cloaker que marca o visitante na primeira visita passa a responder
sempre igual para quem volta -- e o visitante real do anuncio e SEMPRE
primeira visita, vindo do Facebook. Por isso `perfil="nenhum"` existe: e o
modo que reproduz a condicao que se quer medir. Persistir ajuda a ENTRAR;
nao persistir mantem o experimento honesto.

O Referer entra aqui como entra nas personas HTTP (personas.FB_REFERRER): e o
sinal barato que varios cloakers leem, e o navegador do PDF original nao o
mandava.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from ..paths import probe_profile_dir, profile_dir
from ..signals import scan_text, scan_values
from .personas import FB_REFERRER

PERFIS = ("probe", "fb", "nenhum")


def perfil_para(nome: str):
    """Diretorio de perfil, ou None para sessao descartavel."""
    if nome == "nenhum":
        return None
    if nome == "fb":
        return profile_dir()
    return probe_profile_dir()


def _proxy_playwright(proxy: str | None) -> dict | None:
    """Traduz o proxy normalizado para o formato do Chromium.

    O Chromium quer credencial em campo separado, nao embutida na URL -- e
    para SOCKS5 ele ignora credencial completamente (limitacao do proprio
    Chromium, nao do Playwright). Silenciar isso faria a sonda sair pelo IP de
    casa achando que estava no proxy, que e o erro mais caro deste projeto.
    """
    if not proxy:
        return None
    parts = urlparse(proxy if "://" in proxy else f"http://{proxy}")
    if not parts.hostname:
        raise ValueError(f"proxy irreconhecivel: {proxy}")
    conf = {"server": f"{parts.scheme}://{parts.hostname}:{parts.port or 80}"}
    if parts.username:
        if parts.scheme.startswith("socks"):
            raise ValueError(
                "O Chromium nao aplica usuario/senha em proxy SOCKS5. Use o "
                "proxy em HTTP para a persona de navegador, ou libere seu IP "
                "por allowlist no painel do provedor. (As personas HTTP "
                "continuam usando o SOCKS5 normalmente.)")
        conf["username"] = parts.username
        conf["password"] = parts.password or ""
    return conf


def run_navegador(url: str, proxy: str | None = None, timeout: int = 30000,
                  perfil: str = "probe", headless: bool = True):
    """Uma passada com Chromium real. Devolve um Probe, igual as personas HTTP.

    Devolver o MESMO tipo e o ponto: assim o resultado entra em
    to_scan_results, no banco, no relatorio e na interface sem nenhum caminho
    especial -- e pode ser comparado com as outras personas, que e o unico
    jeito de saber se o navegador viu algo diferente.
    """
    # _normalize e o [:12] vem do run_persona de proposito: o hash so serve
    # se for COMPARAVEL com o das personas HTTP -- e a comparacao de corpos e
    # que diz se o navegador viu algo diferente. Hash calculado de outro jeito
    # divergiria sempre, por construcao, e inventaria um cloaker inexistente.
    from .engine import CHALLENGE_MARKERS, TITLE_RE, Probe, _normalize

    r = Probe(persona=f"navegador:{perfil}")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        r.error = "playwright nao instalado (pip install playwright)"
        return r

    try:
        conf_proxy = _proxy_playwright(proxy)
    except ValueError as e:
        r.error = str(e)
        return r

    perfil_dir = perfil_para(perfil)
    lancamento = {
        "headless": headless,
        # Sem --no-sandbox e sem --disable-web-security: nenhum dos dois ajuda
        # a passar cloaker e os dois derrubam protecao do proprio navegador
        # que esta abrindo pagina hostil.
        "args": ["--disable-blink-features=AutomationControlled"],
    }
    if conf_proxy:
        lancamento["proxy"] = conf_proxy

    contexto = {
        "viewport": {"width": 1366, "height": 768},
        "locale": "en-US",
        "timezone_id": "America/New_York",
        "extra_http_headers": {"Accept-Language": "en-US,en;q=0.9"},
    }

    with sync_playwright() as p:
        browser = None
        if perfil_dir is not None:
            ctx = p.chromium.launch_persistent_context(
                user_data_dir=str(perfil_dir), **lancamento, **contexto)
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
        else:
            browser = p.chromium.launch(**lancamento)
            ctx = browser.new_context(**contexto)
            page = ctx.new_page()

        try:
            from playwright_stealth import Stealth
            Stealth().apply_stealth_sync(page)
        except Exception:
            pass  # stealth e melhoria, nao requisito: sem ele a sonda vale igual

        try:
            # O Referer do Facebook e o mesmo que as personas HTTP mandam.
            # `networkidle` espera 500ms sem NENHUMA requisicao. Numa pagina
            # com pixel e tracker, por proxy movel, isso pode nunca acontecer
            # -- e o goto estoura o timeout mesmo com a pagina ja renderizada.
            # Medido: o mesmo alvo que o curl busca em 2s pelo proxy dava
            # ERR_TIMED_OUT aqui. `domcontentloaded` + uma espera curta pega o
            # HTML depois do JS sem depender da rede silenciar.
            resp = page.goto(url, wait_until="domcontentloaded",
                             timeout=timeout, referer=FB_REFERRER)
            try:
                page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:
                pass  # rede que nao silencia nao invalida o que ja carregou
            page.wait_for_timeout(1500)
            html = page.content()
            r.ok = True
            r.status = resp.status if resp else None
            r.final_url = page.url
            r.body_len = len(html)
            r.body_sha = hashlib.sha256(
                _normalize(html).encode("utf-8", "replace")).hexdigest()[:12]
            m = TITLE_RE.search(html)
            r.title = re.sub(r"\s+", " ", m.group(1)).strip()[:90] if m else ""
            r.signals = scan_text(html)
            r.values = scan_values(html)
            r.is_challenge = bool(CHALLENGE_MARKERS.search(html))
            if resp is not None:
                r.hops = [resp.url]
        except Exception as e:
            r.error = f"{type(e).__name__}: {e}"
        finally:
            try:
                ctx.close()
            except Exception:
                pass
            if browser is not None:
                try:
                    browser.close()   # sem isto o processo do Chromium vaza
                except Exception:
                    pass
    return r
