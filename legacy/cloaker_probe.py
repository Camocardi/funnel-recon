#!/usr/bin/env python3
"""
cloaker_probe.py — mapeia QUAL camada do filtro de um cloaker está sendo acionada.

Isto NAO "quebra" cloaker. Ele dispara a mesma URL com varias personas
(TLS fingerprint + headers + referrer diferentes), segue a cadeia de redirect
de cada uma e compara os resultados. O diff te diz onde esta o filtro:

  - Todas as respostas identicas  -> filtro e IP/ASN/geo. So proxy resolve.
  - Respostas diferentes          -> filtro e header/TLS/referrer. Da pra ajustar.

Instalacao:
    pip install curl_cffi rich

Uso:
    python cloaker_probe.py "https://achadaspremium.shop/?fbclid=IwAR..."
    python cloaker_probe.py URL --proxy http://user:pass@host:porta
    python cloaker_probe.py URL --proxy socks5://... --json out.json
"""

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict

try:
    from curl_cffi import requests as cffi
except ImportError:
    sys.exit("Faltou dependencia. Rode:  pip install curl_cffi rich")


FB_REFERRER = "https://l.facebook.com/"

# ---------------------------------------------------------------------------
# PERSONAS
# ---------------------------------------------------------------------------
# 'impersonate' e o alvo de fingerprint TLS/JA3 do curl_cffi.
# A ordem importa: comecamos pelo pior caso (script cru) e subimos ate
# o navegador in-app do Facebook, que e o trafego que o cloaker MAIS quer deixar passar.

@dataclass
class Persona:
    name: str
    impersonate: str | None
    headers: dict = field(default_factory=dict)
    note: str = ""


PERSONAS = [
    Persona(
        name="python-cru",
        impersonate=None,
        headers={"User-Agent": "python-requests/2.31.0"},
        note="Baseline. Se ISTO passar, nao ha cloaker nenhum.",
    ),
    Persona(
        name="facebookexternalhit",
        impersonate=None,
        headers={
            "User-Agent": "facebookexternalhit/1.1 "
                          "(+http://www.facebook.com/externalhit_uatext.php)"
        },
        note="Crawler do Meta. O cloaker existe justamente pra enganar este.",
    ),
    Persona(
        name="googlebot",
        impersonate=None,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; "
                          "+http://www.google.com/bot.html)"
        },
        note="Alguns cloakers tem branch separado pra SEO.",
    ),
    Persona(
        name="chrome-desktop-us",
        impersonate="chrome124",
        headers={"Accept-Language": "en-US,en;q=0.9"},
        note="Chrome real (JA3 valido), sem referrer.",
    ),
    Persona(
        name="chrome-desktop-us+fb",
        impersonate="chrome124",
        headers={"Accept-Language": "en-US,en;q=0.9", "Referer": FB_REFERRER},
        note="Igual acima, mas com referrer do Facebook.",
    ),
    Persona(
        name="android-chrome-us+fb",
        impersonate="chrome131_android",
        headers={"Accept-Language": "en-US,en;q=0.9", "Referer": FB_REFERRER},
        note="Mobile Android. Maioria do trafego real e daqui.",
    ),
    Persona(
        name="safari-ios-us+fb",
        impersonate="safari17_2_ios",
        headers={"Accept-Language": "en-US,en;q=0.9", "Referer": FB_REFERRER},
        note="iPhone. Publico de maior valor, filtro costuma ser mais frouxo.",
    ),
    Persona(
        name="fb-inapp-ios",
        impersonate="safari17_2_ios",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21E236 "
                "[FBAN/FBIOS;FBDV/iPhone15,2;FBMD/iPhone;FBSN/iOS;FBSV/17.4;"
                "FBSS/3;FBID/phone;FBLC/en_US;FBOP/5]"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": FB_REFERRER,
        },
        note="Navegador in-app do Facebook. Os tokens FBAN/FBAV sao o sinal "
             "mais forte de clique organico. Melhor aposta da lista.",
    ),
    Persona(
        name="fb-inapp-ptbr",
        impersonate="safari17_2_ios",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21E236 "
                "[FBAN/FBIOS;FBDV/iPhone15,2;FBMD/iPhone;FBSN/iOS;FBSV/17.4;"
                "FBSS/3;FBID/phone;FBLC/pt_BR;FBOP/5]"
            ),
            "Accept-Language": "pt-BR,pt;q=0.9",
            "Referer": FB_REFERRER,
        },
        note="Controle de idioma: identico ao anterior, mas pt-BR. "
             "Se este divergir do en-US, o filtro le Accept-Language.",
    ),
]


# ---------------------------------------------------------------------------
# PROBE
# ---------------------------------------------------------------------------

@dataclass
class Result:
    persona: str
    ok: bool
    status: int | None = None
    hops: list = field(default_factory=list)
    final_url: str = ""
    title: str = ""
    body_sha: str = ""
    body_len: int = 0
    signals: list = field(default_factory=list)
    error: str = ""


# Pistas de que voce chegou na money page, nao na white page.
MONEY_PATTERNS = {
    "telegram": re.compile(r"(?:t\.me/|telegram\.me/|tg://)([A-Za-z0-9_]{4,})", re.I),
    "whatsapp": re.compile(r"(?:wa\.me/|api\.whatsapp\.com/send\?phone=)(\d{8,})", re.I),
    "meta_pixel": re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,})", re.I),
    "keitaro": re.compile(r"(?:kclickid|_subid|keitaro)", re.I),
    "js_redirect": re.compile(r"(?:window\.location(?:\.href)?\s*=|meta\s+http-equiv=[\"']refresh)", re.I),
}


def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:90] if m else ""


def scan_signals(html: str) -> list:
    found = []
    for label, pat in MONEY_PATTERNS.items():
        m = pat.search(html)
        if m:
            val = m.group(1) if m.groups() else ""
            found.append(f"{label}:{val}" if val else label)
    return found


# Os nomes de alvo do curl_cffi mudam entre versoes. Em vez de fixar um e
# quebrar, descemos a escada ate achar um que a versao instalada aceite.
FALLBACK_LADDER = {
    "android": ["chrome131_android", "chrome124_android", "chrome99_android"],
    "ios": ["safari17_2_ios", "safari17_0_ios", "safari15_5"],
    "desktop": ["chrome124", "chrome120", "chrome110", "chrome"],
}


def _candidates(target: str | None) -> list:
    if not target:
        return [None]
    if "android" in target:
        ladder = FALLBACK_LADDER["android"]
    elif "ios" in target or "safari" in target:
        ladder = FALLBACK_LADDER["ios"]
    else:
        ladder = FALLBACK_LADDER["desktop"]
    return [target] + [c for c in ladder if c != target]


def probe(url: str, p: Persona, proxy: str | None, timeout: int) -> Result:
    r = Result(persona=p.name, ok=False)
    kwargs = {
        "headers": p.headers,
        "timeout": timeout,
        "allow_redirects": True,
        "max_redirects": 12,
    }
    if proxy:
        kwargs["proxies"] = {"http": proxy, "https": proxy}

    resp = None
    for candidate in _candidates(p.impersonate):
        attempt = dict(kwargs)
        if candidate:
            attempt["impersonate"] = candidate
        try:
            resp = cffi.get(url, **attempt)
            break
        except Exception as e:
            msg = str(e)
            r.error = f"{type(e).__name__}: {msg}"
            # So vale tentar o proximo se a falha foi o alvo nao existir.
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
    # Normaliza antes de hashear: nonces e timestamps mudam a cada request
    # e criariam diff falso entre personas identicas.
    norm = re.sub(r"[0-9a-f]{16,}|\d{10,}", "", body)
    norm = re.sub(r"\s+", " ", norm).strip()
    r.body_sha = hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()[:12]
    r.title = extract_title(body)
    r.signals = scan_signals(body)
    return r


# ---------------------------------------------------------------------------
# RELATORIO
# ---------------------------------------------------------------------------

def report(results: list, proxy: str | None):
    print("\n" + "=" * 78)
    print("RESULTADO POR PERSONA")
    print("=" * 78)
    print(f"{'persona':<24}{'st':<5}{'hops':<6}{'bytes':<9}{'hash':<14}titulo")
    print("-" * 78)
    for r in results:
        if not r.ok:
            print(f"{r.persona:<24}{'ERR':<5}{'-':<6}{'-':<9}{'-':<14}{r.error[:30]}")
            continue
        print(f"{r.persona:<24}{r.status:<5}{len(r.hops):<6}"
              f"{r.body_len:<9}{r.body_sha:<14}{r.title[:32]}")

    good = [r for r in results if r.ok]

    print("\n" + "=" * 78)
    print("LEITURA")
    print("=" * 78)

    if not good:
        print("Nenhuma request completou. Cheque conectividade / proxy.")
        return

    # --- Guarda 1: URL invalida -------------------------------------------
    # Sem esta checagem o script confundia "caminho inexistente" com "cloaker
    # bloqueando tudo igual": um 404 e naturalmente identico pra toda persona.
    if all(r.status and r.status >= 400 for r in good):
        print("[X] TODAS as respostas foram erro (4xx/5xx). O veredito abaixo NAO vale.")
        print("    Isso quase sempre significa URL errada, nao cloaker.")
        print("    Voce testou a raiz do dominio? O cloaker mora num CAMINHO especifico.")
        print("    Pegue a URL completa que o anuncio aponta (com path e parametros)")
        print("    e rode de novo. Sem isso nao ha o que diagnosticar.\n")

    # --- Guarda 2: desafio de bot -----------------------------------------
    challenged = [r for r in good if r.status in (403, 503) and
                  re.search(r"cloudflare|attention required|just a moment|cf-ray", r.title, re.I)]
    if challenged:
        print(f"[i] {len(challenged)} persona(s) levaram desafio de bot (Cloudflare/WAF), "
              f"nao resposta do cloaker:")
        for r in challenged:
            print(f"      {r.persona}")
        print("    Existe WAF na frente do cloaker. Personas com fingerprint TLS de")
        print("    navegador real passaram; as de TLS cru nao. Isso e sinal de que a")
        print("    camada de impersonate esta funcionando.\n")

    # Desafios e erros nao sao paginas de conteudo: nao entram na comparacao.
    good = [r for r in good if r not in challenged and r.status and r.status < 400]
    if not good:
        print("Nenhuma resposta de conteudo (200) pra comparar. Corrija a URL e repita.")
        return

    hashes = {r.body_sha for r in good}

    if len(hashes) == 1:
        print("[!] TODAS as personas receberam a MESMA pagina.")
        print("    Nem o Googlebot nem o iPhone in-app divergiram. Isso significa")
        print("    que o filtro decidiu antes de olhar headers ou TLS -> e IP/ASN/geo.")
        if not proxy:
            print("\n    Voce rodou sem proxy, entao seu IP e o suspeito.")
            print("    Repita com --proxy apontando pra IP movel/residencial no PAIS ALVO.")
            print("    Sem isso, ajustar header e desperdicio de tempo.")
        else:
            print("\n    Voce ja usou proxy e mesmo assim nada mudou. Provavel que o proxy")
            print("    seja datacenter disfarcado, ou que exista camada JS de fingerprint")
            print("    (canvas/WebGL) que so browser real passa. Proximo passo e")
            print("    Camoufox ou patchright, nao mais tuning de header.")
    else:
        print(f"[+] {len(hashes)} respostas DISTINTAS. O filtro le headers/TLS/referrer.")
        print("    Agrupe e compare quem recebeu o que:\n")
        buckets = {}
        for r in good:
            buckets.setdefault(r.body_sha, []).append(r)
        for sha, group in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            names = ", ".join(g.persona for g in group)
            print(f"    {sha}  ({group[0].body_len:>7} b)  {names}")
        print("\n    Compare o que muda entre os grupos: idioma, referrer, mobile x desktop.")
        print("    A variavel que separa os grupos e o filtro.")

    hits = [r for r in good if r.signals]
    if hits:
        print("\n" + "=" * 78)
        print("SINAIS DE MONEY PAGE ENCONTRADOS")
        print("=" * 78)
        for r in hits:
            print(f"  {r.persona:<24} {', '.join(r.signals)}")
            if r.final_url != r.hops[0]:
                print(f"  {'':<24} destino final: {r.final_url[:70]}")
    else:
        print("\n  Nenhum sinal de money page (t.me, wa.me, pixel) em nenhuma resposta.")


def main():
    ap = argparse.ArgumentParser(description="Diagnostica qual camada do cloaker esta filtrando.")
    ap.add_argument("url", help="URL de destino COMPLETA, com fbclid e demais parametros")
    ap.add_argument("--proxy", help="ex: http://user:pass@host:porta  ou socks5://...")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--json", help="salvar resultado bruto em arquivo")
    args = ap.parse_args()

    print(f"alvo  : {args.url}")
    print(f"proxy : {args.proxy or 'NENHUM (seu IP real)'}")
    print(f"testes: {len(PERSONAS)}\n")

    results = []
    for p in PERSONAS:
        print(f"  -> {p.name} ...", end=" ", flush=True)
        r = probe(args.url, p, args.proxy, args.timeout)
        print("ok" if r.ok else f"falhou ({r.error[:40]})")
        results.append(r)

    report(results, args.proxy)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)
        print(f"\nJSON salvo em {args.json}")


if __name__ == "__main__":
    main()
