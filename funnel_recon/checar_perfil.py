"""O que um cloaker VE do seu navegador -- para voce checar antes de gastar clique.

Os campos abaixo sao exatamente os que o `captcha.min.js` do The White Rabbit
coleta (lido de uma money page real). Isto NAO engana o filtro: roda os mesmos
testes no SEU navegador e diz o que ele entregaria. Se `webdriver` vier true ou
`plugins` vier 0, voce e recusado antes de clicar em nada, e proxy nenhum
resolve -- o problema esta no ambiente, nao no IP.

Uso pratico: cole SNIPPET_JS no console do perfil do Dolphin/navegador que voce
vai usar, e compare com as regras em avaliar().
"""

from __future__ import annotations

# Cole isto no console do navegador que voce vai usar. Devolve um objeto com o
# que o cloaker le. Sao os campos do captcha.min.js do TWR, nada a mais.
SNIPPET_JS = r"""
(() => {
  const r = {
    webdriver: navigator.webdriver,
    plugins: navigator.plugins ? navigator.plugins.length : 0,
    language: navigator.language,
    languages: (navigator.languages || []).join(","),
    platform: navigator.platform,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemory: navigator.deviceMemory,
    maxTouchPoints: navigator.maxTouchPoints,
    touch: ('ontouchstart' in window) || navigator.maxTouchPoints > 0,
    cookieEnabled: navigator.cookieEnabled,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    inner: [innerWidth, innerHeight],
    outer: [outerWidth, outerHeight],
    dpr: devicePixelRatio,
    screen: [screen.width, screen.height, screen.colorDepth],
    referrer: document.referrer,
    battery: !!navigator.getBattery,
    ua: navigator.userAgent,
  };
  console.log(JSON.stringify(r, null, 2));
  return r;
})()
"""


def avaliar(dados: dict, geo_pais: str | None = None,
            geo_timezone: str | None = None) -> list[dict]:
    """Aplica as regras do TWR aos dados coletados. Cada item: campo, ok, nota.

    `geo_pais`/`geo_timezone` sao o que o ipapi.co (que o proprio script chama)
    veria pelo SEU IP -- passe-os para pegar a incoerencia geo x fuso, que e a
    checagem mais forte e a que mais derrubou o usuario.
    """
    achados: list[dict] = []

    def add(campo, ok, nota):
        achados.append({"campo": campo, "ok": ok, "nota": nota})

    wd = dados.get("webdriver")
    add("webdriver", wd is False or wd is None,
        "navegador automatizado (Playwright/Selenium) -- recusa quase certa"
        if wd else "ok: sem flag de automacao")

    plugins = dados.get("plugins", 0)
    add("plugins", plugins and plugins > 0,
        "0 plugins e assinatura de headless" if not plugins
        else f"ok: {plugins} plugins")

    inner = dados.get("inner") or [0, 0]
    outer = dados.get("outer") or [0, 0]
    outer_ok = outer[0] and outer[1] and outer[0] >= inner[0]
    add("janela", bool(outer_ok),
        "outer_width/height zerado ou menor que inner -- tipico de headless"
        if not outer_ok else "ok: janela com moldura real")

    hc = dados.get("hardwareConcurrency")
    add("hardwareConcurrency", bool(hc),
        "sem contagem de nucleos e sinal de ambiente sintetico" if not hc
        else f"ok: {hc} nucleos")

    tz = dados.get("timezone") or ""
    if geo_timezone:
        bate = tz == geo_timezone
        add("fuso x IP", bate,
            f"fuso do navegador ({tz}) != fuso do IP ({geo_timezone}) -- "
            "incoerencia que o cloaker cruza" if not bate
            else f"ok: fuso bate com o IP ({tz})")
    else:
        add("fuso", bool(tz), f"fuso: {tz or '(vazio)'}"
            " -- passe geo_timezone para checar coerencia com o IP")

    lang = dados.get("language") or ""
    if geo_pais:
        pais = geo_pais.upper()
        esperado = {"US": "en", "BR": "pt", "ES": "es", "MX": "es"}.get(pais)
        bate = (not esperado) or lang.lower().startswith(esperado)
        add("idioma x pais", bate,
            f"idioma {lang} destoa do pais do IP ({pais})" if not bate
            else f"ok: idioma {lang} coerente com {pais}")

    ref = dados.get("referrer") or ""
    add("referrer", "facebook.com" in ref or "l.facebook" in ref,
        "sem referrer do Facebook -- clique organico manda l.facebook.com; "
        "colar URL na barra nao" if "facebook" not in ref
        else "ok: veio do Facebook")

    return achados
