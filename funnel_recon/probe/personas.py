"""Personas do estagio [3]: combinacoes de TLS + headers + referrer.

A ordem importa e nao e cosmetica. Vai do pior caso (script cru, que todo
cloaker bloqueia) ate o navegador in-app do Facebook, que e o trafego que o
cloaker MAIS quer deixar passar -- porque e o clique que ele pagou para ter.
Ler a tabela de cima para baixo mostra em qual degrau o filtro acordou.

Os pares de controle sao o que torna o diagnostico util: duas personas que
diferem em UMA variavel so. Se elas divergirem, a variavel e o filtro.
  - chrome-desktop-us  x  chrome-desktop-us+fb   -> isola o REFERRER
  - fb-inapp-ios       x  fb-inapp-ptbr          -> isola o IDIOMA
  - chrome-desktop-us  x  android-chrome-us+fb   -> isola desktop x mobile
"""

from __future__ import annotations

from dataclasses import dataclass, field

FB_REFERRER = "https://l.facebook.com/"

# Os nomes de alvo do curl_cffi mudam entre versoes, e alvo inexistente levanta
# ImpersonateError. Em vez de fixar um e quebrar na proxima atualizacao,
# descemos a escada ate achar um que a versao instalada aceite.
# Verificado contra curl_cffi 0.16: `safari17_0_ios` e `chrome124_android`
# nao existem mais e foram removidos das escadas.
FALLBACK_LADDER = {
    "android": ["chrome131_android", "chrome99_android"],
    "ios": ["safari18_4_ios", "safari18_0_ios", "safari17_2_ios", "safari_ios"],
    "desktop": ["chrome146", "chrome142", "chrome136", "chrome124", "chrome"],
}


@dataclass
class Persona:
    name: str
    impersonate: str | None
    headers: dict = field(default_factory=dict)
    note: str = ""


PERSONAS: list[Persona] = [
    Persona(
        name="python-cru",
        impersonate=None,
        headers={"User-Agent": "python-requests/2.31.0"},
        note="Baseline. Se ISTO passar, nao ha cloaker nenhum.",
    ),
    Persona(
        name="facebookexternalhit",
        impersonate=None,
        headers={"User-Agent": "facebookexternalhit/1.1 "
                               "(+http://www.facebook.com/externalhit_uatext.php)"},
        note="Crawler do Meta. O cloaker existe justamente pra enganar este.",
    ),
    Persona(
        name="googlebot",
        impersonate=None,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; "
                               "+http://www.google.com/bot.html)"},
        note="Alguns cloakers tem branch separado pra SEO.",
    ),
    Persona(
        name="chrome-desktop-us",
        impersonate="chrome146",
        headers={"Accept-Language": "en-US,en;q=0.9"},
        note="Chrome real (JA3 valido), SEM referrer. Controle de referrer.",
    ),
    Persona(
        name="chrome-desktop-us+fb",
        impersonate="chrome146",
        headers={"Accept-Language": "en-US,en;q=0.9", "Referer": FB_REFERRER},
        note="Identico ao anterior, COM referrer do Facebook. Se divergir, "
             "o filtro le o Referer.",
    ),
    Persona(
        name="android-chrome-us+fb",
        impersonate="chrome131_android",
        headers={"Accept-Language": "en-US,en;q=0.9", "Referer": FB_REFERRER},
        note="Mobile Android. Maioria do trafego real e daqui.",
    ),
    Persona(
        name="safari-ios-us+fb",
        impersonate="safari18_4_ios",
        headers={"Accept-Language": "en-US,en;q=0.9", "Referer": FB_REFERRER},
        note="iPhone. Publico de maior valor, filtro costuma ser mais frouxo.",
    ),
    Persona(
        name="fb-inapp-ios",
        impersonate="safari18_4_ios",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22E240 "
                "[FBAN/FBIOS;FBDV/iPhone16,2;FBMD/iPhone;FBSN/iOS;FBSV/18.4;"
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
        impersonate="safari18_4_ios",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/22E240 "
                "[FBAN/FBIOS;FBDV/iPhone16,2;FBMD/iPhone;FBSN/iOS;FBSV/18.4;"
                "FBSS/3;FBID/phone;FBLC/pt_BR;FBOP/5]"
            ),
            "Accept-Language": "pt-BR,pt;q=0.9",
            "Referer": FB_REFERRER,
        },
        note="Controle de idioma: identico ao anterior, mas pt-BR. Se este "
             "divergir do en-US, o filtro le Accept-Language.",
    ),
]


def candidates(target: str | None) -> list[str | None]:
    """Escada de alvos a tentar para uma persona."""
    if not target:
        return [None]
    if "android" in target:
        ladder = FALLBACK_LADDER["android"]
    elif "ios" in target or "safari" in target:
        ladder = FALLBACK_LADDER["ios"]
    else:
        ladder = FALLBACK_LADDER["desktop"]
    return [target] + [c for c in ladder if c != target]


def by_name(names: list[str]) -> list[Persona]:
    index = {p.name: p for p in PERSONAS}
    return [index[n] for n in names if n in index]
