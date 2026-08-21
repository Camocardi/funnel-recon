"""Sinais de money page e ruido conhecido. Compartilhado entre OSINT [2],
probe [3] e classificador [6] -- uma lista so, para nao divergirem.

Fonte: secoes 3 e 6 do brief.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Destino de funil: para onde a money page manda o usuario de verdade.
FUNNEL_PATTERNS: dict[str, re.Pattern[str]] = {
    "telegram_link": re.compile(r"(?:https?://)?t\.me/[+\w/]+", re.I),
    "telegram_scheme": re.compile(r"tg://(?:resolve|join)\S*", re.I),
    # Precisa de CONTEXTO. `\b\w{3,32}bot\b` sozinho casava com "chatbot",
    # "robot", "Abbot" -- e transformava qualquer pagina institucional em
    # suspeita de funil de Telegram.
    "telegram_bot": re.compile(r"(?:@|t\.me/|telegram\.me/)[A-Za-z0-9_]{3,30}bot\b", re.I),
    "whatsapp_link": re.compile(r"(?:https?://)?(?:wa\.me|api\.whatsapp\.com|chat\.whatsapp\.com)/\S+", re.I),
}

# Instrumentacao: nao prova money page sozinha, mas white pages genericas
# raramente carregam pixel de conversao apontado para campanha ativa.
TRACKING_PATTERNS: dict[str, re.Pattern[str]] = {
    "fb_pixel": re.compile(r"fbq\s*\(\s*['\"]init['\"]", re.I),
    "gtag": re.compile(r"gtag\s*\(\s*['\"]config['\"]", re.I),
    "tracker_keitaro": re.compile(r"\b(?:kclickid|keitaro|_subid)\b", re.I),
    "tracker_binom": re.compile(r"\bbinom\b|\bclickid=|\bcamp_id\b", re.I),
    "tracker_redtrack": re.compile(r"\bredtrack|rtkclickid\b", re.I),
    "js_redirect": re.compile(r"(?:window\.)?location(?:\.href)?\s*=|location\.replace\s*\(", re.I),
    "meta_refresh": re.compile(r"<meta[^>]+http-equiv=['\"]?refresh", re.I),
}

# Plataformas de cloaking vendidas como servico (SaaS). Achar uma delas entre
# os dominios do alvo e o sinal mais direto que existe nesta ferramenta: nao e
# inferencia sobre comportamento, e a ferramenta do adversario aparecendo pelo
# proprio nome. Tambem muda o que esperar do probe -- cloaker de prateleira
# filtra por IP/ASN antes de olhar qualquer header.
#
# A lista e curta de proposito: so entra marca CONFIRMADA em dado real. Para
# o resto existe a heuristica abaixo, que reporta como suspeita, nao como fato.
CLOAKER_BRANDS = {
    "cloakby": "CloakBy",    # visto em track.cloakby.com, dados reais
    "cloakup": "CloakUp",    # citado por operador como top de linha, ago/2026
    "thewhiterabbit": "The White Rabbit",  # idem -- "nivel absurdo de quebrar"
    "whiterabbit": "The White Rabbit",
}
CLOAK_HINT = re.compile(r"cloak", re.I)

# Caminho de redirecionador de tracker: `/l/<hash>`, `/go/<id>`, etc.
# Encontrar isto significa que a URL util tem PATH -- sondar a raiz da 404.
REDIRECTOR_PATH = re.compile(r"^/(?:l|go|r|click|out|link|redir)/[A-Za-z0-9_-]{4,}$", re.I)

# Erro 4 da secao 4: o fallback de DOM capturava links internos do Meta.
# Todo dominio que sair de qualquer coletor passa por aqui.
META_HOSTS = {
    "facebook.com", "www.facebook.com", "m.facebook.com", "l.facebook.com",
    "fb.me", "fbcdn.net", "transparency.meta.com", "meta.com", "www.meta.com",
    "instagram.com", "www.instagram.com", "whatsapp.com", "messenger.com",
    "fb.com", "static.xx.fbcdn.net", "scontent.xx.fbcdn.net",
}


def is_meta_host(host: str) -> bool:
    """True para dominios do proprio Meta (ruido, nunca alvo)."""
    host = (host or "").lower().strip().lstrip(".")
    if host in META_HOSTS:
        return True
    return any(host == m or host.endswith("." + m) for m in META_HOSTS)


# Padroes que extraem o VALOR, nao so a presenca: o handle do bot e o ID do
# pixel sao o achado em si -- e o handle e clicavel, da para ir no funil direto.
VALUE_PATTERNS: dict[str, re.Pattern[str]] = {
    "telegram": re.compile(r"(?:t\.me/|telegram\.me/|tg://resolve\?domain=)([+A-Za-z0-9_]{4,64})", re.I),
    "bot_handle": re.compile(r"@([A-Za-z0-9_]{4,30}[Bb]ot)\b"),
    "whatsapp": re.compile(r"(?:wa\.me/|api\.whatsapp\.com/send\?phone=)(\+?\d{8,15})", re.I),
    "meta_pixel": re.compile(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,})", re.I),
    # Onde o dinheiro entra. Achar isto e o fim da linha da investigacao: o
    # checkout carrega o ID do produto, que identifica a oferta mesmo quando
    # o dominio da VSL for trocado amanha.
    # So a URL de order form -- a que leva a pagar. O `(?![^\s"'<>]*\.
    # (?:css|js|png|...))` derruba os assets do proprio checkout (folha de
    # estilo, selo, imagem), que numa pagina da Digistore sao dezenas e
    # afogariam o link que interessa.
    "checkout": re.compile(
        r'(https?://[^\s"\'<>]*(?:checkout-ds24|digistore24|hotmart|kiwify|'
        r'monetizze|braip|clickbank|buygoods|payment\.|checkout\.)'
        r'[^\s"\'<>]*?/(?:product|checkout|order|pay|buy|pb/order)/[^\s"\'<>]*)', re.I),
    # Player de VSL: confirma que a pagina e a OFERTA, e nao a white page.
    # Vale por si: uma pagina generica de despejo nao carrega player de venda.
    "vsl_player": re.compile(
        r'(https?://[^\s"\'<>]*(?:converteai\.net|vturb|pandavideo|'
        r'vslplayer)[^\s"\'<>]*)', re.I),
    # O ID do video da VSL, no formato do VTurb/converteai. Isto e o que
    # DIFERENCIA uma VSL da outra: quando o operador troca o video, muda este
    # id -- e ai da para provar "a VSL que voce ve nao e a que temos" sem
    # depender de olhar as duas no olho. Foi a pergunta exata que travou a
    # investigacao: era a VSL nova ou a antiga?
    "vsl_video": re.compile(
        r'(?:converteai\.net|vturb[^"\'<>]*?)/([a-f0-9]{8}-[a-f0-9]{4}-'
        r'[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', re.I),
}


def scan_text(text: str) -> list[str]:
    """Nomes dos sinais encontrados no texto. Ordem estavel."""
    if not text:
        return []
    found = []
    for name, pat in {**FUNNEL_PATTERNS, **TRACKING_PATTERNS}.items():
        if pat.search(text):
            found.append(name)
    return found


def scan_values(text: str, limit: int = 25) -> list[str]:
    """Sinais com o valor capturado: `telegram:+abc123`, `meta_pixel:1234...`.

    Complementa scan_text: aquele diz QUE existe funil, este diz QUAL e.
    """
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for name, pat in VALUE_PATTERNS.items():
        for m in pat.finditer(text):
            item = f"{name}:{m.group(1)}"
            if item not in seen:
                seen.add(item)
                out.append(item)
            if len(out) >= limit:
                return out
    return out


# Destinos que SAO funil por natureza: sair para eles nao e ser despejado.
FUNNEL_HOSTS = {"t.me", "telegram.me", "wa.me", "api.whatsapp.com",
                "chat.whatsapp.com", "web.whatsapp.com"}

# Prefixos de valor que indicam funil de verdade. `meta_pixel:` NAO entra:
# pixel do Facebook existe em toda loja do planeta, e trata-lo como prova de
# money page fazia o app anunciar "cheguei na money page" sobre o site de uma
# faculdade americana -- caso real.
FUNNEL_VALUE_PREFIXES = ("telegram:", "bot_handle:", "whatsapp:", "checkout:")


def is_funnel_value(value: str) -> bool:
    return value.startswith(FUNNEL_VALUE_PREFIXES)


def is_funnel_host(host: str) -> bool:
    h = registrable_host(host)
    return h in FUNNEL_HOSTS


def bounced_offsite(final_url: str, target_url: str) -> str:
    """Host de terceiro para onde a resposta levou, ou "" se ficou em casa.

    O cloaker moderno nao monta white page: ele DESPEJA quem falha no filtro
    no site real de outra pessoa. Nos dados reais, `achadaspremium.shop` jogava
    todas as personas em `cwc.edu` (Central Wyoming College) e
    `sensualdesireart.site/quiz` jogava em um site de tarot. E a white page
    mais barata que existe -- SSL valido, conteudo real, historico real -- e
    quem revisa o anuncio nao tem o que denunciar.

    Sair para t.me/wa.me nao conta: isso e o funil, nao o despejo.
    """
    if not final_url or not target_url:
        return ""
    destino = registrable_host(final_url)
    if not destino or is_funnel_host(destino):
        return ""
    if apex_domain(destino) == apex_domain(target_url):
        return ""
    return destino


def has_funnel_signal(signals: list[str]) -> bool:
    return any(s in FUNNEL_PATTERNS for s in signals)


def looks_like_redirector(url: str) -> bool:
    try:
        return bool(REDIRECTOR_PATH.match(urlparse(url).path or ""))
    except ValueError:
        return False


def registrable_host(url_or_host: str) -> str:
    """Extrai o host de uma URL, ou devolve a string se ja for host."""
    s = (url_or_host or "").strip()
    if "://" in s:
        s = urlparse(s).netloc
    return s.split("@")[-1].split(":")[0].lower().rstrip(".")


# Sufixos de dois rotulos. Sem esta lista, `x.alvo.com.br` teria apex
# `com.br` -- e ai a busca por subdominios irmaos pediria "tudo que existe
# em .com.br" para o Certificate Transparency.
#
# Nao e a Public Suffix List inteira de proposito: ela tem ~9.000 entradas,
# muda sozinha e exigiria baixar e atualizar. Estes cobrem o que aparece em
# operacao de anuncio; o pior caso de um sufixo ausente e enumerar de menos,
# nunca pedir a internet inteira.
MULTI_TLD = {
    "com.br", "net.br", "org.br", "com.pt", "co.uk", "org.uk", "me.uk",
    "com.au", "net.au", "com.mx", "com.ar", "com.co", "com.es", "com.tr",
    "co.jp", "co.kr", "co.in", "co.za", "co.nz", "com.pe", "com.cl",
}


def cloaker_platform(url_or_host: str) -> tuple[str, bool]:
    """(nome_da_plataforma, confirmado). ("", False) quando nao parece cloaker.

    `confirmado=False` significa "o nome do dominio tem cara de cloaker mas nao
    esta na lista". Vale reportar -- e barato de conferir a olho -- mas nao vale
    afirmar, e o relatorio precisa dizer qual dos dois e.
    """
    apex = apex_domain(url_or_host)
    rotulo = apex.split(".")[0] if apex else ""
    if rotulo in CLOAKER_BRANDS:
        return CLOAKER_BRANDS[rotulo], True
    if rotulo and CLOAK_HINT.search(rotulo):
        return rotulo, False
    return "", False


def apex_domain(url_or_host: str) -> str:
    """O dominio registravel: `massagem.sensualdesireart.site` -> o apex.

    Existe porque Certificate Transparency so revela IRMAOS quando a consulta
    e feita no apex. Perguntar por `%.massagem.sensualdesireart.site` devolve
    o proprio e mais nada -- foi exatamente o que aconteceu na primeira
    analise real, e o `app.`/`track.` da mesma operacao ficaram invisiveis.
    """
    host = registrable_host(url_or_host)
    partes = host.split(".")
    if len(partes) <= 2:
        return host
    if ".".join(partes[-2:]) in MULTI_TLD:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])
