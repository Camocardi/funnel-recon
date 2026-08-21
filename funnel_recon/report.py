"""Relatorio de terminal do OSINT.

Principio da secao 2 e 6: relatorio honesto. Ausencia de achado e dita como
ausencia ("0 scans, ninguem capturou"), nunca disfarcada de resultado, e o
proximo passo concreto vem junto.
"""

from __future__ import annotations

from collections import defaultdict

from .schema import ScanResult

W = 78
LINE, THIN = "=" * W, "-" * W


def _by_prefix(signals: list[str], prefix: str) -> list[str]:
    return [s.split(":", 1)[1] for s in signals if s.startswith(prefix + ":")]


def _has(signals: list[str], name: str) -> bool:
    return name in signals


def render_domain(domain: str, results: list[ScanResult]) -> str:
    out: list[str] = ["", LINE, f"DOMINIO: {domain}", LINE]
    by_source = {r.source: r for r in results}
    all_signals = [s for r in results for s in r.signals]

    out.append(f"{'fonte':<14}{'status':<34}sinais")
    out.append(THIN)
    for r in results:
        status = r.error[:32] if r.verdict == "error" else (r.status or "-")
        mark = "ERRO " if r.verdict == "error" else ""
        out.append(f"{r.source:<14}{mark + str(status):<34}{len(r.signals)}")

    # --- achados que mudam o proximo passo ---------------------------------
    findings: list[str] = []

    redirs = _by_prefix(all_signals, "archived_redirector")
    if redirs:
        findings.append(
            "[+] CAMINHO DE REDIRECIONADOR ARQUIVADO — este e o formato da URL real.\n"
            + "".join(f"      {u}\n" for u in redirs[:6])
            + "    Sonde ESTE caminho, nao a raiz. Raiz de tracker da 404 (erro 1 da secao 4)."
        )

    revealing = _by_prefix(all_signals, "revealing_subdomain")
    if revealing:
        findings.append(
            "[+] SUBDOMINIO REVELADOR\n"
            + "".join(f"      {s}\n" for s in revealing[:8])
            + "    Infra de funil exposta em Certificate Transparency."
        )

    finals = _by_prefix(all_signals, "urlscan_final_url")
    if finals:
        findings.append(
            "[+] urlscan JA CAPTUROU este dominio — alguem clicou por voce.\n"
            + "".join(f"      {u}\n" for u in finals[:5])
            + "".join(f"      screenshot: {u}\n" for u in _by_prefix(all_signals, "urlscan_screenshot")[:3])
        )

    funnel = sorted({s.split(":", 1)[1] for s in all_signals
                     if s.startswith(("in_scanned_url:", "in_archived_url:"))})
    if funnel:
        findings.append(
            f"[!] SINAL DE FUNIL em URL publica: {', '.join(funnel)}\n"
            "    Money page pode estar exposta sem precisar furar o cloaker."
        )

    third = _by_prefix(all_signals, "third_party_host")
    if third:
        findings.append(
            "[i] HOSTS DE TERCEIRO contatados pela pagina (candidatos a asset\n"
            "    externo de criativo -> mandar para o probe [3]):\n"
            + "      " + ", ".join(third[:12])
        )

    created = _by_prefix(all_signals, "domain_created")
    age = _by_prefix(all_signals, "domain_age_days")
    young = _by_prefix(all_signals, "young_domain")
    if created and age:
        reg = _by_prefix(all_signals, "registrar")
        line = f"[{'!' if young else 'i'}] REGISTRADO EM {created[0]} ({age[0]} dias atras)"
        if reg:
            line += f", via {reg[0]}"
        if young:
            line += ("\n    Infra descartavel — coerente com operacao de cloaking,\n"
                     "    nao com negocio de verdade.")
        findings.append(line)
    elif _has(all_signals, "domain_age_unknown"):
        findings.append("[i] Idade do dominio desconhecida (RDAP sem evento de registro).")
    if _has(all_signals, "behind_cloudflare"):
        findings.append(
            "[i] Cloudflare na frente. Um 403/503 no probe e DESAFIO DE WAF,\n"
            "    nao resposta do cloaker — nao confunda as camadas (erro 3 da secao 4)."
        )
    if _has(all_signals, "no_mx_record"):
        findings.append("[i] Sem registro MX: dominio nao recebe e-mail, nao e negocio real.")

    if findings:
        out += ["", "ACHADOS", THIN]
        out += findings
    else:
        out += ["", "ACHADOS", THIN,
                "    Nenhum achado acionavel. Cada 'nao' estreita o problema:"]

    # --- ausencias, ditas como ausencia ------------------------------------
    gaps: list[str] = []
    if _has(all_signals, "no_public_scan"):
        gaps.append("urlscan: 0 scans — ninguem capturou este dominio ainda.")
    if _has(all_signals, "no_wayback_snapshot"):
        gaps.append("wayback: 0 snapshots — sem historico arquivado.")
    if not _by_prefix(all_signals, "subdomain"):
        gaps.append("crt.sh: nenhum subdominio em Certificate Transparency.")
    if _has(all_signals, "whois_unavailable"):
        gaps.append("whois: registro nao disponivel (comum em .shop/.xyz).")
    errs = [r for r in results if r.verdict == "error"]
    for r in errs:
        gaps.append(f"{r.source}: FALHOU — {r.error[:60]}")
    if gaps:
        out += ["", "AUSENCIAS E LACUNAS", THIN] + [f"    {g}" for g in gaps]

    # --- proximo passo -----------------------------------------------------
    out += ["", "PROXIMO PASSO", THIN]
    if redirs:
        out.append(f"    python -m funnel_recon probe \"{redirs[0]}\"")
    elif finals:
        out.append(f"    python -m funnel_recon probe \"{finals[0]}\"")
    else:
        out.append("    OSINT nao expos o funil. Isso NAO significa que nao ha funil —")
        out.append("    significa que a pegada publica esta limpa, o que e esperado num")
        out.append("    dominio descartavel. Va para o estagio [1]: colete os anuncios na")
        out.append("    Biblioteca e pegue a URL REAL (com path + fbclid) do export.")
        out.append("    Sondar a raiz do dominio aqui seria repetir o erro 1 da secao 4.")

    return "\n".join(out)


def _correlate(all_results: dict[str, list[ScanResult]]) -> list[str]:
    """Dominios que compartilham infraestrutura sao do mesmo operador.

    O par de nameservers e o sinal mais forte: DNS gerenciado (Cloudflare e
    afins) atribui o par por CONTA, nao por dominio. Dois dominios com o mesmo
    par sairam da mesma conta. Registrar sozinho vale pouco (Hostinger tem
    milhoes de clientes); vale como reforco quando o NS ja bateu.
    """
    buckets: dict[str, dict[str, set[str]]] = {
        "ns_pair": defaultdict(set), "ip": defaultdict(set), "registrar": defaultdict(set),
    }
    for domain, results in all_results.items():
        for r in results:
            for sig in r.signals:
                for key in buckets:
                    if sig.startswith(key + ":"):
                        buckets[key][sig.split(":", 1)[1]].add(domain)

    out: list[str] = []
    for value, doms in sorted(buckets["ns_pair"].items()):
        if len(doms) > 1:
            out.append(f"[+] MESMO PAR DE NAMESERVERS -> mesma conta de DNS, mesmo operador:")
            out.append(f"      {value}")
            out.append(f"      {', '.join(sorted(doms))}")
            out.append("    Pivo: um DNS reverso por este par de NS lista os OUTROS")
            out.append("    dominios do mesmo dono, inclusive os que voce ainda nao viu.")
    for value, doms in sorted(buckets["ip"].items()):
        if len(doms) > 1:
            out.append(f"[+] MESMO IP {value}: {', '.join(sorted(doms))}")
    for value, doms in sorted(buckets["registrar"].items()):
        if len(doms) > 1:
            out.append(f"[i] Mesmo registrar ({value}): {', '.join(sorted(doms))}"
                       " — fraco sozinho, reforco se o NS tambem bateu.")
    return out


def render(all_results: dict[str, list[ScanResult]]) -> str:
    parts = [render_domain(d, rs) for d, rs in all_results.items()]

    if len(all_results) > 1:
        parts += ["", LINE, f"CORRELACAO ENTRE {len(all_results)} DOMINIOS", LINE]
        corr = _correlate(all_results)
        parts += corr if corr else ["    Nenhuma infraestrutura compartilhada detectada."]

        errs = sum(1 for rs in all_results.values() for r in rs if r.verdict == "error")
        if errs:
            parts.append(f"\n    {errs} consulta(s) de fonte falharam.")
    return "\n".join(parts)


# ===========================================================================
# PROBE [3]
# ===========================================================================

PREFLIGHT_MSG = {
    "url_e_raiz": (
        "[!] Voce passou a RAIZ do dominio, sem caminho depois da barra.\n"
        "    Esse foi o erro que custou varias rodadas na investigacao original:\n"
        "    o cloaker mora num CAMINHO (`/l/<hash>`), e a raiz de um tracker\n"
        "    responde 404 por natureza. 404 e igual pra toda persona, entao o\n"
        "    diagnostico sairia 'filtro por IP' sem que isso fosse verdade.\n"
        "    Pegue a URL completa na coluna `url` do export do coletor [1]."
    ),
    "sem_fbclid": (
        "[i] URL sem `fbclid`. Muitos cloakers so entregam a money page pra\n"
        "    quem chega com click ID do Facebook. Vale rodar assim mesmo, mas\n"
        "    se tudo vier branco, pegue a URL com fbclid antes de culpar o IP."
    ),
    "url_sem_esquema": "[!] URL sem http:// ou https://.",
    "url_invalida": "[!] URL invalida.",
}


def render_probe(url: str, probes, proxy: str | None, warns: list[str]) -> str:
    out: list[str] = ["", LINE, "RESULTADO POR PERSONA", LINE]
    out.append(f"{'persona':<24}{'st':<6}{'hops':<6}{'bytes':<10}{'hash':<14}titulo")
    out.append(THIN)
    for p in probes:
        if not p.ok:
            out.append(f"{p.persona:<24}{'ERR':<6}{'-':<6}{'-':<10}{'-':<14}{p.error[:28]}")
            continue
        flag = "WAF" if p.is_challenge else str(p.status)
        out.append(f"{p.persona:<24}{flag:<6}{len(p.hops):<6}"
                   f"{p.body_len:<10}{p.body_sha:<14}{p.title[:30]}")

    out += ["", LINE, "LEITURA", LINE]

    ok = [p for p in probes if p.ok]
    if not ok:
        out.append("Nenhuma requisicao completou. Cheque conexao / proxy / URL.")
        return "\n".join(out)

    # --- Guarda 1: URL errada (erro 2 da secao 4) --------------------------
    if all(p.status and p.status >= 400 for p in ok):
        out.append("[X] TODAS as respostas foram erro (4xx/5xx). O veredito NAO vale.")
        out.append("    4xx/5xx e identico pra toda persona POR DEFINICAO, entao isso")
        out.append("    nunca prova 'cloaker filtrando tudo igual'. Quase sempre e URL")
        out.append("    errada.")
        if "url_e_raiz" in warns:
            out.append("    E de fato voce passou a raiz do dominio. E isso.")
        return "\n".join(out)

    # --- Guarda 2: WAF nao e cloaker (erro 3 da secao 4) -------------------
    challenged = [p for p in ok if p.is_challenge]
    if challenged:
        out.append(f"[i] {len(challenged)} persona(s) levaram DESAFIO DE WAF "
                   "(Cloudflare/DDoS-Guard),")
        out.append("    o que e uma camada ANTES do cloaker, nao a resposta dele:")
        for p in challenged:
            out.append(f"      {p.persona}")
        out.append("    Personas com TLS de navegador real costumam passar; as de TLS")
        out.append("    cru, nao. Se foi esse o padrao, o impersonate esta funcionando.")
        out.append("")

    content = [p for p in ok if not p.is_challenge and p.status and p.status < 400]
    if not content:
        out.append("Nenhuma resposta de conteudo (200) pra comparar.")
        out.append("Todas viraram erro ou desafio de WAF. Corrija a URL ou vare o WAF")
        out.append("antes de tentar diagnosticar o cloaker.")
        return "\n".join(out)

    buckets: dict[str, list] = {}
    for p in content:
        buckets.setdefault(p.body_sha, []).append(p)

    if len(buckets) == 1:
        # "Todas iguais" tem DUAS explicacoes opostas, e o script original
        # tratava as duas como a mesma: (a) cloaker filtrando por IP, ou
        # (b) nao existe cloaker nenhum nesta URL. Um site comum tambem
        # entrega a mesma pagina pra todo mundo. O desempate e o CONTEUDO.
        has_funnel = any(p.values or any(
            s in ("telegram_link", "telegram_scheme", "whatsapp_link", "telegram_bot")
            for s in p.signals) for p in content)
        bots_ok = [p for p in content
                   if p.persona in ("python-cru", "facebookexternalhit", "googlebot")]

        if has_funnel:
            out.append("[+] TODAS as personas receberam a MESMA pagina -- e ela TEM")
            out.append("    sinais de funil. Ou seja: voce ja esta vendo a money page.")
            out.append("    Isso nao e bloqueio, e sucesso. Ou nao ha cloaker de destino")
            out.append("    nesta URL, ou o seu IP ja passa no filtro dele.")
            out.append("    Veja o funil na secao abaixo e pare por aqui.")
            return "\n".join(out + _funnel_section(content))

        if bots_ok:
            out.append("[?] TODAS as personas receberam a MESMA pagina, INCLUSIVE as de")
            out.append(f"    bot cru ({', '.join(p.persona for p in bots_ok)}).")
            out.append("    Cuidado: isso tem duas leituras opostas e o teste sozinho")
            out.append("    NAO separa as duas:")
            out.append("      a) nao existe cloaker de destino nesta URL -- e so uma")
            out.append("         pagina normal, que serve o mesmo pra todo mundo;")
            out.append("      b) existe cloaker, ele decidiu pelo IP, e voce esta do")
            out.append("         lado errado -- por isso todos veem a mesma white page.")
            out.append("")
            out.append("    Um cloaker que se preocupa em enganar revisor quase sempre")
            out.append("    trata `facebookexternalhit` de forma diferente. Ele nao ter")
            out.append("    tratado pesa a favor de (a).")
            out.append("    Para separar de vez: repita com --proxy no pais-alvo. Se a")
            out.append("    pagina mudar, era (b). Se nao mudar, era (a).")
            out.append("")
            return "\n".join(out)

        out.append("[!] TODAS as personas receberam A MESMA pagina.")
        out.append("    Nem o Googlebot nem o iPhone in-app divergiram. Isso significa")
        out.append("    que o filtro decidiu ANTES de olhar header ou TLS -> e IP/ASN/geo.")
        out.append("")
        if not proxy:
            out.append("    Voce rodou sem proxy, entao o suspeito e o SEU IP.")
            out.append("    Proximo passo: --proxy apontando pra IP movel/residencial no")
            out.append("    PAIS-ALVO. Ate la, mexer em header e desperdicio de tempo.")
        else:
            out.append("    Voce ja usou proxy e nada mudou. Duas hipoteses:")
            out.append("      a) o proxy e datacenter disfarcado de residencial;")
            out.append("      b) ha camada JS de fingerprint (canvas/WebGL) que so")
            out.append("         browser real passa -> estagio [5], Camoufox/Patchright.")
            out.append("    Nao e mais questao de header.")
    else:
        out.append(f"[+] {len(buckets)} respostas DISTINTAS. O filtro le header/TLS/referrer")
        out.append("    -- ou seja, DA pra ajustar, nao depende so de comprar IP.")
        out.append("")
        for sha, group in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            names = ", ".join(g.persona for g in group)
            out.append(f"    {sha}  ({group[0].body_len:>8} b)  {names}")
        out.append("")
        out += _control_pairs(content)

    # --- o achado -----------------------------------------------------------
    hits = [p for p in content if p.values or p.signals]
    if hits:
        out += ["", LINE, "SINAIS DE MONEY PAGE", LINE]
        for p in hits:
            detail = ", ".join(p.values or p.signals)
            out.append(f"  {p.persona:<24} {detail[:60]}")
            if p.final_url and p.hops and p.final_url != p.hops[0]:
                out.append(f"  {'':<24} destino final: {p.final_url[:64]}")
        funnel = sorted({v for p in hits for v in p.values
                         if v.startswith(("telegram:", "whatsapp:", "bot_handle:"))})
        if funnel:
            out += ["", "  >>> ISTO E O FUNIL:"]
            for f in funnel:
                out.append(f"        {f}")
    else:
        out += ["", "  Nenhum sinal de funil (t.me, wa.me, handle de bot, pixel) em",
                "  nenhuma resposta. Se voce ja chegou na money page, ela pode estar",
                "  montando o link por JS -- caso em que so o estagio [5] (browser real)",
                "  enxerga."]
    return "\n".join(out)


def _funnel_section(content: list) -> list[str]:
    hits = [p for p in content if p.values]
    if not hits:
        return []
    out = ["", LINE, "SINAIS DE MONEY PAGE", LINE]
    funnel = sorted({v for p in hits for v in p.values})
    for f in funnel:
        out.append(f"        {f}")
    return out


def _control_pairs(content: list) -> list[str]:
    """Le os pares de controle: duas personas que diferem em UMA variavel.

    E o que transforma 'as respostas divergiram' em 'a variavel X e o filtro'.
    """
    sha = {p.persona: p.body_sha for p in content}
    pairs = [
        ("chrome-desktop-us", "chrome-desktop-us+fb", "o REFERRER do Facebook"),
        ("fb-inapp-ios", "fb-inapp-ptbr", "o IDIOMA (Accept-Language)"),
        ("chrome-desktop-us+fb", "android-chrome-us+fb", "desktop x mobile"),
    ]
    out = ["    Pares de controle (mesma requisicao, uma variavel diferente):"]
    found = False
    for a, b, what in pairs:
        if a in sha and b in sha:
            found = True
            verdict = "DIVERGIU -> o filtro le " + what if sha[a] != sha[b] else \
                      "igual -> " + what + " nao e o filtro"
            out.append(f"      {a} x {b}: {verdict}")
    return out if found else []


# ===========================================================================
# COMPARADOR DE CRIATIVO [5c]
# ===========================================================================

def render_feed(posts: list[dict], diffs: list, paginas: dict[str, list[str]]) -> str:
    """Resultado de uma rodada de feed.

    O desfecho mais comum e nao ter visto o alvo, e essa e a parte dificil de
    relatar: "nada encontrado" e "nada observado" parecem iguais na tela e
    significam coisas opostas. Um diz que o criativo confere; o outro diz que
    nao houve medicao nenhuma. Este relatorio nunca junta os dois.
    """
    do_alvo = [p for p in posts if p.get("page_id") in paginas]
    out = ["", LINE, f"FEED: {len(posts)} anuncios vistos, "
                     f"{len(do_alvo)} das paginas que voce analisou", LINE]

    if not posts:
        out += ["", "Nenhum anuncio patrocinado apareceu na rolagem.",
                "Isso e sobre o SEU feed, nao sobre o alvo: nao houve medicao.",
                "Tente de novo mais tarde, ou role mais (--max-posts).", ""]
        return "\n".join(out)

    if not do_alvo:
        nomes = ", ".join(sorted({p.get("page_name") or "?" for p in posts})[:6])
        out += ["",
                "Vi anuncio patrocinado, mas nenhum das paginas analisadas.",
                "",
                "  ISTO NAO E RESULTADO NEGATIVO. Nao da para invocar o anuncio",
                "  de um anunciante: voce ve o que o Meta decide te mostrar. Nao",
                "  ter aparecido nao diz nada sobre o criativo dele.",
                "",
                "  Para aumentar a chance: interaja com conteudo do nicho do alvo",
                "  antes de rodar de novo -- curtir, comentar, ficar no assunto.",
                "  E o que faz a concorrencia dele passar a te perseguir.",
                "",
                "  Se o alvo segmenta outro pais ou outro publico, o anuncio nunca",
                "  vai chegar neste feed. Ai o caminho e o estagio [4], nao este.",
                "",
                f"  Quem apareceu: {nomes}", ""]
        return "\n".join(out)

    trocados = [d for d in diffs if d.is_cloaked is True]
    ambiguos = [d for d in diffs if d.is_cloaked is None and d.distance is not None]
    iguais = [d for d in diffs if d.is_cloaked is False]

    out += ["", f"Comparei {len(diffs)} criativos entregues com os aprovados", THIN]
    out.append(f"  conferem com a Biblioteca .......... {len(iguais)}")
    out.append(f"  na faixa ambigua .................. {len(ambiguos)}")
    out.append(f"  DIVERGEM .......................... {len(trocados)}")

    if trocados:
        out += ["", "CRIATIVO ENTREGUE DIFERE DO APROVADO", THIN]
        for d in trocados:
            out.append(f"  {d.ad_id:<28} distancia {d.distance}/64")
        out += ["",
                "  O que o feed serviu nao se parece com NENHUM criativo que a",
                "  pagina publicou na Biblioteca. Duas leituras possiveis, e a",
                "  ferramenta nao separa as duas sozinha:",
                "    - bait-and-switch: aprovaram limpo e trocaram depois;",
                "    - criativo dinamico: montado na entrega, e legitimo.",
                "  Abrir os dois lado a lado resolve em dez segundos."]

    if ambiguos:
        out += ["", "  Na faixa ambigua o app nao arrisca veredito -- olhe voce:"]
        for d in ambiguos:
            out.append(f"    {d.ad_id:<26} distancia {d.distance}/64")

    if not trocados and not ambiguos and iguais:
        out += ["",
                "  Todo criativo entregue confere com o aprovado. Para ESTES",
                "  anuncios, nesta entrega, nao ha cloaking de criativo.",
                "  Vale so para o que foi visto -- o que nao apareceu no feed",
                "  continua sem medicao."]
    out.append("")
    return "\n".join(out)


def render_robustness(url: str, rob: dict, proxy: str | None = None) -> str:
    """Nota de robustez do cloaker: vale o que custa?

    Le o que a matriz de personas mostrou e traduz em veredito de qualidade --
    diagnostico, nao receita. "Vazou pro googlebot" = fraco; "nem com o IP
    certo mudou" = forte (so JS abre).
    """
    rotulo = {
        "fraco": "FRACO -- nao vale o preco",
        "medio": "MEDIO -- cede ao IP certo",
        "forte": "FORTE -- so fingerprint de JS abre",
        "indeterminado": "INDETERMINADO -- falta o teste com proxy",
        "sem_dado": "SEM DADO",
    }.get(rob["grade"], rob["grade"])

    out = ["", LINE, "ROBUSTEZ DO CLOAKER", LINE,
           f"  alvo : {url[:64]}",
           f"  via  : {'proxy ' + proxy if proxy else 'IP direto (sem proxy)'}",
           "", f"  NOTA: {rotulo}", THIN]
    if rob["axes_read"]:
        out.append("  Sinais que o cloaker LE (cada um e um a menos que vaza):")
        for eixo in rob["axes_read"]:
            out.append(f"      - {eixo}")
    else:
        out.append("  Nenhum sinal HTTP fez a resposta divergir.")
    if rob["leaked"]:
        out += ["", "  VAZOU a oferta para: " + ", ".join(sorted(set(rob["leaks"])))]
    out += ["", "  " + rob["note"]]
    if rob["grade"] == "indeterminado":
        out.append("  Rode nesta mesma URL com --proxy no pais-alvo para fechar.")
    out.append("")
    return "\n".join(out)


# ===========================================================================
# COLETOR [1]
# ===========================================================================

def render_collect(ads, histogram, targets) -> str:
    out = ["", LINE, f"COLETA: {len(ads)} anuncios", LINE]

    encerrados = [a for a in ads if a.is_active is False]
    ativos = [a for a in ads if a.is_active is True]
    if encerrados or ativos:
        sem_status = len(ads) - len(ativos) - len(encerrados)
        partes = [f"{len(ativos)} no ar",
                  f"{len(encerrados)} encerrado" + ("s" if len(encerrados) != 1 else "")]
        if sem_status:
            partes.append(f"{sem_status} sem status")
        out.append("  " + ", ".join(partes))
        if encerrados:
            out.append("  Os encerrados vao na frente na fila do probe: ninguem volta")
            out.append("  pra arrumar o filtro de campanha morta, e e ai que vaza.")
        out.append("")

    out.append("DOMINIOS DE DESTINO")
    out.append(THIN)
    total = sum(n for _, n, _ in histogram) or 1
    for host, n, is_outlier in histogram:
        bar = "#" * max(1, round(28 * n / histogram[0][1]))
        tag = "  <- OUTLIER" if is_outlier else ""
        out.append(f"  {host:<30} {n:>4} {100*n/total:>5.1f}%  {bar}{tag}")

    # O caminho, logo abaixo de cada dominio. Sem isto o leitor copia o host,
    # abre a raiz e leva 404 -- com a URL util na tela o tempo todo.
    from .collect.normalize import path_histogram
    caminhos = path_histogram(ads)
    if caminhos:
        out += ["", "CAMINHOS (use este, nao o dominio sozinho)", THIN]
        for host, _, _ in histogram:
            for caminho, url, n, variante in caminhos.get(host, []):
                tag = "  <- VARIANTE" if variante else ""
                out.append(f"  {n:>5}  {host}{caminho}{tag}")
        out.append("")
        out.append("  Abrir so o dominio costuma dar 404: em app Node a raiz nem")
        out.append("  existe. O caminho e o que o anuncio manda o clique.")

    if len(histogram) > 1 and not any(o for _, _, o in histogram):
        out.append("")
        out.append("  Nenhum outlier. Dois ou mais dominios com volume parecido sao")
        out.append("  FUNIS SIMULTANEOS, nao rotacao de dominio -- trate cada um como")
        out.append("  uma operacao separada (erro 6 da secao 4).")

    leaking = [a for a in ads if a.leaks]
    if leaking:
        out += ["", "VAZAMENTOS (funil exposto no proprio texto do anuncio)", THIN]
        seen = set()
        for ad in leaking:
            for leak in ad.leaks:
                if leak in seen:
                    continue
                seen.add(leak)
                out.append(f"  {leak:<44} anuncio {ad.ad_id}")
        out.append("")
        out.append("  Isto vale mais que qualquer probe: o funil vazou sozinho, sem")
        out.append("  precisar furar cloaker. Va direto no destino.")

    if targets:
        out += ["", "ALVOS DE PROBE, EM ORDEM DE PRIORIDADE", THIN]
        out.append("  Criterio: URL com caminho de redirecionador > dominio outlier >")
        out.append("  tem fbclid > ENCERRADA > mais antiga (cloaker mal configurado).")
        out.append("")
        for i, ad in enumerate(targets, 1):
            marca = {False: "ENCERRADO", True: "no ar   "}.get(ad.is_active, "  ?     ")
            out.append(f"  {i}. [{ad.start_date or '????-??-??'} {marca}] {ad.full_url[:54]}")
        out += ["", "  Rode o primeiro assim:", "",
                f'    python -m funnel_recon probe "{targets[0].full_url}"']

    no_url = sum(1 for a in ads if not a.full_url)
    if no_url:
        out += ["", f"  ({no_url} anuncios sem URL de destino no export -- normal em",
                "   criativo que nao leva pra fora, ou campo que o Meta nao devolveu.)"]
    return "\n".join(out)
