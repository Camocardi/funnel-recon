"""O orquestrador: a cascata da secao 6, de ponta a ponta.

Recebe UM link da Biblioteca e faz o resto. Cada estagio custa mais que o
anterior (tempo, depois dinheiro), entao a cascata para no primeiro que
resolve -- nao adianta comprar proxy se o funil ja vazou no texto do anuncio.

O principio da secao 2 vive aqui: isto nao e um quebrador. Quando bate na
parede fisica -- precisa de IP no pais-alvo, ou precisa observar o feed real
-- ele diz isso com clareza em vez de fingir que resolve.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

from . import conhecidas, db
from .collect.bio import bio_de_paginas
from .collect.normalize import (domain_histogram, normalize_row,
                                path_histogram, pick_probe_targets)
from .creative import hash_many, temporal_diffs
from .osint.runner import normalize_targets, osint_many
from .probe.engine import (preflight, preflight_dns, probe_url,
                           to_scan_results)
from .sidedoor import probe_sidedoors
from .schema import Ad, ScanResult
from .signals import cloaker_platform

Progress = Callable[[str, str, dict], None]  # (estagio, evento, dados)

# Quantos criativos hashear por coleta. Cada um e um download do CDN do Meta a
# partir do IP de casa; 2.000 anuncios sao 2.000 downloads, o que demora muito
# e desenha um padrao de trafego que nao interessa desenhar. Quarenta cobre o
# que a cascata realmente usa.
MAX_CREATIVE_HASHES = 40

# As duas trilhas do projeto sao independentes e custam coisas diferentes:
# destino gasta requisicao contra o servidor do alvo (e expoe o seu IP);
# criativo gasta download de imagem do CDN do Meta. Quem so quer uma delas nao
# tem por que pagar o custo da outra.
MODES = ("tudo", "funil", "criativo")


def _escolher_criativos(ads: list[Ad], conhecidos: set[str], limite: int) -> list[Ad]:
    """Quais anuncios valem o download do criativo.

    Ordem: primeiro quem JA tem hash gravado -- so esses permitem a comparacao
    no tempo, que e a deteccao de bait-and-switch que sai de graca. Depois a
    fila do probe, que sao os anuncios sobre os quais a cascata vai concluir
    alguma coisa. O resto preenche o que sobrar do limite.
    """
    fila: list[Ad] = [a for a in ads if a.ad_id in conhecidos]
    vistos = {a.ad_id for a in fila}
    for a in pick_probe_targets(ads, limite) + ads:
        if a.ad_id not in vistos:
            vistos.add(a.ad_id)
            fila.append(a)
        if len(fila) >= limite:
            break
    return fila[:limite]


@dataclass
class Findings:
    """O que a cascata descobriu. E isto que a interface desenha."""

    library_url: str = ""
    ads: list[Ad] = field(default_factory=list)
    histogram: list[tuple[str, int, bool]] = field(default_factory=list)
    # {host: [(caminho, url_exemplo, n, e_variante)]} -- o caminho e onde mora
    # o valor, e a tela que so mostra host manda o usuario para a raiz.
    paths: dict = field(default_factory=dict)
    cloakers: list[tuple[str, str, bool]] = field(default_factory=list)
    leaks: list[tuple[str, str]] = field(default_factory=list)  # (achado, ad_id)
    osint: dict[str, list[ScanResult]] = field(default_factory=dict)
    probes: dict[str, list[ScanResult]] = field(default_factory=dict)
    # A coleta viu a pagina inteira ou so uma amostra? Pagina grande e cortada
    # de proposito (ver collect/browser.py), e quase toda conclusao daqui pra
    # baixo -- histograma, outlier, fila de alvos -- muda de significado quando
    # a base e amostra. Carregar isso junto e o que impede o relatorio de
    # afirmar coisa que ele nao pode saber.
    truncated: bool = False
    truncated_reason: str = ""
    # Internet gasta na coleta, medida no fio (ver collect/browser.py). A
    # coleta roda pela conexao local: ela NAO passa pelo proxy, que so e usado
    # no probe.
    bytes_coleta: int = 0
    rede_por_tipo: dict = field(default_factory=dict)
    # Dominio que a PAGINA declara como site proprio. Nao vem da Biblioteca:
    # `link_url` e o destino do anuncio, a bio e outro dominio. Ver collect/bio.py.
    bio_dominios: list = field(default_factory=list)
    creative_diffs: list = field(default_factory=list)  # CreativeDiff, kind="tempo"
    creative_hashed: int = 0
    # Paginas abertas por porta lateral (apex, inventario do CMS). Ficam fora
    # de `probes` porque nao sao tentativas contra o filtro: sao outra porta.
    sidedoors: list = field(default_factory=list)
    # id da VSL -> como ela ja e conhecida (marcada a mao ou vista no
    # historico). Vazio quando tudo que a porta lateral serviu e inedito.
    vsls_conhecidas: dict = field(default_factory=dict)
    creative_compared: int = 0   # quantos tinham hash antigo para comparar
    mode: str = "tudo"
    verdict: str = "unknown"
    headline: str = ""
    blocked_by: str | None = None
    next_step: str = ""
    stages: list[dict] = field(default_factory=list)
    error: str | None = None


def _noop(stage: str, event: str, data: dict) -> None:
    pass


async def run_pipeline(
    library_url: str,
    progress: Progress | None = None,
    proxy: str | None = None,
    max_probe_targets: int = 2,
    save: bool = True,
    collect_fn=None,
    max_ads: int | None = None,
    max_seconds: float | None = None,
    max_creative_hashes: int = MAX_CREATIVE_HASHES,
    mode: str = "tudo",
    # "all" = ativos + encerrados (padrao); "active" = so o que esta no ar.
    # Ver collect.browser.with_all_statuses para o porque de existirem os dois.
    status: str = "all",
) -> Findings:
    say = progress or _noop
    mode = mode if mode in MODES else "tudo"
    f = Findings(library_url=library_url, mode=mode)

    # ---- [1] COLETOR ------------------------------------------------------
    say("coletar", "inicio", {})
    try:
        if collect_fn is None:
            from .collect.browser import collect as collect_fn_default
            collect_fn = collect_fn_default

        def on_collect(msg: str, data: dict):
            if msg == "parcial":
                f.truncated = True
                f.truncated_reason = data.get("motivo", "")
            if msg == "rede":
                f.bytes_coleta = data.get("bytes", 0)
                f.rede_por_tipo = data.get("por_tipo", {})
            say("coletar", msg, data)

        limites = {"status": status}
        if max_ads is not None:
            limites["max_ads"] = max_ads
        if max_seconds is not None:
            limites["max_seconds"] = max_seconds
        raw = await collect_fn(library_url, on_progress=on_collect, **limites)
    except Exception as e:
        f.error = f"{type(e).__name__}: {e}"
        f.headline = "Nao consegui coletar os anuncios."
        f.next_step = str(e)
        say("coletar", "erro", {"erro": f.error})
        return f

    f.ads = [ad for ad in (normalize_row(r) for r in raw) if ad]
    f.histogram = domain_histogram(f.ads, sample=f.truncated)
    f.paths = path_histogram(f.ads, sample=f.truncated)

    # Plataforma de cloaking entre os proprios dominios do anunciante: o
    # adversario se identificando. Muda o proximo passo, porque cloaker de
    # prateleira decide por IP/ASN antes de olhar header -- ajustar persona
    # nao vai a lugar nenhum.
    vistos: set[str] = set()
    for host, _, _ in f.histogram:
        nome, confirmado = cloaker_platform(host)
        if nome and host not in vistos:
            vistos.add(host)
            f.cloakers.append((host, nome, confirmado))
    say("coletar", "fim", {"ads": len(f.ads), "dominios": len(f.histogram),
                           "parcial": f.truncated})

    if not f.ads:
        f.headline = "Nenhum anuncio encontrado nessa pagina."
        f.next_step = ("Confira se o link e de uma PAGINA de anunciante na Biblioteca "
                       "e se ela tem anuncios ativos.")
        return f

    # ---- vazamento: o atalho que dispensa todo o resto --------------------
    f.leaks = [(leak, ad.ad_id) for ad in f.ads for leak in ad.leaks]
    funnel_leaks = [(l, i) for l, i in f.leaks
                    if l.startswith(("telegram:", "whatsapp:", "bot_handle:"))]
    if funnel_leaks:
        f.verdict = "money"
        f.headline = f"Funil encontrado sem precisar furar cloaker: {funnel_leaks[0][0]}"
        f.next_step = ("O anunciante deixou o canal do funil escapar no proprio texto "
                       "do anuncio. Va direto nele.")
        say("coletar", "vazamento", {"achados": [l for l, _ in funnel_leaks]})

    # ---- [5c] criativo da Biblioteca: hashear agora ------------------------
    # Antes de gravar, de proposito. `save_ad` e INSERT OR REPLACE e apagaria o
    # hash da coleta anterior -- que e exatamente a base de comparacao.
    conn = db.connect() if save else None
    antes: dict[str, str] = {}
    escolhidos: list[Ad] = []
    midia = {r.get("ad_id"): (r.get("media") or []) for r in raw if isinstance(r, dict)}

    if mode == "funil":
        say("criativo", "pulado", {"motivo": "voce pediu so o funil"})
    else:
        antes = db.creative_hashes(conn, [a.ad_id for a in f.ads]) if conn else {}
        escolhidos = _escolher_criativos(f.ads, set(antes), max_creative_hashes)

    if escolhidos:
        say("criativo", "inicio", {"anuncios": len(escolhidos), "com_historico": len(antes)})
        try:
            agora = await hash_many(
                [(a.ad_id, midia.get(a.ad_id, [])) for a in escolhidos],
                on_done=lambda n: say("criativo", "hasheando", {"prontos": n}))
        except Exception as e:
            # Criativo e uma trilha paralela: falhar aqui nao pode derrubar a
            # analise de destino, que e a que o usuario veio buscar.
            agora = {}
            say("criativo", "erro", {"erro": f"{type(e).__name__}: {e}"})

        for ad in f.ads:
            if ad.ad_id in agora:
                ad.creative_phash = agora[ad.ad_id]
        f.creative_hashed = len(agora)
        f.creative_compared = sum(1 for k in agora if k in antes)
        f.creative_diffs = [d for d in temporal_diffs(antes, agora)
                            if d.is_cloaked is not False]
        say("criativo", "fim", {"hasheados": len(agora),
                                "comparados": f.creative_compared,
                                "divergencias": len(f.creative_diffs)})

    if conn:
        for ad in f.ads:
            db.save_ad(conn, ad)
        for d in f.creative_diffs:
            db.save_creative_diff(conn, d)

    if mode == "criativo":
        # Nem OSINT nem probe: as duas existem para achar o DESTINO, e o probe
        # ainda bate no servidor do alvo a partir do IP de casa. Nao gastar
        # isso quando ninguem pediu e o ponto do modo.
        motivo = "voce pediu so os criativos"
        say("osint", "pulado", {"motivo": motivo})
        say("probe", "pulado", {"motivo": motivo})
        _decide(f, proxy, conn)
        return f

    # ---- [2] OSINT --------------------------------------------------------
    hosts = normalize_targets([h for h, _, _ in f.histogram])[:6]
    say("osint", "inicio", {"dominios": hosts})

    # A bio da PAGINA declara um site proprio, que nao e o `link_url` do
    # anuncio e nao aparece em export nenhum da Biblioteca. Entra no estagio
    # de OSINT porque e exatamente isso: pegada publica do anunciante.
    paginas = [pid for pid, _ in Counter(
        a.page_id for a in f.ads if getattr(a, "page_id", None)).most_common(10)]
    if paginas:
        try:
            f.bio_dominios = await bio_de_paginas(
                paginas, on_progress=lambda m, d: say("osint", m, d))
            vivos = [b for b in f.bio_dominios if b["resolve"]]
            say("osint", "bio", {"paginas": len(paginas),
                                 "dominios": len(f.bio_dominios),
                                 "vivos": len(vivos)})
        except Exception as e:
            # Exige sessao logada e navegador. Falhar aqui nao pode custar o
            # resto da cascata -- e um canal a mais, nao o principal.
            say("osint", "bio_falhou", {"erro": f"{type(e).__name__}: {e}"})

    if hosts:
        f.osint = await osint_many(hosts, concurrency=4)
        if save:
            db.save_scans(db.connect(), [r for rs in f.osint.values() for r in rs])
    osint_signals = [s for rs in f.osint.values() for r in rs for s in r.signals]
    say("osint", "fim", {"sinais": len(osint_signals)})

    # Caminho de redirecionador arquivado tem prioridade: e a URL real, de graca.
    archived = [s.split(":", 1)[1] for s in osint_signals
                if s.startswith("archived_redirector:")]

    # ---- [3] PROBE --------------------------------------------------------
    targets = pick_probe_targets(f.ads, max_probe_targets, sample=f.truncated)
    urls = archived[:1] + [a.full_url for a in targets if a.full_url]
    urls = list(dict.fromkeys(urls))[:max_probe_targets]

    if funnel_leaks:
        # Ja temos o funil. Sondar seria gastar requisicao (e expor o IP) por
        # informacao que ja esta na mao.
        say("probe", "pulado", {"motivo": "funil ja vazou no texto do anuncio"})
    elif not urls:
        say("probe", "pulado", {"motivo": "nenhum anuncio com URL de destino"})
        f.next_step = ("Os anuncios coletados nao tem URL de destino no payload. "
                       "Pode ser campanha que nao leva pra fora, ou o Meta nao "
                       "devolveu o campo.")
    else:
        for url in urls:
            warns = preflight(url) + preflight_dns(url)
            say("probe", "inicio", {"url": url, "avisos": warns})
            # Dominio morto custa 9 personas x timeout do proxy. Medido numa
            # rodada real: 281 dos 378 segundos totais foram gastos assim, num
            # alvo que o DNS nem resolve. O CLI ja abortava; aqui o aviso era
            # so impresso. Anuncio ativo na Biblioteca com dominio derrubado e
            # comum, entao isto acontece com frequencia.
            if "dominio_nao_resolve" in warns:
                say("probe", "pulado", {"motivo": f"o dominio de {url} nao "
                                                  f"existe mais (NXDOMAIN)"})
                continue
            # Proxy residencial movel tem latencia alta e instavel: com 25s
            # foi comum perder persona por timeout, e persona perdida e
            # variavel perdida no diagnostico.
            probes = await asyncio.to_thread(
                probe_url, url, proxy, 45 if proxy else 25, None, 0.4,
                lambda i, total, p: say("probe", "persona",
                                        {"url": url, "i": i + 1, "total": total,
                                         "persona": p.name}),
            )
            results = to_scan_results(url, probes, "probe_proxy" if proxy else "probe",
                                      proxy)
            f.probes[url] = results
            if save:
                db.save_scans(db.connect(), results)
            say("probe", "fim", {"url": url,
                                 "vereditos": [r.verdict for r in results]})
            if any(r.verdict == "money" for r in results):
                break

    # ---- [3b] PORTAS LATERAIS ---------------------------------------------
    # So quando o probe nao chegou. Se a oferta ja apareceu, bater em mais
    # nada e gastar requisicao e expor o IP de graca.
    chegou = any(r.verdict == "money" for rs in f.probes.values() for r in rs)
    if not chegou and urls:
        say("sidedoor", "inicio", {"alvo": urls[0]})
        try:
            f.sidedoors = await probe_sidedoors(
                urls[0], on_progress=lambda m, d: say("sidedoor", m, d))
        except Exception as e:
            say("sidedoor", "erro", {"erro": f"{type(e).__name__}: {e}"})
        if save and f.sidedoors:
            db.save_scans(db.connect(), f.sidedoors)
    elif chegou:
        say("sidedoor", "pulado", {"motivo": "a oferta ja apareceu no probe"})

    _decide(f, proxy, conn)
    _nota_criativo(f)
    return f


def _nota_criativo(f: Findings) -> None:
    """Costura o achado de criativo no passo seguinte, sem sequestrar o veredito.

    As duas trilhas respondem perguntas diferentes: um criativo trocado nao diz
    para onde o clique vai. Virar veredito de destino seria errado -- mas ficar
    calado tambem, porque o cartao do criativo fica bem abaixo na pagina e
    passa despercebido justamente quando importa.
    """
    if f.mode == "criativo" or not f.creative_diffs:
        return
    n = len(f.creative_diffs)
    f.next_step = (f.next_step.rstrip() + " " if f.next_step else "") + (
        f"Em paralelo, na trilha de criativo: {n} anuncio"
        f"{'s' if n > 1 else ''} mostra hoje uma imagem diferente da de antes "
        f"-- ver o cartao mais abaixo.")


def _decide(f: Findings, proxy: str | None, conn=None) -> None:
    """O classificador [6], versao honesta.

    Regra que atravessa o brief inteiro: quando a cascata nao resolveu, o
    relatorio diz O QUE FALTA -- e o que falta e quase sempre acesso (IP no
    pais certo, olho no feed real), nao mais uma tentativa de codigo.
    """
    if f.verdict == "money":  # vazamento ja decidiu
        return

    # Modo criativo nao sondou nada, entao nao pode concluir nada sobre o
    # destino. Cair no fluxo normal aqui faria o app dizer "caminhos
    # automaticos esgotados, compre proxy" para quem nunca pediu o destino.
    if f.mode == "criativo":
        if f.creative_diffs:
            f.verdict = "criativo"
            n = len(f.creative_diffs)
            f.headline = (f"{n} criativo{'s' if n > 1 else ''} mudou desde a "
                          f"analise anterior desta pagina.")
            f.next_step = ("Mesmo ad_id, imagem diferente: e a assinatura do "
                           "bait-and-switch. Abra os anuncios da lista e "
                           "compare com o olho -- criativo dinamico produz o "
                           "mesmo sinal e nao e ma-fe.")
        elif f.creative_compared:
            f.headline = (f"Os {f.creative_compared} criativos que ja tinham "
                          f"historico continuam iguais.")
            f.next_step = ("Nenhuma troca desde a ultima analise. Vale so para "
                           "o que a Biblioteca mostra -- para saber o que e "
                           "ENTREGUE no feed, rode `funnel_recon feed`.")
        elif f.creative_hashed:
            f.headline = (f"{f.creative_hashed} criativos guardados. "
                          f"Ainda nao ha com o que comparar.")
            f.next_step = ("Esta foi a primeira analise desta pagina, entao nao "
                           "existe versao anterior. Rode de novo daqui a alguns "
                           "dias: a troca de criativo aparece na comparacao.")
        else:
            f.headline = "Nenhum criativo pode ser processado."
            f.next_step = ("Os anuncios desta pagina nao trouxeram imagem no "
                           "payload -- se forem so video sem thumbnail, nao ha "
                           "o que hashear sem baixar o video inteiro.")
        return

    all_results = [r for rs in f.probes.values() for r in rs]
    money = [r for r in all_results if r.verdict == "money"]
    if money:
        achados = sorted({s for r in money for s in r.signals
                          if s.startswith(("telegram:", "whatsapp:", "bot_handle:"))})
        f.verdict = "money"
        f.headline = ("Cheguei na money page: " + ", ".join(achados)) if achados \
            else "Cheguei numa pagina diferente da que a maioria recebe."
        f.next_step = "Confira o destino final na aba de detalhes."
        return

    if not all_results:
        f.verdict = "unknown"
        f.headline = f.headline or "Coletei os anuncios, mas nao houve o que sondar."
        return

    content = [r for r in all_results if r.verdict in ("white", "unknown")]
    challenge = [r for r in all_results if r.verdict == "challenge"]
    errors = [r for r in all_results if r.verdict == "error"]

    if not content and challenge:
        f.verdict = "challenge"
        f.blocked_by = "waf"
        f.headline = "Um WAF (Cloudflare) barrou antes de chegar no cloaker."
        f.next_step = ("Isso e uma camada ANTES do cloaker, nao a resposta dele. "
                       "O proximo passo e o estagio [5]: browser real com "
                       "fingerprint de JS, nao mais ajuste de header.")
        return

    if not content and errors:
        # Antes de culpar a URL: o 407 e do proxy, nao do alvo. O alvo pode
        # nem ter sido tocado.
        if any("proxy_recusou" in r.signals for r in errors):
            f.verdict = "error"
            f.blocked_by = "proxy"
            f.headline = "O proxy recusou as requisicoes (HTTP 407)."
            f.next_step = (
                "407 e o proxy respondendo, nao o alvo -- pacote expirado, "
                "cota esgotada ou credencial recusada. O alvo pode nem ter "
                "sido tocado, entao nao ha nada a concluir sobre cloaker. "
                "Confira o saldo e o status do pacote no painel do provedor e "
                "rode de novo.")
            return
        f.verdict = "error"
        f.blocked_by = "url"
        f.headline = "Todas as respostas foram erro."
        f.next_step = ("4xx/5xx e igual pra toda persona por definicao, entao isso "
                       "nao prova cloaker. Quase sempre e URL errada.")
        return

    # Porta lateral achou a oferta. Vem ANTES do despejo de proposito: ser
    # recusado no cloaker deixa de ser a conclusao quando a oferta ja esta na
    # mao por outro caminho.
    laterais = [r for r in f.sidedoors if r.verdict == "money"]
    if laterais:
        checkouts = sorted({v.split(":", 1)[1] for r in laterais for v in r.signals
                            if v.startswith("checkout:")})
        paginas = [v.split(":", 1)[1] for r in laterais for v in r.signals
                   if v.startswith("sidedoor_url:")]

        # A porta lateral abriu -- mas serviu o que? Um operador que ja foi
        # investigado deixa a VSL velha exposta no dominio raiz de proposito:
        # quem cai nela acha que venceu o cloaker e para de procurar. Se TODA
        # VSL que vazou aqui ja e conhecida, o que esta na mao e a isca, e o
        # destino real do anuncio continua fechado.
        ids = sorted({i for r in laterais for i in conhecidas.ids_de(r.signals)})
        f.vsls_conhecidas = conhecidas.avaliar(ids, conn)
        so_conhecidas = bool(ids) and len(f.vsls_conhecidas) == len(ids)

        f.blocked_by = None
        if so_conhecidas:
            rotulos = sorted({d.get("rotulo", "conhecida")
                              for d in f.vsls_conhecidas.values()})
            f.verdict = "isca"
            f.headline = ("A porta lateral abriu, mas serviu a VSL que voce ja "
                          "tinha (" + ", ".join(rotulos) + ").")
            f.next_step = (
                f"O dominio raiz respondeu sem cloaker, so que a VSL de la nao e "
                f"nova: {', '.join(ids)} ja constava. Isso e o padrao de quem ja "
                f"foi investigado -- a oferta velha fica exposta para dar por "
                f"encerrada a busca, enquanto o trafego aprovado do anuncio segue "
                f"para outra. O destino real continua atras do cloaker. "
                + (f"Checkout desta aqui: {', '.join(checkouts[:3])}. " if checkouts else "")
                + "Proximo passo: HTML salvo por alguem com acesso legitimo no "
                  "pais-alvo (Cmd+S -> pagina completa) e `page` para comparar; "
                  "ou proxy residencial no pais do anuncio.")
            return

        f.verdict = "money"
        f.headline = ("Cheguei na oferta por fora do cloaker: "
                      + (checkouts[0] if checkouts else paginas[0]))
        f.next_step = (
            f"O cloaker protege o endereco que o anuncio aponta, mas o dominio "
            f"raiz ficou aberto -- {len(laterais)} pagina(s) com a oferta "
            f"responderam normalmente daqui. "
            + (f"Checkout: {', '.join(checkouts[:3])}. " if checkouts else "")
            + (f"VSL inedita. " if ids else "")
            + "Nao foi preciso furar filtro nenhum: e um erro de configuracao "
              "do operador, e ele pode fechar isso a qualquer momento -- "
              "guarde as paginas agora.")
        return

    # Todas as respostas terminaram no MESMO site de terceiro. Isso nao e
    # "travado": e a saida de rejeicao do cloaker, e saber para onde ele
    # despeja o recusado e mais informativo que saber que as paginas batem.
    # Sem isto o usuario abre o site de despejo, ve uma faculdade americana ou
    # um site de tarot, e conclui que a ferramenta se perdeu.
    despejos = [sig.split(":", 1)[1] for r in content for sig in r.signals
                if sig.startswith("bounced_offsite:")]
    if despejos and len(set(despejos)) == 1 and len(despejos) >= max(2, len(content) - 1):
        destino = despejos[0]
        f.verdict = "white"
        f.blocked_by = "ip" if proxy is None else "fingerprint"
        f.headline = f"Voce foi recusado e despejado em {destino}."
        f.next_step = (
            f"Todas as personas terminaram no mesmo site de terceiro. Esse site "
            f"nao tem relacao com a oferta e nao e uma pista: e para onde o "
            f"cloaker manda quem NAO passa no filtro. Usar o site real de "
            f"outra pessoa como pagina de recusa e o padrao -- tem SSL valido, "
            f"conteudo real e historico real, entao quem revisa o anuncio nao "
            f"tem o que denunciar. "
            + ("Nenhuma persona passou, o que significa que a decisao veio antes "
               "de qualquer cabecalho: e IP/ASN/geo. So proxy residencial no "
               "pais-alvo muda isso."
               if proxy is None else
               "Mesmo com proxy o despejo continuou: ou o proxy e datacenter "
               "disfarcado, ou ha camada de fingerprint em JS -- estagio [5]."))
        return

    shas = {r.body_sha for r in content if r.body_sha}
    if len(shas) <= 1:
        f.verdict = "white"
        f.blocked_by = "ip" if proxy is None else "fingerprint"
        if proxy is None:
            f.headline = "Todas as personas receberam a mesma pagina."
            f.next_step = (
                "Duas leituras possiveis, e o teste sozinho nao separa: ou nao ha "
                "cloaker de destino nesta URL, ou ha e ele filtrou pelo SEU IP. "
                "Para decidir, e preciso repetir com IP movel/residencial no "
                "pais-alvo (servico pago, ~US$5-15/GB). Ate la, mexer em header "
                "nao muda nada -- essa e a parede fisica descrita na secao 2.")
        else:
            f.headline = "Mesmo com proxy, todas as personas receberam a mesma pagina."
            f.next_step = (
                "Ou o proxy e datacenter disfarcado de residencial, ou ha camada "
                "de fingerprint em JS (canvas/WebGL) que so browser real passa. "
                "Proximo passo e o estagio [5], nao mais tuning de header.")
        return

    f.verdict = "unknown"
    f.blocked_by = None
    f.headline = f"{len(shas)} paginas diferentes entre as personas."
    f.next_step = ("O filtro le header/TLS/referrer -- ou seja, DA para ajustar sem "
                   "comprar IP. Veja nos detalhes qual par de controle divergiu.")
