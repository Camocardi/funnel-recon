"""CLI do funnel_recon. Cada estagio roda sozinho antes de entrar na cascata
(regra da secao 11)."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import db
from .collect.normalize import domain_histogram, load_export, pick_probe_targets
from .osint.runner import SOURCES, normalize_targets, osint_many
from .probe.engine import (preflight, preflight_dns, probe_url,
                           to_scan_results)
from .probe.personas import PERSONAS, by_name
from .report import (PREFLIGHT_MSG, render, render_collect, render_feed,
                     render_probe, render_robustness)


def _load_targets(args) -> list[str]:
    raw = list(args.domains)
    if args.from_file:
        text = Path(args.from_file).read_text(encoding="utf-8")
        if args.from_file.endswith(".json"):
            data = json.loads(text)
            rows = data if isinstance(data, list) else data.get("ads", [])
            for row in rows:
                for key in ("host", "display_host", "url", "full_url"):
                    if isinstance(row, dict) and row.get(key):
                        raw.append(row[key])
                        break
        else:
            raw += [l.strip() for l in text.splitlines() if l.strip()]
    return normalize_targets(raw)


def cmd_osint(args) -> int:
    targets = _load_targets(args)
    if not targets:
        print("Nenhum alvo valido. Passe dominios ou --from-file.", file=sys.stderr)
        return 2

    sources = args.sources.split(",") if args.sources else None
    if sources:
        unknown = [s for s in sources if s not in SOURCES]
        if unknown:
            print(f"Fonte desconhecida: {', '.join(unknown)}. "
                  f"Validas: {', '.join(SOURCES)}", file=sys.stderr)
            return 2

    print(f"alvos  : {', '.join(targets)}")
    print(f"fontes : {', '.join(sources or SOURCES)}")
    print("consultando...", flush=True)

    results = asyncio.run(osint_many(targets, sources, concurrency=args.concurrency))
    print(render(results))

    if not args.no_db:
        conn = db.connect(args.db) if args.db else db.connect()
        n = db.save_scans(conn, [r for rs in results.values() for r in rs])
        print(f"\n{n} linhas gravadas em scan_result.")

    if args.json:
        payload = {d: [asdict(r) for r in rs] for d, rs in results.items()}
        Path(args.json).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )
        print(f"JSON bruto salvo em {args.json}")
    return 0


def cmd_matrix(args) -> int:
    """[3] Matriz de robustez: mede quao bom o cloaker e, sem tentar burlar.

    Roda as personas contra a URL (e, com --proxy, tambem por ele) e da a nota:
    vaza pro crawler = fraco; cede ao IP certo = medio; nem com IP certo muda =
    forte. Responde "vale pagar por este cloaker?" com dado, nao achismo.
    """
    from .probe.engine import probe_url, robustness, to_scan_results

    url = args.url
    warns = preflight(url) + preflight_dns(url)
    if warns and "url_e_raiz" in warns and not args.force:
        print(PREFLIGHT_MSG, file=sys.stderr)
        return 2

    print(f"medindo robustez de: {url}")
    print("rodando a matriz de personas (IP direto)...", flush=True)
    direto = to_scan_results(url, probe_url(url, timeout=args.timeout), "probe", None)

    por_proxy = None
    if args.proxy:
        print(f"repetindo pelo proxy {args.proxy}...", flush=True)
        por_proxy = to_scan_results(
            url, probe_url(url, proxy=args.proxy, timeout=args.timeout),
            "probe_proxy", args.proxy)

    rob = robustness(direto, por_proxy)
    print(render_robustness(url, rob, args.proxy))

    if not args.no_db:
        conn = db.connect(args.db) if args.db else db.connect()
        db.save_scans(conn, direto + (por_proxy or []))
    return 0


def cmd_origin(args) -> int:
    """[3c] Diagnostica onde o cloaker decide: na borda (CDN) ou no servidor.

    So diagnostico. Resolve os dominios, classifica cada IP e diz, para cada
    alvo, se vale caçar origem (esta atras de CDN e vazou IP real) ou se e
    parede (servidor final -- a decisao e no unico lugar por onde a resposta
    sai). NAO tenta o bypass ativo: isso e passo manual, seu, fora daqui.
    """
    from .osint.runner import normalize_targets
    from .signals import apex_domain
    from .origin import discover

    apexes = sorted({apex_domain(h) for h in normalize_targets(args.domains)})
    if not apexes:
        print("Passe um dominio ou URL.", file=sys.stderr)
        return 2

    async def rodar():
        import asyncio as _a
        return await _a.gather(*(discover(a, []) for a in apexes))

    for r in asyncio.run(rodar()):
        borda = r["apex_atras_de_cdn"]
        cabeca = "BORDA (CDN)" if borda else "SERVIDOR FINAL"
        cdn = "/".join(r["cdn"]) if r["cdn"] else "-"
        print(f"\n{r['apex']}  ->  {cabeca}   cdn={cdn}")
        if not borda:
            print("  Cloaker no servidor: nao ha borda para contornar. So proxy")
            print("  no pais-alvo abre isto -- descoberta de origem nao ajuda.")
            continue
        cands = r["origin_candidates"]
        if not cands:
            print("  Atras de CDN, mas nenhum subdominio vazou o IP real.")
            continue
        print("  Atras de CDN e COM origem vazada. Candidatos a testar na mao:")
        for c in cands[:5]:
            tag = "  (dica: mail/cpanel/ftp)" if c["from_hint"] else ""
            print(f"    {c['ip']:<24} visto em {', '.join(c['hosts'])}{tag}")
        alvo = cands[0]["ip"]
        print("\n  1) Confirme que o IP e origem de VERDADE, nao outra CDN")
        print("     (rode voce; se o CN for *.b-cdn.net/*.cloudfront.net/etc,")
        print("      e mais uma borda, nao a origem):")
        print(f"    curl -sv --connect-timeout 8 https://{alvo}/ \\")
        print(f"      -H 'Host: {r['apex']}' 2>&1 | grep -iE 'subject:|refused|timed out'")
        print("\n  2) So se o CN for do dominio real, teste o bypass da borda:")
        print(f"    curl -s --resolve {r['apex']}:443:{alvo} \\")
        print(f"      https://{r['apex']}/ -H 'Referer: https://l.facebook.com/' \\")
        print(f"      -o origem.html -w 'HTTP %{{http_code}}\\n'")
    return 0


def cmd_page(args) -> int:
    """[5c] Radiografa uma pagina (URL ou HTML salvo) e extrai a oferta.

    O caminho de quando alguem COM acesso ao alvo salva a VSL que o cloaker
    esconde: a ferramenta le o arquivo e diz video, checkout, produto e pixel,
    e compara com o que ja temos -- e a mesma VSL ou uma nova?
    """
    from .page import compare, fingerprint, from_file, from_url

    fontes = list(args.fonte)
    radiografias = []
    for f in fontes:
        try:
            if f.startswith(("http://", "https://")):
                fp = asyncio.run(from_url(f))
                if fp.get("bounced"):
                    print(f"AVISO: {f} redirecionou para {fp['final_url']} -- "
                          f"provavel despejo do cloaker. Para a VSL real, peca a "
                          f"quem tem acesso para SALVAR a pagina e passe o arquivo.",
                          file=sys.stderr)
            else:
                fp = from_file(f)
        except FileNotFoundError:
            print(f"Arquivo nao encontrado: {f}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"Nao consegui ler {f}: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
        radiografias.append(fp)

    for fp in radiografias:
        print(f"\n=== {fp['source']} ===")
        if fp.get("title"):
            print(f"  titulo   : {fp['title']}")
        for campo, rotulo in (("video", "video VSL"), ("accounts", "conta VSL"),
                              ("product_ids", "produto"),
                              ("checkouts", "checkout"), ("funnels", "funil"),
                              ("pixels", "pixel")):
            for v in fp.get(campo, []):
                print(f"  {rotulo:<9}: {v}")
        if not any(fp.get(c) for c in ("video", "checkouts", "funnels")):
            print("  (nenhum sinal de oferta -- pagina de despejo, ou HTML incompleto)")

    if len(radiografias) == 2:
        c = compare(radiografias[0], radiografias[1])
        rotulo = {
            "mesma_vsl": "MESMA VSL (mesmo video)",
            "mesma_oferta_video_novo": "MESMA OFERTA, VIDEO NOVO -- a VSL foi trocada",
            "oferta_diferente": "OFERTA DIFERENTE",
            "mesma_oferta": "mesma oferta (sem video para comparar)",
            "indeterminado": "indeterminado (falta video ou produto dos dois lados)",
        }[c["veredito"]]
        print(f"\n>>> {rotulo}")
        if c["video_so_em_b"]:
            print(f"    video novo: {', '.join(c['video_so_em_b'])}")
        if c["produto_comum"]:
            print(f"    mesmo produto: {', '.join(c['produto_comum'])}")
    return 0


def cmd_feed(args) -> int:
    """[5c] Rola o feed e compara o criativo entregue com o da Biblioteca.

    Comando separado, e nao um estagio da cascata, de proposito: isto rola o
    SEU feed pessoal com a SUA conta logada. Colar um link da Biblioteca nao
    e consentimento para isso -- tem que ser um ato deliberado.
    """
    from .collect.feed import NotLoggedIn, harvest
    from .creative import feed_diffs

    conn = db.connect(args.db) if args.db else db.connect()
    lib = db.creative_hashes_by_page(conn, args.page_id or None)
    if not lib:
        print("Nenhum criativo com impressao digital no banco.\n"
              "Analise uma pagina no app primeiro: e a coleta que grava as\n"
              "impressoes digitais, e sem elas nao ha com o que comparar.",
              file=sys.stderr)
        return 1

    print(f"Comparando contra {sum(len(v) for v in lib.values())} criativos "
          f"de {len(lib)} pagina(s).")
    print("Uma janela do navegador vai abrir e rolar o seu feed. "
          "Deixe rolando.\n")

    def progresso(msg, data):
        if msg in ("patrocinados", "rolando"):
            print(f"\r  {data.get('total', 0)} patrocinados vistos, "
                  f"{data.get('do_alvo', 0)} das paginas analisadas", end="", flush=True)
        elif msg == "fim":
            print(f"\r  {data.get('total', 0)} patrocinados vistos "
                  f"({data.get('motivo', '')})" + " " * 20)

    async def rodar():
        posts = await harvest(page_ids=set(lib), on_progress=progresso,
                              max_posts=args.max_posts, max_seconds=args.max_seconds)
        return posts, await feed_diffs(posts, lib)

    try:
        posts, diffs = asyncio.run(rodar())
    except NotLoggedIn as e:
        print(f"\n{e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"\nA coleta do feed falhou: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    print(render_feed(posts, diffs, lib))

    if diffs and not args.no_db:
        for d in diffs:
            db.save_creative_diff(conn, d)
        print(f"{len(diffs)} comparacoes gravadas em creative_diff.")
    return 0


def cmd_import(args) -> int:
    """[1] Le o export da extensao e grava os anuncios no schema da secao 10."""
    try:
        ads = load_export(args.file)
    except FileNotFoundError:
        print(f"Arquivo nao encontrado: {args.file}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Nao consegui ler o export: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    if not ads:
        print("Nenhum anuncio valido no arquivo. Confira se e o CSV/JSON exportado",
              "pela extensao adlib-harvester.", file=sys.stderr)
        return 1

    hist = domain_histogram(ads)
    targets = pick_probe_targets(ads, args.top)
    print(render_collect(ads, hist, targets))

    if not args.no_db:
        conn = db.connect(args.db) if args.db else db.connect()
        for ad in ads:
            db.save_ad(conn, ad)
        print(f"\n{len(ads)} anuncios gravados na tabela `ad`.")
    return 0


def cmd_probe(args) -> int:
    """[3] Dispara a URL com varias personas e diz qual camada filtra."""
    from . import proxy_salvo

    url = args.url
    # O proxy salvo entra sozinho. Colar a string a mao em todo comando foi a
    # origem de erro mais frequente na pratica (esquema errado, letra trocada,
    # `sessid` novo do painel trocando o IP entre rodadas) -- e todos eles se
    # disfarcam de "o alvo bloqueou".
    if args.sem_proxy:
        args.proxy = None
    elif not args.proxy:
        args.proxy = proxy_salvo.carregar()

    # preflight e puro; preflight_dns consulta a rede. Juntos aqui porque para
    # quem roda o comando os dois sao "o que da para saber antes de gastar
    # requisicao".
    warns = preflight(url) + preflight_dns(url)
    for w in warns:
        print(PREFLIGHT_MSG.get(w, w))
    bloqueios = [w for w in ("dominio_nao_resolve", "url_e_raiz") if w in warns]
    if bloqueios and not args.force:
        print("\nAbortado antes de gastar requisicao. Use --force para rodar assim mesmo.")
        return 2
    if warns:
        print()

    personas = by_name(args.personas.split(",")) if args.personas else PERSONAS
    if not personas:
        print(f"Persona desconhecida. Validas: {', '.join(p.name for p in PERSONAS)}",
              file=sys.stderr)
        return 2

    timeout = args.timeout or (45 if args.proxy else 25)
    print(f"alvo  : {url}")
    print(f"proxy : {proxy_salvo.mascarar(args.proxy) if args.proxy else 'NENHUM (seu IP real)'}")
    print(f"testes: {len(personas)}\n")

    def progress(i, total, p):
        print(f"  -> [{i+1}/{total}] {p.name} ...", flush=True)

    if args.navegador != "nao" and args.perfil == "fb":
        print("  aviso: o perfil 'fb' esta logado no Meta. Cookie e por dominio,\n"
              "  entao ele NAO ajuda a passar cloaker de terceiro -- e faz o pixel\n"
              "  do alvo te ver logado. Use --perfil probe salvo se o alvo for o\n"
              "  proprio Meta.\n")

    probes = probe_url(url, proxy=args.proxy, timeout=timeout,
                       personas=personas, delay=args.delay, on_progress=progress,
                       navegador=args.navegador, perfil=args.perfil)
    print(render_probe(url, probes, args.proxy, warns))

    if not args.no_db:
        conn = db.connect(args.db) if args.db else db.connect()
        stage = "probe_proxy" if args.proxy else "probe"
        n = db.save_scans(conn, to_scan_results(url, probes, stage, args.proxy, args.ad_id))
        print(f"\n{n} linhas gravadas em scan_result.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="funnel_recon",
        description="Reconhecimento de funil de anuncios do Meta.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("osint", help="[2] pegada publica de um ou mais dominios")
    o.add_argument("domains", nargs="*", help="dominio ou URL (URL vira host)")
    o.add_argument("--from-file", help="arquivo .txt (um por linha) ou .json do coletor [1]")
    o.add_argument("--sources", help=f"subconjunto de: {','.join(SOURCES)}")
    o.add_argument("--concurrency", type=int, default=4)
    o.add_argument("--json", help="salvar resultado bruto neste arquivo")
    o.add_argument("--db", help="caminho do SQLite (padrao: data/scans.db)")
    o.add_argument("--no-db", action="store_true", help="nao gravar no banco")
    o.set_defaults(func=cmd_osint)

    i = sub.add_parser("import", help="[1] carregar o export CSV/JSON da extensao")
    i.add_argument("file", help="CSV ou JSON exportado pelo adlib-harvester")
    i.add_argument("--top", type=int, default=5, help="quantos alvos de probe sugerir")
    i.add_argument("--db")
    i.add_argument("--no-db", action="store_true")
    i.set_defaults(func=cmd_import)

    p = sub.add_parser("probe", help="[3] testar uma URL com varias personas")
    p.add_argument("url", help="URL COMPLETA, com caminho e fbclid")
    p.add_argument("--proxy", help="http://user:pass@host:porta ou a string "
                                   "unica do painel. Omitido, usa o que estiver "
                                   "salvo em `funnel_recon proxy`")
    p.add_argument("--sem-proxy", action="store_true", dest="sem_proxy",
                   help="ignorar o proxy salvo e sair pelo IP daqui")
    p.add_argument("--personas", help="subconjunto, separado por virgula")
    p.add_argument("--timeout", type=int, default=None,
                   help="segundos por persona (padrao: 25, ou 45 com --proxy, "
                        "porque proxy residencial movel tem latencia alta)")
    p.add_argument("--delay", type=float, default=0.4,
                   help="pausa entre personas (evita parecer burst pro WAF)")
    p.add_argument("--ad-id", help="ligar o resultado a um anuncio ja importado")
    p.add_argument("--force", action="store_true",
                   help="rodar mesmo com a URL sendo a raiz do dominio")
    p.add_argument("--navegador", choices=("nao", "auto", "sempre"), default="nao",
                   help="[5] Chromium real como persona extra: 'auto' so quando "
                        "nenhuma persona HTTP trouxe pagina (parede de JS)")
    p.add_argument("--perfil", choices=("probe", "fb", "nenhum"), default="probe",
                   help="perfil do navegador. 'probe' (padrao): perfil proprio "
                        "que ACUMULA cookie do alvo -- guarda o cf_clearance do "
                        "Cloudflare, entao a proxima visita nao bate na parede. "
                        "'nenhum': primeira visita sempre, que e a condicao do "
                        "visitante real vindo do anuncio -- use quando quiser o "
                        "experimento limpo. 'fb': o perfil logado no Meta, so "
                        "util se o ALVO for pagina do Meta")
    p.add_argument("--db")
    p.add_argument("--no-db", action="store_true")
    p.set_defaults(func=cmd_probe)

    fd = sub.add_parser("feed", help="[5c] comparar o criativo entregue no feed "
                                     "com o da Biblioteca")
    fd.add_argument("--page-id", action="append",
                    help="limitar a estas paginas (padrao: todas as do banco)")
    fd.add_argument("--max-posts", type=int, default=400,
                    help="parar depois de tantos patrocinados")
    fd.add_argument("--max-seconds", type=float, default=240.0,
                    help="parar depois de tantos segundos rolando")
    fd.add_argument("--db")
    fd.add_argument("--no-db", action="store_true")
    fd.set_defaults(func=cmd_feed)

    mx = sub.add_parser("matrix", help="[3] medir a robustez de um cloaker "
                                       "(vale pagar por ele?)")
    mx.add_argument("url", help="URL COMPLETA (com caminho e fbclid)")
    mx.add_argument("--proxy", help="proxy no pais-alvo, para medir o eixo de IP")
    mx.add_argument("--timeout", type=int, default=25)
    mx.add_argument("--force", action="store_true")
    mx.add_argument("--db")
    mx.add_argument("--no-db", action="store_true")
    mx.set_defaults(func=cmd_matrix)

    og = sub.add_parser("origin", help="[3c] diagnostico: cloaker na borda (CDN) "
                                       "ou no servidor final?")
    og.add_argument("domains", nargs="+", help="dominio(s) ou URL(s)")
    og.set_defaults(func=cmd_origin)

    pg = sub.add_parser("page", help="[5c] radiografar uma pagina (URL ou HTML "
                                     "salvo): video, checkout, produto, pixel")
    pg.add_argument("fonte", nargs="+",
                    help="URL, ou caminho de HTML salvo. Dois: compara os dois "
                         "(e a mesma VSL ou uma nova?)")
    pg.set_defaults(func=cmd_page)

    cr = sub.add_parser("criativos", help="abrir a pasta com as imagens de "
                                         "criativo ja salvas")
    cr.add_argument("--abrir", action="store_true", help="abre no Finder")
    cr.set_defaults(func=cmd_criativos)

    op = sub.add_parser("operador", help="operadores conhecidos pela conta de "
                                        "VSL -- para reconhecer campanha nova cedo")
    op.add_argument("--marcar", metavar="CONTA", help="uuid da conta converteai")
    op.add_argument("--rotulo", default="")
    op.add_argument("--nota", default="")
    op.add_argument("--esquecer", metavar="CONTA")
    op.set_defaults(func=cmd_operador)

    cp = sub.add_parser("perfil", help="mostra o que um cloaker VE do seu "
                                       "navegador (checagem, nao bypass)")
    cp.add_argument("--snippet", action="store_true",
                    help="imprime o JS para colar no console do navegador")
    cp.add_argument("--pais", help="pais que o ipapi.co ve pelo seu IP (ex: US)")
    cp.add_argument("--fuso", help="fuso do seu IP (ex: America/New_York)")
    cp.add_argument("--json", help="cole aqui o objeto que o snippet devolveu, "
                                   "para avaliar as regras")
    cp.set_defaults(func=cmd_perfil)

    vi = sub.add_parser("vsl-id", help="[5c] identidade de uma money page e os "
                                       "irmaos do mesmo operador")
    vi.add_argument("url", help="URL da money page (a VSL, nao o link do anuncio)")
    vi.add_argument("--db")
    vi.set_defaults(func=cmd_vsl_id)

    px = sub.add_parser("proxy", help="guardar o proxy uma vez, em vez de "
                                      "colar a string em todo comando")
    px.add_argument("--salvar", metavar="STRING",
                    help="aceita 'host:porta:user:senha' (a string unica do "
                         "painel) ou 'http://user:senha@host:porta'")
    px.add_argument("--testar", action="store_true",
                    help="consulta real: mostra IP, ASN e regiao de saida")
    px.add_argument("--esquecer", action="store_true")
    px.set_defaults(func=cmd_proxy)

    v = sub.add_parser("vsl", help="[5c] marcar VSLs que voce ja conhece "
                                   "(a antiga/saturada, a isca)")
    v.add_argument("--marcar", metavar="ID",
                   help="id do player ou do video (NAO o da conta)")
    v.add_argument("--rotulo", default="antiga/saturada",
                   help="como chamar essa VSL no relatorio")
    v.add_argument("--nota", default="", help="lembrete livre")
    v.add_argument("--esquecer", metavar="ID", help="tirar um id da lista")
    v.set_defaults(func=cmd_vsl)

    a = sub.add_parser("app", help="abrir a interface (modo normal de uso)")
    a.add_argument("--host", default="127.0.0.1")
    a.add_argument("--port", type=int, default=8765)
    a.add_argument("--no-open", action="store_true",
                   help="nao abrir o navegador sozinho")
    a.set_defaults(func=cmd_app)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())


def cmd_criativos(args) -> int:
    """Lista/abre as pastas de imagens de criativo salvas nas coletas."""
    import subprocess

    from .paths import creatives_dir

    base = creatives_dir()
    pastas = sorted([d for d in base.iterdir() if d.is_dir()], reverse=True)
    if not pastas:
        print(f"nenhuma imagem salva ainda em {base}")
        print("rode uma coleta (qualquer modo menos hash desligado) primeiro.")
        return 0
    print(f"pastas de criativo em {base}:")
    for d in pastas[:12]:
        n = len(list(d.glob("*.jpg"))) + len(list(d.glob("*.png")))
        print(f"  {d.name}   {n} imagens")
    if args.abrir:
        subprocess.run(["open", str(pastas[0])], check=False)
        print(f"\nabri a mais recente: {pastas[0]}")
    else:
        print(f"\nabra no Finder:  open '{pastas[0]}'")
        print("ou rode:         funnel_recon criativos --abrir")
    return 0


def cmd_operador(args) -> int:
    """Lista e mantem os operadores conhecidos (a conta de VSL e o pivo)."""
    from . import operadores

    if args.esquecer:
        print("esquecido." if operadores.esquecer(args.esquecer)
              else "essa conta nao estava na lista.")
        return 0
    if args.marcar:
        d = operadores.marcar(args.marcar, args.rotulo, args.nota)
        print(f"marcado: {args.marcar.strip().lower()}  ({d['rotulo']})")

    itens = operadores.listar()
    if not itens:
        print("nenhum operador marcado ainda.\n"
              "  funnel_recon operador --marcar <conta> --rotulo 'nome'\n"
              "  a conta sai de `vsl-id` numa money page.")
        return 0
    print(f"\n{len(itens)} operador(es) conhecido(s):")
    for conta, d in itens:
        print(f"  {conta}  {d.get('rotulo', ''):<28} {d.get('visto_em', '')[:10]}"
              + (f"  -- {d['nota']}" if d.get("nota") else ""))
    return 0


def cmd_perfil(args) -> int:
    """O que o cloaker ve do seu navegador. Checagem do proprio ambiente."""
    import json as _json

    from .checar_perfil import SNIPPET_JS, avaliar

    if args.snippet or not args.json:
        print("Cole isto no console do navegador que voce vai usar (Dolphin,")
        print("Chrome, o que for), copie o objeto que ele imprime, e rode de novo")
        print("com --json '<objeto>' (e --pais/--fuso do que o seu IP mostra):\n")
        print(SNIPPET_JS)
        return 0

    try:
        dados = _json.loads(args.json)
    except Exception as e:
        print(f"nao consegui ler o JSON: {e}", file=sys.stderr)
        return 2

    print("\nO que um cloaker (padrao The White Rabbit) veria:\n")
    problemas = 0
    for a in avaliar(dados, geo_pais=args.pais, geo_timezone=args.fuso):
        marca = "  ok " if a["ok"] else "  !! "
        if not a["ok"]:
            problemas += 1
        print(f"{marca}{a['campo']:16} {a['nota']}")
    print()
    if problemas:
        print(f"{problemas} sinal(is) te denunciam. Corrija no perfil ANTES de "
              "gastar clique -- proxy nao resolve nenhum deles.")
    else:
        print("Nenhum sinal obvio de automacao ou incoerencia. O ambiente esta "
              "coerente com um visitante real.")
    return 0


def cmd_vsl_id(args) -> int:
    """Radiografa uma money page e caça as outras ofertas do mesmo operador."""
    import asyncio

    from . import db
    from .vsl_identity import identidade, ip_do_host, irmaos_no_banco

    r = asyncio.run(identidade(args.url))
    print(f"\n{r['url']}")
    if r["bounced"]:
        print("  [!] a URL redirecionou para outro dominio -- pode ser despejo,")
        print("      nao a money page. Sinais abaixo podem estar vazios.")
    print(f"  titulo  : {r['titulo'][:70]}")
    print(f"  conta   : {r['account'] or '(nao achei conta de VSL nesta pagina)'}")
    for v in r["videos"]:
        print(f"  video   : {v}")
    for c in r["checkouts"]:
        print(f"  checkout: {c[:80]}")
    ips = ip_do_host(r["host"])
    for ip in ips:
        print(f"  servidor: {ip}")

    if not r["account"]:
        return 0

    conn = db.connect(args.db) if args.db else db.connect()
    irmaos = [x for x in irmaos_no_banco(conn, r["account"])
              if x["url"] != r["url"] and x["url"] != r["final_url"]]
    print(f"\n  mesma conta {r['account']} em outras paginas ja vistas: {len(irmaos)}")
    for x in irmaos:
        print(f"    {x['url'][:64]}")
        if x["videos"]:
            print(f"       videos: {', '.join(x['videos'])}")
        if x["checkouts"]:
            print(f"       checkout: {x['checkouts'][0][:64]}")
        if x["visto_em"]:
            print(f"       visto em: {x['visto_em']}")
    if not irmaos:
        print("    (nenhuma ainda -- radiografe outras money pages para o banco")
        print("     aprender a ligar; a conta e o pivo)")
    return 0


def cmd_proxy(args) -> int:
    """Guarda, mostra e testa o proxy padrao."""
    from . import proxy_salvo

    if args.esquecer:
        print("esquecido." if proxy_salvo.esquecer() else "nao havia proxy salvo.")
        return 0

    if args.salvar:
        try:
            v = proxy_salvo.salvar(args.salvar)
        except ValueError as e:
            print(f"nao consegui entender essa string: {e}", file=sys.stderr)
            return 2
        print(f"salvo: {proxy_salvo.mascarar(v)}")
        if not v.startswith("http"):
            print("  aviso: esquema nao-HTTP. A persona de navegador nao aplica\n"
                  "  credencial em SOCKS5 -- se o endpoint aceitar HTTP, prefira.")

    atual = proxy_salvo.carregar()
    if not atual:
        print("nenhum proxy salvo.\n"
              "  funnel_recon proxy --salvar 'host:porta:usuario:senha' --testar")
        return 0
    print(f"proxy atual: {proxy_salvo.mascarar(atual)}")

    if args.testar:
        print("testando...", flush=True)
        try:
            d = proxy_salvo.testar(atual)
        except Exception as e:
            print(f"  FALHOU: {type(e).__name__}: {str(e)[:140]}", file=sys.stderr)
            return 1
        print(f"  saida  : {d.get('ip')}  {d.get('org', '')}")
        print(f"  local  : {d.get('city', '')}/{d.get('region', '')} "
              f"{d.get('country', '')}")
    return 0


def cmd_vsl(args) -> int:
    """Lista e mantem as VSLs ja conhecidas.

    Sem argumento nenhum, lista -- e o uso mais comum: "o que eu ja sei?".
    """
    from . import conhecidas

    if args.esquecer:
        print("esquecida." if conhecidas.esquecer(args.esquecer)
              else "esse id nao estava na lista.")
        return 0

    if args.marcar:
        d = conhecidas.marcar(args.marcar, args.rotulo, args.nota)
        print(f"marcada: {args.marcar.strip().lower()}  ({d['rotulo']})")

    itens = conhecidas.listar()
    if not itens:
        print("nenhuma VSL marcada ainda.\n"
              "  funnel_recon vsl --marcar <id do player> --rotulo 'antiga/saturada'\n"
              "  o id sai do relatorio: e o segmento /players/<id>, nunca o da conta.")
        return 0
    print(f"\n{len(itens)} VSL(s) conhecida(s):")
    for vsl_id, d in itens:
        print(f"  {vsl_id}  {d.get('rotulo', ''):<18} {d.get('marcada_em', '')[:10]}"
              + (f"  -- {d['nota']}" if d.get("nota") else ""))
    return 0


def cmd_app(args) -> int:
    """Abre a interface. E este o modo normal de usar."""
    from .web.app import serve
    print("Funnel Recon")
    print(f"  interface: http://{args.host}:{args.port}")
    print("  (deixe esta janela aberta enquanto usa; Ctrl+C encerra)")
    try:
        serve(args.host, args.port, abrir=not args.no_open)
    except KeyboardInterrupt:
        print("\nencerrado.")
    return 0
