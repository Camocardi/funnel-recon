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
from .probe.engine import preflight, probe_url, to_scan_results
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
    warns = preflight(url)
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
        for campo, rotulo in (("video", "video VSL"), ("product_ids", "produto"),
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
    url = args.url
    warns = preflight(url)
    for w in warns:
        print(PREFLIGHT_MSG.get(w, w))
    if "url_e_raiz" in warns and not args.force:
        print("\nAbortado antes de gastar requisicao. Use --force para rodar assim mesmo.")
        return 2
    if warns:
        print()

    personas = by_name(args.personas.split(",")) if args.personas else PERSONAS
    if not personas:
        print(f"Persona desconhecida. Validas: {', '.join(p.name for p in PERSONAS)}",
              file=sys.stderr)
        return 2

    print(f"alvo  : {url}")
    print(f"proxy : {args.proxy or 'NENHUM (seu IP real)'}")
    print(f"testes: {len(personas)}\n")

    def progress(i, total, p):
        print(f"  -> [{i+1}/{total}] {p.name} ...", flush=True)

    probes = probe_url(url, proxy=args.proxy, timeout=args.timeout,
                       personas=personas, delay=args.delay, on_progress=progress)
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
    p.add_argument("--proxy", help="http://user:pass@host:porta ou socks5://...")
    p.add_argument("--personas", help="subconjunto, separado por virgula")
    p.add_argument("--timeout", type=int, default=25)
    p.add_argument("--delay", type=float, default=0.4,
                   help="pausa entre personas (evita parecer burst pro WAF)")
    p.add_argument("--ad-id", help="ligar o resultado a um anuncio ja importado")
    p.add_argument("--force", action="store_true",
                   help="rodar mesmo com a URL sendo a raiz do dominio")
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

# No arquivo cli.py, adicione este comando

@cli.command()
@click.argument("url")
@click.option("--proxy", help="Proxy: socks5://user:pass@host:porta")
@click.option("--force-browser", is_flag=True, help="Forçar uso de navegador real")
@click.option("--no-fallback", is_flag=True, help="Desabilitar fallback para navegador")
def probe(url, proxy, force_browser, no_fallback):
    """Sonda uma URL real com fallback para navegador se detectar despejo."""
    from funnel_recon.probe import probe_url
    
    result = probe_url(
        url=url,
        proxy=proxy,
        use_js_fallback=not no_fallback,
        force_browser=force_browser,
    )
    
    # Exibe resultado formatado
    print("\n" + "="*60)
    print("📊 RESULTADO DA PROBE")
    print("="*60)
    print(f"URL: {url}")
    print(f"Proxy: {proxy or 'Nenhum'}")
    print(f"Método usado: {result.get('method', 'desconhecido')}")
    print(f"Despejo? {'SIM' if result.get('bounced') else 'NÃO'}")
    if result.get('bounce_reason'):
        print(f"Motivo do despejo: {result['bounce_reason']}")
    
    # Mostra trecho do HTML
    html = result.get('html', '')
    print(f"\n📄 HTML (primeiros 500 caracteres):")
    print("-"*60)
    print(html[:500])
    print("-"*60)
    print(f"Tamanho total: {len(html):,} caracteres")
