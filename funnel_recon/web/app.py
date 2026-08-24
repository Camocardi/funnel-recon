"""A interface do app: FastAPI servindo uma pagina unica em localhost.

Roda local de proposito. A camada decisiva do cloaker de destino e o IP, e
servidor em nuvem tem ASN de datacenter -- exatamente o primeiro sinal que
todo cloaker bloqueia. A maquina de casa tem IP residencial, que e o ativo
que se aluga caro. Alem disso a coleta precisa da sessao logada do Facebook,
que so existe aqui.

O progresso vai para a pagina por SSE: a cascata pode levar minutos e ficar
olhando para uma tela parada e o oposto de "facil de usar".
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from ..orchestrate import run_pipeline

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Funnel Recon")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/criativo/{pasta}/{arquivo}")
async def criativo(pasta: str, arquivo: str):
    """Serve uma imagem de criativo salva, para a galeria do relatorio.

    Restrito a support/creatives: `pasta`/`arquivo` sao validados contra
    path traversal -- so nome simples, so dentro da base.
    """
    from .. import paths
    base = paths.creatives_dir().resolve()
    alvo = (base / pasta / arquivo).resolve()
    if base not in alvo.parents or not alvo.is_file():
        return JSONResponse({"erro": "nao encontrado"}, status_code=404)
    return FileResponse(alvo, filename=f"criativo_{arquivo}")


@app.get("/api/analisar")
async def analisar(url: str, proxy: str | None = None, modo: str = "tudo",
                   max_ads: int | None = None, max_seconds: float | None = None,
                   status: str = "all"):
    """Roda a cascata e transmite cada evento assim que acontece.

    `max_ads`/`max_seconds` existem como parametro de query, sem campo na tela:
    o padrao (2.000 anuncios) serve para qualquer pagina, e quem precisa de
    outro numero sabe montar a URL. Colocar isso na interface daria a entender
    que aumentar o teto melhora o resultado -- e nao melhora: numa pagina
    gigante, o caminho certo e filtrar a busca na Biblioteca, nao coletar mais.
    """
    fila: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    # TUDO entra na fila pelo mesmo caminho, de proposito. Os eventos de
    # estagio precisam de call_soon_threadsafe porque o probe roda em outra
    # thread; se o resultado final entrasse direto com `await fila.put`, ele
    # poderia ultrapassar eventos ainda agendados e o `None` encerraria o
    # stream antes deles -- eventos sumiam da tela. Uma via so preserva a ordem.
    def enfileirar(item):
        loop.call_soon_threadsafe(fila.put_nowait, item)

    def progress(stage: str, event: str, data: dict):
        enfileirar({"tipo": "estagio", "estagio": stage,
                    "evento": event, "dados": data})

    async def worker():
        try:
            f = await run_pipeline(url, progress=progress, proxy=proxy or None,
                                   max_ads=max_ads, max_seconds=max_seconds,
                                   mode=modo, status=status)
            enfileirar({"tipo": "final", "resultado": _serialize(f)})
        except Exception as e:  # nunca deixar a pagina pendurada
            enfileirar({"tipo": "erro", "mensagem": f"{type(e).__name__}: {e}"})
        finally:
            enfileirar(None)

    async def stream():
        """Transmite os eventos, com pulso quando nao ha novidade.

        A coleta abre um navegador de verdade e isso leva ~10s antes de
        qualquer evento sair. Sem pulso, a pagina fica muda nesse buraco e o
        usuario nao sabe se travou. O pulso tambem impede que proxy ou
        navegador derrubem uma conexao SSE parada.
        """
        task = asyncio.create_task(worker())
        inicio = asyncio.get_running_loop().time()
        try:
            while True:
                try:
                    item = await asyncio.wait_for(fila.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    decorrido = asyncio.get_running_loop().time() - inicio
                    yield ("data: " + json.dumps(
                        {"tipo": "pulso", "segundos": round(decorrido)}) + "\n\n")
                    continue
                if item is None:
                    break
                yield f"data: {json.dumps(item, ensure_ascii=False, default=str)}\n\n"
        finally:
            task.cancel()

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


def _galeria(f) -> list[dict]:
    """Um card por criativo escalado: contagem, hosts e a imagem salva (se ha).

    Casa cada grupo de collation com o arquivo de imagem do seu representante,
    para o relatorio mostrar a miniatura -- e nao so o numero de copias.
    """
    from pathlib import Path

    from ..collation import representantes

    reps = {a.ad_id: a for a in representantes(f.ads, limite=12)}
    resumo_por_grupo = {g["collation_id"]: g for g in f.criativos_pulverizados}
    pasta = Path(f.creatives_dir) if f.creatives_dir else None
    nome_pasta = pasta.name if pasta else ""

    # ad_id do representante por collation_id, para casar com o resumo
    rep_por_grupo = {}
    for a in reps.values():
        rep_por_grupo.setdefault(getattr(a, "collation_id", ""), a.ad_id)

    saida = []
    for g in f.criativos_pulverizados:
        cid = g["collation_id"]
        ad_id = rep_por_grupo.get(cid)
        img = ""
        if ad_id and pasta:
            for ext in (".jpg", ".png"):
                if (pasta / f"{ad_id}{ext}").is_file():
                    img = f"/criativo/{nome_pasta}/{ad_id}{ext}"
                    break
        rep = reps.get(ad_id)
        # link do criativo em VIDEO (quando o representante e video, nao imagem)
        video = ""
        lib = getattr(rep, "creative_lib_url", "") if rep else ""
        if lib and "/o1/v/" in lib:
            video = lib
        saida.append({"declarado": g["declarado"], "vistos": g["vistos"],
                      "hosts": g["hosts"], "img": img, "video": video,
                      "ativos": g.get("ativos", 0), "inativos": g.get("inativos", 0),
                      "so_inativos": g.get("so_inativos", False),
                      "inicio": g.get("inicio"), "fim": g.get("fim")})
    return saida


def _serialize(f) -> dict:
    return {
        "veredito": f.verdict,
        "manchete": f.headline,
        "proximo_passo": f.next_step,
        "travado_em": f.blocked_by,
        "erro": f.error,
        "total_anuncios": len(f.ads),
        # Amostra ou pagina inteira? Sem isto a interface desenha um histograma
        # de 2.000 anuncios como se fosse o retrato de uma pagina de 50.000.
        "parcial": f.truncated,
        "parcial_motivo": f.truncated_reason,
        "modo": f.mode,
        "criativo": {
            "hasheados": f.creative_hashed,
            "comparados": f.creative_compared,
            "divergencias": [asdict(d) for d in f.creative_diffs],
        },
        "histograma": [{"host": h, "n": n, "outlier": o} for h, n, o in f.histogram],
        "caminhos": {h: [{"caminho": c, "url": u, "n": n, "variante": v}
                         for c, u, n, v in cs] for h, cs in f.paths.items()},
        "cloakers": [{"host": h, "plataforma": p_, "confirmado": c}
                     for h, p_, c in f.cloakers],
        "vazamentos": [{"achado": a, "ad_id": i} for a, i in f.leaks],
        "osint": {d: [asdict(r) for r in rs] for d, rs in f.osint.items()},
        "probes": {u: [asdict(r) for r in rs] for u, rs in f.probes.items()},
        "portas_laterais": [asdict(r) for r in f.sidedoors],
        # id da VSL -> como ela ja e conhecida. O front usa para separar a
        # isca (VSL velha, deixada exposta) da oferta de verdade.
        "vsls_conhecidas": f.vsls_conhecidas,
        "operadores_vistos": f.operadores_vistos,
        "rede": {"bytes": f.bytes_coleta, "por_tipo": f.rede_por_tipo},
        "bio_dominios": f.bio_dominios,
        "criativos_pulverizados": _galeria(f),
        "fachada": f.fachada,
        "anuncios": [asdict(a) for a in f.ads[:200]],
    }


def serve(host: str = "127.0.0.1", port: int = 8765, abrir: bool = True):
    import uvicorn
    if abrir:
        import threading
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{host}:{port}")).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
