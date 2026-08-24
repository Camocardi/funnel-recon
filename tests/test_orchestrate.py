"""Testes da cascata: modos, freios e a trilha de criativo. Sem rede.

Coleta, OSINT, probe e download de criativo entram como dubles. O que se testa
aqui e a ORQUESTRACAO -- quem roda, quem e pulado, e o que o app conclui com o
que sobrou. Cada estagio real ja tem teste proprio.

O caso que mais importa: no modo "so criativos" nada foi sondado, entao o app
nao pode concluir nada sobre o destino. Sem isso ele diria "caminhos
automaticos esgotados, compre proxy" para quem nunca pediu o destino.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon import db, orchestrate

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


def contem(name, texto, trecho):
    if trecho.lower() not in (texto or "").lower():
        failures.append(f"{name}: nao achei {trecho!r} em {texto!r}")


IMG = "https://cdn.fb/a.jpg"
LINHAS = [
    {"ad_id": "a1", "url": "https://white.shop/p", "page_id": "555",
     "media": [IMG], "start": "2026-07-01", "is_active": True},
    {"ad_id": "a2", "url": "https://alvo.shop/l/h?fbclid=Iw", "page_id": "555",
     "media": [IMG], "start": "2026-04-01", "is_active": False},
]
HASHES = {"a1": "ffffffffffffffff", "a2": "0f0f0f0f0f0f0f0f"}

chamou = {"osint": 0, "probe": 0, "hash": 0}


def coletor(parcial=False, linhas=None):
    async def falso(url, on_progress=None, **kw):
        if parcial:
            on_progress("parcial", {"ads": 2, "motivo": "teto_de_anuncios"})
        return list(linhas if linhas is not None else LINHAS)
    return falso


async def hash_falso(items, concurrency=6, on_done=None, salvar_em=None, salvar_apenas=None):
    chamou["hash"] += 1
    return {k: HASHES[k] for k, _ in items if k in HASHES}


async def osint_falso(hosts, concurrency=4):
    chamou["osint"] += 1
    return {}


def probe_falso(*a, **kw):
    chamou["probe"] += 1
    return []


orchestrate.hash_many = hash_falso
orchestrate.osint_many = osint_falso
orchestrate.probe_url = probe_falso

URL = "https://www.facebook.com/ads/library/?view_all_page_id=555"


def rodar(**kw):
    eventos = []
    kw.setdefault("collect_fn", coletor())
    f = asyncio.run(orchestrate.run_pipeline(
        URL, progress=lambda e, x, d: eventos.append((e, x, d)), **kw))
    return f, eventos


def pulados(eventos):
    return {e for e, x, _ in eventos if x == "pulado"}


with tempfile.TemporaryDirectory() as tmp:
    db.db_path = lambda: Path(tmp) / "t.db"

    # --- modo "so o funil": AGORA tambem hasheia -----------------------
    # O hash roda em todo modo (menos max_creative_hashes=0), porque e ele que
    # constroi o historico ontem x hoje -- deteccao de troca de criativo que
    # nao depende da money page. So o video pesado fica de fora; a thumbnail e
    # barata. Ver orchestrate: bloco de criativo.
    chamou.update(osint=0, probe=0, hash=0)
    f, ev = rodar(mode="funil")
    check("funil roda o osint", chamou["osint"], 1)
    check("funil AGORA hasheia para o historico", chamou["hash"], 1)
    check("funil guarda hash", f.creative_hashed > 0, True)

    # --- max_creative_hashes=0 desliga o hash de proposito -------------
    chamou.update(osint=0, probe=0, hash=0)
    f, ev = rodar(mode="funil", max_creative_hashes=0)
    check("hash desligado nao hasheia", chamou["hash"], 0)
    check("estagio de criativo marcado como pulado", "criativo" in pulados(ev), True)

    # --- modo "so os criativos": nao sonda o alvo -----------------------
    chamou.update(osint=0, probe=0, hash=0)
    f, ev = rodar(mode="criativo")
    check("criativo nao roda osint", chamou["osint"], 0)
    check("criativo nao sonda o alvo", chamou["probe"], 0)
    check("osint e probe marcados como pulados", pulados(ev), {"osint", "probe"})
    check("criativo hasheia", f.creative_hashed, 2)
    # Primeira analise: nada a comparar, e o app tem que DIZER isso em vez de
    # se calar ou de fingir conclusao.
    check("sem historico nao inventa veredito", f.verdict, "unknown")
    contem("explica que nao ha versao anterior", f.next_step, "primeira analise")
    contem("diz o que fazer", f.next_step, "rode de novo")
    # E nunca a conclusao de destino, que ninguem pediu:
    if "proxy" in (f.next_step or "").lower():
        failures.append("modo criativo sugeriu proxy sem ter sondado nada")

    # --- segunda passada: o criativo de a2 mudou ------------------------
    HASHES["a2"] = "ffffffffffffff00"
    f, ev = rodar(mode="criativo")
    check("troca detectada", [(d.ad_id, d.kind) for d in f.creative_diffs], [("a2", "tempo")])
    check("veredito proprio da trilha de criativo", f.verdict, "criativo")
    contem("manchete fala da mudanca", f.headline, "mudou")
    contem("nao acusa sozinho", f.next_step, "criativo dinamico")
    check("contou o que deu para comparar", f.creative_compared, 2)

    # --- modo "tudo": as duas trilhas, sem uma sequestrar a outra -------
    chamou.update(osint=0, probe=0, hash=0)
    HASHES["a2"] = "1f1f1f1f1f1f1f1f"      # muda de novo
    f, ev = rodar()
    check("tudo roda osint", chamou["osint"], 1)
    check("tudo hasheia", chamou["hash"], 1)
    # O invariante: a trilha de criativo NAO pode sequestrar o veredito de
    # destino -- ele continua sendo o que o probe concluiu (aqui "unknown",
    # porque o probe dublado nao devolve resposta) -- mas tambem nao pode
    # sumir da tela, entao aparece no passo seguinte.
    check("achado de criativo nao vira veredito de destino", f.verdict, "unknown")
    if f.verdict == "criativo":
        failures.append("trilha de criativo sequestrou o veredito no modo tudo")
    contem("mas aparece no passo seguinte", f.next_step, "trilha de criativo")

    # --- freio: amostra nao marca outlier -------------------------------
    f, _ = rodar(collect_fn=coletor(parcial=True))
    check("parcial propagado", (f.truncated, f.truncated_reason),
          (True, "teto_de_anuncios"))
    check("amostra nao marca outlier", [h for h, _, o in f.histogram if o], [])

    f, _ = rodar()
    check("coleta completa nao se declara parcial", f.truncated, False)

    # --- modo invalido nao pode virar coleta silenciosamente diferente --
    f, _ = rodar(mode="qualquer-coisa")
    check("modo desconhecido cai no padrao", f.mode, "tudo")

    # --- pagina sem anuncio para antes de tudo --------------------------
    chamou.update(osint=0, probe=0, hash=0)
    f, _ = rodar(collect_fn=coletor(linhas=[]))
    check("sem anuncio nao gasta rede", (chamou["osint"], chamou["hash"]), (0, 0))
    contem("explica o vazio", f.headline, "nenhum anuncio")

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f_ in failures:
        print("  -", f_)
    raise SystemExit(1)
print("orquestracao ok")
