"""Testes do parser de payload GraphQL. Sem rede."""

import json
import sys
import urllib.parse as up
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from funnel_recon.collect.browser import (MAX_ADS, MAX_SECONDS,
                                           STAGNANT_LIMIT, stop_reason,
                                           with_all_statuses)
from funnel_recon.collect.parse import (extract_ads, merge_rec, to_date,
                                        unwrap_facebook_link)

failures = []


def check(name, got, want):
    if got != want:
        failures.append(f"{name}: esperado {want!r}, veio {got!r}")


REAL = "https://cantinhoprivado.shop/l/ab68b001?fbclid=IwcGRvZ123"
WRAPPED = "https://l.facebook.com/l.php?u=" + up.quote(REAL, safe="") + "&h=AT1"

# A URL real vem embrulhada; sem desembrulhar, todo anuncio parece do facebook
check("desembrulha", unwrap_facebook_link(WRAPPED), REAL)
check("nao mexe no que ja e direto", unwrap_facebook_link(REAL), REAL)
check("vazio", unwrap_facebook_link(""), "")
check("nao-string", unwrap_facebook_link(None), "")
# l.php de outro host nao e o redirecionador do Meta
check("host diferente", unwrap_facebook_link("https://evil.com/l.php?u=x"),
      "https://evil.com/l.php?u=x")

check("epoch", to_date(1774000000), "2026-03-20")
check("iso", to_date("2026-03-17T10:00:00"), "2026-03-17")
check("lixo", to_date("qualquer coisa"), "")
check("zero", to_date(0), "")

payload = json.dumps({"data": {"x": [{
    "ad_archive_id": "1234567890",
    "start_date": 1774000000,
    "snapshot": {
        "link_url": WRAPPED,
        "page_name": "Ana Alves",
        "cta_text": "Saiba mais",
        "title": "Cantinho",
        "body": {"text": "chama no @CantinhoPrivadoBot"},
        "videos": [{"video_hd_url": "https://cdn-terceiro.com/v.mp4"}],
    }}]}})
ads = extract_ads(payload)
check("um anuncio", len(ads), 1)
a = ads[0]
check("id", a["ad_id"], "1234567890")
check("url real extraida", a["url"], REAL)
check("body de dict.text", a["body"], "chama no @CantinhoPrivadoBot")
check("midia aninhada", a["media"], ["https://cdn-terceiro.com/v.mp4"])
check("data", a["start"], "2026-03-20")

# Payloads concatenados por linha: o Meta faz isso
check("multilinha", len(extract_ads(payload + "\n" + payload.replace("1234567890", "9999999999"))), 2)
check("lixo nao quebra", extract_ads("nao e json"), [])
check("vazio", extract_ads(""), [])
# id curto demais nao e ad_archive_id
check("id curto ignorado", extract_ads(json.dumps({"ad_archive_id": "12"})), [])

# --- status de veiculacao ---------------------------------------------------
# O parser tem que distinguir tres coisas: no ar, encerrado, e "nao me disseram".
check("sem campo = None", a["is_active"], None)


def um(**extra):
    return extract_ads(json.dumps({"ad_archive_id": "1234567890", **extra}))[0]


check("ativo", um(is_active=True)["is_active"], True)
check("encerrado", um(is_active=False)["is_active"], False)
check("encerrado como 0", um(isActive=0)["is_active"], False)
check("data de fim", um(end_date=1774000000)["end"], "2026-03-20")
# Nao inventar status a partir de campo alheio: 5 nao e booleano disfarcado.
check("numero fora de 0/1 nao vira status", um(is_active=5)["is_active"], None)

# A fusao de payloads parciais nao pode tratar False como ausencia -- False e
# justamente o valor que interessa, e o teste `if v` o descartaria.
prev = {"ad_id": "1", "is_active": None, "url": ""}
merge_rec(prev, {"ad_id": "1", "is_active": False, "url": "https://x.shop/l/a"})
check("False sobrevive a fusao", prev["is_active"], False)
check("campo vazio e preenchido", prev["url"], "https://x.shop/l/a")
# Status que ja veio nao e sobrescrito por um payload posterior mais pobre.
merge_rec(prev, {"is_active": True})
check("status nao e sobrescrito", prev["is_active"], False)

# --- freios da coleta -------------------------------------------------------
# Pagina de 50.000 anuncios: STAGNANT_LIMIT nunca dispara, entao quem tem que
# parar a coleta e o teto -- e o motivo NAO pode ser "fim_da_lista", senao o
# relatorio trata 2.000 de 50.000 como se fosse a pagina toda.
check("continua no comeco", stop_reason(0, 0.0, 0), None)
check("teto de anuncios", stop_reason(MAX_ADS, 10.0, 0), "teto_de_anuncios")
check("teto vale acima tambem", stop_reason(MAX_ADS + 500, 10.0, 0), "teto_de_anuncios")
check("prazo esgotado", stop_reason(10, MAX_SECONDS, 0), "prazo_esgotado")
check("fim de verdade", stop_reason(10, 1.0, STAGNANT_LIMIT), "fim_da_lista")
# Teto e prazo vencem estagnacao: a pagina pode ter parado de carregar POR
# estar sobrecarregada, e chamar isso de fim da lista seria mentira.
check("teto vence estagnacao", stop_reason(MAX_ADS, 1.0, STAGNANT_LIMIT), "teto_de_anuncios")
check("prazo vence estagnacao", stop_reason(1, MAX_SECONDS, STAGNANT_LIMIT), "prazo_esgotado")
check("limite proprio respeitado", stop_reason(50, 0.0, 0, max_ads=50), "teto_de_anuncios")

# --- a URL da Biblioteca tem que pedir ativos E inativos ---------------------
BASE = "https://www.facebook.com/ads/library/?view_all_page_id=123&country=BR"
check("acrescenta active_status", "active_status=all" in with_all_statuses(BASE), True)
check("preserva o resto", "view_all_page_id=123" in with_all_statuses(BASE), True)
check("nao duplica", with_all_statuses(BASE + "&active_status=active").count("active_status"), 1)
check("troca o valor", "active_status=all" in with_all_statuses(BASE + "&active_status=active"), True)
# URL que nao e do Meta nao e nossa pra reescrever
check("host de fora intacto", with_all_statuses("https://x.shop/p?a=1"), "https://x.shop/p?a=1")

if failures:
    print(f"FALHOU ({len(failures)}):")
    for f in failures:
        print("  -", f)
    raise SystemExit(1)
print("parser ok")
