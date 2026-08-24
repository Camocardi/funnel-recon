"""Anuncio-fachada: criativo que nao tem relacao com o destino real.

O que o usuario viu com os proprios olhos e estava certo: uma pagina "Dr.
Selena Moore - Sexologist" rodando dezenas de anuncios de "Mini Projector -
$4.99", e no meio deles UM anuncio apontando para o dominio real de intimidade
(drselenaxmooresexologistintimacy.com). Os projetores sao isca de revisao:
produto generico, barato, inofensivo, passa facil pelo Meta. O funil de verdade
fica escondido na multidao.

Nao e o cloaker de destino (esse troca a landing por IP). E outra camada, na
propria Biblioteca: o CRIATIVO nao combina com a OFERTA. E como o Meta serve a
imagem para todos, isso vaza -- da para ver sem furar nada.

A deteccao e por CONTRASTE dentro da mesma pagina: quando a maioria esmagadora
dos criativos fala de um produto generico e uma minoria aponta para outro
dominio/tema, a maioria e fachada e a minoria e o alvo.
"""

from __future__ import annotations

import re
from collections import Counter

# Produtos genericos de dropship usados como isca de revisao. Nao e a oferta;
# e a fachada que passa no Meta.
ISCA_GENERICA = re.compile(
    r"mini projector|projector|smart ?watch|led lamp|phone case|earbuds|"
    r"free shipping|\$\d+\.\d{2}", re.I)


def _texto(ad) -> str:
    return " ".join(str(getattr(ad, c, "") or "") for c in ("title", "body", "cta"))


def analisar(ads: list) -> dict:
    """Separa fachada de alvo numa pagina. {} se nada de anormal.

    Retorna a contagem de iscas genericas, os anuncios que fogem do padrao
    (os candidatos a funil real) e os dominios de destino que eles revelam.
    """
    if len(ads) < 3:
        return {}

    iscas, foras = [], []
    for a in ads:
        if ISCA_GENERICA.search(_texto(a)):
            iscas.append(a)
        else:
            foras.append(a)

    # So e "fachada" se a isca DOMINA (>= 60%) e ha um punhado fugindo dela.
    if not iscas or len(iscas) < 0.6 * len(ads) or not foras:
        return {}

    destinos = Counter(a.display_host for a in foras
                       if getattr(a, "display_host", None))
    return {
        "iscas": len(iscas),
        "total": len(ads),
        "amostra_isca": _texto(iscas[0])[:60],
        "fogem": len(foras),
        "destinos_reais": [{"host": h, "n": n} for h, n in destinos.most_common(6)],
    }
