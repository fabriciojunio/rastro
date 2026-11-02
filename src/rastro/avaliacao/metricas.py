"""Métricas de ranqueamento para análise de variantes.

Quem usa o rastro lê a lista de cima para baixo e para em algum ponto. Por isso
as métricas olham o topo: quantas variantes reais aparecem nas k primeiras
posições, em que posição aparece a primeira, e quanto do topo é código que já
foi corrigido, que é o falso positivo que mais custa confiança na ferramenta.
"""

from collections.abc import Sequence
from enum import StrEnum


class Rotulo(StrEnum):
    VARIANTE = "variante"
    """Ainda vulnerável, parente da semente. É o que se quer achar."""
    CORRIGIDO = "corrigido"
    """Parente da semente, mas já corrigido. O falso positivo difícil."""
    OUTRO = "outro"
    """Sem relação com a semente."""


def _validar_k(k: int) -> None:
    if k < 1:
        raise ValueError("k precisa ser pelo menos 1")


def recall_em_k(ranking: Sequence[Rotulo], k: int) -> float:
    """Fração das variantes que aparece nas k primeiras posições."""
    _validar_k(k)
    total = ranking.count(Rotulo.VARIANTE)
    if total == 0:
        return 0.0
    return list(ranking[:k]).count(Rotulo.VARIANTE) / total


def precisao_em_k(ranking: Sequence[Rotulo], k: int) -> float:
    """Fração das k primeiras posições que é variante."""
    _validar_k(k)
    topo = list(ranking[:k])
    if not topo:
        return 0.0
    return topo.count(Rotulo.VARIANTE) / len(topo)


def corrigidos_em_k(ranking: Sequence[Rotulo], k: int) -> float:
    """Fração das k primeiras posições que é código já corrigido."""
    _validar_k(k)
    topo = list(ranking[:k])
    if not topo:
        return 0.0
    return topo.count(Rotulo.CORRIGIDO) / len(topo)


def reciproco_do_primeiro(ranking: Sequence[Rotulo]) -> float:
    """1 sobre a posição da primeira variante; zero se não houver nenhuma.

    A média disso sobre várias sementes é o MRR.
    """
    for posicao, rotulo in enumerate(ranking, start=1):
        if rotulo is Rotulo.VARIANTE:
            return 1.0 / posicao
    return 0.0


def precisao_media(ranking: Sequence[Rotulo]) -> float:
    """Média da precisão em cada posição onde aparece uma variante (AP)."""
    acertos = 0
    soma = 0.0
    for posicao, rotulo in enumerate(ranking, start=1):
        if rotulo is Rotulo.VARIANTE:
            acertos += 1
            soma += acertos / posicao
    return soma / acertos if acertos else 0.0
