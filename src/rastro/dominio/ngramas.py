"""Comparação de sequências de tokens por n-gramas.

N-grama de token é o que torna a comparação tolerante a reordenação local sem
perder a ordem por completo: dois trechos com as mesmas chamadas na mesma
sequência dividem os n-gramas, mesmo com variáveis de nomes diferentes.
"""

from collections.abc import Hashable, Sequence
from typing import TypeAlias, TypeVar

Ngrama: TypeAlias = tuple[str, ...]
_T = TypeVar("_T", bound=Hashable)


def ngramas(tokens: Sequence[str], n: int) -> frozenset[Ngrama]:
    """Conjunto dos n-gramas de uma sequência. Sequência curta vira um n-grama só."""
    if n < 1:
        raise ValueError("n precisa ser pelo menos 1")
    if not tokens:
        return frozenset()
    if len(tokens) < n:
        return frozenset({tuple(tokens)})
    return frozenset(tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1))


def jaccard(a: frozenset[_T], b: frozenset[_T]) -> float:
    """Tamanho da interseção sobre o da união. Dois vazios contam como zero."""
    uniao = a | b
    if not uniao:
        return 0.0
    return len(a & b) / len(uniao)


def cobertura(procurados: frozenset[_T], presentes: frozenset[_T]) -> float:
    """Fração dos procurados que aparece em presentes. Nada procurado conta zero."""
    if not procurados:
        return 0.0
    return len(procurados & presentes) / len(procurados)
