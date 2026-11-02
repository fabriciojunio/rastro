"""O que a aplicação precisa do mundo de fora, sem saber quem entrega."""

from typing import Protocol

from rastro.dominio.modelos import Linguagem


class AnalisadorDeTrecho(Protocol):
    def tokens(self, trecho: str, linguagem: Linguagem) -> tuple[str, ...]: ...

    def chamadas(self, trecho: str, linguagem: Linguagem) -> frozenset[str]: ...
