"""O vocabulário do rastro: linguagem, função analisada e semente."""

from dataclasses import dataclass
from enum import StrEnum


class Linguagem(StrEnum):
    JAVA = "java"
    PHP = "php"
    C = "c"


@dataclass(frozen=True, slots=True)
class Funcao:
    """Uma função do código analisado, candidata a ser variante da semente."""

    nome: str
    linguagem: Linguagem
    caminho: str
    linha: int
    codigo: str

    def __post_init__(self) -> None:
        if not self.codigo.strip():
            raise ValueError("função sem código")
        if self.linha < 1:
            raise ValueError("linha começa em 1")


class SementeInvalida(ValueError):
    """A semente não descreve uma correção."""


@dataclass(frozen=True, slots=True)
class Semente:
    """Uma vulnerabilidade conhecida: o código antes e depois da correção.

    É o que chega numa CVE ou num relato de bug bounty. A versão corrigida não
    é enfeite: é dela que sai a assinatura da correção, que separa a variante
    ainda vulnerável do código parecido que já foi corrigido.
    """

    identificador: str
    linguagem: Linguagem
    vulneravel: str
    corrigido: str

    def __post_init__(self) -> None:
        if not self.identificador.strip():
            raise SementeInvalida("semente sem identificador")
        if not self.vulneravel.strip() or not self.corrigido.strip():
            raise SementeInvalida("semente precisa do código vulnerável e do corrigido")
        if self.vulneravel.strip() == self.corrigido.strip():
            raise SementeInvalida("código vulnerável e corrigido são iguais: não há correção")
