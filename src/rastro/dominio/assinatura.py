"""A assinatura da correção: o que a correção tirou e o que pôs.

É a ideia central do rastro. Clone de código acha o que é parecido com a falha,
e por isso também acha o código que já foi corrigido, que continua parecido. A
assinatura diz o que diferencia os dois: uma variante ainda vulnerável tem os
n-gramas que a correção removeu e não tem os que ela acrescentou.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from rastro.dominio.ngramas import Ngrama, cobertura, ngramas


@dataclass(frozen=True, slots=True)
class AssinaturaDaCorrecao:
    removidos: frozenset[Ngrama]
    adicionados: frozenset[Ngrama]

    @classmethod
    def de(
        cls, tokens_vulneravel: Sequence[str], tokens_corrigido: Sequence[str], n: int
    ) -> "AssinaturaDaCorrecao":
        antes = ngramas(tokens_vulneravel, n)
        depois = ngramas(tokens_corrigido, n)
        return cls(removidos=antes - depois, adicionados=depois - antes)

    def falha_presente(self, candidato: frozenset[Ngrama]) -> float:
        """Quanto do que a correção removeu ainda está no candidato."""
        return cobertura(self.removidos, candidato)

    def correcao_presente(self, candidato: frozenset[Ngrama]) -> float:
        """Quanto do que a correção acrescentou já está no candidato."""
        return cobertura(self.adicionados, candidato)
