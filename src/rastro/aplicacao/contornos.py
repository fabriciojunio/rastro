"""Lugares que receberam a correção: onde procurar contorno.

A assinatura da correção rebaixa o código que já tem a correção, e é isso que
tira o falso positivo. Mas é nesse código que mora o contorno de uma correção
incompleta: a CVE-2024-4577 do PHP está na mesma função que recebeu a correção
da CVE-2012-1823. Esta lista não descarta esses lugares; separa-os.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from rastro.aplicacao.caracteristicas import NOMES, CandidatoAnalisado, SementeAnalisada, vetor

LIMIAR_DA_CORRECAO = 0.5
"""A maior parte do que a correção acrescentou está no candidato."""

LIMIAR_DA_SEMELHANCA = 0.3
"""O candidato é o mesmo código corrigido, e não qualquer função que use a chamada segura.

A comparação é com a versão corrigida, porque é com ela que um lugar que
recebeu a correção se parece.
"""

_SIM = NOMES.index("sim_corrigido")
_CORRECAO = NOMES.index("correcao_presente")


@dataclass(frozen=True, slots=True)
class CandidatoAContorno:
    candidato: CandidatoAnalisado
    semelhanca: float
    correcao_presente: float


def candidatos_a_contorno(
    semente: SementeAnalisada, candidatos: Sequence[CandidatoAnalisado]
) -> list[CandidatoAContorno]:
    """Os parecidos com o código corrigido que têm a correção, do mais parecido ao menos."""
    achados = []
    for candidato in candidatos:
        x = vetor(semente, candidato)
        if x[_CORRECAO] >= LIMIAR_DA_CORRECAO and x[_SIM] >= LIMIAR_DA_SEMELHANCA:
            achados.append(CandidatoAContorno(candidato, x[_SIM], x[_CORRECAO]))
    return sorted(achados, key=lambda a: (-a.semelhanca, a.candidato.funcao.caminho))
