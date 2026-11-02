"""Descrição numérica de um par (semente, candidato), que o modelo aprende a pesar.

Cada característica responde a uma pergunta de quem faz análise de variantes:
o candidato parece com a falha? parece com a correção? tem o que a correção
tirou? já tem o que ela pôs? chama as mesmas funções perigosas?
"""

import math
from dataclasses import dataclass

from rastro.aplicacao.portas import AnalisadorDeTrecho
from rastro.dominio.assinatura import AssinaturaDaCorrecao
from rastro.dominio.modelos import Funcao, Semente
from rastro.dominio.ngramas import Ngrama, cobertura, jaccard, ngramas

TAMANHO_DO_NGRAMA = 3

NOMES = (
    "sim_vulneravel",
    "sim_corrigido",
    "contencao_vulneravel",
    "falha_presente",
    "correcao_presente",
    "sim_chamadas",
    "chamadas_removidas_presentes",
    "chamadas_adicionadas_presentes",
    "log_razao_tamanho",
)


@dataclass(frozen=True, slots=True)
class SementeAnalisada:
    semente: Semente
    ngramas_vulneravel: frozenset[Ngrama]
    ngramas_corrigido: frozenset[Ngrama]
    assinatura: AssinaturaDaCorrecao
    chamadas_vulneravel: frozenset[str]
    chamadas_removidas: frozenset[str]
    chamadas_adicionadas: frozenset[str]
    tamanho: int


@dataclass(frozen=True, slots=True)
class CandidatoAnalisado:
    funcao: Funcao
    ngramas: frozenset[Ngrama]
    chamadas: frozenset[str]
    tamanho: int


def analisar_semente(
    semente: Semente, analisador: AnalisadorDeTrecho, n: int = TAMANHO_DO_NGRAMA
) -> SementeAnalisada:
    tokens_v = analisador.tokens(semente.vulneravel, semente.linguagem)
    tokens_c = analisador.tokens(semente.corrigido, semente.linguagem)
    chamadas_v = analisador.chamadas(semente.vulneravel, semente.linguagem)
    chamadas_c = analisador.chamadas(semente.corrigido, semente.linguagem)
    return SementeAnalisada(
        semente=semente,
        ngramas_vulneravel=ngramas(tokens_v, n),
        ngramas_corrigido=ngramas(tokens_c, n),
        assinatura=AssinaturaDaCorrecao.de(tokens_v, tokens_c, n),
        chamadas_vulneravel=chamadas_v,
        chamadas_removidas=chamadas_v - chamadas_c,
        chamadas_adicionadas=chamadas_c - chamadas_v,
        tamanho=len(tokens_v),
    )


def analisar_candidato(
    funcao: Funcao, analisador: AnalisadorDeTrecho, n: int = TAMANHO_DO_NGRAMA
) -> CandidatoAnalisado:
    tokens = analisador.tokens(funcao.codigo, funcao.linguagem)
    return CandidatoAnalisado(
        funcao=funcao,
        ngramas=ngramas(tokens, n),
        chamadas=analisador.chamadas(funcao.codigo, funcao.linguagem),
        tamanho=len(tokens),
    )


def vetor(semente: SementeAnalisada, candidato: CandidatoAnalisado) -> list[float]:
    """As características do par, na ordem de NOMES."""
    return [
        jaccard(candidato.ngramas, semente.ngramas_vulneravel),
        jaccard(candidato.ngramas, semente.ngramas_corrigido),
        cobertura(semente.ngramas_vulneravel, candidato.ngramas),
        semente.assinatura.falha_presente(candidato.ngramas),
        semente.assinatura.correcao_presente(candidato.ngramas),
        jaccard(candidato.chamadas, semente.chamadas_vulneravel),
        cobertura(semente.chamadas_removidas, candidato.chamadas),
        cobertura(semente.chamadas_adicionadas, candidato.chamadas),
        # Log para a função dez vezes maior pesar como a dez vezes menor.
        math.log((candidato.tamanho + 1) / (semente.tamanho + 1)),
    ]
