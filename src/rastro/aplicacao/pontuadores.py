"""Quem dá a nota de cada candidato: as baselines e o modelo aprendido.

Todos recebem a mesma coisa (a semente e os candidatos já analisados) e devolvem
uma nota por candidato; quanto maior, mais alto no ranking. Assim a comparação
das perguntas de pesquisa mede o pontuador, e não diferenças de preparo.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from rastro.aplicacao.caracteristicas import (
    NOMES,
    CandidatoAnalisado,
    SementeAnalisada,
    vetor,
)


class Pontuador(Protocol):
    @property
    def nome(self) -> str: ...

    def pontuar(
        self, semente: SementeAnalisada, candidatos: Sequence[CandidatoAnalisado]
    ) -> list[float]: ...


@dataclass(frozen=True, slots=True)
class CloneExato:
    """Baseline no estilo do VUDDY: só o código abstraído idêntico conta."""

    nome: str = "clone_exato"

    def pontuar(
        self, semente: SementeAnalisada, candidatos: Sequence[CandidatoAnalisado]
    ) -> list[float]:
        return [1.0 if c.impressao == semente.impressao else 0.0 for c in candidatos]


@dataclass(frozen=True, slots=True)
class Jaccard:
    """Baseline de semelhança: n-gramas em comum com o código vulnerável."""

    nome: str = "jaccard"

    def pontuar(
        self, semente: SementeAnalisada, candidatos: Sequence[CandidatoAnalisado]
    ) -> list[float]:
        return [vetor(semente, c)[NOMES.index("sim_vulneravel")] for c in candidatos]


@dataclass(frozen=True, slots=True)
class JaccardMenosCorrecao:
    """Heurística sem aprendizado: perto da falha e longe da correção.

    Separa o ganho da ideia (usar a correção) do ganho do modelo.
    """

    nome: str = "jaccard_menos_correcao"

    def pontuar(
        self, semente: SementeAnalisada, candidatos: Sequence[CandidatoAnalisado]
    ) -> list[float]:
        i_v, i_c = NOMES.index("sim_vulneravel"), NOMES.index("sim_corrigido")
        notas = []
        for c in candidatos:
            x = vetor(semente, c)
            notas.append(x[i_v] - x[i_c])
        return notas


CARACTERISTICAS_SEM_CORRECAO = (
    "sim_vulneravel",
    "contencao_vulneravel",
    "sim_chamadas",
    "log_razao_tamanho",
)


class ModeloNaoTreinado(RuntimeError):
    """O modelo foi usado antes de aprender."""


@dataclass(slots=True)
class ModeloAprendido:
    """Classificador de gradient boosting sobre as características do par.

    A nota é a probabilidade de o candidato ser variante ainda vulnerável.
    ``colunas`` permite treinar só com parte das características: sem as que
    olham a correção, é a ablação da pergunta de pesquisa 2.
    """

    nome: str
    colunas: tuple[str, ...] = NOMES
    semente_aleatoria: int = 42
    _modelo: HistGradientBoostingClassifier | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        desconhecidas = set(self.colunas) - set(NOMES)
        if desconhecidas:
            raise ValueError(f"características desconhecidas: {sorted(desconhecidas)}")

    def _matriz(
        self, semente: SementeAnalisada, candidatos: Sequence[CandidatoAnalisado]
    ) -> np.ndarray:
        indices = [NOMES.index(c) for c in self.colunas]
        linhas = [[x[i] for i in indices] for x in (vetor(semente, c) for c in candidatos)]
        return np.asarray(linhas, dtype=float).reshape(len(candidatos), len(indices))

    def treinar(
        self,
        pares: Sequence[tuple[SementeAnalisada, Sequence[CandidatoAnalisado], Sequence[bool]]],
    ) -> None:
        """Aprende com sementes já rotuladas: True quando o candidato é variante."""
        matrizes = [self._matriz(s, cs) for s, cs, _ in pares]
        rotulos = [r for _, _, rs in pares for r in rs]
        if not matrizes or len(set(rotulos)) < 2:
            raise ValueError("o treino precisa de exemplos positivos e negativos")
        modelo = HistGradientBoostingClassifier(
            max_iter=200,
            learning_rate=0.1,
            # Variante é rara perto do resto; sem peso, o modelo aprende a dizer não.
            class_weight="balanced",
            random_state=self.semente_aleatoria,
        )
        modelo.fit(np.vstack(matrizes), np.asarray(rotulos, dtype=int))
        self._modelo = modelo

    def pontuar(
        self, semente: SementeAnalisada, candidatos: Sequence[CandidatoAnalisado]
    ) -> list[float]:
        if self._modelo is None:
            raise ModeloNaoTreinado(f"o modelo {self.nome} ainda não foi treinado")
        if not candidatos:
            return []
        probabilidades = self._modelo.predict_proba(self._matriz(semente, candidatos))
        return [float(p) for p in probabilidades[:, 1]]
