"""Experimento das perguntas 1 e 2: ranquear variantes e não marcar o já corrigido.

Cada família da Juliet vira uma tarefa: a semente é o ``bad()`` do fluxo 01 com
a sua correção, e os candidatos são as outras variantes de fluxo da família
(variante ou corrigido) mais uma amostra de funções de outras CWEs.

A validação cruzada separa as dobras por CWE. O modelo é testado numa classe de
falha que ele nunca viu, que é a situação real de quem recebe uma CVE nova; e,
no treino, saem até os candidatos "outros" que vêm das CWEs de teste.
"""

import random
import statistics
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from scipy.stats import wilcoxon

from rastro.aplicacao.caracteristicas import (
    CandidatoAnalisado,
    SementeAnalisada,
    analisar_candidato,
    analisar_semente,
)
from rastro.aplicacao.pontuadores import ModeloAprendido, Pontuador
from rastro.aplicacao.portas import AnalisadorDeTrecho
from rastro.avaliacao.metricas import (
    Rotulo,
    corrigidos_em_k,
    precisao_em_k,
    precisao_media,
    recall_em_k,
    reciproco_do_primeiro,
)
from rastro.dominio.modelos import Linguagem, Semente
from rastro.infraestrutura.juliet import CasoJuliet

METRICAS: dict[str, Callable[[Sequence[Rotulo]], float]] = {
    "recall@1": lambda r: recall_em_k(r, 1),
    "recall@5": lambda r: recall_em_k(r, 5),
    "recall@10": lambda r: recall_em_k(r, 10),
    "precisao@10": lambda r: precisao_em_k(r, 10),
    "mrr": reciproco_do_primeiro,
    "ap": precisao_media,
    "corrigidos@10": lambda r: corrigidos_em_k(r, 10),
}

_ORDEM_DA_CORRECAO = ("B2G", "G2B", "")


class Escopo(StrEnum):
    FAMILIA = "familia"
    """Parentes são as outras variantes de fluxo da família: quase clones."""
    CWE = "cwe"
    """Parentes são as outras famílias da mesma CWE: a mesma falha em outro código.

    É o caso real de análise de variantes. A própria família fica de fora.
    """


@dataclass(frozen=True, slots=True)
class Tarefa:
    familia: str
    grupo: str
    semente: SementeAnalisada
    candidatos: tuple[CandidatoAnalisado, ...]
    rotulos: tuple[Rotulo, ...]
    grupos_dos_candidatos: tuple[str, ...]


def escolher_correcao(corrigidos: Sequence[CasoJuliet]) -> CasoJuliet | None:
    """A correção da semente: B2G corrige o uso do dado, como um patch de verdade."""
    for tipo in _ORDEM_DA_CORRECAO:
        opcoes = sorted(
            (c for c in corrigidos if c.tipo_da_correcao == tipo), key=lambda c: c.funcao.nome
        )
        if opcoes:
            return opcoes[0]
    return None


@dataclass(frozen=True, slots=True)
class ConfiguracaoDasTarefas:
    escopo: Escopo = Escopo.FAMILIA
    parentes_por_tarefa: int = 300
    """Só no escopo cwe: quantos parentes sortear das outras famílias."""
    outros_por_tarefa: int = 200
    semente_aleatoria: int = 42


def montar_tarefas(
    casos: Sequence[CasoJuliet],
    analisador: AnalisadorDeTrecho,
    configuracao: ConfiguracaoDasTarefas | None = None,
) -> list[Tarefa]:
    configuracao = configuracao or ConfiguracaoDasTarefas()
    escopo = configuracao.escopo
    sorteio = random.Random(configuracao.semente_aleatoria)
    analisados: dict[tuple[str, int], CandidatoAnalisado] = {}

    def analisado(caso: CasoJuliet) -> CandidatoAnalisado:
        chave = (caso.funcao.caminho, caso.funcao.linha)
        if chave not in analisados:
            analisados[chave] = analisar_candidato(caso.funcao, analisador)
        return analisados[chave]

    por_familia: dict[str, list[CasoJuliet]] = defaultdict(list)
    por_cwe: dict[str, list[CasoJuliet]] = defaultdict(list)
    for caso in casos:
        por_familia[caso.familia].append(caso)
        por_cwe[caso.cwe].append(caso)
    externos_por_cwe = {
        cwe: [c for outra in sorted(por_cwe) if outra != cwe for c in por_cwe[outra]]
        for cwe in por_cwe
    }

    tarefas = []
    for familia in sorted(por_familia):
        da_familia = por_familia[familia]
        vulneraveis = [c for c in da_familia if c.fluxo == 1 and c.rotulo is Rotulo.VARIANTE]
        correcao = escolher_correcao(
            [c for c in da_familia if c.fluxo == 1 and c.rotulo is Rotulo.CORRIGIDO]
        )
        cwe = da_familia[0].cwe
        if escopo is Escopo.FAMILIA:
            parentes = [c for c in da_familia if c.fluxo != 1]
        else:
            da_cwe = [c for c in por_cwe[cwe] if c.familia != familia]
            parentes = sorteio.sample(da_cwe, min(configuracao.parentes_por_tarefa, len(da_cwe)))
        if not vulneraveis or correcao is None:
            continue
        if not any(c.rotulo is Rotulo.VARIANTE for c in parentes):
            continue
        externos = externos_por_cwe[cwe]
        amostra = sorteio.sample(externos, min(configuracao.outros_por_tarefa, len(externos)))
        semente = Semente(
            familia, Linguagem.JAVA, vulneraveis[0].funcao.codigo, correcao.funcao.codigo
        )
        selecionados = parentes + amostra
        tarefas.append(
            Tarefa(
                familia=familia,
                grupo=cwe,
                semente=analisar_semente(semente, analisador),
                candidatos=tuple(analisado(c) for c in selecionados),
                rotulos=tuple(c.rotulo for c in parentes) + (Rotulo.OUTRO,) * len(amostra),
                grupos_dos_candidatos=tuple(c.cwe for c in selecionados),
            )
        )
    return tarefas


def ranquear(
    notas: Sequence[float], rotulos: Sequence[Rotulo], sorteio: random.Random
) -> list[Rotulo]:
    """Ordena pela nota; empate é desfeito por sorteio, nunca pela ordem de entrada.

    Os candidatos chegam com a família primeiro. Desempatar pela ordem daria ao
    clone exato, que empata quase tudo em zero, um acerto que não é dele.
    """
    desempate = [sorteio.random() for _ in notas]
    ordem = sorted(range(len(notas)), key=lambda i: (-notas[i], desempate[i]))
    return [rotulos[i] for i in ordem]


def _medir(ranking: Sequence[Rotulo]) -> dict[str, float]:
    return {nome: funcao(ranking) for nome, funcao in METRICAS.items()}


def _dobras(grupos: Sequence[str], quantidade: int, sorteio: random.Random) -> list[set[str]]:
    embaralhados = sorted(set(grupos))
    sorteio.shuffle(embaralhados)
    dobras: list[set[str]] = [set() for _ in range(quantidade)]
    for i, grupo in enumerate(embaralhados):
        dobras[i % quantidade].add(grupo)
    return dobras


def _exemplos_de_treino(
    tarefas: Sequence[Tarefa], grupos_de_teste: set[str]
) -> list[tuple[SementeAnalisada, list[CandidatoAnalisado], list[bool]]]:
    exemplos = []
    for tarefa in tarefas:
        mantidos = [
            (c, r)
            for c, r, g in zip(
                tarefa.candidatos, tarefa.rotulos, tarefa.grupos_dos_candidatos, strict=True
            )
            if g not in grupos_de_teste
        ]
        exemplos.append(
            (tarefa.semente, [c for c, _ in mantidos], [r is Rotulo.VARIANTE for _, r in mantidos])
        )
    return exemplos


@dataclass(frozen=True, slots=True)
class ConfiguracaoDoModelo:
    nome: str
    colunas: tuple[str, ...]


def validacao_cruzada(
    tarefas: Sequence[Tarefa],
    baselines: Sequence[Pontuador],
    modelos: Sequence[ConfiguracaoDoModelo],
    dobras: int = 5,
    semente_aleatoria: int = 42,
) -> list[dict[str, Any]]:
    """Uma linha por (pontuador, tarefa) com as métricas da tarefa."""
    grupos = [t.grupo for t in tarefas]
    if len(set(grupos)) < 2:
        raise ValueError("a validação cruzada por CWE precisa de pelo menos duas CWEs")
    quantidade = min(dobras, len(set(grupos)))
    sorteio = random.Random(semente_aleatoria)
    linhas: list[dict[str, Any]] = []
    for numero, grupos_de_teste in enumerate(_dobras(grupos, quantidade, sorteio)):
        teste = [t for t in tarefas if t.grupo in grupos_de_teste]
        treino = [t for t in tarefas if t.grupo not in grupos_de_teste]
        pontuadores: list[Pontuador] = list(baselines)
        for configuracao in modelos:
            modelo = ModeloAprendido(configuracao.nome, configuracao.colunas, semente_aleatoria)
            modelo.treinar(_exemplos_de_treino(treino, grupos_de_teste))
            pontuadores.append(modelo)
        for pontuador in pontuadores:
            for tarefa in teste:
                notas = pontuador.pontuar(tarefa.semente, tarefa.candidatos)
                ranking = ranquear(notas, tarefa.rotulos, random.Random(f"{tarefa.familia}"))
                linhas.append(
                    {
                        "pontuador": pontuador.nome,
                        "dobra": numero,
                        "grupo": tarefa.grupo,
                        "familia": tarefa.familia,
                        **_medir(ranking),
                    }
                )
    return linhas


def intervalo_bootstrap(
    valores: Sequence[float], repeticoes: int = 2000, semente_aleatoria: int = 42
) -> tuple[float, float]:
    """Intervalo de 95% da média por bootstrap percentil."""
    if not valores:
        return (0.0, 0.0)
    sorteio = random.Random(semente_aleatoria)
    medias = sorted(
        statistics.fmean(sorteio.choices(valores, k=len(valores))) for _ in range(repeticoes)
    )
    return (medias[int(0.025 * repeticoes)], medias[int(0.975 * repeticoes) - 1])


def resumir(linhas: Sequence[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    """Média e intervalo de 95% de cada métrica, por pontuador."""
    por_pontuador: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for linha in linhas:
        por_pontuador[linha["pontuador"]].append(linha)
    resumo: dict[str, dict[str, dict[str, Any]]] = {}
    for nome, suas in sorted(por_pontuador.items()):
        resumo[nome] = {}
        for metrica in METRICAS:
            valores = [float(linha[metrica]) for linha in suas]
            baixo, alto = intervalo_bootstrap(valores)
            resumo[nome][metrica] = {
                "media": statistics.fmean(valores),
                "ic95": [baixo, alto],
                "tarefas": len(valores),
            }
    return resumo


def comparar(
    linhas: Sequence[dict[str, Any]], a: str, b: str, metrica: str
) -> dict[str, float | int | None]:
    """Teste de Wilcoxon pareado por tarefa entre dois pontuadores.

    Pareado porque os dois ranquearam as mesmas tarefas; não paramétrico
    porque métrica de ranking não tem distribuição normal.
    """
    valores_a = {
        linha["familia"]: float(linha[metrica]) for linha in linhas if linha["pontuador"] == a
    }
    valores_b = {
        linha["familia"]: float(linha[metrica]) for linha in linhas if linha["pontuador"] == b
    }
    comuns = sorted(set(valores_a) & set(valores_b))
    diferencas = [valores_a[f] - valores_b[f] for f in comuns]
    if not comuns or all(d == 0 for d in diferencas):
        return {"tarefas": len(comuns), "diferenca_media": 0.0, "p": None}
    resultado = wilcoxon([valores_a[f] for f in comuns], [valores_b[f] for f in comuns])
    return {
        "tarefas": len(comuns),
        "diferenca_media": statistics.fmean(diferencas),
        "p": float(resultado.pvalue),
    }
