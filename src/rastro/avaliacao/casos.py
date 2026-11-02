"""Casos reais da pergunta 3: a semente vem de uma correção publicada e o alvo é o
código antes da correção seguinte, que achou a mesma falha de novo.

Cada arquivo é identificado pelo commit e conferido por SHA-256, então quem roda
o caso analisa exatamente os mesmos bytes.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rastro.aplicacao.caracteristicas import analisar_candidato, analisar_semente
from rastro.aplicacao.contornos import candidatos_a_contorno
from rastro.aplicacao.pontuadores import Pontuador
from rastro.dominio.modelos import Funcao, Linguagem, Semente
from rastro.infraestrutura.arvore import AnalisadorDeCodigo
from rastro.infraestrutura.download import ErroDeUso, baixar, conferir_hash


@dataclass(frozen=True, slots=True)
class ArquivoNoCommit:
    repositorio: str
    commit: str
    caminho: str
    sha256: str

    @property
    def url(self) -> str:
        return f"https://raw.githubusercontent.com/{self.repositorio}/{self.commit}/{self.caminho}"

    @property
    def nome_local(self) -> str:
        return f"{self.repositorio.replace('/', '_')}_{self.commit[:12]}_{Path(self.caminho).name}"


@dataclass(frozen=True, slots=True)
class CasoReal:
    identificador: str
    descricao: str
    linguagem: Linguagem
    funcao_da_semente: str
    vulneravel: ArquivoNoCommit
    corrigido: ArquivoNoCommit
    alvo: ArquivoNoCommit
    funcoes_esperadas: tuple[str, ...]
    """Onde a correção seguinte foi feita: é o que se espera achar."""


_PHP = "php/php-src"
_CGI = "sapi/cgi/cgi_main.c"
_SPRING = "spring-projects/spring-framework"
_BEANS = "src/main/java/org/springframework/beans/CachedIntrospectionResults.java"
_CIR_2010 = f"org.springframework.beans/{_BEANS}"
_CIR_2022 = f"spring-beans/{_BEANS}"

CASOS: dict[str, CasoReal] = {
    "php": CasoReal(
        identificador="CVE-2012-1823 -> CVE-2024-4577",
        descricao=(
            "A correção de 2012 bloqueou opções do php-cgi vindas da query string; em 2024 o "
            "hífen suave convertido pelo Best-Fit do Windows contornou a mesma checagem."
        ),
        linguagem=Linguagem.C,
        funcao_da_semente="main",
        vulneravel=ArquivoNoCommit(
            _PHP,
            "f5936cceeb26d6094f0e142fcaed510ba5549c4f",
            _CGI,
            "04dcb80007cbb30e9457a4ab07144ad8517aefcfa05753c71d009cf06cbe7c9b",
        ),
        corrigido=ArquivoNoCommit(
            _PHP,
            "0556103f6a347308351436897b3b632450504dd0",
            _CGI,
            "4be8182e7b5eaf34b164c0504fe81b3ee66c9f8c75687788c144e4e91615044a",
        ),
        alvo=ArquivoNoCommit(
            _PHP,
            "4b15f5d4ec750b31ec8911f5eb0915a45f96feca",
            _CGI,
            "d8af6a45bedefe2edd0f9eec298950466dc62964942c0d853c749acc681efc0b",
        ),
        funcoes_esperadas=("main",),
    ),
    "spring": CasoReal(
        identificador="CVE-2010-1622 -> CVE-2022-22965",
        descricao=(
            "A correção de 2010 impediu o data binding de chegar ao classLoader de Class; em 2022 "
            "o Spring4Shell chegou a ele por outro caminho, e a correção foi feita no mesmo "
            "construtor e em introspectInterfaces, que não tinha filtro nenhum."
        ),
        linguagem=Linguagem.JAVA,
        funcao_da_semente="CachedIntrospectionResults",
        vulneravel=ArquivoNoCommit(
            _SPRING,
            "dea5918d66aa25ea9ad9f44598cea3f765e21f75",
            _CIR_2010,
            "6dab8b9cc76487caa14574e8df15408758f3f9bbb85d840334099d0637779cc7",
        ),
        corrigido=ArquivoNoCommit(
            _SPRING,
            "3a5af35d37c79d0644d49b93f792a4c18fe8eb71",
            _CIR_2010,
            "4b4b6a822436850e932751ded7e82186e71c2a167d4725597e655eb8ad1ee9f3",
        ),
        alvo=ArquivoNoCommit(
            _SPRING,
            "1627f57f1f77abe17dd607c75476b9e4cb22ffbb",
            _CIR_2022,
            "2a86beb48e5c87d7255261d7bc61e8b0da993cdce299301f681a73a60e1ee6a8",
        ),
        funcoes_esperadas=("CachedIntrospectionResults", "introspectInterfaces"),
    ),
}


def obter(arquivo: ArquivoNoCommit, pasta: Path) -> str:
    """O conteúdo do arquivo, baixado se faltar e sempre conferido pelo hash."""
    local = pasta / arquivo.nome_local
    if local.is_file():
        conferir_hash(local, arquivo.sha256)
    else:
        baixar(arquivo.url, local, arquivo.sha256)
    return local.read_text(encoding="utf-8", errors="replace")


def _funcao(funcoes: Sequence[Funcao], nome: str, onde: str) -> Funcao:
    for funcao in funcoes:
        if funcao.nome == nome:
            return funcao
    raise ErroDeUso(f"a função {nome} não está em {onde}")


def avaliar_caso(
    caso: CasoReal, pasta: Path, analisador: AnalisadorDeCodigo, pontuadores: Sequence[Pontuador]
) -> dict[str, Any]:
    textos = {
        papel: obter(arquivo, pasta)
        for papel, arquivo in (
            ("vulneravel", caso.vulneravel),
            ("corrigido", caso.corrigido),
            ("alvo", caso.alvo),
        )
    }
    funcoes = {
        papel: analisador.funcoes(texto, caso.linguagem, getattr(caso, papel).caminho)
        for papel, texto in textos.items()
    }
    semente = Semente(
        caso.identificador,
        caso.linguagem,
        _funcao(funcoes["vulneravel"], caso.funcao_da_semente, "o arquivo vulnerável").codigo,
        _funcao(funcoes["corrigido"], caso.funcao_da_semente, "o arquivo corrigido").codigo,
    )
    for esperada in caso.funcoes_esperadas:
        _funcao(funcoes["alvo"], esperada, "o alvo")
    analisada = analisar_semente(semente, analisador)
    candidatos = [analisar_candidato(f, analisador) for f in funcoes["alvo"]]
    indices = {
        esperada: next(i for i, c in enumerate(candidatos) if c.funcao.nome == esperada)
        for esperada in caso.funcoes_esperadas
    }
    posicoes: dict[str, dict[str, int]] = {}
    for pontuador in pontuadores:
        notas = pontuador.pontuar(analisada, candidatos)
        # Empate conta contra: a função esperada fica depois de todas com a mesma nota.
        posicoes[pontuador.nome] = {
            esperada: sum(1 for n in notas if n >= notas[i]) for esperada, i in indices.items()
        }
    contornos = [c.candidato.funcao.nome for c in candidatos_a_contorno(analisada, candidatos)]
    return {
        "caso": caso.identificador,
        "descricao": caso.descricao,
        "funcoes_no_alvo": len(candidatos),
        "funcoes_esperadas": list(caso.funcoes_esperadas),
        "posicao": posicoes,
        "na_lista_de_contornos": {e: e in contornos for e in caso.funcoes_esperadas},
        "contornos": contornos,
    }
