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
    funcao_esperada: str
    """Onde a correção seguinte foi feita: é o que se espera achar."""


_PHP = "php/php-src"
_CGI = "sapi/cgi/cgi_main.c"

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
        funcao_esperada="main",
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
    _funcao(funcoes["alvo"], caso.funcao_esperada, "o alvo")
    analisada = analisar_semente(semente, analisador)
    candidatos = [analisar_candidato(f, analisador) for f in funcoes["alvo"]]
    esperada = next(i for i, c in enumerate(candidatos) if c.funcao.nome == caso.funcao_esperada)
    posicoes = {}
    for pontuador in pontuadores:
        notas = pontuador.pontuar(analisada, candidatos)
        # Empate conta contra: a função esperada fica depois de todas com a mesma nota.
        posicoes[pontuador.nome] = sum(1 for n in notas if n >= notas[esperada])
    contornos = [c.candidato.funcao.nome for c in candidatos_a_contorno(analisada, candidatos)]
    return {
        "caso": caso.identificador,
        "descricao": caso.descricao,
        "funcoes_no_alvo": len(candidatos),
        "funcao_esperada": caso.funcao_esperada,
        "posicao": posicoes,
        "na_lista_de_contornos": caso.funcao_esperada in contornos,
        "contornos": contornos,
    }
