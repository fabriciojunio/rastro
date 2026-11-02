"""Leitura da Juliet Test Suite para Java (NIST SARD, v1.3).

Cada arquivo de caso tem um nome no formato
``CWE89_SQL_Injection__Environment_execute_10.java``: a CWE, a variante
funcional (de onde vem o dado e onde ele é usado) e a variante de fluxo (01 a
84). Dentro dele, ``bad()`` tem a falha e os ``good*()`` são versões corrigidas
do mesmo código.

Só entram os fluxos de 01 a 19, em que o caso cabe num arquivo. A partir do 21
o dado atravessa métodos e classes, e uma função isolada não contém a falha
inteira.
"""

import re
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from rastro.avaliacao.metricas import Rotulo
from rastro.dominio.modelos import Funcao, Linguagem
from rastro.infraestrutura.arvore import AnalisadorDeCodigo

SHA256_JULIET_JAVA_1_3 = "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"
URL_JULIET_JAVA_1_3 = (
    "https://samate.nist.gov/SARD/downloads/test-suites/"
    "2017-10-01-juliet-test-suite-for-java-v1-3.zip"
)

_ULTIMO_FLUXO_DE_ARQUIVO_UNICO = 19
_ARQUIVO = re.compile(r"/testcases/.+/(?P<nome>CWE\d+_[^/]+)\.java$")
_NOME = re.compile(r"^(?P<cwe>CWE\d+)_.+?__(?P<funcional>.+)_(?P<fluxo>\d{2})$")


@dataclass(frozen=True, slots=True)
class CasoJuliet:
    cwe: str
    familia: str
    fluxo: int
    funcao: Funcao
    rotulo: Rotulo

    @property
    def tipo_da_correcao(self) -> str:
        """G2B corrige a origem do dado; B2G corrige o uso. Vazio em bad()."""
        nome = self.funcao.nome
        if "B2G" in nome:
            return "B2G"
        if "G2B" in nome:
            return "G2B"
        return ""


def identificar(caminho: str) -> tuple[str, str, int] | None:
    """(cwe, família, fluxo) de um caminho da Juliet, ou None se não é caso de arquivo único."""
    arquivo = _ARQUIVO.search(caminho.replace("\\", "/"))
    if arquivo is None:
        return None
    nome = _NOME.match(arquivo["nome"])
    if nome is None:
        return None
    fluxo = int(nome["fluxo"])
    if fluxo > _ULTIMO_FLUXO_DE_ARQUIVO_UNICO:
        return None
    cwe = nome["cwe"]
    return cwe, f"{cwe}/{nome['funcional']}", fluxo


def rotular(nome_do_metodo: str) -> Rotulo | None:
    """bad é variante; good com sufixo é corrigido; o resto não entra.

    ``good()`` sem sufixo só chama os outros, e ``main`` é o executor do caso.
    """
    if nome_do_metodo == "bad":
        return Rotulo.VARIANTE
    if nome_do_metodo.startswith("good") and nome_do_metodo != "good":
        return Rotulo.CORRIGIDO
    return None


def ler_casos(
    arquivo_zip: Path, analisador: AnalisadorDeCodigo, cwes: frozenset[str] | None = None
) -> Iterator[CasoJuliet]:
    """Os métodos rotulados dos casos de arquivo único, opcionalmente filtrando CWEs."""
    with zipfile.ZipFile(arquivo_zip) as pacote:
        for entrada in sorted(pacote.namelist()):
            dados = identificar(entrada)
            if dados is None:
                continue
            cwe, familia, fluxo = dados
            if cwes is not None and cwe not in cwes:
                continue
            codigo = pacote.read(entrada).decode("utf-8", errors="replace")
            for funcao in analisador.funcoes(codigo, Linguagem.JAVA, entrada):
                rotulo = rotular(funcao.nome)
                if rotulo is not None:
                    yield CasoJuliet(cwe, familia, fluxo, funcao, rotulo)
