import zipfile
from pathlib import Path

import pytest

from rastro.avaliacao.metricas import Rotulo
from rastro.infraestrutura.arvore import AnalisadorDeCodigo
from rastro.infraestrutura.juliet import identificar, ler_casos, rotular

# Arquivo no formato da Juliet, escrito para o teste.
CASO = """
package testcases.CWE89_SQL_Injection.s02;
public class CWE89_SQL_Injection__Environment_execute_{fluxo} extends AbstractTestCase {{
    public void bad() throws Throwable {{
        String data = System.getenv("ADD");
        /* POTENTIAL FLAW */
        sqlStatement.execute("select * from u where n='" + data + "'");
    }}
    public void good() throws Throwable {{ goodG2B(); goodB2G(); }}
    private void goodG2B() throws Throwable {{
        String data = "foo";
        sqlStatement.execute("select * from u where n='" + data + "'");
    }}
    private void goodB2G() throws Throwable {{
        String data = System.getenv("ADD");
        /* FIX */
        PreparedStatement p = conexao.prepareStatement("select * from u where n=?");
        p.setString(1, data);
        p.execute();
    }}
    public static void main(String[] args) {{ mainFromParent(args); }}
}}
"""


@pytest.mark.parametrize(
    ("caminho", "esperado"),
    [
        (
            "Java/src/testcases/CWE89_SQL_Injection/s02/CWE89_SQL_Injection__Environment_execute_10.java",
            ("CWE89", "CWE89/Environment_execute", 10),
        ),
        (
            "Java/src/testcases/CWE190_Integer_Overflow/s01/CWE190_Integer_Overflow__int_File_add_01.java",
            ("CWE190", "CWE190/int_File_add", 1),
        ),
    ],
)
def test_identifica_cwe_familia_e_fluxo(caminho: str, esperado: tuple[str, str, int]) -> None:
    assert identificar(caminho) == esperado


@pytest.mark.parametrize(
    "caminho",
    [
        # Fluxo de vários arquivos: a falha não cabe numa função.
        "Java/src/testcases/CWE89_SQL_Injection/s02/CWE89_SQL_Injection__File_prepareStatement_41.java",
        "Java/src/testcases/CWE89_SQL_Injection/s02/CWE89_SQL_Injection__getParameter_Servlet_executeBatch_54e.java",
        "Java/src/testcasesupport/IO.java",
        "Java/doc/changelog_Juliet_Java.txt",
    ],
)
def test_ignora_o_que_nao_e_caso_de_arquivo_unico(caminho: str) -> None:
    assert identificar(caminho) is None


@pytest.mark.parametrize(
    ("nome", "esperado"),
    [
        ("bad", Rotulo.VARIANTE),
        ("goodG2B", Rotulo.CORRIGIDO),
        ("goodB2G2", Rotulo.CORRIGIDO),
        ("good1", Rotulo.CORRIGIDO),
        ("good", None),
        ("main", None),
        ("badSink", None),
    ],
)
def test_rotulo_pelo_nome_do_metodo(nome: str, esperado: Rotulo | None) -> None:
    assert rotular(nome) == esperado


def _zip_com(tmp_path: Path, arquivos: dict[str, str]) -> Path:
    caminho = tmp_path / "juliet.zip"
    with zipfile.ZipFile(caminho, "w") as pacote:
        for nome, conteudo in arquivos.items():
            pacote.writestr(nome, conteudo)
    return caminho


def test_le_os_metodos_rotulados_do_zip(tmp_path: Path) -> None:
    base = "Java/src/testcases/CWE89_SQL_Injection/s02/CWE89_SQL_Injection__Environment_execute_"
    pacote = _zip_com(
        tmp_path,
        {
            base + "01.java": CASO.format(fluxo="01"),
            base + "10.java": CASO.format(fluxo="10"),
            base + "41.java": CASO.format(fluxo="41"),
            "Java/src/testcasesupport/IO.java": "class IO { void bad() {} }",
        },
    )
    casos = list(ler_casos(pacote, AnalisadorDeCodigo()))

    assert {c.fluxo for c in casos} == {1, 10}
    assert sorted((c.fluxo, c.funcao.nome, c.rotulo) for c in casos) == [
        (1, "bad", Rotulo.VARIANTE),
        (1, "goodB2G", Rotulo.CORRIGIDO),
        (1, "goodG2B", Rotulo.CORRIGIDO),
        (10, "bad", Rotulo.VARIANTE),
        (10, "goodB2G", Rotulo.CORRIGIDO),
        (10, "goodG2B", Rotulo.CORRIGIDO),
    ]
    assert {c.familia for c in casos} == {"CWE89/Environment_execute"}
    assert {c.tipo_da_correcao for c in casos} == {"", "G2B", "B2G"}


def test_filtra_por_cwe(tmp_path: Path) -> None:
    caminho = "Java/src/testcases/CWE89_SQL_Injection/s02/"
    caminho += "CWE89_SQL_Injection__Environment_execute_01.java"
    pacote = _zip_com(tmp_path, {caminho: CASO.format(fluxo="01")})
    assert list(ler_casos(pacote, AnalisadorDeCodigo(), frozenset({"CWE190"}))) == []
