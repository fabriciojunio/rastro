import pytest

from rastro.dominio.modelos import Linguagem
from rastro.infraestrutura.arvore import AnalisadorDeCodigo

JAVA = """
class Conta {
    // POTENTIAL FLAW: concatenação na consulta
    public void bad(String nome) throws Exception {
        Statement s = conexao.createStatement();
        s.execute("select * from t where n='" + nome + "'");
        int limite = 10;
    }

    public Conta() { iniciar(); }
}
"""

PHP = """<?php
function buscar($id) {
    /* FIX: usar consulta preparada */
    return mysql_query("select * from t where id=" . $id);
}
class Repo {
    public function rodar($x) { $this->db->query($x); }
}
"""

C = """
int copiar(char *destino, const char *origem) {
    memcpy(destino, origem, 64); /* sem checar o tamanho */
    return 0;
}
static char *dup(const char *s) { return strdup(s); }
"""


@pytest.fixture(scope="module")
def analisador() -> AnalisadorDeCodigo:
    return AnalisadorDeCodigo()


def test_extrai_metodos_e_construtor_java(analisador: AnalisadorDeCodigo) -> None:
    funcoes = analisador.funcoes(JAVA, Linguagem.JAVA, "Conta.java")
    assert [f.nome for f in funcoes] == ["bad", "Conta"]
    assert funcoes[0].linha == 4
    assert funcoes[0].caminho == "Conta.java"
    assert funcoes[0].codigo.startswith("public void bad")


def test_extrai_funcao_e_metodo_php(analisador: AnalisadorDeCodigo) -> None:
    funcoes = analisador.funcoes(PHP, Linguagem.PHP, "repo.php")
    assert [f.nome for f in funcoes] == ["buscar", "rodar"]


def test_php_sem_tag_de_abertura_tambem_e_lido(analisador: AnalisadorDeCodigo) -> None:
    funcoes = analisador.funcoes("function f($a) { return $a; }", Linguagem.PHP, "f.php")
    assert [f.nome for f in funcoes] == ["f"]


def test_extrai_funcoes_c_inclusive_com_ponteiro_no_retorno(analisador: AnalisadorDeCodigo) -> None:
    funcoes = analisador.funcoes(C, Linguagem.C, "copia.c")
    assert [f.nome for f in funcoes] == ["copiar", "dup"]


def test_tokens_abstraem_nomes_textos_e_numeros(analisador: AnalisadorDeCodigo) -> None:
    funcao = analisador.funcoes(JAVA, Linguagem.JAVA, "Conta.java")[0]
    tokens = analisador.tokens(funcao.codigo, Linguagem.JAVA)
    assert "nome" not in tokens
    assert "limite" not in tokens
    assert "STR" in tokens
    assert "NUM" in tokens
    # O nome do método analisado também some: "bad" entregaria o rótulo.
    assert "bad" not in tokens


def test_tokens_guardam_chamadas_e_tipos(analisador: AnalisadorDeCodigo) -> None:
    funcao = analisador.funcoes(JAVA, Linguagem.JAVA, "Conta.java")[0]
    tokens = analisador.tokens(funcao.codigo, Linguagem.JAVA)
    assert "execute" in tokens
    assert "createStatement" in tokens
    assert "Statement" in tokens


def test_comentarios_nao_viram_token(analisador: AnalisadorDeCodigo) -> None:
    tokens = analisador.tokens(PHP, Linguagem.PHP)
    texto = " ".join(tokens)
    assert "FIX" not in texto
    assert "consulta" not in texto


def test_tokens_nao_incluem_o_envoltorio(analisador: AnalisadorDeCodigo) -> None:
    tokens = analisador.tokens("void f() { g(); }", Linguagem.JAVA)
    assert tokens == ("void", "ID", "(", ")", "{", "g", "(", ")", ";", "}")


def test_mesmo_codigo_com_nomes_diferentes_da_mesmos_tokens(analisador: AnalisadorDeCodigo) -> None:
    a = analisador.tokens("void f(String a) { s.execute(a); }", Linguagem.JAVA)
    b = analisador.tokens("void outro(String bb) { st.execute(bb); }", Linguagem.JAVA)
    assert a == b


@pytest.mark.parametrize(
    ("linguagem", "trecho", "esperado"),
    [
        (Linguagem.JAVA, 'void f() { s.execute("a"); IO.writeLine(1); }', {"execute", "writeLine"}),
        (
            Linguagem.PHP,
            "$a = mysql_query($q); $o->run(); X::make();",
            {"mysql_query", "run", "make"},
        ),
        (Linguagem.C, "void f() { memcpy(a, b, 1); s->g(); }", {"memcpy"}),
    ],
)
def test_chamadas_por_linguagem(
    analisador: AnalisadorDeCodigo, linguagem: Linguagem, trecho: str, esperado: set[str]
) -> None:
    assert analisador.chamadas(trecho, linguagem) == esperado


def test_trecho_java_que_ja_tem_classe_nao_e_envolvido(analisador: AnalisadorDeCodigo) -> None:
    tokens = analisador.tokens("class A { void f() {} }", Linguagem.JAVA)
    assert tokens[:3] == ("class", "ID", "{")


def test_aninhamento_profundo_nao_estoura(analisador: AnalisadorDeCodigo) -> None:
    # Código gerado chega a milhares de níveis; recursão em Python para em mil.
    niveis = 3000
    corpo = "if (a) {" * niveis + "g();" + "}" * niveis
    codigo = f"class A {{ void f() {{ {corpo} }} }}"
    funcoes = analisador.funcoes(codigo, Linguagem.JAVA, "Fundo.java")
    assert [f.nome for f in funcoes] == ["f"]
    tokens = analisador.tokens(funcoes[0].codigo, Linguagem.JAVA)
    assert tokens.count("if") == niveis
    assert "g" in tokens
