import math

import pytest

from rastro.aplicacao.caracteristicas import (
    NOMES,
    analisar_candidato,
    analisar_semente,
    vetor,
)
from rastro.dominio.modelos import Funcao, Linguagem, Semente
from rastro.infraestrutura.arvore import AnalisadorDeCodigo

VULNERAVEL = """void bad(String nome) {
    Statement s = conexao.createStatement();
    s.execute("select * from t where n='" + nome + "'");
}"""

CORRIGIDO = """void good(String nome) {
    PreparedStatement s = conexao.prepareStatement("select * from t where n=?");
    s.setString(1, nome);
    s.execute();
}"""

VARIANTE = """void outra(String usuario) {
    String q = "delete from t where n='" + usuario + "'";
    Statement st = conexao.createStatement();
    st.execute(q);
}"""

SEM_RELACAO = """int soma(int a, int b) {
    return a + b;
}"""


@pytest.fixture(scope="module")
def analisador() -> AnalisadorDeCodigo:
    return AnalisadorDeCodigo()


def _funcao(codigo: str) -> Funcao:
    return Funcao("f", Linguagem.JAVA, "A.java", 1, codigo)


def _caracteristicas(analisador: AnalisadorDeCodigo, codigo: str) -> dict[str, float]:
    semente = analisar_semente(Semente("CWE89", Linguagem.JAVA, VULNERAVEL, CORRIGIDO), analisador)
    candidato = analisar_candidato(_funcao(codigo), analisador)
    return dict(zip(NOMES, vetor(semente, candidato), strict=True))


def test_vetor_tem_uma_posicao_por_nome(analisador: AnalisadorDeCodigo) -> None:
    assert len(_caracteristicas(analisador, VARIANTE)) == len(NOMES)


def test_o_proprio_vulneravel_e_identico_a_falha(analisador: AnalisadorDeCodigo) -> None:
    c = _caracteristicas(analisador, VULNERAVEL)
    assert c["sim_vulneravel"] == 1.0
    assert c["falha_presente"] == 1.0
    assert c["log_razao_tamanho"] == 0.0


def test_o_proprio_corrigido_tem_a_correcao_e_nao_a_falha(analisador: AnalisadorDeCodigo) -> None:
    c = _caracteristicas(analisador, CORRIGIDO)
    assert c["sim_corrigido"] == 1.0
    assert c["correcao_presente"] == 1.0
    assert c["chamadas_adicionadas_presentes"] == 1.0
    assert c["chamadas_removidas_presentes"] == 0.0


def test_variante_chama_o_que_a_correcao_removeu(analisador: AnalisadorDeCodigo) -> None:
    c = _caracteristicas(analisador, VARIANTE)
    assert c["chamadas_removidas_presentes"] == 1.0
    assert c["chamadas_adicionadas_presentes"] == 0.0
    assert c["sim_chamadas"] == 1.0


def test_funcao_sem_relacao_fica_longe_de_tudo(analisador: AnalisadorDeCodigo) -> None:
    c = _caracteristicas(analisador, SEM_RELACAO)
    assert c["sim_vulneravel"] < 0.1
    assert c["sim_chamadas"] == 0.0
    assert c["log_razao_tamanho"] < 0


def test_variante_fica_mais_perto_da_falha_que_da_correcao(analisador: AnalisadorDeCodigo) -> None:
    c = _caracteristicas(analisador, VARIANTE)
    assert c["falha_presente"] > c["correcao_presente"]
    assert math.isfinite(c["log_razao_tamanho"])


def test_impressao_igual_para_clone_com_nomes_trocados(analisador: AnalisadorDeCodigo) -> None:
    a = analisar_candidato(_funcao("void f(String a) { s.execute(a); }"), analisador)
    b = analisar_candidato(_funcao("void g(String bb) { t.execute(bb); }"), analisador)
    c = analisar_candidato(_funcao("void g(String bb) { t.executeQuery(bb); }"), analisador)
    assert a.impressao == b.impressao
    assert a.impressao != c.impressao
