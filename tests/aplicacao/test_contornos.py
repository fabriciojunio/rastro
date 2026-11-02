from rastro.aplicacao.caracteristicas import (
    CandidatoAnalisado,
    analisar_candidato,
    analisar_semente,
)
from rastro.aplicacao.contornos import candidatos_a_contorno
from rastro.dominio.modelos import Funcao, Linguagem, Semente
from rastro.infraestrutura.arvore import AnalisadorDeCodigo

# No formato do caso do PHP: a correção acrescenta uma checagem antes do uso.
VULNERAVEL = """void tratar(char *q) {
    processar_opcoes(q);
    executar(q);
}"""
CORRIGIDO = """void tratar(char *q) {
    if (q[0] == '-' && strchr(q, '=') == NULL) { return; }
    processar_opcoes(q);
    executar(q);
}"""
# Recebeu a mesma correção, com um ajuste por cima: é onde um contorno moraria.
JA_CORRIGIDO = """void tratar(char *q) {
    int ignorar = 0;
    if (q[0] == '-' && strchr(q, '=') == NULL) { return; }
    processar_opcoes(q);
    executar(q);
}"""
AINDA_VULNERAVEL = """void outra(char *s) {
    processar_opcoes(s);
    executar(s);
}"""
SEM_RELACAO = """int soma(int a, int b) { return a + b; }"""


def _candidato(codigo: str, analisador: AnalisadorDeCodigo) -> CandidatoAnalisado:
    return analisar_candidato(Funcao("f", Linguagem.C, "a.c", 1, codigo), analisador)


def test_so_lista_o_que_recebeu_a_correcao_e_parece_com_o_corrigido() -> None:
    analisador = AnalisadorDeCodigo()
    semente = analisar_semente(Semente("CVE-X", Linguagem.C, VULNERAVEL, CORRIGIDO), analisador)
    candidatos = [_candidato(c, analisador) for c in (JA_CORRIGIDO, AINDA_VULNERAVEL, SEM_RELACAO)]

    achados = candidatos_a_contorno(semente, candidatos)

    assert [a.candidato.funcao.codigo for a in achados] == [JA_CORRIGIDO]
    assert achados[0].correcao_presente >= 0.5
    assert achados[0].semelhanca >= 0.3


def test_sem_candidatos_nao_ha_contorno() -> None:
    analisador = AnalisadorDeCodigo()
    semente = analisar_semente(Semente("CVE-X", Linguagem.C, VULNERAVEL, CORRIGIDO), analisador)
    assert candidatos_a_contorno(semente, []) == []
