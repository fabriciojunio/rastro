import pytest

from rastro.aplicacao.caracteristicas import (
    CandidatoAnalisado,
    SementeAnalisada,
    analisar_candidato,
    analisar_semente,
)
from rastro.aplicacao.pontuadores import (
    CARACTERISTICAS_SEM_CORRECAO,
    CloneExato,
    Jaccard,
    JaccardMenosCorrecao,
    ModeloAprendido,
    ModeloNaoTreinado,
)
from rastro.dominio.modelos import Funcao, Linguagem, Semente
from rastro.infraestrutura.arvore import AnalisadorDeCodigo

VULNERAVEL = 'void f(String n) { Statement s = c.createStatement(); s.execute("q" + n); }'
CORRIGIDO = (
    'void f(String n) { PreparedStatement s = c.prepareStatement("q?"); '
    "s.setString(1, n); s.execute(); }"
)
CLONE = 'void g(String x) { Statement t = d.createStatement(); t.execute("z" + x); }'
VARIANTE = 'void h(String y) { if (ok) { Statement t = d.createStatement(); t.execute("w" + y); } }'
JA_CORRIGIDO = (
    'void k(String y) { PreparedStatement t = d.prepareStatement("w?"); '
    "t.setString(1, y); t.execute(); }"
)
OUTRO = "int soma(int a, int b) { return a + b; }"


@pytest.fixture(scope="module")
def analisador() -> AnalisadorDeCodigo:
    return AnalisadorDeCodigo()


@pytest.fixture(scope="module")
def semente(analisador: AnalisadorDeCodigo) -> SementeAnalisada:
    return analisar_semente(Semente("S", Linguagem.JAVA, VULNERAVEL, CORRIGIDO), analisador)


@pytest.fixture(scope="module")
def candidatos(analisador: AnalisadorDeCodigo) -> list[CandidatoAnalisado]:
    codigos = [CLONE, VARIANTE, JA_CORRIGIDO, OUTRO]
    return [
        analisar_candidato(Funcao("f", Linguagem.JAVA, "A.java", 1, c), analisador) for c in codigos
    ]


def test_clone_exato_so_acha_o_clone(
    semente: SementeAnalisada, candidatos: list[CandidatoAnalisado]
) -> None:
    assert CloneExato().pontuar(semente, candidatos) == [1.0, 0.0, 0.0, 0.0]


def test_jaccard_poe_o_clone_no_topo_e_o_sem_relacao_no_fim(
    semente: SementeAnalisada, candidatos: list[CandidatoAnalisado]
) -> None:
    notas = Jaccard().pontuar(semente, candidatos)
    assert notas[0] == max(notas)
    assert notas[3] == min(notas)


def test_heuristica_com_correcao_derruba_o_codigo_ja_corrigido(
    semente: SementeAnalisada, candidatos: list[CandidatoAnalisado]
) -> None:
    notas = JaccardMenosCorrecao().pontuar(semente, candidatos)
    assert notas[1] > notas[2]
    assert notas[2] < 0


def test_modelo_aprende_a_separar_variante_de_corrigido(
    semente: SementeAnalisada, candidatos: list[CandidatoAnalisado]
) -> None:
    modelo = ModeloAprendido("completo")
    rotulos = [True, True, False, False]
    # Repetido para o boosting ter amostras suficientes no teste.
    modelo.treinar([(semente, candidatos, rotulos)] * 30)
    notas = modelo.pontuar(semente, candidatos)
    assert min(notas[0], notas[1]) > max(notas[2], notas[3])
    assert all(0.0 <= n <= 1.0 for n in notas)
    assert modelo.pontuar(semente, []) == []


def test_modelo_com_parte_das_caracteristicas(
    semente: SementeAnalisada, candidatos: list[CandidatoAnalisado]
) -> None:
    modelo = ModeloAprendido("sem_correcao", CARACTERISTICAS_SEM_CORRECAO)
    modelo.treinar([(semente, candidatos, [True, True, False, False])] * 30)
    assert len(modelo.pontuar(semente, candidatos)) == 4


def test_modelo_sem_treino_recusa_pontuar(
    semente: SementeAnalisada, candidatos: list[CandidatoAnalisado]
) -> None:
    with pytest.raises(ModeloNaoTreinado):
        ModeloAprendido("x").pontuar(semente, candidatos)


def test_treino_sem_os_dois_lados_e_recusado(
    semente: SementeAnalisada, candidatos: list[CandidatoAnalisado]
) -> None:
    with pytest.raises(ValueError, match="positivos e negativos"):
        ModeloAprendido("x").treinar([(semente, candidatos, [False] * 4)])
    with pytest.raises(ValueError, match="positivos e negativos"):
        ModeloAprendido("x").treinar([])


def test_caracteristica_desconhecida_e_recusada() -> None:
    with pytest.raises(ValueError, match="desconhecidas"):
        ModeloAprendido("x", ("nao_existe",))
