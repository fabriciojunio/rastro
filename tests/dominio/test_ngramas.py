import pytest

from rastro.dominio.ngramas import cobertura, jaccard, ngramas


def test_ngramas_de_tamanho_dois() -> None:
    assert ngramas(["a", "b", "c"], 2) == {("a", "b"), ("b", "c")}


def test_sequencia_menor_que_n_vira_um_ngrama() -> None:
    assert ngramas(["a"], 3) == {("a",)}


def test_sequencia_vazia_nao_tem_ngrama() -> None:
    assert ngramas([], 2) == frozenset()


def test_n_menor_que_um_e_recusado() -> None:
    with pytest.raises(ValueError, match="pelo menos 1"):
        ngramas(["a"], 0)


def test_jaccard_de_iguais_e_um_e_de_disjuntos_e_zero() -> None:
    a = ngramas(["x", "y", "z"], 2)
    b = ngramas(["p", "q", "r"], 2)
    assert jaccard(a, a) == 1.0
    assert jaccard(a, b) == 0.0


def test_jaccard_parcial() -> None:
    a = frozenset({("a",), ("b",)})
    b = frozenset({("b",), ("c",)})
    assert jaccard(a, b) == pytest.approx(1 / 3)


def test_jaccard_de_dois_vazios_e_zero() -> None:
    assert jaccard(frozenset(), frozenset()) == 0.0


def test_cobertura() -> None:
    procurados = frozenset({("a",), ("b",)})
    assert cobertura(procurados, frozenset({("a",), ("z",)})) == 0.5
    assert cobertura(frozenset(), frozenset({("a",)})) == 0.0
