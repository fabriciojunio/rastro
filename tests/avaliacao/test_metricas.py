import pytest

from rastro.avaliacao.metricas import (
    Rotulo,
    corrigidos_em_k,
    precisao_em_k,
    precisao_media,
    recall_em_k,
    reciproco_do_primeiro,
)

V, C, X = Rotulo.VARIANTE, Rotulo.CORRIGIDO, Rotulo.OUTRO
RANKING = [C, V, X, V, C, X, V]


def test_recall_em_k() -> None:
    assert recall_em_k(RANKING, 1) == 0.0
    assert recall_em_k(RANKING, 2) == pytest.approx(1 / 3)
    assert recall_em_k(RANKING, 7) == 1.0
    assert recall_em_k(RANKING, 100) == 1.0


def test_recall_sem_variante_e_zero() -> None:
    assert recall_em_k([C, X], 2) == 0.0


def test_precisao_em_k() -> None:
    assert precisao_em_k(RANKING, 4) == 0.5
    assert precisao_em_k([], 3) == 0.0


def test_corrigidos_em_k_mede_o_falso_positivo_dificil() -> None:
    assert corrigidos_em_k(RANKING, 1) == 1.0
    assert corrigidos_em_k(RANKING, 5) == pytest.approx(2 / 5)
    assert corrigidos_em_k([], 5) == 0.0


def test_reciproco_do_primeiro() -> None:
    assert reciproco_do_primeiro(RANKING) == 0.5
    assert reciproco_do_primeiro([V]) == 1.0
    assert reciproco_do_primeiro([C, X]) == 0.0


def test_precisao_media() -> None:
    # Variantes nas posições 2, 4 e 7: (1/2 + 2/4 + 3/7) / 3
    assert precisao_media(RANKING) == pytest.approx((1 / 2 + 2 / 4 + 3 / 7) / 3)
    assert precisao_media([V, V]) == 1.0
    assert precisao_media([X]) == 0.0


@pytest.mark.parametrize("funcao", [recall_em_k, precisao_em_k, corrigidos_em_k])
def test_k_menor_que_um_e_recusado(funcao: object) -> None:
    with pytest.raises(ValueError, match="pelo menos 1"):
        funcao(RANKING, 0)  # type: ignore[operator]
