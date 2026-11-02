import pytest

from rastro.dominio.modelos import Funcao, Linguagem, Semente, SementeInvalida


def test_semente_guarda_antes_e_depois_da_correcao() -> None:
    semente = Semente("CVE-2012-1823", Linguagem.PHP, "a(x);", "a(limpar(x));")
    assert semente.identificador == "CVE-2012-1823"
    assert semente.linguagem is Linguagem.PHP


@pytest.mark.parametrize(
    ("identificador", "vulneravel", "corrigido"),
    [
        ("", "a();", "b();"),
        ("CVE-1", "", "b();"),
        ("CVE-1", "a();", "   "),
    ],
)
def test_semente_incompleta_e_recusada(identificador: str, vulneravel: str, corrigido: str) -> None:
    with pytest.raises(SementeInvalida):
        Semente(identificador, Linguagem.JAVA, vulneravel, corrigido)


def test_semente_sem_mudanca_nao_e_correcao() -> None:
    with pytest.raises(SementeInvalida, match="não há correção"):
        Semente("CVE-1", Linguagem.C, "f(x);", "  f(x);  ")


def test_funcao_sem_codigo_e_recusada() -> None:
    with pytest.raises(ValueError, match="sem código"):
        Funcao("f", Linguagem.C, "a.c", 1, "  ")


def test_funcao_com_linha_zero_e_recusada() -> None:
    with pytest.raises(ValueError, match="linha"):
        Funcao("f", Linguagem.C, "a.c", 0, "int f() {}")
