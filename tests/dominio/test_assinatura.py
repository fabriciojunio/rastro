from rastro.dominio.assinatura import AssinaturaDaCorrecao
from rastro.dominio.ngramas import ngramas

# Uma injeção de SQL e a correção com consulta parametrizada, já em tokens
# abstraídos, como o tokenizador entrega.
VULNERAVEL = ["ID", ".", "execute", "(", "STR", "+", "ID", ")"]
CORRIGIDO = ["ID", ".", "prepareStatement", "(", "STR", ")", ";", "ID", ".", "setString"]


def test_removidos_sao_do_vulneravel_e_adicionados_do_corrigido() -> None:
    assinatura = AssinaturaDaCorrecao.de(VULNERAVEL, CORRIGIDO, 2)
    assert (".", "execute") in assinatura.removidos
    assert ("STR", "+") in assinatura.removidos
    assert (".", "prepareStatement") in assinatura.adicionados
    # O que os dois têm em comum não entra em nenhum lado.
    assert ("ID", ".") not in assinatura.removidos
    assert ("ID", ".") not in assinatura.adicionados


def test_variante_ainda_vulneravel_tem_a_falha_e_nao_tem_a_correcao() -> None:
    assinatura = AssinaturaDaCorrecao.de(VULNERAVEL, CORRIGIDO, 2)
    variante = ngramas(["ID", "=", "ID", ";", "ID", ".", "execute", "(", "STR", "+", "ID", ")"], 2)
    assert assinatura.falha_presente(variante) == 1.0
    # Não chega a zero: o bigrama genérico (";", "ID") também está entre os
    # que a correção acrescentou. Por isso o modelo recebe as duas medidas, e
    # não um corte fixo numa delas.
    assert assinatura.correcao_presente(variante) < 0.2


def test_codigo_ja_corrigido_tem_a_correcao() -> None:
    assinatura = AssinaturaDaCorrecao.de(VULNERAVEL, CORRIGIDO, 2)
    corrigido = ngramas(CORRIGIDO, 2)
    assert assinatura.correcao_presente(corrigido) == 1.0
    assert assinatura.falha_presente(corrigido) < 0.5
