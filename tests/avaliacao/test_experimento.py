import random

import pytest

from rastro.aplicacao.caracteristicas import NOMES
from rastro.aplicacao.pontuadores import CARACTERISTICAS_SEM_CORRECAO, CloneExato, Jaccard
from rastro.avaliacao.experimento import (
    METRICAS,
    ConfiguracaoDasTarefas,
    ConfiguracaoDoModelo,
    Escopo,
    Tarefa,
    _exemplos_de_treino,
    comparar,
    escolher_correcao,
    intervalo_bootstrap,
    montar_tarefas,
    ranquear,
    resumir,
    validacao_cruzada,
)
from rastro.avaliacao.metricas import Rotulo
from rastro.dominio.modelos import Funcao, Linguagem
from rastro.infraestrutura.arvore import AnalisadorDeCodigo
from rastro.infraestrutura.juliet import CasoJuliet

# Casos sintéticos no formato da Juliet, só para teste. Cada CWE tem uma chamada
# perigosa e a correção troca essa chamada por outra.
SINKS = {
    "CWE1": ("execute", "prepareStatement"),
    "CWE2": ("exec", "escapar"),
    "CWE3": ("write", "validar"),
}
ENVOLTORIOS = ("if (IO.t) {", "while (k > 0) {", "if (IO.f()) {", "for (int i = 0; i < 1; i++) {")


def _codigo(cwe: str, tipo: str, fluxo: int, familia: int) -> str:
    perigoso, seguro = SINKS[cwe]
    abre = ENVOLTORIOS[fluxo % len(ENVOLTORIOS)]
    fonte = f"fonte{familia}()"
    if tipo == "bad":
        corpo = f'String d = {fonte}; r.{perigoso}("a" + d);'
    elif tipo == "goodB2G":
        corpo = f"String d = {fonte}; r.{seguro}(d); r.limpar(d);"
    else:
        corpo = f'String d = "fixo"; r.{perigoso}("a" + d);'
    return f"void {tipo}() {{ {abre} {corpo} }} }}"


def _casos() -> list[CasoJuliet]:
    casos = []
    for cwe in SINKS:
        for familia in (1, 2):
            for fluxo in (1, 2, 3, 4):
                for tipo, rotulo in (
                    ("bad", Rotulo.VARIANTE),
                    ("goodG2B", Rotulo.CORRIGIDO),
                    ("goodB2G", Rotulo.CORRIGIDO),
                ):
                    caminho = f"Java/src/testcases/{cwe}_X/{cwe}_X__f{familia}_{fluxo:02d}.java"
                    funcao = Funcao(
                        tipo, Linguagem.JAVA, caminho, 1, _codigo(cwe, tipo, fluxo, familia)
                    )
                    casos.append(CasoJuliet(cwe, f"{cwe}/f{familia}", fluxo, funcao, rotulo))
    return casos


@pytest.fixture(scope="module")
def tarefas() -> list[Tarefa]:
    return montar_tarefas(
        _casos(), AnalisadorDeCodigo(), ConfiguracaoDasTarefas(outros_por_tarefa=10)
    )


def test_correcao_prefere_b2g() -> None:
    corrigidos = [
        c
        for c in _casos()
        if c.familia == "CWE1/f1" and c.fluxo == 1 and c.rotulo is Rotulo.CORRIGIDO
    ]
    escolhida = escolher_correcao(corrigidos)
    assert escolhida is not None
    assert escolhida.tipo_da_correcao == "B2G"
    assert escolher_correcao([]) is None


def test_uma_tarefa_por_familia_com_os_rotulos_certos(tarefas: list[Tarefa]) -> None:
    assert [t.familia for t in tarefas] == [
        "CWE1/f1",
        "CWE1/f2",
        "CWE2/f1",
        "CWE2/f2",
        "CWE3/f1",
        "CWE3/f2",
    ]
    tarefa = tarefas[0]
    # Fluxos 2 a 4: três bad e seis good da família, mais dez de outras CWEs.
    assert tarefa.rotulos.count(Rotulo.VARIANTE) == 3
    assert tarefa.rotulos.count(Rotulo.CORRIGIDO) == 6
    assert tarefa.rotulos.count(Rotulo.OUTRO) == 10


def test_a_semente_nao_aparece_entre_os_candidatos(tarefas: list[Tarefa]) -> None:
    for tarefa in tarefas:
        da_familia = [
            c.funcao.caminho
            for c, g in zip(tarefa.candidatos, tarefa.grupos_dos_candidatos, strict=True)
            if g == tarefa.grupo
        ]
        assert da_familia
        assert not any(c.endswith("_01.java") for c in da_familia)


def test_outros_vem_de_outras_cwes(tarefas: list[Tarefa]) -> None:
    for tarefa in tarefas:
        for rotulo, grupo in zip(tarefa.rotulos, tarefa.grupos_dos_candidatos, strict=True):
            if rotulo is Rotulo.OUTRO:
                assert grupo != tarefa.grupo
            else:
                assert grupo == tarefa.grupo


def test_montagem_e_deterministica() -> None:
    a = montar_tarefas(_casos(), AnalisadorDeCodigo(), ConfiguracaoDasTarefas(outros_por_tarefa=10))
    b = montar_tarefas(_casos(), AnalisadorDeCodigo(), ConfiguracaoDasTarefas(outros_por_tarefa=10))
    assert [t.grupos_dos_candidatos for t in a] == [t.grupos_dos_candidatos for t in b]


def test_familia_sem_correcao_ou_sem_parente_fica_de_fora() -> None:
    casos = [c for c in _casos() if not (c.familia == "CWE1/f1" and c.rotulo is Rotulo.CORRIGIDO)]
    casos = [c for c in casos if not (c.familia == "CWE2/f1" and c.fluxo != 1)]
    familias = [
        t.familia
        for t in montar_tarefas(
            casos, AnalisadorDeCodigo(), ConfiguracaoDasTarefas(outros_por_tarefa=5)
        )
    ]
    assert "CWE1/f1" not in familias
    assert "CWE2/f1" not in familias


def test_empate_nao_e_desfeito_pela_ordem_de_entrada() -> None:
    rotulos = [Rotulo.VARIANTE] + [Rotulo.OUTRO] * 30
    primeiras = {ranquear([0.0] * 31, rotulos, random.Random(s))[0] for s in range(40)}
    assert primeiras == {Rotulo.VARIANTE, Rotulo.OUTRO}


def test_ranquear_respeita_a_nota() -> None:
    ranking = ranquear(
        [0.1, 0.9, 0.5], [Rotulo.OUTRO, Rotulo.VARIANTE, Rotulo.CORRIGIDO], random.Random(1)
    )
    assert ranking == [Rotulo.VARIANTE, Rotulo.CORRIGIDO, Rotulo.OUTRO]


def test_treino_tira_os_candidatos_das_cwes_de_teste(tarefas: list[Tarefa]) -> None:
    exemplos = _exemplos_de_treino([tarefas[0]], {"CWE2"})
    _, candidatos, rotulos = exemplos[0]
    assert all("CWE2" not in c.funcao.caminho for c in candidatos)
    assert len(candidatos) == len(rotulos)


def test_validacao_cruzada_mede_todos_os_pontuadores_em_todas_as_tarefas(
    tarefas: list[Tarefa],
) -> None:
    linhas = validacao_cruzada(
        tarefas,
        [CloneExato(), Jaccard()],
        [
            ConfiguracaoDoModelo("completo", NOMES),
            ConfiguracaoDoModelo("sem_correcao", CARACTERISTICAS_SEM_CORRECAO),
        ],
        dobras=3,
    )
    assert len(linhas) == 4 * len(tarefas)
    assert {linha["pontuador"] for linha in linhas} == {
        "clone_exato",
        "jaccard",
        "completo",
        "sem_correcao",
    }
    for linha in linhas:
        for metrica in METRICAS:
            assert 0.0 <= linha[metrica] <= 1.0


def test_validacao_cruzada_e_reprodutivel(tarefas: list[Tarefa]) -> None:
    a = validacao_cruzada(tarefas, [Jaccard()], [ConfiguracaoDoModelo("completo", NOMES)], dobras=3)
    b = validacao_cruzada(tarefas, [Jaccard()], [ConfiguracaoDoModelo("completo", NOMES)], dobras=3)
    assert a == b


def test_validacao_cruzada_precisa_de_duas_cwes(tarefas: list[Tarefa]) -> None:
    with pytest.raises(ValueError, match="duas CWEs"):
        validacao_cruzada([t for t in tarefas if t.grupo == "CWE1"], [Jaccard()], [])


def test_intervalo_bootstrap() -> None:
    assert intervalo_bootstrap([0.5] * 10) == (0.5, 0.5)
    assert intervalo_bootstrap([]) == (0.0, 0.0)
    baixo, alto = intervalo_bootstrap([0.0, 1.0] * 20)
    assert 0.0 < baixo <= 0.5 <= alto < 1.0


def test_resumo_e_comparacao(tarefas: list[Tarefa]) -> None:
    linhas = validacao_cruzada(tarefas, [CloneExato(), Jaccard()], [], dobras=3)
    resumo = resumir(linhas)
    assert set(resumo) == {"clone_exato", "jaccard"}
    assert resumo["jaccard"]["mrr"]["tarefas"] == len(tarefas)
    igual = comparar(linhas, "jaccard", "jaccard", "mrr")
    assert igual["p"] is None
    diferente = comparar(linhas, "jaccard", "clone_exato", "recall@10")
    assert diferente["tarefas"] == len(tarefas)


def test_escopo_cwe_usa_outras_familias_e_deixa_a_propria_de_fora() -> None:
    tarefas = montar_tarefas(
        _casos(),
        AnalisadorDeCodigo(),
        ConfiguracaoDasTarefas(Escopo.CWE, 50, 5),
    )
    assert len(tarefas) == 6
    for tarefa in tarefas:
        propria = tarefa.familia.split("/")[1]
        da_cwe = [
            (c.funcao.caminho, r)
            for c, r, g in zip(
                tarefa.candidatos, tarefa.rotulos, tarefa.grupos_dos_candidatos, strict=True
            )
            if g == tarefa.grupo
        ]
        # Duas famílias por CWE, quatro fluxos, três funções: a outra família inteira.
        assert len(da_cwe) == 12
        assert not any(f"__{propria}_" in caminho for caminho, _ in da_cwe)
        assert sum(r is Rotulo.VARIANTE for _, r in da_cwe) == 4


def test_escopo_cwe_respeita_o_limite_de_parentes() -> None:
    tarefas = montar_tarefas(
        _casos(),
        AnalisadorDeCodigo(),
        ConfiguracaoDasTarefas(Escopo.CWE, 6, 5),
    )
    for tarefa in tarefas:
        assert sum(g == tarefa.grupo for g in tarefa.grupos_dos_candidatos) <= 6
