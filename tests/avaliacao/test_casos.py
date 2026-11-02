import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from rastro.aplicacao.pontuadores import CloneExato, Jaccard, JaccardMenosCorrecao
from rastro.avaliacao import casos
from rastro.avaliacao.casos import CASOS, ArquivoNoCommit, CasoReal, avaliar_caso, obter
from rastro.dominio.modelos import Linguagem
from rastro.infraestrutura.arvore import AnalisadorDeCodigo
from rastro.infraestrutura.download import ErroDeUso
from rastro.interfaces.cli import principal

# No formato do caso do PHP, escrito para o teste.
ANTES = "int main(char *q) { processar(q); executar(q); return 0; }\nint aux(int a) { return a; }\n"
DEPOIS = (
    "int main(char *q) { if (q[0] == '-' && strchr(q, '=') == NULL) { return 1; }"
    " processar(q); executar(q); return 0; }\nint aux(int a) { return a; }\n"
)
ALVO = (
    "int main(char *q) { int x = 0; if (q[0] == '-' && strchr(q, '=') == NULL) { return 1; }"
    " processar(q); executar(q); return 0; }\n"
    "int outra(char *s) { processar(s); executar(s); return 0; }\n"
    "int soma(int a, int b) { return a + b; }\n"
)


def _arquivo(pasta: Path, commit: str, conteudo: str) -> ArquivoNoCommit:
    arquivo = ArquivoNoCommit(
        "dono/repo", commit, "src/cgi.c", hashlib.sha256(conteudo.encode()).hexdigest()
    )
    (pasta / arquivo.nome_local).write_bytes(conteudo.encode())
    return arquivo


@pytest.fixture
def caso(tmp_path: Path) -> CasoReal:
    return CasoReal(
        identificador="TESTE-1",
        descricao="caso de teste",
        linguagem=Linguagem.C,
        funcao_da_semente="main",
        vulneravel=_arquivo(tmp_path, "a" * 40, ANTES),
        corrigido=_arquivo(tmp_path, "b" * 40, DEPOIS),
        alvo=_arquivo(tmp_path, "c" * 40, ALVO),
        funcoes_esperadas=("main",),
    )


def test_os_casos_reais_apontam_para_commits_completos() -> None:
    for caso in CASOS.values():
        for arquivo in (caso.vulneravel, caso.corrigido, caso.alvo):
            assert len(arquivo.commit) == 40
            assert len(arquivo.sha256) == 64
            assert arquivo.url.startswith("https://raw.githubusercontent.com/")


def test_url_e_nome_local_vem_do_commit() -> None:
    arquivo = CASOS["php"].alvo
    assert arquivo.url == (
        "https://raw.githubusercontent.com/php/php-src/"
        "4b15f5d4ec750b31ec8911f5eb0915a45f96feca/sapi/cgi/cgi_main.c"
    )
    assert arquivo.nome_local == "php_php-src_4b15f5d4ec75_cgi_main.c"


def test_caso_mostra_a_posicao_e_o_contorno(caso: CasoReal, tmp_path: Path) -> None:
    resultado = avaliar_caso(
        caso, tmp_path, AnalisadorDeCodigo(), [CloneExato(), Jaccard(), JaccardMenosCorrecao()]
    )
    assert resultado["funcoes_no_alvo"] == 3
    # O main recebeu a correção. O Jaccard o põe logo atrás de "outra", que é a
    # variante sem correção; quem rebaixa a correção o põe no fim.
    assert resultado["posicao"]["jaccard"] == {"main": 2}
    assert resultado["posicao"]["jaccard_menos_correcao"] == {"main": 3}
    # Empate conta contra: no clone exato todos empatam em zero.
    assert resultado["posicao"]["clone_exato"] == {"main": 3}
    assert resultado["na_lista_de_contornos"] == {"main": True}
    assert resultado["contornos"] == ["main"]


def test_arquivo_alterado_e_recusado(caso: CasoReal, tmp_path: Path) -> None:
    (tmp_path / caso.alvo.nome_local).write_text("int main() { return 0; }", encoding="utf-8")
    with pytest.raises(ErroDeUso, match="não confere"):
        obter(caso.alvo, tmp_path)


def test_funcao_que_nao_existe_e_avisada(caso: CasoReal, tmp_path: Path) -> None:
    with pytest.raises(ErroDeUso, match="nao_existe"):
        avaliar_caso(
            replace(caso, funcoes_esperadas=("nao_existe",)),
            tmp_path,
            AnalisadorDeCodigo(),
            [Jaccard()],
        )


def test_arquivo_que_falta_e_baixado(
    caso: CasoReal, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conteudo = (tmp_path / caso.alvo.nome_local).read_bytes()
    (tmp_path / caso.alvo.nome_local).unlink()
    pedidos: list[str] = []

    def baixar_falso(url: str, destino: Path, sha256: str) -> None:
        pedidos.append(url)
        destino.write_bytes(conteudo)

    monkeypatch.setattr(casos, "baixar", baixar_falso)
    assert obter(caso.alvo, tmp_path) == conteudo.decode()
    assert pedidos == [caso.alvo.url]


def test_comando_caso_com_o_modelo_treinado(
    caso: CasoReal,
    tmp_path: Path,
    juliet: tuple[Path, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    zip_juliet, sha256 = juliet
    monkeypatch.setitem(CASOS, "teste", caso)
    args = ["caso", "teste", "--dados", str(tmp_path), "--json"]
    assert principal([*args, "--treinar-com", str(zip_juliet), "--sha256", sha256]) == 0
    assert "modelo_completo" in json.loads(capsys.readouterr().out)["posicao"]


def test_comando_caso(
    caso: CasoReal,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(CASOS, "teste", caso)
    assert principal(["caso", "teste", "--dados", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["posicao"]["jaccard"] == {"main": 2}
    assert principal(["caso", "teste", "--dados", str(tmp_path)]) == 0
    texto = capsys.readouterr().out
    assert "main na posição 2 de 3" in texto
    assert "main na lista de onde procurar contorno: sim" in texto
