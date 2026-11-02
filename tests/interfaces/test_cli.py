import hashlib
import io
import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from rastro.infraestrutura import download
from rastro.infraestrutura.download import ErroDeUso, baixar, conferir_hash
from rastro.interfaces import cli
from rastro.interfaces.cli import principal

VULNERAVEL = """void bad(String nome) {
    Statement s = conexao.createStatement();
    s.execute("select * from t where n='" + nome + "'");
}"""
CORRIGIDO = """void good(String nome) {
    PreparedStatement s = conexao.prepareStatement("select * from t where n=?");
    s.setString(1, nome);
    s.execute();
}"""
ALVO = """class Servico {
    void jaCorrigido(String u) {
        PreparedStatement p = conexao.prepareStatement("delete from t where n=?");
        p.setString(1, u);
        p.execute();
    }
    void variante(String u) {
        if (ativo) {
            Statement st = conexao.createStatement();
            st.execute("delete from t where n='" + u + "'");
        }
    }
    int soma(int a, int b) { return a + b; }
}"""


@pytest.fixture
def semente(tmp_path: Path) -> tuple[Path, Path, Path]:
    vulneravel = tmp_path / "vulneravel.java"
    corrigido = tmp_path / "corrigido.java"
    alvo = tmp_path / "alvo"
    vulneravel.write_text(VULNERAVEL, encoding="utf-8")
    corrigido.write_text(CORRIGIDO, encoding="utf-8")
    alvo.mkdir()
    (alvo / "Servico.java").write_text(ALVO, encoding="utf-8")
    (alvo / "leia.txt").write_text("void variante() {}", encoding="utf-8")
    return vulneravel, corrigido, alvo


def _args(semente: tuple[Path, Path, Path], *extra: str) -> list[str]:
    vulneravel, corrigido, alvo = semente
    return [
        "variantes",
        "--id",
        "CWE89-exemplo",
        "--vulneravel",
        str(vulneravel),
        "--corrigido",
        str(corrigido),
        "--alvo",
        str(alvo),
        *extra,
    ]


def test_variantes_poe_a_variante_acima_do_ja_corrigido(
    semente: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert principal(_args(semente, "--json")) == 0
    saida = json.loads(capsys.readouterr().out)
    nomes = [c["funcao"] for c in saida["candidatos"]]
    assert saida["pontuador"] == "jaccard_menos_correcao"
    assert saida["funcoes_analisadas"] == 3
    assert nomes[0] == "variante"
    assert nomes.index("variante") < nomes.index("jaCorrigido")
    # O já corrigido não some: aparece na lista de onde procurar contorno.
    assert [c["funcao"] for c in saida["contornos"]] == ["jaCorrigido"]
    # Arquivo que não é .java não entra.
    assert all(c["arquivo"].endswith(".java") for c in saida["candidatos"])


def test_variantes_em_texto_e_com_limite(
    semente: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert principal(_args(semente, "--top", "1")) == 0
    linhas = capsys.readouterr().out.strip().splitlines()
    assert linhas[0].startswith("3 funções analisadas")
    assert "Servico.java" in linhas[1]
    assert "Receberam a correção; confira se há contorno:" in linhas
    assert "jaCorrigido" in linhas[-1]


def test_arquivo_grande_demais_e_ignorado(
    semente: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "TAMANHO_MAXIMO_DE_ARQUIVO", 10)
    assert principal(_args(semente, "--json")) == 0
    assert json.loads(capsys.readouterr().out)["candidatos"] == []


def test_variantes_extrai_a_funcao_dos_arquivos_inteiros(
    semente: tuple[Path, Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    vulneravel, corrigido, _ = semente
    vulneravel.write_text("class A { int x() { return 1; } " + VULNERAVEL + " }", encoding="utf-8")
    corrigido.write_text("class A { int x() { return 1; } " + CORRIGIDO + " }", encoding="utf-8")
    # No arquivo corrigido o método se chama good; os dois precisam ter o mesmo nome.
    corrigido.write_text(
        corrigido.read_text(encoding="utf-8").replace("good(", "bad("), encoding="utf-8"
    )
    assert principal(_args(semente, "--json", "--funcao", "bad")) == 0
    assert json.loads(capsys.readouterr().out)["candidatos"][0]["funcao"] == "variante"


def test_variantes_avisa_quando_a_funcao_nao_existe(
    semente: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert principal(_args(semente, "--funcao", "nao_existe")) == 2
    assert "nao_existe" in capsys.readouterr().err


@pytest.mark.parametrize("quebra", ["vulneravel", "alvo", "igual", "top"])
def test_entrada_invalida_sai_com_dois(
    semente: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str], quebra: str
) -> None:
    vulneravel, corrigido, alvo = semente
    args = _args(semente)
    if quebra == "vulneravel":
        args[args.index(str(vulneravel))] = str(vulneravel) + ".nao"
    elif quebra == "alvo":
        args[args.index(str(alvo))] = str(alvo / "nao")
    elif quebra == "igual":
        corrigido.write_text(VULNERAVEL, encoding="utf-8")
    else:
        args += ["--top", "0"]
    assert principal(args) == 2
    assert "erro:" in capsys.readouterr().err


def test_hash_que_nao_confere_e_recusado(tmp_path: Path) -> None:
    arquivo = tmp_path / "a.bin"
    arquivo.write_bytes(b"conteudo")
    conferir_hash(arquivo, hashlib.sha256(b"conteudo").hexdigest())
    with pytest.raises(ErroDeUso, match="não confere"):
        conferir_hash(arquivo, "0" * 64)


class _Resposta(io.BytesIO):
    def __enter__(self) -> "_Resposta":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def test_download_so_fica_com_hash_certo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pedidos: list[Any] = []

    def abrir(pedido: Any, **_: Any) -> _Resposta:
        pedidos.append(pedido)
        return _Resposta(b"dados")

    monkeypatch.setattr("urllib.request.urlopen", abrir)
    destino = tmp_path / "sub" / "j.zip"
    baixar("https://exemplo.org/j.zip", destino, hashlib.sha256(b"dados").hexdigest())
    assert destino.read_bytes() == b"dados"
    # O SARD recusa o agente padrão do Python com 403.
    assert pedidos[0].get_header("User-agent") == download.AGENTE

    outro = tmp_path / "x.zip"
    with pytest.raises(ErroDeUso):
        baixar("https://exemplo.org/j.zip", outro, "0" * 64)
    assert not outro.exists()
    assert not list(tmp_path.glob("*.parcial"))


def test_download_sem_https_e_recusado(tmp_path: Path) -> None:
    with pytest.raises(ErroDeUso, match="HTTPS"):
        baixar("http://exemplo.org/j.zip", tmp_path / "j.zip", "0" * 64)


def test_experimento_grava_o_relatorio(
    tmp_path: Path, juliet: tuple[Path, str], capsys: pytest.CaptureFixture[str]
) -> None:
    zip_juliet, sha256 = juliet
    saida = tmp_path / "res" / "experimento.json"
    codigo = principal(
        [
            "experimento",
            "--juliet",
            str(zip_juliet),
            "--sha256",
            sha256,
            "--outros",
            "5",
            "--dobras",
            "2",
            "--saida",
            str(saida),
        ]
    )
    assert codigo == 0
    relatorio = json.loads(saida.read_text(encoding="utf-8"))
    assert relatorio["configuracao"]["tarefas"] == 4
    assert relatorio["configuracao"]["cwes"] == ["CWE78", "CWE89"]
    assert set(relatorio["resumo"]) == {
        "clone_exato",
        "jaccard",
        "jaccard_menos_correcao",
        "modelo_sem_correcao",
        "modelo_completo",
    }
    assert "modelo_completo x jaccard" in relatorio["comparacoes"]
    assert len(relatorio["por_tarefa"]) == 5 * 4
    assert "4 tarefas em 2 CWEs" in capsys.readouterr().out


def test_experimento_no_escopo_cwe(tmp_path: Path, juliet: tuple[Path, str]) -> None:
    zip_juliet, sha256 = juliet
    saida = tmp_path / "cwe.json"
    codigo = principal(
        [
            "experimento",
            "--juliet",
            str(zip_juliet),
            "--sha256",
            sha256,
            "--escopo",
            "cwe",
            "--parentes",
            "50",
            "--outros",
            "5",
            "--dobras",
            "2",
            "--saida",
            str(saida),
        ]
    )
    assert codigo == 0
    configuracao = json.loads(saida.read_text(encoding="utf-8"))["configuracao"]
    assert configuracao["escopo"] == "cwe"
    assert configuracao["tarefas"] == 4


def test_experimento_sem_juliet_e_sem_baixar_e_recusado(tmp_path: Path) -> None:
    assert principal(["experimento", "--juliet", str(tmp_path / "nao.zip")]) == 2


def test_experimento_baixa_quando_pedido(
    tmp_path: Path, juliet: tuple[Path, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    zip_juliet, sha256 = juliet
    dados = zip_juliet.read_bytes()
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Resposta(dados))
    destino = tmp_path / "dados" / "j.zip"
    codigo = principal(
        [
            "experimento",
            "--juliet",
            str(destino),
            "--baixar",
            "--sha256",
            sha256,
            "--outros",
            "5",
            "--dobras",
            "2",
            "--saida",
            str(tmp_path / "r.json"),
        ]
    )
    assert codigo == 0
    assert destino.read_bytes() == dados


def test_variantes_com_modelo_treinado_na_juliet(
    juliet: tuple[Path, str],
    semente: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    zip_juliet, sha256 = juliet
    args = _args(semente, "--json", "--treinar-com", str(zip_juliet), "--sha256", sha256)
    assert principal(args) == 0
    assert json.loads(capsys.readouterr().out)["pontuador"] == "modelo_completo"


def test_python_menos_m_rastro(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["rastro", "--help"])
    with pytest.raises(SystemExit) as saida:
        runpy.run_module("rastro", run_name="__main__")
    assert saida.value.code == 0
    assert "variantes" in capsys.readouterr().out
