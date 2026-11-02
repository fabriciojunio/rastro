import hashlib
import io
import json
import runpy
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from rastro.interfaces import cli
from rastro.interfaces.cli import ErroDeUso, baixar, conferir_hash, principal

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
    assert nomes[0] == "variante"
    assert nomes.index("variante") < nomes.index("jaCorrigido")
    # Arquivo que não é .java não entra.
    assert all(c["arquivo"].endswith(".java") for c in saida["candidatos"])


def test_variantes_em_texto_e_com_limite(
    semente: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert principal(_args(semente, "--top", "1")) == 0
    linhas = capsys.readouterr().out.strip().splitlines()
    assert linhas[0].startswith("3 funções analisadas")
    assert len(linhas) == 2
    assert "Servico.java" in linhas[1]


def test_arquivo_grande_demais_e_ignorado(
    semente: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "TAMANHO_MAXIMO_DE_ARQUIVO", 10)
    assert principal(_args(semente, "--json")) == 0
    assert json.loads(capsys.readouterr().out)["candidatos"] == []


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
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Resposta(b"dados"))
    destino = tmp_path / "sub" / "j.zip"
    baixar("https://exemplo.org/j.zip", destino, hashlib.sha256(b"dados").hexdigest())
    assert destino.read_bytes() == b"dados"

    outro = tmp_path / "x.zip"
    with pytest.raises(ErroDeUso):
        baixar("https://exemplo.org/j.zip", outro, "0" * 64)
    assert not outro.exists()
    assert not list(tmp_path.glob("*.parcial"))


def test_download_sem_https_e_recusado(tmp_path: Path) -> None:
    with pytest.raises(ErroDeUso, match="HTTPS"):
        baixar("http://exemplo.org/j.zip", tmp_path / "j.zip", "0" * 64)


# Zip no formato da Juliet, só para teste: duas CWEs, duas famílias, quatro fluxos.
MODELO_DE_CASO = """
public class {classe} extends AbstractTestCase {{
    public void bad() throws Throwable {{
        {abre} String data = fonte{familia}(); r.{perigoso}("a" + data); }}
    }}
    private void goodG2B() throws Throwable {{
        {abre} String data = "fixo"; r.{perigoso}("a" + data); }}
    }}
    private void goodB2G() throws Throwable {{
        {abre} String data = fonte{familia}(); r.{seguro}(data); r.limpar(data); }}
    }}
}}
"""
ABERTURAS = ("if (IO.t) {", "while (k > 0) {", "if (IO.f()) {", "for (int i = 0; i < 1; i++) {")
SINKS = {"CWE89_SQL": ("execute", "prepareStatement"), "CWE78_OS": ("exec", "escapar")}


def _juliet(tmp_path: Path) -> tuple[Path, str]:
    caminho = tmp_path / "juliet.zip"
    with zipfile.ZipFile(caminho, "w") as pacote:
        for prefixo, (perigoso, seguro) in SINKS.items():
            for familia in (1, 2):
                for fluxo in (1, 2, 3, 4):
                    classe = f"{prefixo}__f{familia}_{fluxo:02d}"
                    nome = f"Java/src/testcases/{prefixo}/s01/{classe}.java"
                    pacote.writestr(
                        nome,
                        MODELO_DE_CASO.format(
                            classe=classe,
                            abre=ABERTURAS[fluxo - 1],
                            familia=familia,
                            perigoso=perigoso,
                            seguro=seguro,
                        ),
                    )
    return caminho, hashlib.sha256(caminho.read_bytes()).hexdigest()


def test_experimento_grava_o_relatorio(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    juliet, sha256 = _juliet(tmp_path)
    saida = tmp_path / "res" / "experimento.json"
    codigo = principal(
        [
            "experimento",
            "--juliet",
            str(juliet),
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


def test_experimento_sem_juliet_e_sem_baixar_e_recusado(tmp_path: Path) -> None:
    assert principal(["experimento", "--juliet", str(tmp_path / "nao.zip")]) == 2


def test_experimento_baixa_quando_pedido(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    juliet, sha256 = _juliet(tmp_path)
    dados = juliet.read_bytes()
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
    tmp_path: Path, semente: tuple[Path, Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    juliet, sha256 = _juliet(tmp_path)
    args = _args(semente, "--json", "--treinar-com", str(juliet), "--sha256", sha256)
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
