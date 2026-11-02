import csv
import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from rastro.aplicacao.caracteristicas import NOMES
from rastro.avaliacao.figuras import PONTUADORES, gerar_figuras, numero, principal

PNG = b"\x89PNG\r\n\x1a\n"


def _resumo(base: float) -> dict[str, Any]:
    resumo = {
        p: {
            "ap": {"media": base + i / 10, "ic95": [base + i / 10 - 0.01, base + i / 10 + 0.01]},
            "corrigidos@10": {"media": 0.4 - i / 20},
        }
        for i, p in enumerate(PONTUADORES)
    }
    importancia = {n: {"media": i / 100, "desvio": 0.01} for i, n in enumerate(NOMES)}
    return {"resumo": resumo, "importancia_modelo_completo": importancia}


@pytest.fixture
def dados(tmp_path: Path) -> Path:
    pasta = tmp_path / "dados"
    pasta.mkdir()
    for escopo, n, base in (
        ("cwe", 2, 0.2),
        ("cwe", 3, 0.3),
        ("cwe", 4, 0.25),
        ("familia", 3, 0.5),
    ):
        (pasta / f"juliet-{escopo}-n{n}-resumo.json").write_text(
            json.dumps(_resumo(base)), encoding="utf-8"
        )
    return pasta


def test_numero_usa_virgula_decimal() -> None:
    assert numero(0.7481, 3) == "0,748"
    assert numero(36.4, 1) == "36,4"


def test_gera_as_seis_figuras_com_png_svg_e_csv(dados: Path, tmp_path: Path) -> None:
    saida = tmp_path / "figuras"
    arquivos = gerar_figuras(dados, saida)
    nomes = {a.name for a in arquivos}
    for figura in (
        "fig1-ap-escopo-cwe",
        "fig2-corrigidos-no-topo",
        "fig3-sensibilidade-ngrama",
        "fig4-importancia",
        "fig5-escopos",
        "fig6-funcionamento",
    ):
        assert f"{figura}.png" in nomes
        assert f"{figura}.svg" in nomes
        assert (saida / f"{figura}.png").read_bytes().startswith(PNG)
    assert len([a for a in arquivos if a.suffix == ".csv"]) == 5


def test_csv_traz_os_valores_dos_dados(dados: Path, tmp_path: Path) -> None:
    saida = tmp_path / "figuras"
    gerar_figuras(dados, saida)
    with (saida / "fig1-ap-escopo-cwe.csv").open(encoding="utf-8") as arquivo:
        linhas = list(csv.DictReader(arquivo))
    # No escopo cwe com n = 3 a base é 0,3 e o modelo completo é o quinto: 0,3 + 0,4.
    assert linhas[-1] == {
        "metodo": "Modelo completo",
        "ap": "0,700",
        "ic95_baixo": "0,690",
        "ic95_alto": "0,710",
    }
    with (saida / "fig3-sensibilidade-ngrama.csv").open(encoding="utf-8") as arquivo:
        sensibilidade = list(csv.DictReader(arquivo))
    assert [r["n"] for r in sensibilidade if r["metodo"] == "Modelo completo"] == ["2", "3", "4"]


def test_falta_de_dados_e_avisada(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert principal(["--dados", str(tmp_path), "--saida", str(tmp_path / "s")]) == 2
    assert "falta" in capsys.readouterr().err
    assert not (tmp_path / "s").exists()


def test_python_menos_m(
    dados: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    saida = tmp_path / "f"
    monkeypatch.setattr(sys, "argv", ["figuras", "--dados", str(dados), "--saida", str(saida)])
    monkeypatch.delitem(sys.modules, "rastro.avaliacao.figuras", raising=False)
    with pytest.raises(SystemExit) as fim:
        runpy.run_module("rastro.avaliacao.figuras", run_name="__main__")
    assert fim.value.code == 0
    assert "fig6-funcionamento.png" in capsys.readouterr().out
