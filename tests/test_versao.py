import tomllib
from pathlib import Path

import pytest

from rastro import __version__
from rastro.interfaces.cli import principal


def test_versao_do_codigo_e_a_do_pyproject() -> None:
    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text("utf-8"))
    assert __version__ == pyproject["project"]["version"]


def test_opcao_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as saida:
        principal(["--version"])
    assert saida.value.code == 0
    assert capsys.readouterr().out.strip() == f"rastro {__version__}"
