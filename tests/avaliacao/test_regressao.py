import json
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

from rastro.avaliacao.regressao import conferir, principal

SAIDA: dict[str, Any] = {
    "funcoes_analisadas": 75712,
    "candidatos": [
        {"arquivo": "beans\\A.java", "funcao": "outra"},
        {"arquivo": "beans/A.java", "funcao": "introspectInterfaces"},
    ],
    "contornos": [{"arquivo": "beans\\A.java", "funcao": "CachedIntrospectionResults"}],
}


def test_contorno_na_lista_passa_e_mede_a_variante() -> None:
    linhas, achou = conferir(
        SAIDA,
        ("beans/A.java", "CachedIntrospectionResults"),
        ("beans/A.java", "introspectInterfaces"),
    )
    assert achou is True
    assert linhas == [
        "Funções analisadas: 75712",
        "Lista de contornos: 1 item(ns); CachedIntrospectionResults está nela",
        "Variante introspectInterfaces: posição 2",
    ]


def test_variante_fora_do_topo_e_medida_sem_reprovar() -> None:
    linhas, achou = conferir(
        SAIDA, ("beans/A.java", "CachedIntrospectionResults"), ("beans/A.java", "sumiu")
    )
    assert achou is True
    assert linhas[-1] == "Variante sumiu: posição acima de 2"


def test_contorno_fora_da_lista_reprova() -> None:
    _, achou = conferir(SAIDA, ("beans/A.java", "main"), None)
    assert achou is False


def test_linha_de_comando(tmp_path: Path) -> None:
    saida = tmp_path / "saida.json"
    saida.write_text(json.dumps(SAIDA), encoding="utf-8")
    relatorio = tmp_path / "medida.txt"
    base = [str(saida), "--relatorio", str(relatorio)]
    ok = principal([*base, "--contorno", "beans/A.java|CachedIntrospectionResults"])
    assert ok == 0
    assert "está nela" in relatorio.read_text(encoding="utf-8")
    assert principal([*base, "--contorno", "beans/A.java|main"]) == 1


def test_local_mal_formado_e_recusado(tmp_path: Path) -> None:
    saida = tmp_path / "saida.json"
    saida.write_text(json.dumps(SAIDA), encoding="utf-8")
    with pytest.raises(ValueError, match="ARQUIVO"):
        principal([str(saida), "--contorno", "sem-barra"])


def test_python_menos_m_como_na_ci(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    saida = tmp_path / "saida.json"
    saida.write_text(json.dumps(SAIDA), encoding="utf-8")
    argv = [
        "regressao",
        str(saida),
        "--contorno",
        "beans/A.java|CachedIntrospectionResults",
        "--relatorio",
        str(tmp_path / "m.txt"),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    # Sai do cache para o runpy rodar o módulo do zero, como o python -m faz.
    monkeypatch.delitem(sys.modules, "rastro.avaliacao.regressao", raising=False)
    with pytest.raises(SystemExit) as fim:
        runpy.run_module("rastro.avaliacao.regressao", run_name="__main__")
    assert fim.value.code == 0
