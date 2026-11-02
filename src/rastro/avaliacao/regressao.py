"""Conferência da medição em repositório real, usada pela CI.

Cobra o que o rastro garante nos casos reais (o lugar do contorno aparece na
lista de contornos) e mede, sem reprovar, a posição da variante no repositório
inteiro, que é onde o ranqueamento se dilui.

Uso: python -m rastro.avaliacao.regressao saida.json --contorno ARQ|FUNCAO [--variante ARQ|FUNCAO]
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

Local = tuple[str, str]


def _locais(itens: Sequence[dict[str, Any]]) -> list[Local]:
    return [(str(i["arquivo"]).replace("\\", "/"), str(i["funcao"])) for i in itens]


def _local(texto: str) -> Local:
    arquivo, _, funcao = texto.partition("|")
    if not arquivo or not funcao:
        raise ValueError(f"local precisa ser ARQUIVO|FUNCAO: {texto!r}")
    return arquivo, funcao


def conferir(
    saida: dict[str, Any], contorno: Local, variante: Local | None
) -> tuple[list[str], bool]:
    contornos = _locais(saida["contornos"])
    topo = _locais(saida["candidatos"])
    achou = contorno in contornos
    linhas = [
        f"Funções analisadas: {saida['funcoes_analisadas']}",
        f"Lista de contornos: {len(contornos)} item(ns); "
        f"{contorno[1]} {'está' if achou else 'NÃO está'} nela",
    ]
    if variante is not None:
        posicao = topo.index(variante) + 1 if variante in topo else None
        texto = str(posicao) if posicao else f"acima de {len(topo)}"
        linhas.append(f"Variante {variante[1]}: posição {texto}")
    return linhas, achou


def principal(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rastro.avaliacao.regressao")
    parser.add_argument("saida")
    parser.add_argument("--contorno", required=True)
    parser.add_argument("--variante")
    parser.add_argument("--relatorio", default="medida.txt")
    argumentos = parser.parse_args(argv)
    saida = json.loads(Path(argumentos.saida).read_text(encoding="utf-8"))
    variante = _local(argumentos.variante) if argumentos.variante else None
    linhas, achou = conferir(saida, _local(argumentos.contorno), variante)
    texto = "\n".join(linhas)
    print(texto)
    Path(argumentos.relatorio).write_text(texto + "\n", encoding="utf-8")
    return 0 if achou else 1


if __name__ == "__main__":
    sys.exit(principal())
