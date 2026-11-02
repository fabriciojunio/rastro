"""Figuras do TCC, geradas dos resumos publicados das execuções da CI.

Cada figura sai acompanhada de um CSV com os valores exatos: quem lê a
monografia confere o número sem depender da cor nem da escala.

Uso: python -m rastro.avaliacao.figuras --dados docs/dados --saida docs/figuras
"""

import argparse
import csv
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.figure import Figure
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.ticker import FuncFormatter

# Paleta de referência validada (três primeiras posições, modo claro).
SUPERFICIE = "#fcfcfb"
TEXTO = "#0b0b0b"
TEXTO_SECUNDARIO = "#52514e"
GRADE = "#e4e3df"
SERIE = ("#2a78d6", "#eb6834", "#1baf7a")

PONTUADORES = (
    "clone_exato",
    "jaccard",
    "jaccard_menos_correcao",
    "modelo_sem_correcao",
    "modelo_completo",
)
ROTULOS = {
    "clone_exato": "Clone exato",
    "jaccard": "Jaccard",
    "jaccard_menos_correcao": "Jaccard menos a correção",
    "modelo_sem_correcao": "Modelo sem a correção",
    "modelo_completo": "Modelo completo",
}

Linha = tuple[str | int, ...]


def numero(valor: float, casas: int) -> str:
    """Número com vírgula decimal, como se escreve em português."""
    return f"{valor:.{casas}f}".replace(".", ",")


def _virgula(valor: float, _posicao: int) -> str:
    return f"{valor:g}".replace(".", ",")


class DadosAusentes(FileNotFoundError):
    """Falta o resumo de uma execução que a figura usa."""


def _ler(pasta: Path, escopo: str, ngrama: int) -> dict[str, Any]:
    arquivo = pasta / f"juliet-{escopo}-n{ngrama}-resumo.json"
    if not arquivo.is_file():
        raise DadosAusentes(f"falta {arquivo}")
    dados: dict[str, Any] = json.loads(arquivo.read_text(encoding="utf-8"))
    return dados


def _nova(largura: float = 7.0, altura: float = 3.4) -> tuple[Figure, Axes]:
    figura, eixo = plt.subplots(figsize=(largura, altura))
    figura.patch.set_facecolor(SUPERFICIE)
    eixo.set_facecolor(SUPERFICIE)
    for lado in ("top", "right"):
        eixo.spines[lado].set_visible(False)
    for lado in ("left", "bottom"):
        eixo.spines[lado].set_color(GRADE)
    eixo.tick_params(colors=TEXTO_SECUNDARIO, labelsize=9)
    eixo.grid(axis="x", color=GRADE, linewidth=0.8)
    eixo.set_axisbelow(True)
    eixo.xaxis.set_major_formatter(FuncFormatter(_virgula))
    eixo.yaxis.set_major_formatter(FuncFormatter(_virgula))
    return figura, eixo


def _titulo(eixo: Axes, texto: str) -> None:
    eixo.set_title(texto, fontsize=10, color=TEXTO, loc="left")


def _salvar(figura: Figure, saida: Path, nome: str) -> list[Path]:
    figura.tight_layout()
    caminhos = [saida / f"{nome}.png", saida / f"{nome}.svg"]
    figura.savefig(caminhos[0], dpi=200, facecolor=SUPERFICIE)
    figura.savefig(caminhos[1], facecolor=SUPERFICIE)
    plt.close(figura)
    return caminhos


def _csv(saida: Path, nome: str, cabecalho: Sequence[str], linhas: Sequence[Linha]) -> Path:
    caminho = saida / f"{nome}.csv"
    with caminho.open("w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.writer(arquivo)
        escritor.writerow(cabecalho)
        escritor.writerows(linhas)
    return caminho


def _barras(
    eixo: Axes, valores: Sequence[float], casas: int, erros: Sequence[float] | None = None
) -> None:
    eixo.barh(
        range(len(valores)),
        valores,
        height=0.55,
        color=SERIE[0],
        xerr=erros,
        error_kw={"ecolor": TEXTO_SECUNDARIO, "elinewidth": 1, "capsize": 3},
    )
    folga = max(valores) * 0.015
    for posicao, valor in enumerate(valores):
        deslocamento = (erros[posicao] if erros else 0.0) + folga
        eixo.text(
            valor + deslocamento,
            posicao,
            numero(valor, casas),
            va="center",
            fontsize=9,
            color=TEXTO,
        )


def _metodos(eixo: Axes) -> None:
    eixo.set_yticks(range(len(PONTUADORES)), [ROTULOS[p] for p in PONTUADORES], color=TEXTO)


def figura_ap(dados: dict[str, Any], saida: Path) -> list[Path]:
    """RQ1: precisão média de cada método, com o intervalo de 95%."""
    resumo = dados["resumo"]
    medias = [resumo[p]["ap"]["media"] for p in PONTUADORES]
    baixo = [resumo[p]["ap"]["ic95"][0] for p in PONTUADORES]
    alto = [resumo[p]["ap"]["ic95"][1] for p in PONTUADORES]
    erros = [max(m - b, a - m) for m, b, a in zip(medias, baixo, alto, strict=True)]
    figura, eixo = _nova()
    _barras(eixo, medias, 3, erros)
    _metodos(eixo)
    eixo.set_xlim(0, 1)
    eixo.set_xlabel("Precisão média (AP), com intervalo de 95%", color=TEXTO_SECUNDARIO)
    _titulo(eixo, "Variantes em CWE não vista no treino (Juliet Java 1.3, escopo cwe)")
    tabela: list[Linha] = [
        (ROTULOS[p], numero(m, 3), numero(b, 3), numero(a, 3))
        for p, m, b, a in zip(PONTUADORES, medias, baixo, alto, strict=True)
    ]
    cabecalho = ("metodo", "ap", "ic95_baixo", "ic95_alto")
    return [
        *_salvar(figura, saida, "fig1-ap-escopo-cwe"),
        _csv(saida, "fig1-ap-escopo-cwe", cabecalho, tabela),
    ]


def figura_corrigidos(dados: dict[str, Any], saida: Path) -> list[Path]:
    """RQ2: fração do top 10 que é código já corrigido."""
    resumo = dados["resumo"]
    valores = [100 * resumo[p]["corrigidos@10"]["media"] for p in PONTUADORES]
    figura, eixo = _nova()
    _barras(eixo, valores, 1)
    _metodos(eixo)
    eixo.set_xlim(0, max(valores) * 1.2)
    eixo.set_xlabel(
        "Código já corrigido entre os 10 primeiros (%), menor é melhor", color=TEXTO_SECUNDARIO
    )
    _titulo(eixo, "Falso positivo difícil no topo do ranking (escopo cwe)")
    tabela: list[Linha] = [
        (ROTULOS[p], numero(v, 1)) for p, v in zip(PONTUADORES, valores, strict=True)
    ]
    return [
        *_salvar(figura, saida, "fig2-corrigidos-no-topo"),
        _csv(saida, "fig2-corrigidos-no-topo", ("metodo", "corrigidos_top10_pct"), tabela),
    ]


def figura_sensibilidade(por_n: dict[int, dict[str, Any]], saida: Path) -> list[Path]:
    """O resultado com n-gramas de 2, 3 e 4 tokens."""
    series = ("modelo_completo", "jaccard_menos_correcao", "jaccard")
    tamanhos = sorted(por_n)
    figura, eixo = _nova(7.0, 3.6)
    eixo.grid(axis="y", color=GRADE, linewidth=0.8)
    eixo.grid(axis="x", visible=False)
    linhas: list[Linha] = []
    for cor, serie in zip(SERIE, series, strict=True):
        valores = [por_n[n]["resumo"][serie]["ap"]["media"] for n in tamanhos]
        eixo.plot(
            tamanhos,
            valores,
            color=cor,
            linewidth=2,
            marker="o",
            markersize=7,
            markeredgecolor=SUPERFICIE,
            markeredgewidth=1.5,
            label=ROTULOS[serie],
        )
        eixo.text(
            tamanhos[-1] + 0.08, valores[-1], ROTULOS[serie], va="center", fontsize=9, color=TEXTO
        )
        linhas.extend(
            (ROTULOS[serie], n, numero(v, 3)) for n, v in zip(tamanhos, valores, strict=True)
        )
    eixo.set_xticks(tamanhos, [str(n) for n in tamanhos])
    eixo.set_xlim(tamanhos[0] - 0.2, tamanhos[-1] + 1.3)
    eixo.set_ylim(0, 1)
    eixo.set_xlabel("Tamanho do n-grama de tokens", color=TEXTO_SECUNDARIO)
    eixo.set_ylabel("Precisão média (AP)", color=TEXTO_SECUNDARIO)
    eixo.legend(loc="lower left", frameon=False, fontsize=9)
    _titulo(eixo, "Sensibilidade ao tamanho do n-grama (escopo cwe)")
    return [
        *_salvar(figura, saida, "fig3-sensibilidade-ngrama"),
        _csv(saida, "fig3-sensibilidade-ngrama", ("metodo", "n", "ap"), linhas),
    ]


def figura_importancia(dados: dict[str, Any], saida: Path) -> list[Path]:
    """Queda da AP quando cada característica é embaralhada."""
    importancia = dados["importancia_modelo_completo"]
    nomes = sorted(importancia, key=lambda n: importancia[n]["media"])
    medias = [importancia[n]["media"] for n in nomes]
    desvios = [importancia[n]["desvio"] for n in nomes]
    figura, eixo = _nova(7.6, 3.8)
    eixo.barh(
        range(len(nomes)),
        medias,
        height=0.55,
        color=SERIE[0],
        xerr=desvios,
        error_kw={"ecolor": TEXTO_SECUNDARIO, "elinewidth": 1, "capsize": 3},
    )
    eixo.axvline(0, color=TEXTO_SECUNDARIO, linewidth=0.8)
    eixo.set_yticks(range(len(nomes)), nomes, color=TEXTO, fontsize=8.5)
    eixo.set_xlabel(
        "Queda da AP ao embaralhar (média ± desvio entre dobras)", color=TEXTO_SECUNDARIO
    )
    _titulo(eixo, "Importância das características (escopo cwe, n = 3)")
    tabela: list[Linha] = [
        (n, numero(m, 4), numero(d, 4)) for n, m, d in zip(nomes, medias, desvios, strict=True)
    ]
    return [
        *_salvar(figura, saida, "fig4-importancia"),
        _csv(saida, "fig4-importancia", ("caracteristica", "media", "desvio"), tabela[::-1]),
    ]


def figura_escopos(familia: dict[str, Any], cwe: dict[str, Any], saida: Path) -> list[Path]:
    """A Juliet fácil (variantes de fluxo) e a difícil (outras famílias da CWE)."""
    altura = 0.36
    figura, eixo = _nova(7.0, 3.8)
    linhas: list[Linha] = []
    grupos = ((SERIE[1], "Escopo família", familia), (SERIE[0], "Escopo cwe", cwe))
    for deslocamento, (cor, rotulo, dados) in zip((-altura / 2, altura / 2), grupos, strict=True):
        valores = [dados["resumo"][p]["ap"]["media"] for p in PONTUADORES]
        posicoes = [i + deslocamento for i in range(len(PONTUADORES))]
        eixo.barh(posicoes, valores, height=altura - 0.04, color=cor, label=rotulo)
        for y, v in zip(posicoes, valores, strict=True):
            eixo.text(v + 0.012, y, numero(v, 2), va="center", fontsize=8, color=TEXTO)
        linhas.extend(
            (rotulo, ROTULOS[p], numero(v, 3)) for p, v in zip(PONTUADORES, valores, strict=True)
        )
    _metodos(eixo)
    eixo.set_xlim(0, 1.1)
    eixo.set_xlabel("Precisão média (AP)", color=TEXTO_SECUNDARIO)
    # Na mesma ordem em que as barras aparecem: cwe em cima, família embaixo.
    alcas, rotulos = eixo.get_legend_handles_labels()
    eixo.legend(alcas[::-1], rotulos[::-1], loc="lower right", frameon=False, fontsize=9)
    _titulo(eixo, "Variantes de fluxo (quase clones) e outras famílias da mesma CWE")
    return [
        *_salvar(figura, saida, "fig5-escopos"),
        _csv(saida, "fig5-escopos", ("escopo", "metodo", "ap"), linhas),
    ]


_CAIXAS = {
    "semente": (2, 30, 20, 11, "Semente\nfunção antes e depois\nda correção"),
    "base": (2, 6, 20, 11, "Base de código\nJava, PHP ou C"),
    "tokens": (28, 18, 20, 11, "tree-sitter\ntokens abstraídos\n(sem comentários)"),
    "assinatura": (54, 30, 20, 11, "Assinatura da correção\no que saiu e o que entrou"),
    "carac": (54, 6, 20, 11, "9 características\npor par semente e\nfunção candidata"),
    "lista1": (80, 30, 18, 11, "Lista 1\nvariantes sem\na correção\n(modelo ou heurística)"),
    "lista2": (80, 6, 18, 11, "Lista 2\nonde procurar\ncontorno\n(limiares fixos)"),
}
_SETAS = (
    ((22, 35.5), (28, 25)),
    ((22, 11.5), (28, 21)),
    ((48, 25), (54, 35.5)),
    ((48, 22), (54, 11.5)),
    ((64, 30), (64, 17)),
    ((74, 11.5), (80, 35.5)),
    ((74, 11.5), (80, 11.5)),
)


def figura_funcionamento(saida: Path) -> list[Path]:
    """Como o rastro trabalha, da semente às duas listas."""
    figura, eixo = plt.subplots(figsize=(8.0, 3.6))
    figura.patch.set_facecolor(SUPERFICIE)
    eixo.set_xlim(0, 100)
    eixo.set_ylim(0, 46)
    eixo.axis("off")
    for chave, (x, y, largura, altura, texto) in _CAIXAS.items():
        destaque = chave.startswith("lista")
        eixo.add_patch(
            FancyBboxPatch(
                (x, y),
                largura,
                altura,
                boxstyle="round,pad=0.4,rounding_size=1.2",
                facecolor="#eaf2fc" if destaque else "#f1f0ec",
                edgecolor=SERIE[0] if destaque else GRADE,
                linewidth=1.2,
            )
        )
        eixo.text(
            x + largura / 2,
            y + altura / 2,
            texto,
            ha="center",
            va="center",
            fontsize=8,
            color=TEXTO,
        )
    for inicio, fim in _SETAS:
        eixo.add_patch(
            FancyArrowPatch(
                inicio,
                fim,
                arrowstyle="-|>",
                mutation_scale=10,
                color=TEXTO_SECUNDARIO,
                linewidth=1,
            )
        )
    _titulo(eixo, "Como o rastro funciona")
    return _salvar(figura, saida, "fig6-funcionamento")


def gerar_figuras(dados: Path, saida: Path) -> list[Path]:
    cwe = _ler(dados, "cwe", 3)
    por_n = {n: _ler(dados, "cwe", n) for n in (2, 3, 4)}
    familia = _ler(dados, "familia", 3)
    saida.mkdir(parents=True, exist_ok=True)
    return [
        *figura_ap(cwe, saida),
        *figura_corrigidos(cwe, saida),
        *figura_sensibilidade(por_n, saida),
        *figura_importancia(cwe, saida),
        *figura_escopos(familia, cwe, saida),
        *figura_funcionamento(saida),
    ]


def principal(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rastro.avaliacao.figuras")
    parser.add_argument("--dados", default="docs/dados")
    parser.add_argument("--saida", default="docs/figuras")
    argumentos = parser.parse_args(argv)
    try:
        arquivos = gerar_figuras(Path(argumentos.dados), Path(argumentos.saida))
    except DadosAusentes as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2
    for arquivo in arquivos:
        print(arquivo)
    return 0


if __name__ == "__main__":
    sys.exit(principal())
