"""Linha de comando do rastro.

``rastro variantes``: o uso do dia a dia. Recebe a semente (o arquivo
vulnerável e o corrigido) e uma pasta de código, e lista as funções mais
parecidas com a falha e menos parecidas com a correção.

``rastro experimento``: o experimento do TCC sobre a Juliet Java 1.3.
"""

import argparse
import io
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rastro.aplicacao.caracteristicas import NOMES, analisar_candidato, analisar_semente
from rastro.aplicacao.contornos import candidatos_a_contorno
from rastro.aplicacao.pontuadores import (
    CARACTERISTICAS_SEM_CORRECAO,
    CloneExato,
    Jaccard,
    JaccardMenosCorrecao,
    ModeloAprendido,
    Pontuador,
)
from rastro.avaliacao.casos import CASOS, avaliar_caso
from rastro.avaliacao.experimento import (
    ConfiguracaoDasTarefas,
    ConfiguracaoDoModelo,
    Escopo,
    comparar,
    montar_tarefas,
    resumir,
    validacao_cruzada,
)
from rastro.avaliacao.metricas import Rotulo
from rastro.dominio.modelos import Funcao, Linguagem, Semente, SementeInvalida
from rastro.infraestrutura.arvore import AnalisadorDeCodigo
from rastro.infraestrutura.download import ErroDeUso, baixar, conferir_hash
from rastro.infraestrutura.juliet import SHA256_JULIET_JAVA_1_3, URL_JULIET_JAVA_1_3, ler_casos

EXTENSOES = {
    Linguagem.JAVA: (".java",),
    Linguagem.PHP: (".php",),
    Linguagem.C: (".c", ".h"),
}
# Arquivo maior que isso é gerado ou minificado, e só atrasaria a análise.
TAMANHO_MAXIMO_DE_ARQUIVO = 2 * 1024 * 1024


def _ler(caminho: Path) -> str:
    if not caminho.is_file():
        raise ErroDeUso(f"arquivo não encontrado: {caminho}")
    return caminho.read_text(encoding="utf-8", errors="replace")


def _funcoes_do_alvo(
    alvo: Path, linguagem: Linguagem, analisador: AnalisadorDeCodigo
) -> list[Funcao]:
    if not alvo.is_dir():
        raise ErroDeUso(f"pasta não encontrada: {alvo}")
    funcoes = []
    for arquivo in sorted(alvo.rglob("*")):
        if (
            arquivo.is_symlink()
            or not arquivo.is_file()
            or arquivo.suffix.lower() not in EXTENSOES[linguagem]
            or arquivo.stat().st_size > TAMANHO_MAXIMO_DE_ARQUIVO
        ):
            continue
        codigo = arquivo.read_text(encoding="utf-8", errors="replace")
        funcoes.extend(analisador.funcoes(codigo, linguagem, str(arquivo.relative_to(alvo))))
    return funcoes


def _modelo_treinado(juliet: Path, sha256: str, analisador: AnalisadorDeCodigo) -> ModeloAprendido:
    """O modelo do resultado principal: treinado no escopo cwe, o caso real de variante."""
    conferir_hash(juliet, sha256)
    configuracao = ConfiguracaoDasTarefas(escopo=Escopo.CWE)
    tarefas = montar_tarefas(list(ler_casos(juliet, analisador)), analisador, configuracao)
    modelo = ModeloAprendido("modelo_completo", NOMES)
    modelo.treinar(
        [(t.semente, t.candidatos, [r is Rotulo.VARIANTE for r in t.rotulos]) for t in tarefas]
    )
    return modelo


def comando_variantes(argumentos: argparse.Namespace) -> int:
    linguagem = Linguagem(argumentos.linguagem)
    analisador = AnalisadorDeCodigo()
    try:
        semente = Semente(
            argumentos.id,
            linguagem,
            _ler(Path(argumentos.vulneravel)),
            _ler(Path(argumentos.corrigido)),
        )
    except SementeInvalida as erro:
        raise ErroDeUso(str(erro)) from erro
    funcoes = _funcoes_do_alvo(Path(argumentos.alvo), linguagem, analisador)
    pontuador: Pontuador = JaccardMenosCorrecao()
    if argumentos.treinar_com:
        pontuador = _modelo_treinado(Path(argumentos.treinar_com), argumentos.sha256, analisador)
    analisada = analisar_semente(semente, analisador)
    candidatos = [analisar_candidato(f, analisador) for f in funcoes]
    notas = pontuador.pontuar(analisada, candidatos)
    ordem = sorted(range(len(candidatos)), key=lambda i: (-notas[i], candidatos[i].funcao.caminho))
    resultado = [
        {
            "posicao": posicao,
            "nota": round(notas[i], 4),
            "arquivo": candidatos[i].funcao.caminho,
            "linha": candidatos[i].funcao.linha,
            "funcao": candidatos[i].funcao.nome,
        }
        for posicao, i in enumerate(ordem[: argumentos.top], start=1)
    ]
    contornos = [
        {
            "arquivo": c.candidato.funcao.caminho,
            "linha": c.candidato.funcao.linha,
            "funcao": c.candidato.funcao.nome,
            "semelhanca_com_o_corrigido": round(c.semelhanca, 4),
            "correcao_presente": round(c.correcao_presente, 4),
        }
        for c in candidatos_a_contorno(analisada, candidatos)[: argumentos.top]
    ]
    if argumentos.json:
        saida = {"pontuador": pontuador.nome, "candidatos": resultado, "contornos": contornos}
        print(json.dumps(saida, ensure_ascii=False))
    else:
        print(f"{len(funcoes)} funções analisadas com {pontuador.nome}.")
        for item in resultado:
            print(
                f"{item['posicao']:>3}. {item['nota']:>7.4f}  "
                f"{item['arquivo']}:{item['linha']}  {item['funcao']}"
            )
        if contornos:
            print()
            print("Receberam a correção; confira se há contorno:")
            for item in contornos:
                print(f"     {item['arquivo']}:{item['linha']}  {item['funcao']}")
    return 0


def comando_experimento(argumentos: argparse.Namespace) -> int:
    juliet = Path(argumentos.juliet)
    if not juliet.is_file():
        if not argumentos.baixar:
            raise ErroDeUso(f"{juliet} não existe; use --baixar para buscar no NIST SARD")
        baixar(URL_JULIET_JAVA_1_3, juliet, argumentos.sha256)
    conferir_hash(juliet, argumentos.sha256)
    cwes = frozenset(argumentos.cwes.split(",")) if argumentos.cwes else None
    inicio = time.perf_counter()
    analisador = AnalisadorDeCodigo()
    casos = list(ler_casos(juliet, analisador, cwes))
    configuracao = ConfiguracaoDasTarefas(
        Escopo(argumentos.escopo), argumentos.parentes, argumentos.outros, argumentos.semente
    )
    tarefas = montar_tarefas(casos, analisador, configuracao)
    preparo = time.perf_counter() - inicio
    baselines: list[Pontuador] = [CloneExato(), Jaccard(), JaccardMenosCorrecao()]
    modelos = [
        ConfiguracaoDoModelo("modelo_sem_correcao", CARACTERISTICAS_SEM_CORRECAO),
        ConfiguracaoDoModelo("modelo_completo", NOMES),
    ]
    linhas = validacao_cruzada(tarefas, baselines, modelos, argumentos.dobras, argumentos.semente)
    resumo = resumir(linhas)
    comparacoes = {
        f"modelo_completo x {outro}": {
            metrica: comparar(linhas, "modelo_completo", outro, metrica)
            for metrica in ("mrr", "recall@10", "corrigidos@10")
        }
        for outro in sorted(resumo)
        if outro != "modelo_completo"
    }
    relatorio: dict[str, Any] = {
        "configuracao": {
            "juliet_sha256": argumentos.sha256,
            "cwes": sorted({t.grupo for t in tarefas}),
            "metodos_rotulados": len(casos),
            "tarefas": len(tarefas),
            "candidatos_por_tarefa": sorted({len(t.candidatos) for t in tarefas}),
            "escopo": argumentos.escopo,
            "parentes_por_tarefa": argumentos.parentes,
            "outros_por_tarefa": argumentos.outros,
            "dobras": argumentos.dobras,
            "semente_aleatoria": argumentos.semente,
            "caracteristicas": list(NOMES),
        },
        "tempo_segundos": {
            "preparo": round(preparo, 1),
            "total": round(time.perf_counter() - inicio, 1),
        },
        "resumo": resumo,
        "comparacoes": comparacoes,
        "por_tarefa": linhas,
    }
    saida = Path(argumentos.saida)
    saida.parent.mkdir(parents=True, exist_ok=True)
    saida.write_text(json.dumps(relatorio, ensure_ascii=False, indent=2), encoding="utf-8")
    _imprimir_resumo(relatorio)
    return 0


def comando_caso(argumentos: argparse.Namespace) -> int:
    caso = CASOS[argumentos.nome]
    analisador = AnalisadorDeCodigo()
    pontuadores: list[Pontuador] = [CloneExato(), Jaccard(), JaccardMenosCorrecao()]
    if argumentos.treinar_com:
        pontuadores.append(
            _modelo_treinado(Path(argumentos.treinar_com), argumentos.sha256, analisador)
        )
    resultado = avaliar_caso(caso, Path(argumentos.dados), analisador, pontuadores)
    if argumentos.json:
        print(json.dumps(resultado, ensure_ascii=False))
        return 0
    print(f"{resultado['caso']}: {resultado['descricao']}")
    total = resultado["funcoes_no_alvo"]
    for nome, posicoes in resultado["posicao"].items():
        for funcao, posicao in posicoes.items():
            print(f"  {nome:<24} {funcao} na posição {posicao} de {total}")
    for funcao, esta in resultado["na_lista_de_contornos"].items():
        print(f"  {funcao} na lista de onde procurar contorno: {'sim' if esta else 'não'}")
    return 0


def _imprimir_resumo(relatorio: dict[str, Any]) -> None:
    config = relatorio["configuracao"]
    print(f"{config['tarefas']} tarefas em {len(config['cwes'])} CWEs")
    colunas = ("recall@1", "recall@10", "mrr", "ap", "corrigidos@10")
    print(f"{'pontuador':<22}" + "".join(f"{c:>15}" for c in colunas))
    for nome, metricas in relatorio["resumo"].items():
        print(f"{nome:<22}" + "".join(f"{metricas[c]['media']:>15.3f}" for c in colunas))


def montar_analisador_de_argumentos() -> argparse.ArgumentParser:
    raiz = argparse.ArgumentParser(prog="rastro", description=__doc__)
    sub = raiz.add_subparsers(dest="comando", required=True)

    variantes = sub.add_parser("variantes", help="procura variantes de uma falha conhecida")
    variantes.add_argument(
        "--id", required=True, help="identificador da semente, ex. CVE-2024-4577"
    )
    variantes.add_argument("--vulneravel", required=True, help="arquivo com a função vulnerável")
    variantes.add_argument("--corrigido", required=True, help="arquivo com a função corrigida")
    variantes.add_argument("--alvo", required=True, help="pasta com o código a analisar")
    variantes.add_argument(
        "--linguagem", choices=[ling.value for ling in Linguagem], default="java"
    )
    variantes.add_argument("--top", type=int, default=20)
    variantes.add_argument("--json", action="store_true", help="saída em JSON")
    variantes.add_argument(
        "--treinar-com", help="zip da Juliet Java 1.3 para treinar o modelo antes de ranquear"
    )
    variantes.add_argument("--sha256", default=SHA256_JULIET_JAVA_1_3)
    variantes.set_defaults(funcao=comando_variantes)

    experimento = sub.add_parser("experimento", help="roda o experimento sobre a Juliet")
    experimento.add_argument("--juliet", default="dados/juliet-java-1.3.zip")
    experimento.add_argument("--baixar", action="store_true", help="baixa do NIST SARD se faltar")
    experimento.add_argument("--sha256", default=SHA256_JULIET_JAVA_1_3)
    experimento.add_argument("--cwes", help="lista separada por vírgula; padrão: todas")
    experimento.add_argument(
        "--escopo",
        choices=[e.value for e in Escopo],
        default=Escopo.FAMILIA.value,
        help="familia: variantes de fluxo (quase clones); cwe: outras famílias da mesma CWE",
    )
    experimento.add_argument("--parentes", type=int, default=300, help="só no escopo cwe")
    experimento.add_argument("--outros", type=int, default=200)
    experimento.add_argument("--dobras", type=int, default=5)
    experimento.add_argument("--semente", type=int, default=42)
    experimento.add_argument("--saida", default="resultados/experimento.json")
    experimento.set_defaults(funcao=comando_experimento)

    caso = sub.add_parser("caso", help="roda um caso real de vulnerabilidade recorrente")
    caso.add_argument("nome", choices=sorted(CASOS))
    caso.add_argument("--dados", default="dados/casos")
    caso.add_argument("--json", action="store_true")
    caso.add_argument(
        "--treinar-com", help="zip da Juliet Java 1.3 para incluir o modelo treinado nela"
    )
    caso.add_argument("--sha256", default=SHA256_JULIET_JAVA_1_3)
    caso.set_defaults(funcao=comando_caso)
    return raiz


def principal(argv: Sequence[str] | None = None) -> int:
    # No Windows, com a saída redirecionada, o Python usaria a página de código do
    # sistema e os acentos sairiam trocados.
    for fluxo in (sys.stdout, sys.stderr):
        if isinstance(fluxo, io.TextIOWrapper):
            fluxo.reconfigure(encoding="utf-8")
    argumentos = montar_analisador_de_argumentos().parse_args(argv)
    if getattr(argumentos, "top", 1) < 1:
        print("erro: --top precisa ser pelo menos 1", file=sys.stderr)
        return 2
    try:
        codigo: int = argumentos.funcao(argumentos)
    except ErroDeUso as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2
    return codigo
