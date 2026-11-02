"""Leitura de código com tree-sitter: funções, tokens abstraídos e chamadas.

A abstração segue a ideia do VUDDY (S&P 2017): nome de variável, texto e número
viram marcadores, porque a variante de uma falha raramente usa os mesmos nomes.
Duas coisas ficam com o texto original, porque são elas que caracterizam a
falha: o nome da função chamada (``execute``, ``memcpy``, ``mysql_query``) e o
nome dos tipos.

Comentários são descartados. Na Juliet eles dizem "POTENTIAL FLAW" e "FIX" no
próprio código; contá-los seria entregar o rótulo ao modelo.
"""

from collections.abc import Iterator
from dataclasses import dataclass

import tree_sitter_c
import tree_sitter_java
import tree_sitter_php
from tree_sitter import Language, Node, Parser, Tree

from rastro.dominio.modelos import Funcao, Linguagem


@dataclass(frozen=True, slots=True)
class _Regras:
    funcoes: frozenset[str]
    comentarios: frozenset[str]
    textos: frozenset[str]
    numeros: frozenset[str]
    identificadores: frozenset[str]
    tipos: frozenset[str]
    # tipo do nó de chamada -> campo que guarda o nome chamado
    chamadas: dict[str, str]
    prefixo: str
    sufixo: str


_REGRAS: dict[Linguagem, _Regras] = {
    Linguagem.JAVA: _Regras(
        funcoes=frozenset({"method_declaration", "constructor_declaration"}),
        comentarios=frozenset({"line_comment", "block_comment"}),
        textos=frozenset({"string_literal", "character_literal", "text_block"}),
        numeros=frozenset(
            {
                "decimal_integer_literal",
                "hex_integer_literal",
                "octal_integer_literal",
                "binary_integer_literal",
                "decimal_floating_point_literal",
                "hex_floating_point_literal",
            }
        ),
        identificadores=frozenset({"identifier"}),
        tipos=frozenset({"type_identifier"}),
        chamadas={"method_invocation": "name"},
        prefixo="class Rastro {\n",
        sufixo="\n}",
    ),
    Linguagem.PHP: _Regras(
        funcoes=frozenset({"function_definition", "method_declaration"}),
        comentarios=frozenset({"comment"}),
        textos=frozenset({"string", "encapsed_string", "heredoc", "nowdoc"}),
        numeros=frozenset({"integer", "float"}),
        identificadores=frozenset({"name", "variable_name"}),
        tipos=frozenset(),
        chamadas={
            "function_call_expression": "function",
            "member_call_expression": "name",
            "nullsafe_member_call_expression": "name",
            "scoped_call_expression": "name",
        },
        prefixo="<?php\n",
        sufixo="",
    ),
    Linguagem.C: _Regras(
        funcoes=frozenset({"function_definition"}),
        comentarios=frozenset({"comment"}),
        textos=frozenset({"string_literal", "char_literal", "concatenated_string"}),
        numeros=frozenset({"number_literal"}),
        identificadores=frozenset({"identifier", "field_identifier"}),
        tipos=frozenset({"type_identifier", "primitive_type"}),
        chamadas={"call_expression": "function"},
        prefixo="",
        sufixo="",
    ),
}

_GRAMATICAS: dict[Linguagem, Language] = {
    Linguagem.JAVA: Language(tree_sitter_java.language()),
    Linguagem.PHP: Language(tree_sitter_php.language_php()),
    Linguagem.C: Language(tree_sitter_c.language()),
}

MARCA_IDENTIFICADOR = "ID"
MARCA_TEXTO = "STR"
MARCA_NUMERO = "NUM"


class AnalisadorDeCodigo:
    """Extrai funções e tokens de Java, PHP e C."""

    def __init__(self) -> None:
        self._parsers = {linguagem: Parser(g) for linguagem, g in _GRAMATICAS.items()}

    def funcoes(self, codigo: str, linguagem: Linguagem, caminho: str) -> list[Funcao]:
        """Todas as funções e métodos de um arquivo, na ordem em que aparecem."""
        regras = _REGRAS[linguagem]
        if linguagem is Linguagem.PHP and not codigo.lstrip().startswith("<?"):
            codigo = regras.prefixo + codigo
        # A árvore fica numa variável enquanto os nós são usados: o nó não
        # segura a árvore, e sem ela o percurso lia memória já liberada.
        arvore = self._parsers[linguagem].parse(codigo.encode("utf-8"))
        encontradas = []
        for no in _percorrer(arvore.root_node):
            if no.type in regras.funcoes:
                encontradas.append(
                    Funcao(
                        nome=_nome_da_funcao(no),
                        linguagem=linguagem,
                        caminho=caminho,
                        linha=no.start_point.row + 1,
                        codigo=_texto(no),
                    )
                )
        return encontradas

    def tokens(self, trecho: str, linguagem: Linguagem) -> tuple[str, ...]:
        """Tokens abstraídos do trecho, sem comentários."""
        arvore, inicio, fim = self._analisar_trecho(trecho, linguagem)
        return tuple(_tokenizar(arvore.root_node, _REGRAS[linguagem], inicio, fim))

    def chamadas(self, trecho: str, linguagem: Linguagem) -> frozenset[str]:
        """Nomes das funções e métodos chamados no trecho."""
        arvore, inicio, fim = self._analisar_trecho(trecho, linguagem)
        regras = _REGRAS[linguagem]
        return frozenset(
            _texto(no)
            for no in _percorrer(arvore.root_node)
            if inicio <= no.start_byte
            and no.end_byte <= fim
            and no.type in regras.identificadores
            and _e_nome_chamado(no, regras)
        )

    def _analisar_trecho(self, trecho: str, linguagem: Linguagem) -> tuple[Tree, int, int]:
        """Envolve o trecho para ele virar código válido e devolve onde ele começa e acaba.

        Um método Java solto não é uma unidade de compilação; dentro de uma
        classe ele é analisado como método, e as chamadas são reconhecidas.
        Só os tokens dentro do trecho original contam.
        """
        regras = _REGRAS[linguagem]
        prefixo = regras.prefixo
        if linguagem is Linguagem.JAVA and "class " in trecho:
            prefixo = ""
        if linguagem is Linguagem.PHP and trecho.lstrip().startswith("<?"):
            prefixo = ""
        sufixo = regras.sufixo if prefixo else ""
        inicio = len(prefixo.encode("utf-8"))
        fim = inicio + len(trecho.encode("utf-8"))
        fonte = (prefixo + trecho + sufixo).encode("utf-8")
        return self._parsers[linguagem].parse(fonte), inicio, fim


def _percorrer(raiz: Node) -> Iterator[Node]:
    """Pré-ordem com pilha explícita: código gerado passa do limite de recursão."""
    pilha = [raiz]
    while pilha:
        no = pilha.pop()
        yield no
        pilha.extend(reversed(no.children))


def _texto(no: Node) -> str:
    return no.text.decode("utf-8", errors="replace") if no.text else ""


def _nome_da_funcao(no: Node) -> str:
    nome = no.child_by_field_name("name")
    if nome is not None:
        return _texto(nome)
    # Em C o nome fica dentro do declarador: int *f(int a) -> pointer -> function -> f
    declarador = no.child_by_field_name("declarator")
    while declarador is not None:
        if declarador.type == "identifier":
            return _texto(declarador)
        declarador = declarador.child_by_field_name("declarator")
    return "?"


def _e_nome_chamado(no: Node, regras: _Regras) -> bool:
    pai = no.parent
    if pai is None:
        return False
    campo = regras.chamadas.get(pai.type)
    if campo is None:
        return False
    alvo = pai.child_by_field_name(campo)
    return alvo is not None and alvo.start_byte == no.start_byte and alvo.end_byte == no.end_byte


def _token_do_no(no: Node, regras: _Regras) -> str | None:
    """O token em que o nó vira inteiro, ou None se é preciso descer nos filhos."""
    tipo = no.type
    if tipo in regras.textos:
        return MARCA_TEXTO
    if tipo in regras.numeros:
        return MARCA_NUMERO
    if tipo in regras.identificadores:
        return _texto(no) if _e_nome_chamado(no, regras) else MARCA_IDENTIFICADOR
    if tipo in regras.tipos or no.child_count == 0:
        # Tipos, palavras-chave, pontuação e folhas como void, true, null e this.
        return _texto(no)
    return None


def _tokenizar(raiz: Node, regras: _Regras, inicio: int, fim: int) -> list[str]:
    saida: list[str] = []
    pilha = [raiz]
    while pilha:
        no = pilha.pop()
        fora_do_trecho = no.end_byte <= inicio or no.start_byte >= fim
        if fora_do_trecho or no.type in regras.comentarios:
            continue
        token = _token_do_no(no, regras)
        if token is not None:
            saida.append(token)
        else:
            pilha.extend(reversed(no.children))
    return saida
