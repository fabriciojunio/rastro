# 0004. tree-sitter fixado na 0.25

Data: 02/11/2026. Situação: aceita.

## Contexto

Com o `tree-sitter` 0.26.0, analisar arquivos da Juliet em sequência derrubava o processo com
violação de acesso dentro da biblioteca. O mesmo arquivo, isolado, passava. Repetir três arquivos
50 vezes reproduzia a falha toda vez; com a 0.25.2, as mesmas 150 análises e as 14.039 funções de
três CWEs passaram.

## Decisão

Fixar `tree-sitter>=0.25.2,<0.26` e percorrer a árvore com pilha explícita, guardando a árvore em
variável enquanto os nós são usados.

## Consequências

- Atualização para a 0.26 só depois de repetir o teste de análises em sequência sobre a Juliet.
- A pilha explícita também resolve código com aninhamento além do limite de recursão do Python,
  que tem teste próprio (3.000 níveis).
