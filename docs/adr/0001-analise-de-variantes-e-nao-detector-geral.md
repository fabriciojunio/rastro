# 0001. Análise de variantes, e não um detector geral de vulnerabilidades

Data: 02/11/2026. Situação: aceita.

## Contexto

A ideia mais comum de "aprendizado de máquina para segurança" é um modelo que olha uma função e diz
se ela é vulnerável. Os resultados recentes não sustentam isso. No PrimeVul (Ding et al., ICSE
2025), um modelo de código caiu de 68,26% de F1 no BigVul para 3,09% num conjunto com rótulo
confiável e sem vazamento entre treino e teste, e os modelos maiores ficaram perto do aleatório no
cenário mais rigoroso.

## Decisão

O rastro resolve um problema mais estreito e real: dada uma vulnerabilidade conhecida, com o código
antes e depois da correção, achar outros lugares com a mesma falha. É o que as equipes de
segurança de produto fazem depois de cada CVE, e é o que o CodeQL chama de análise de variantes.

## Consequências

- O modelo não precisa saber o que é vulnerável em geral, só comparar com uma semente. O problema
  fica do tamanho que dá para avaliar com honestidade.
- A semente traz a correção, que é a informação que separa a variante do código já corrigido.
- O rastro não acha falha de uma classe que ninguém reportou ainda. Isso fica fora do escopo e
  está dito no README.
