# 0005. Duas saídas: variantes e lugares onde procurar contorno

Data: 02/11/2026. Situação: aceita.

## Contexto

A assinatura da correção tira do topo o código que já tem a correção, e é isso que derruba o código
corrigido entre os dez primeiros de 36,4% para 2,6% na Juliet. Nos dois casos reais (PHP e Spring),
porém, a segunda falha estava no lugar que tinha recebido a primeira correção: a correção era
incompleta. O mesmo critério que tira o falso positivo pôs esses dois lugares em último.

## Decisão

O `rastro variantes` devolve duas listas. A primeira é o ranqueamento, para variantes sem a
correção. A segunda traz as funções que se parecem com o código corrigido (semelhança de pelo
menos 0,3) e têm a maior parte do que a correção acrescentou (pelo menos 0,5): os lugares onde
procurar contorno.

## Consequências

- Nos dois casos reais, o lugar da segunda falha aparece na segunda lista; no Spring inteiro, ela
  tem um item só, o construtor do Spring4Shell.
- Os dois limiares são fixos e foram escolhidos pelo significado, não ajustados nos casos. Se um
  caso novo mostrar que eles cortam demais, o ajuste entra com o caso como teste.
- O ranqueamento continua sendo medido do mesmo jeito; a segunda lista não entra nas métricas da
  Juliet, que não tem correção incompleta.
