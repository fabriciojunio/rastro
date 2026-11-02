# 0002. Juliet Java como gabarito, com dois escopos

Data: 02/11/2026. Situação: aceita.

## Contexto

Avaliar análise de variantes pede saber, para cada semente, quais funções são variantes e quais
são o mesmo código já corrigido. Conjuntos reais de CVE raramente trazem esse segundo grupo, e
rótulo de commit de correção tem ruído alto (é o problema que o PrimeVul documenta).

A Juliet Test Suite do NIST traz os dois: em cada arquivo, `bad()` tem a falha e `good*()` é o
mesmo código corrigido, com rótulo por construção. O custo é ser sintética.

## Decisão

Usar a Juliet Java 1.3 como gabarito controlado, com o pacote conferido por SHA-256, e medir em
dois escopos: `familia` (parentes são as variantes de fluxo da mesma família) e `cwe` (parentes
são outras famílias da mesma CWE, sem a própria). Comentários e o nome da função ficam fora da
tokenização, porque entregam o rótulo.

## Consequências

- O primeiro experimento mostrou que no escopo `familia` o Jaccard bate no teto: as variantes de
  fluxo são quase clones. O resultado principal passou a ser o do escopo `cwe`.
- A validade externa depende de casos reais, que são a RQ3.
