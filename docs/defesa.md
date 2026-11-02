# Defesa

Roteiro da apresentação e as perguntas que a banca deve fazer, com a resposta e onde está o número.
Todos os números saem de [resultados.md](resultados.md).

## Roteiro (20 minutos)

1. **O problema, com um caso (2 min).** A CVE-2012-1823 do PHP foi corrigida. Em 2024, a
   CVE-2024-4577 voltou pela mesma função, por um caminho que a correção não cobriu. Pergunta de
   quem cuida de segurança de produto depois de toda correção: onde mais está essa falha?
2. **Por que não "IA que acha vulnerabilidade" (2 min).** PrimeVul: modelo de código cai de 68% de
   F1 para 3% num conjunto realista. O rastro resolve um problema menor e real: análise de
   variantes a partir de uma semente.
3. **A ideia (3 min).** Clone de código acha o que parece com a falha, e por isso acha também o
   código já corrigido. A assinatura da correção (o que a correção tirou e o que pôs) separa os
   dois. O MVP (USENIX Security 2020) publicou a ideia com regras escritas à mão; aqui a combinação
   é aprendida e avaliada em classes de falha não vistas.
4. **Como foi medido (3 min).** Juliet Java inteira (55.357 métodos), validação cruzada por CWE,
   controle de vazamento (comentário e nome da função fora), bootstrap e Wilcoxon.
5. **Resultado (4 min).** Escopo `cwe`: AP 0,748 contra 0,413 do Jaccard; código corrigido no top
   10 cai de 36,4% para 2,6%; sem as características da correção, volta a 27,6%.
6. **Casos reais e o limite (4 min).** PHP e Spring4Shell: a segunda falha mora no lugar que
   recebeu a primeira correção, e o ranqueamento o rebaixa. Daí a lista de contornos, que aponta
   os dois. No brecha, os três métodos com BOLA ficam nos três primeiros lugares.
7. **Custo e uso (1 min).** Repositório inteiro em meio minuto. Demonstração ao vivo do
   `rastro caso spring`.
8. **Conclusão (1 min).** O que funciona, o que não transfere e o próximo passo.

## Demonstração

Antes de entrar na sala, com internet, para baixar e conferir os arquivos:

```bash
rastro caso php
rastro caso spring
```

Na sala, os mesmos comandos rodam com os arquivos já baixados e conferidos por hash. Se a internet
cair, o resultado é o mesmo.

## Perguntas prováveis

**"Isso não é só o MVP de novo?"**
A ideia de usar a assinatura do patch é do MVP, e o texto diz isso. O que é deste trabalho: a
combinação aprendida em vez de regras; a avaliação em CWE não vista no treino; a ablação que mede
quanto a assinatura explica (corrigidos no top 10 vai de 27,6% para 2,6%); e o resultado negativo
que o MVP também tem por construção, a correção incompleta, com a lista de contornos como resposta.

**"A Juliet é sintética. Por que confiar?"**
Não é para confiar sozinha. Ela foi escolhida porque traz o negativo difícil por construção (o
`good()` ao lado do `bad()`), que conjunto real de CVE não traz. Mostrei onde ela é fácil demais
(escopo `familia`, Jaccard em 0,958) e por isso o resultado principal é o escopo `cwe`. A validade
externa vem dos casos reais, e ali o resultado foi misto, e está escrito assim.

**"O modelo não transferiu para os casos reais. Então ele serve?"**
Nos dois casos, o modelo acertou um lugar e errou dois. Com dois casos não dá para afirmar nem que
transfere nem que não. Por isso o padrão do `rastro variantes` é a heurística com a correção, que
foi previsível nos dois casos, e o modelo é opcional. O ganho do modelo está medido na Juliet, e é
lá que ele vale.

**"Como você sabe que não há vazamento entre treino e teste?"**
As dobras separam CWEs inteiras. No treino saem até os candidatos "outros" que vêm das CWEs de
teste. Comentários ("POTENTIAL FLAW", "FIX") e o nome da função (`bad`, `good`) são descartados na
tokenização. O empate é desfeito por sorteio, não pela ordem de entrada. Está na metodologia,
seção "Controle de vazamento", e há teste automatizado para cada ponto.

**"Por que gradient boosting e não uma rede neural?"**
Nove características numéricas e centenas de milhares de pares de treino por dobra (entre 202 e
500 candidatos por semente, cerca de 700 sementes de treino): é o cenário em que árvores com
boosting costumam ir bem, e a importância por permutação é legível. Uma rede para
código (CodeBERT e afins) é o que o PrimeVul mostrou cair em conjunto realista. O objetivo não era
o maior número, era um resultado que se explica.

**"O p-valor é muito pequeno. Isso não é só porque n é grande?"**
Por isso o resultado vem com o tamanho do efeito e o intervalo de confiança, não só o p. A
diferença de AP é de 0,413 para 0,748, com intervalos que não se cruzam. O p só diz que a
diferença não é acaso; o intervalo diz o tamanho.

**"Quanto custa usar na empresa?"**
Meio minuto por repositório, abaixo de 700 MB, numa máquina padrão do GitHub Actions. O workflow de
custo do projeto é o exemplo de como rodar na CI.

**"Por que nenhum modelo é salvo em arquivo?"**
Carregar `pickle` executa código. Uma ferramenta de segurança que aceita um arquivo de modelo de
fora seria a primeira falha do próprio projeto. Está no ADR 0003.

**"O que fica para depois?"**
Conjunto rotulado real com mais casos (CVEfixes e as correções incompletas conhecidas),
comparação por fatia de programa em vez de função inteira (para falha que atravessa métodos), e
PHP e C no treino.
