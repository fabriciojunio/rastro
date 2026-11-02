# rastro: análise de variantes de vulnerabilidades com aprendizado de máquina e assinatura da correção

Fabrício Júnio

Texto da monografia em Markdown, para depois ir para o modelo da instituição. Números e tabelas
vêm de [resultados.md](resultados.md); o método detalhado está em [metodologia.md](metodologia.md).

## Resumo

Quando uma vulnerabilidade é corrigida, a mesma falha costuma existir em outros pontos do código, e
às vezes no próprio ponto corrigido, por um caminho que a correção não cobriu. Procurar essas
variantes a partir de uma falha conhecida é rotina de quem cuida da segurança de um produto. Este
trabalho apresenta o rastro, uma ferramenta que recebe a função vulnerável e a mesma função
corrigida e ranqueia as funções de uma base de código pela chance de serem variantes ainda
vulneráveis. O rastro combina a semelhança com a falha e a assinatura da correção (o que a correção
removeu e o que acrescentou) num modelo de gradient boosting. Na Juliet Test Suite para Java do
NIST, com validação cruzada que testa o modelo em classes de falha que ele não viu, o modelo chegou
a precisão média de 0,748, contra 0,413 da semelhança simples, e reduziu o código já corrigido entre
os dez primeiros resultados de 36,4% para 2,6%. Sem as características da correção, o mesmo modelo
deixou 27,6% de código corrigido no topo. Em dois casos reais, PHP (CVE-2012-1823 e CVE-2024-4577)
e Spring (CVE-2010-1622 e CVE-2022-22965), a segunda falha estava no lugar que tinha recebido a
primeira correção, o que mostrou um limite do método e levou a uma segunda saída, a lista de
lugares onde procurar contorno, que apontou os dois. O ganho do modelo na Juliet não se transferiu
de forma estável para os casos reais. A ferramenta analisa repositórios inteiros, como o php-src e
o spring-framework, em menos de um minuto.

**Palavras-chave:** segurança de software; análise de variantes; vulnerabilidade recorrente;
aprendizado de máquina; correção incompleta.

## Abstract

When a vulnerability is fixed, the same flaw often lives elsewhere in the code, and sometimes in
the fixed spot itself, through a path the fix did not cover. Looking for these variants from a
known flaw is routine work for product security teams. This work presents rastro, a tool that takes
the vulnerable function and the same function fixed and ranks the functions of a codebase by how
likely they are to be still-vulnerable variants. rastro combines similarity to the flaw with the
fix signature (what the fix removed and what it added) in a gradient boosting model. On NIST's
Juliet Test Suite for Java, with cross-validation that tests the model on vulnerability classes it
never saw, the model reached an average precision of 0.748, against 0.413 for plain similarity, and
cut already-fixed code in the top ten from 36.4% to 2.6%. Without the fix features, the same model
left 27.6% of fixed code at the top. In two real cases, PHP (CVE-2012-1823 and CVE-2024-4577) and
Spring (CVE-2010-1622 and CVE-2022-22965), the second flaw was in the place that had received the
first fix, which exposed a limit of the method and led to a second output, a list of places to look
for bypasses, which pointed to both. The model's gain on Juliet did not transfer reliably to the
real cases. The tool analyses whole repositories such as php-src and spring-framework in under a
minute.

**Keywords:** software security; variant analysis; recurring vulnerability; machine learning;
incomplete fix.

## 1 Introdução

### 1.1 Contexto

Uma correção de segurança fecha o ponto em que a falha foi encontrada. O mesmo erro, porém, raramente
existe num lugar só: o código foi copiado, o mesmo padrão foi usado por outra pessoa em outro
módulo, ou a correção cobriu o caminho do ataque que foi reportado e deixou outro aberto. Por isso,
depois de cada vulnerabilidade, a pergunta de quem cuida da segurança de um produto é onde mais essa
falha está. A essa busca dá-se o nome de análise de variantes, e a documentação do CodeQL a define
como usar uma vulnerabilidade conhecida como semente para encontrar problemas parecidos no código
(GITHUB, 2026).

O caso do PHP mostra o problema. Em 2012, a CVE-2012-1823 permitia passar opções de linha de
comando ao `php-cgi` pela query string, e a correção fez o programa deixar de interpretar opções
quando a query string decodificada começa com hífen e não tem sinal de igual. Em 2024, a
CVE-2024-4577 mostrou que, em Windows com certas páginas de código, o hífen suave (byte 0xAD) passa
pela checagem, que olha a query string, e vira hífen comum na conversão "Best-Fit" dos argumentos,
como registra a mensagem do commit que corrigiu a falha. A mesma injeção volta, e a falha nova
estava na mesma função que tinha recebido a correção antiga.

### 1.2 Problema

As ferramentas que procuram código vulnerável parecido com uma falha conhecida usam semelhança de
código (KIM et al., 2017). Semelhança acha o que parece com a falha e, pelo mesmo motivo, acha o
código que já foi corrigido, que continua parecido. Do outro lado, os modelos de aprendizado de
máquina que tentam dizer se uma função qualquer é vulnerável caem de 68% para 3% de F1 quando
avaliados num conjunto com rótulo confiável (DING et al., 2025). O problema deste trabalho fica
entre os dois: dada uma vulnerabilidade com o código antes e depois da correção, ranquear as
funções de uma base de código de forma que as variantes ainda vulneráveis apareçam antes do código
parecido que já foi corrigido.

### 1.3 Objetivos

**Objetivo geral.** Construir e avaliar uma ferramenta de análise de variantes que combine
semelhança com a falha e assinatura da correção num modelo aprendido.

**Objetivos específicos.**

1. Representar funções de Java, PHP e C de forma comparável, tolerante a nomes de variável
   diferentes e sem vazar o rótulo do conjunto de avaliação.
2. Definir características que meçam a semelhança com a falha, com a correção e a presença do que a
   correção removeu e acrescentou.
3. Comparar o modelo com clone de código, semelhança simples e uma heurística sem aprendizado, em
   classes de falha não vistas no treino (RQ1).
4. Medir quanto as características da correção reduzem o código já corrigido no topo (RQ2).
5. Aplicar a ferramenta a casos reais de falha recorrente (RQ3).
6. Medir o custo de rodar a ferramenta num repositório inteiro (RQ4).

### 1.4 Justificativa

Análise de variantes é parte do trabalho de equipes de segurança de produto e de resposta a
incidentes de produto. Uma ferramenta que ponha as variantes antes do código já corrigido reduz o
tempo dessa revisão e o risco de a mesma falha voltar depois de uma correção. O trabalho também
tem valor de método: mede, com controle de vazamento e teste estatístico, quanto a assinatura da
correção explica, e mostra onde ela falha.

## 2 Fundamentação

### 2.1 Vulnerabilidade, CWE e CVE

Uma vulnerabilidade é uma falha de software que um atacante pode explorar. O CVE (Common
Vulnerabilities and Exposures) dá um identificador a cada vulnerabilidade publicada, e o CWE
(Common Weakness Enumeration) classifica o tipo de falha, como injeção de SQL (CWE-89) ou estouro de
inteiro (CWE-190). Uma mesma CWE aparece em código muito diferente; é essa variedade que torna a
busca por variantes difícil.

### 2.2 Correção incompleta e falha recorrente

Uma correção é incompleta quando fecha o caminho de ataque reportado e deixa outro aberto para a
mesma falha. A falha recorrente é a mesma vulnerabilidade em outro lugar, por reuso de código ou
por repetição do mesmo erro. Os dois casos reais deste trabalho são correções incompletas.

### 2.3 Detecção de clone de código

Clones de código são trechos iguais ou parecidos. A classificação usual distingue clones idênticos
(tipo 1), idênticos a menos de nomes e literais (tipo 2) e com linhas acrescentadas ou removidas
(tipo 3). O VUDDY usa clones de tipo 2 por função, com abstração de identificadores, para encontrar
código vulnerável copiado em escala (KIM et al., 2017).

### 2.4 Aprendizado de máquina para ranqueamento

O rastro trata a busca como ranqueamento: cada par (semente, candidato) recebe uma nota, e a lista
é ordenada por ela. A nota é a probabilidade dada por um classificador de gradient boosting
(FRIEDMAN, 2001), na implementação do scikit-learn (PEDREGOSA et al., 2011). A importância de cada
característica é medida por permutação (BREIMAN, 2001): quanto o desempenho cai quando a coluna é
embaralhada.

### 2.5 Avaliação de ranqueamento

A precisão média (AP) resume a qualidade de toda a lista; o MRR olha a posição do primeiro acerto;
recall e precisão em k olham o topo, que é o que uma pessoa lê. O intervalo de confiança das médias
é obtido por bootstrap (EFRON; TIBSHIRANI, 1993), e as comparações entre métodos usam o teste de
postos sinalizados de Wilcoxon (WILCOXON, 1945), pareado por semente.

## 3 Trabalhos relacionados

O VUDDY (KIM et al., 2017) encontra clones de funções vulneráveis em escala de bilhões de linhas,
mas só olha a falha. O MVP (XIAO et al., 2020) é o trabalho mais próximo: gera uma assinatura da
vulnerabilidade e uma do patch, por fatiamento de programa, e marca a função que casa a primeira e
não casa a segunda, com regras de casamento definidas pelos autores, para C. O MOVERY (WOO et al.,
2022) e o V1SCAN (WOO et al., 2023) tratam de código de terceiros reutilizado com modificação,
também em C e C++. O FIRE (FENG et al., 2024) combina filtros em estágios com análise de
contaminação. O PrimeVul (DING et al., 2025) mostra que modelos de linguagem de código avaliados
em conjuntos com rótulo confiável ficam perto do aleatório na detecção geral de vulnerabilidades.

O rastro parte da ideia do MVP, que é usar a correção, e se diferencia em quatro pontos: a
combinação é aprendida, não escrita à mão; a avaliação é feita em classes de falha não vistas no
treino; a contribuição da assinatura da correção é isolada por ablação, com teste estatístico; e a
ferramenta trabalha com Java, PHP e C por meio de um analisador comum.

## 4 Metodologia

Ver [metodologia.md](metodologia.md), seções 4 a 9.

## 5 Resultados

Ver [resultados.md](resultados.md).

## 6 Discussão

A seção será escrita com os números finais das análises de sensibilidade e de importância.

## 7 Conclusão

A seção será escrita com os números finais das análises de sensibilidade e de importância.

## Referências

BOLAND, F. E.; BLACK, P. E. Juliet 1.1 C/C++ and Java Test Suite. **Computer**, v. 45, n. 10,
p. 88-90, out. 2012. DOI: 10.1109/MC.2012.345.

BREIMAN, L. Random Forests. **Machine Learning**, v. 45, n. 1, p. 5-32, 2001.

DING, Y. et al. Vulnerability Detection with Code Language Models: How Far Are We? In:
INTERNATIONAL CONFERENCE ON SOFTWARE ENGINEERING, 47., 2025, Ottawa. **Proceedings** [...].
Piscataway: IEEE, 2025. p. 1729-1741. DOI: 10.1109/ICSE55347.2025.00038.

EFRON, B.; TIBSHIRANI, R. J. **An Introduction to the Bootstrap**. New York: Chapman & Hall, 1993.

FENG, S. et al. FIRE: Combining Multi-Stage Filtering with Taint Analysis for Scalable Recurring
Vulnerability Detection. In: USENIX SECURITY SYMPOSIUM, 33., 2024, Philadelphia.
**Proceedings** [...]. Berkeley: USENIX Association, 2024. p. 1867-1884.

FRIEDMAN, J. H. Greedy function approximation: a gradient boosting machine. **The Annals of
Statistics**, v. 29, n. 5, p. 1189-1232, 2001.

GITHUB. **About CodeQL**. Disponível em:
https://codeql.github.com/docs/codeql-overview/about-codeql/. Acesso em: 2 nov. 2026.

KIM, S. et al. VUDDY: A Scalable Approach for Vulnerable Code Clone Discovery. In: IEEE SYMPOSIUM
ON SECURITY AND PRIVACY, 2017, San Jose. **Proceedings** [...]. Los Alamitos: IEEE, 2017.
p. 595-614.

PEDREGOSA, F. et al. Scikit-learn: Machine Learning in Python. **Journal of Machine Learning
Research**, v. 12, p. 2825-2830, 2011.

WILCOXON, F. Individual Comparisons by Ranking Methods. **Biometrics Bulletin**, v. 1, n. 6,
p. 80-83, 1945.

WOO, S. et al. MOVERY: A Precise Approach for Modified Vulnerable Code Clone Discovery from
Modified Open-Source Software Components. In: USENIX SECURITY SYMPOSIUM, 31., 2022, Boston.
**Proceedings** [...]. Berkeley: USENIX Association, 2022. p. 3037-3053.

WOO, S. et al. V1SCAN: Discovering 1-day Vulnerabilities in Reused C/C++ Open-source Software
Components Using Code Classification Techniques. In: USENIX SECURITY SYMPOSIUM, 32., 2023,
Anaheim. **Proceedings** [...]. Berkeley: USENIX Association, 2023. p. 6541-6556.

XIAO, Y. et al. MVP: Detecting Vulnerabilities using Patch-Enhanced Vulnerability Signatures. In:
USENIX SECURITY SYMPOSIUM, 29., 2020. **Proceedings** [...]. Berkeley: USENIX Association, 2020.
p. 1165-1182.
