# Metodologia

## 1. Problema

Análise de variantes é o passo que vem depois de uma vulnerabilidade: usar a falha conhecida como
semente e procurar o mesmo problema em outros pontos do código. O GitHub descreve assim o uso do
CodeQL ("using a known security vulnerability as a seed to find similar problems in your code",
[documentação do CodeQL][codeql]), e é rotina de quem trabalha com segurança de produto e resposta a
incidentes de produto (PSIRT).

O caso que motivou o trabalho é o PHP. A CVE-2012-1823 permitia passar opções ao `php-cgi` pela
query string. A correção fez o programa deixar de interpretar opções quando a query string
decodificada começa com hífen e não tem `=`. Em 2024, a CVE-2024-4577 mostrou que, em Windows com
certas páginas de código, o hífen suave (0xAD) passa pela checagem, que olha a query string, e
vira hífen comum na conversão "Best-Fit" dos argumentos, como diz a mensagem do commit da correção
([`93826731`](https://github.com/php/php-src/commit/938267314835de3c2ed1a3da4f2959f1d2709468);
[resumo do caso][php]). A correção fechou o ponto, mas não a classe de falha.

## 2. Perguntas de pesquisa

- **RQ1.** Um modelo que combina semelhança com a falha e assinatura da correção ranqueia variantes
  melhor que clone de código e semelhança simples?
- **RQ2.** As características que olham a correção reduzem o código já corrigido no topo do
  ranking?
- **RQ3.** O rastro encontra variantes em casos reais de vulnerabilidade?
- **RQ4.** Quanto custa rodar o rastro na integração contínua?

As quatro estão respondidas em [resultados.md](resultados.md).

## 3. Trabalhos relacionados

| Trabalho | O que faz | Diferença para o rastro |
|---|---|---|
| VUDDY, Kim et al., IEEE S&P 2017 ([artigo][vuddy]) | clone de função vulnerável com abstração de identificadores, escala para um bilhão de linhas | só clone; não olha a correção. É a baseline `clone_exato` |
| MVP, Xiao et al., USENIX Security 2020 ([artigo][mvp]) | assinatura da vulnerabilidade e assinatura do patch por fatiamento de programa; marca quem casa a primeira e não casa a segunda | é a ideia mais próxima. Usa regras de casamento escritas à mão e é para C. O rastro aprende a combinação, mede a generalização para CWEs não vistas e isola o ganho da assinatura da correção por ablação |
| MOVERY, Woo et al., USENIX Security 2022 ([artigo][movery]) | assinaturas de funções vulneráveis e corrigidas com as linhas centrais; 96% de precisão e de revocação em dez projetos | foco em código de terceiros reutilizado com modificação, em C; regras, sem aprendizado |
| V1SCAN, Woo et al., USENIX Security 2023 ([artigo][v1scan]) | combina detecção por versão e por código para componentes reutilizados | mesmo foco em componentes de terceiros em C/C++ |
| FIRE, Feng et al., USENIX Security 2024 ([artigo][fire]) | filtros em estágios (Bloom, tokens, AST) e análise de contaminação; 90% de precisão | análise de fluxo de dados, mais cara e mais precisa; para C |
| PrimeVul, Ding et al., ICSE 2025 ([artigo][primevul]) | mostra modelo de código caindo de 68,26% de F1 (BigVul) para 3,09% num conjunto realista | motivo para não propor "ML que acha qualquer falha" e para usar avaliação rigorosa |

A contribuição do rastro não é a ideia de usar a correção, que o MVP já publicou. É (a) um
ranqueamento aprendido sobre características simples e explicáveis, (b) a avaliação por CWE não
vista, que é o cenário de uma CVE nova, (c) a ablação que mede quanto a assinatura da correção
explica, com teste estatístico, e (d) uma ferramenta aberta para Java, PHP e C.

## 4. Representação do código

O código é lido com o [tree-sitter](https://tree-sitter.github.io/) (Java, PHP e C). Cada função
vira uma sequência de tokens abstraídos, como no VUDDY:

- identificador de variável vira `ID`, texto vira `STR`, número vira `NUM`;
- o nome da função chamada (`execute`, `memcpy`, `mysql_query`) e o nome dos tipos ficam, porque
  são eles que caracterizam a falha;
- comentários e o nome da própria função são descartados.

A comparação usa trigramas de tokens. A **assinatura da correção** é o conjunto de trigramas que a
correção removeu e o conjunto que ela acrescentou.

## 5. Características

| Nome | O que mede |
|---|---|
| `sim_vulneravel` | Jaccard dos trigramas do candidato com os do código vulnerável |
| `sim_corrigido` | o mesmo com o código corrigido |
| `contencao_vulneravel` | fração dos trigramas vulneráveis presentes no candidato |
| `falha_presente` | fração dos trigramas que a correção removeu presentes no candidato |
| `correcao_presente` | fração dos trigramas que a correção acrescentou presentes no candidato |
| `sim_chamadas` | Jaccard dos nomes de função chamados |
| `chamadas_removidas_presentes` | fração das chamadas que a correção tirou presentes no candidato |
| `chamadas_adicionadas_presentes` | fração das chamadas que a correção pôs presentes no candidato |
| `log_razao_tamanho` | log da razão de tamanho, para não premiar a função enorme que contém tudo |

## 6. Pontuadores

- `clone_exato`: 1 quando os tokens abstraídos são idênticos (clone tipo 2), 0 no resto.
- `jaccard`: `sim_vulneravel`.
- `jaccard_menos_correcao`: `sim_vulneravel - sim_corrigido`. É a ideia da correção sem
  aprendizado, para separar o ganho da ideia do ganho do modelo.
- `modelo_sem_correcao`: gradient boosting com `sim_vulneravel`, `contencao_vulneravel`,
  `sim_chamadas` e `log_razao_tamanho`. É a ablação da RQ2.
- `modelo_completo`: gradient boosting com as nove características.

O modelo é o `HistGradientBoostingClassifier` do scikit-learn, com 200 iterações, taxa de
aprendizado 0,1 e peso de classe balanceado (variante é rara perto do resto). A nota é a
probabilidade de o candidato ser variante.

## 7. Dados

[Juliet Test Suite para Java 1.3][juliet] do NIST SARD (Boland e Black, IEEE Computer, 2012). O
pacote é baixado do SARD e só é usado depois de conferido o SHA-256
`d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60`.

Cada arquivo de caso tem um nome no formato `CWE89_SQL_Injection__Environment_execute_10.java`: a
CWE, a variante funcional (origem e uso do dado) e a variante de fluxo. Dentro dele, `bad()` tem a
falha e os `good*()` são o mesmo código corrigido: `goodG2B` corrige a origem do dado, `goodB2G`
corrige o uso.

- **Família**: a CWE com a variante funcional.
- **Semente**: o `bad()` do fluxo 01, com a correção `goodB2G` (corrige o uso, como um patch de
  verdade) ou, na falta dela, `goodG2B`.
- **Rótulos**: `bad()` é variante; `good*()` é corrigido; função de outra CWE é outro.
- Só os fluxos de 01 a 19 entram, porque neles a falha cabe numa função.

Dois escopos de candidatos:

- `familia`: os parentes são as outras variantes de fluxo da mesma família.
- `cwe`: os parentes são uma amostra de até 300 funções das outras famílias da mesma CWE, sem a
  própria família. É a mesma falha em outro código, o caso real de análise de variantes.

Em ambos entram também 200 funções sorteadas de outras CWEs.

### Controle de vazamento

- Os comentários da Juliet dizem "POTENTIAL FLAW" e "FIX". Eles são descartados na tokenização.
- O nome da função (`bad`, `goodG2B1`) entrega o rótulo. Ele vira `ID` como qualquer
  identificador.
- As dobras da validação cruzada separam CWEs. No treino saem até os candidatos "outros" que vêm
  das CWEs de teste, então nenhuma função da classe testada é vista no treino.
- Empate na nota é desfeito por sorteio com semente fixa, nunca pela ordem de entrada: os
  candidatos chegam com a família primeiro, e o desempate pela ordem daria ao `clone_exato` um
  acerto que não é dele.

## 8. Avaliação

Validação cruzada em 5 dobras agrupadas por CWE. Para cada semente, cada pontuador ranqueia os
candidatos e se mede:

- **AP** (precisão média) e **MRR** (recíproco da posição da primeira variante);
- **recall@k** e **precisão@k**;
- **corrigidos@10**: fração do top 10 que é código já corrigido, a medida da RQ2.

A média de cada métrica vem com intervalo de 95% por bootstrap (2.000 reamostragens). As
comparações entre pontuadores usam o teste de Wilcoxon pareado por semente, porque os dois
ranquearam as mesmas sementes e métrica de ranking não tem distribuição normal.

O experimento é reprodutível: semente aleatória fixa (42), dependências travadas por hash, pacote
de dados conferido por hash. A CI roda o experimento completo e guarda o JSON por 90 dias.

## 9. Ameaças à validade

- **Validade externa.** A Juliet é sintética. As variantes de fluxo de uma família são quase
  clones, e no escopo `familia` o Jaccard bate no teto. Por isso o resultado principal é o do
  escopo `cwe`, e a RQ3 usa casos reais.
- **Rótulo pela função.** `good*()` é tratado como corrigido. `goodG2B` corrige a origem do dado e
  mantém o uso perigoso; para quem olha só a função, ele ainda parece vulnerável. Isso deixa a
  tarefa mais difícil, não mais fácil.
- **Granularidade.** Comparação por função não vê falha que atravessa métodos. Os fluxos de 21 em
  diante ficam de fora.
- **Uma linguagem no treino.** O modelo é treinado em Java. A extração de PHP e C existe, mas o
  conjunto rotulado dessas linguagens ainda não está no experimento.
- **Transferência.** Nos dois casos reais, o modelo treinado na Juliet não se comportou de forma
  estável (acertou um lugar e errou dois). Com dois casos não dá para generalizar, mas o ganho
  medido na Juliet não deve ser lido como o ganho esperado em código real.
- **Validade interna.** Hiperparâmetros fixos, sem busca; não houve ajuste olhando o teste.

[codeql]: https://codeql.github.com/docs/codeql-overview/about-codeql/
[php]: https://documentation.campus.barracuda.com/wiki/spaces/BWAFv76/pages/2720599
[vuddy]: https://www.ieee-security.org/TC/SP2017/papers/71.pdf
[mvp]: https://www.usenix.org/conference/usenixsecurity20/presentation/xiao
[movery]: https://www.usenix.org/conference/usenixsecurity22/presentation/woo
[v1scan]: https://www.usenix.org/conference/usenixsecurity23/presentation/woo
[fire]: https://www.usenix.org/conference/usenixsecurity24/presentation/feng-siyue
[primevul]: https://arxiv.org/abs/2403.18624
[juliet]: https://samate.nist.gov/SARD/test-suites/111
