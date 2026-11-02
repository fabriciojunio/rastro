# Como reproduzir

Tudo o que está em [resultados.md](resultados.md) sai dos comandos abaixo. Os dados vêm de fora
(NIST SARD e GitHub) e só são aceitos com o hash conferido, então quem roda analisa os mesmos
bytes.

## Preparar

Python 3.11.

```bash
git clone https://github.com/fabriciojunio/rastro
cd rastro
python -m venv .venv
. .venv/bin/activate            # no Windows: .venv\Scripts\activate
pip install --require-hashes --no-deps -r requisitos/dev.txt
pip install --no-deps -e .
pytest                          # 126 testes, cobertura acima de 80% exigida
```

## RQ1 e RQ2: Juliet

```bash
rastro experimento --baixar --escopo cwe --saida resultados/juliet-cwe.json
rastro experimento --escopo familia --saida resultados/juliet-familia.json
```

O primeiro baixa a Juliet Java 1.3 (76.798.417 bytes) e confere o SHA-256
`d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60`. Cada rodada leva alguns
minutos e grava o relatório completo, com uma linha por semente.

Valores esperados no escopo `cwe` (semente aleatória 42, 5 dobras, n-grama 3): 870 sementes em 61
CWEs, AP do modelo completo 0,748, do Jaccard 0,413, código corrigido no top 10 de 2,6% e 36,4%.

Sensibilidade ao n-grama: `--ngrama 2` e `--ngrama 4`.

## RQ3: casos reais

```bash
rastro caso php
rastro caso spring
rastro caso spring --treinar-com dados/juliet-java-1.3.zip
```

Cada caso baixa três arquivos do GitHub em commits fixos e confere o SHA-256 de cada um. O
`--treinar-com` acrescenta o modelo treinado na Juliet no escopo `cwe`.

## RQ4: custo

Pelo workflow `Custo em repositório real` (Actions, botão "Run workflow"), ou à mão:

```bash
rastro caso php                                      # baixa as sementes conferidas
git init -q alvo && git -C alvo fetch -q --depth 1 https://github.com/php/php-src 4b15f5d4ec750b31ec8911f5eb0915a45f96feca
git -C alvo checkout -q FETCH_HEAD
rastro variantes --id php --linguagem c --funcao main \
  --vulneravel dados/casos/php_php-src_f5936cceeb26_cgi_main.c \
  --corrigido dados/casos/php_php-src_0556103f6a34_cgi_main.c \
  --alvo alvo --top 20
```

## Na CI

Todo PR para `produção` roda o experimento nas quatro configurações e a medição de custo nos dois
repositórios. Os relatórios ficam como artefato da execução por 90 dias.
