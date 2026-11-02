# Segurança

## Como avisar de uma falha

Use o aviso privado do GitHub (aba **Security**, **Report a vulnerability**) ou escreva para
**fabricioad444@gmail.com** com o que encontrou e como reproduzir. É um projeto
acadêmico mantido por uma pessoa: a resposta depende de disponibilidade.

## O que interessa

O rastro lê código de terceiros e baixa um conjunto de dados da internet, então interessa
principalmente:

- arquivo de código que derrube ou trave a análise (o parser é o tree-sitter, em C);
- caminho que faça o rastro ler fora da pasta indicada em `--alvo`;
- qualquer forma de o download da Juliet ser aceito sem o SHA-256 conferir.

## O que já está feito

- O pacote da Juliet só é usado depois de conferido o SHA-256 fixado no código; o download é só
  por HTTPS e vai para um arquivo temporário, apagado se o hash não bater.
- Nenhum modelo é carregado de arquivo, porque desserializar `pickle` executa código
  ([ADR 0003](docs/adr/0003-sem-modelo-serializado.md)).
- Links simbólicos e arquivos acima de 2 MB são ignorados na pasta analisada.
- Dependências instaladas só com hash conferido; gitleaks, OSV-Scanner e Semgrep a cada push.
