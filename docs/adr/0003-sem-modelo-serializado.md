# 0003. Nenhum modelo carregado de arquivo

Data: 02/11/2026. Situação: aceita.

## Contexto

O jeito comum de guardar um modelo do scikit-learn é o `pickle` (ou o `joblib`, que usa `pickle`).
Carregar um `pickle` executa código: quem controla o arquivo controla o processo. Num projeto de
segurança, um comando que aceita `--modelo arquivo.pkl` vindo de qualquer lugar seria a falha mais
óbvia do repositório.

## Decisão

O `rastro variantes` não carrega modelo de arquivo. Sem opção, usa a heurística com a correção, que
não precisa de treino. Com `--treinar-com`, treina o modelo na hora, a partir da Juliet conferida
por SHA-256.

## Consequências

- O treino leva alguns minutos a cada uso com modelo. Para o uso na pesquisa e na CI, é aceitável.
- Se um dia o tempo pesar, a saída é exportar o modelo num formato que não executa código (por
  exemplo, os limiares das árvores em JSON) e conferir o hash do arquivo, e não voltar ao `pickle`.
