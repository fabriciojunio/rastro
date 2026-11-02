# Changelog

Mudanças relevantes do rastro. Formato baseado em
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e versionamento
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado

- Análise de código com tree-sitter para Java, PHP e C, com tokens abstraídos no estilo do VUDDY.
- Assinatura da correção: o que a correção removeu e o que acrescentou.
- Nove características do par semente e candidato, três baselines e o modelo de gradient boosting.
- Experimento sobre a Juliet Java 1.3 com validação cruzada por CWE, bootstrap e Wilcoxon.
- Casos reais reproduzíveis: PHP (CVE-2012-1823 e CVE-2024-4577) e Spring (CVE-2010-1622 e
  CVE-2022-22965).
- Lista de lugares que receberam a correção, onde procurar contorno.
- Comandos `variantes`, `experimento` e `caso`.
- CI com lint, tipos, testes, gitleaks, OSV-Scanner, Semgrep, o experimento e a medição de custo.

### Corrigido

- O tree-sitter 0.26.0 derrubava o processo em análises seguidas; fixado na 0.25.
- O download da Juliet recebia 403 do NIST SARD com o agente padrão do Python.
- O experimento na CI saía verde sem rodar, porque o `tee` escondia a falha.
