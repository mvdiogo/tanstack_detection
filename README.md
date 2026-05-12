# 🔍 Advanced TanStack / Mini Shai-Hulud Supply Chain Analyzer

> **Ferramenta de auditoria de segurança para supply chain de pacotes Node.js/TanStack**  
> Detecta IOC, código malicioso, segredos expostos, ofuscação e vulnerabilidades em dependências.

```
┌─────────────────────────────────────────┐
│  🚨 Supply Chain Security Scanner v2.0  │
│  • IOC Detection     • Secret Leaks     │
│  • Entropy Analysis  • CI/CD Audit      │
│  • Binary Analysis   • HTML/JSON Reports│
└─────────────────────────────────────────┘
```

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/Bash-4.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-SupplyChain-orange.svg)]()
[![Status: Beta](https://img.shields.io/badge/Status-Beta-yellow.svg)]()

---

## 📋 Índice

- [✨ Funcionalidades](#-funcionalidades)
- [🚀 Instalação](#-instalação)
- [🎯 Uso Rápido](#-uso-rápido)
- [⚙️ Opções da CLI](#️-opções-da-cli)
- [📊 Saídas e Relatórios](#-saídas-e-relatórios)
- [🔧 Configuração Avançada](#-configuração-avançada)
- [🔄 Integração CI/CD](#-integração-cicd)
- [🧪 Exemplos Práticos](#-exemplos-práticos)
- [⚠️ Limitações & Falsos Positivos](#-limitações--falsos-positivos)
- [🤝 Contribuindo](#-contribuindo)
- [📜 Licença](#-licença)
- [🔐 Aviso de Segurança](#-aviso-de-segurança)

---

## ✨ Funcionalidades

### 🔐 Detecção de Ameaças
| Categoria | Descrição |
|-----------|-----------|
| **IOC Scanner** | Busca por domínios maliciosos conhecidos e padrões de ataque |
| **Código Suspeito** | Detecta `child_process`, `eval()`, `execSync`, ofuscação e exfiltração |
| **Segredos Expostos** | Identifica AWS Keys, GitHub/NPM Tokens, chaves SSH e credenciais hardcoded |
| **Entropia Anômala** | Analisa arquivos com alta entropia (possível ofuscação ou payloads codificados) |
| **Lifecycle Hooks** | Alerta para scripts perigosos em `preinstall`, `postinstall`, `prepare`, etc. |

### 📦 Análise de Dependências
- Verificação de `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Detecção de versionamento inseguro (sem `^` ou `~`)
- Varredura profunda em `node_modules` (arquivos `.js`, `.mjs`, `.cjs`)
- Identificação de pacotes @tanstack e validação de integridade

### 🔍 Auditoria de Ambiente
- **GitHub Actions**: Analisa workflows para `pull_request_target`, tokens expostos, permissões excessivas
- **SSH Keys**: Verifica permissões de arquivos e exposição em repositórios
- **Persistência**: Detecta cron jobs, systemd services e binários suspeitos
- **Rede**: Lista conexões ativas para análise forense

### 📊 Relatórios Profissionais
```
📁 tanstack_audit/
├── report.txt   # Log legível em terminal
├── report.json  # Estruturado para integração (SIEM, APIs)
└── report.html  # Visual interativo (dark mode, responsivo)
```

---

## 🚀 Instalação

### Pré-requisitos
```bash
# Sistema
bash >= 4.0, grep, find, stat, sha256sum

# Opcionais (melhoram detecção)
ent          # Análise de entropia: sudo apt install ent
jq           # Processamento JSON: sudo apt install jq
parallel     # Processamento paralelo: sudo apt install parallel
xxd          # Inspeção de binários: sudo apt install xxd
```

### Clone e Execute
```bash
# Clonar repositório
git clone https://github.com/seu-usuario/tanstack-supply-chain-analyzer.git
cd tanstack-supply-chain-analyzer

# Tornar executável
chmod +x analyzer.sh

# Executar no diretório atual
./analyzer.sh
```

### 🐳 Docker (Opcional)
```dockerfile
# Dockerfile mínimo
FROM alpine:latest
RUN apk add --no-cache bash grep find coreutils ent jq parallel xxd
COPY analyzer.sh /usr/local/bin/analyzer
RUN chmod +x /usr/local/bin/analyzer
WORKDIR /audit
ENTRYPOINT ["analyzer"]
```

```bash
# Build e execução
docker build -t supply-chain-audit .
docker run -v $(pwd):/audit supply-chain-audit -d /audit
```

---

## 🎯 Uso Rápido

```bash
# 🔹 Auditoria básica no diretório atual
./analyzer.sh

# 🔹 Analisar projeto específico
./analyzer.sh -d /path/to/meu-projeto

# 🔹 Saída personalizada + modo silencioso (para CI)
./analyzer.sh -d ./app -o ./results -q

# 🔹 Modo verboso para debug
./analyzer.sh -v -d .

# 🔹 Ver ajuda completa
./analyzer.sh -h
```

### 🎨 Exemplo de Saída
```
════════════════════════════════════════
📦 ANÁLISE DE PACOTES
════════════════════════════════════════
[INFO] Analisando package.json
[WARN] Lifecycle hook encontrado: postinstall em package.json
[HIGH] Padrão suspeito 'child_process.execSync' encontrado em node_modules/xpkg/index.js:42

════════════════════════════════════════
🔐 VARIÁVEIS DE AMBIENTE & SECRETS
════════════════════════════════════════
[CRITICAL] Segredo potencial detectado: AKIAIOSFODNN7EXAMPLE... em config/prod.js:15

════════════════════════════════════════
📊 RESUMO
════════════════════════════════════════
Total de achados: 7
  🚨 Crítico: 1
  ⚠️  Alto:    2
  ⚡ Médio:   3
  ℹ️  Baixo:   1

[✓] Relatórios gerados:
  • Texto: ./tanstack_audit/report.txt
  • JSON : ./tanstack_audit/report.json
  • HTML : ./tanstack_audit/report.html
```

---

## ⚙️ Opções da CLI

| Opção | Parâmetro | Descrição | Padrão |
|-------|-----------|-----------|--------|
| `-d` | `DIR` | Diretório alvo para análise | `.` |
| `-o` | `DIR` | Diretório de saída dos relatórios | `./tanstack_audit` |
| `-q` | — | Modo silencioso (apenas erros) | `false` |
| `-v` | — | Modo verboso (logs de debug) | `false` |
| `-h` | — | Mostrar ajuda e sair | — |

### Variáveis de Ambiente (Configuração Avançada)
```bash
export MAX_FILE_SIZE=10485760    # Limite por arquivo: 10MB (padrão: 5MB)
export MAX_FILES=20000           # Máximo de arquivos a escanear (padrão: 10000)
export TIMEOUT_CMD=60            # Timeout por comando em segundos (padrão: 30)
export TARGET_DIR=/caminho/proj  # Alternativa à flag -d
export OUTPUT_DIR=/tmp/audit     # Alternativa à flag -o
```

---

## 📊 Saídas e Relatórios

### 📄 `report.txt` (Texto Puro)
```
[HIGH] child_process.execSync encontrado em node_modules/util/helper.js:12
[CRITICAL] Domínio malicioso detectado: filev2.getsession.org em config/loader.js
[INFO] 127 arquivos analisados em 4.2s
```

### 🗃️ `report.json` (Estruturado)
```json
{
  "analyzer": {
    "name": "TanStack Supply Chain Analyzer",
    "version": "2.0.0",
    "timestamp": "2024-06-15T14:30:00Z",
    "target": "./meu-projeto"
  },
  "summary": {
    "total_findings": 5,
    "by_severity": {
      "critical": 1,
      "high": 2,
      "medium": 1,
      "low": 1
    }
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "SECRET_LEAK",
      "message": "Segredo potencial detectado: AKIAIOSFODNN7EXAMPLE...",
      "file": "config/prod.js",
      "line": 15,
      "remediation": "Remova imediatamente e rotacione a credencial",
      "timestamp": "2024-06-15T14:30:05Z"
    }
  ]
}
```

### 🌐 `report.html` (Visual Interativo)
![Exemplo de relatório HTML](https://via.placeholder.com/800x400/0f0f1a/00d4aa?text=HTML+Report+Preview)  
*Interface dark mode, cards por severidade, responsivo para mobile*

---

## 🔧 Configuração Avançada

### 🔁 Atualizar Base de IOC
Edite os arrays no início do script ou crie um arquivo externo:

```bash
# ioc-custom.json
{
  "domains": ["novo-malware.com", "c2-server.net"],
  "patterns": ["novaRegexDeAtaque", "exfiltrationPattern"],
  "secrets": ["meu_regex_de_token_personalizado"]
}
```

```bash
# No script, após a declaração dos arrays:
if [[ -f "ioc-custom.json" ]]; then
  mapfile -t CUSTOM_DOMAINS < <(jq -r '.domains[]' ioc-custom.json)
  IOC_DOMAINS+=("${CUSTOM_DOMAINS[@]}")
fi
```

### 🎯 Ignorar Falsos Positivos
Crie um arquivo `.scanignore` no diretório alvo:
```bash
# .scanignore
node_modules/legit-package/obfuscated-but-safe.js
tests/fixtures/malware-sample.js
*.min.js
```

E adicione ao `find`:
```bash
find . -type f \( -name "*.js" \) ! -path "*/\$(cat .scanignore | tr '\n' '|' | sed 's/|$//')*"
```

### 🔗 Integração com Ferramentas Externas
```bash
# Adicionar npm audit
if command -v npm &>/dev/null; then
  npm audit --audit-level=high --json 2>/dev/null | \
  jq -r '.vulnerabilities | to_entries[] | select(.value.severity=="high" or .value.severity=="critical") | .key' | \
  while read pkg; do
    add_finding "HIGH" "NPM_AUDIT" "Vulnerabilidade crítica em: $pkg" "package-lock.json" "" "Execute 'npm audit fix' ou atualize a dependência"
  done
fi

# Snyk integration
if command -v snyk &>/dev/null; then
  snyk test --json --severity-threshold=high 2>/dev/null > "${OUTPUT_DIR}/snyk-report.json" || true
fi
```

---

## 🔄 Integração CI/CD

### GitHub Actions
```yaml
# .github/workflows/security-audit.yml
name: 🔍 Supply Chain Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with: { node-version: '20' }

      - name: Install dependencies
        run: npm ci

      - name: Run Supply Chain Analyzer
        run: |
          chmod +x ./analyzer.sh
          ./analyzer.sh -q -d . -o ./audit-results

      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-report
          path: ./audit-results/

      - name: Fail on Critical Findings
        run: |
          if jq -e '.summary.by_severity.critical > 0' ./audit-results/report.json >/dev/null; then
            echo "🚨 Achados críticos detectados!"
            exit 1
          fi
```

### GitLab CI
```yaml
# .gitlab-ci.yml
supply_chain_audit:
  stage: security
  image: alpine:latest
  before_script:
    - apk add --no-cache bash grep find coreutils ent jq
    - chmod +x ./analyzer.sh
  script:
    - ./analyzer.sh -q -d . -o ./audit
  artifacts:
    paths: [audit/]
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Códigos de Saída para Automação
| Código | Significado | Uso em CI |
|--------|-------------|-----------|
| `0` | ✅ Sem achados críticos/altos | Pipeline continua |
| `1` | 🚨 Achados de alta severidade | Pipeline falha (revisão necessária) |
| `2` | ❌ Erro na execução do script | Pipeline falha (investigar infraestrutura) |

---

## 🧪 Exemplos Práticos

### 🔍 Auditoria Pré-Publicação de Pacote NPM
```bash
# Antes de npm publish
./analyzer.sh -d ./meu-pacote -o ./pre-publish-audit

# Verificar se há segredos ou IOC
if grep -q "\[CRITICAL\]\|\[HIGH\]" ./pre-publish-audit/report.txt; then
  echo "🚫 Bloqueando publicação: achados críticos!"
  exit 1
fi

npm publish
```

### 🕵️ Investigação de Pacote Suspeito
```bash
# Baixar e analisar pacote sem instalar
npm pack @algum/pacote-suspeito --pack-destination /tmp
tar -xzf /tmp/algum-pacote-suspeito-*.tgz -C /tmp
./analyzer.sh -d /tmp/package -v
```

### 📦 Auditoria em Massa de Múltiplos Projetos
```bash
#!/bin/bash
# audit-all.sh
for proj in /repos/*; do
  [[ -d "$proj" ]] || continue
  echo "🔍 Auditando: $proj"
  ./analyzer.sh -d "$proj" -o "/audit-results/$(basename "$proj")" -q
done

# Consolidar resultados
jq -s '{total_findings: (map(.summary.total_findings) | add), projects: .}' /audit-results/*/report.json > /audit-results/consolidated.json
```

---

## ⚠️ Limitações & Falsos Positivos

### 🎯 O que o scanner **NÃO** detecta
- Vulnerabilidades lógicas de negócio
- Ataques de dia-zero em dependências
- Código malicioso carregado dinamicamente via rede
- Ofuscação avançada com AST manipulation

### 🔍 Reduzindo Falsos Positivos
```bash
# 1. Use .scanignore para excluir arquivos conhecidos como seguros
echo "vendor/bundle/**/*.js" >> .scanignore

# 2. Ajuste thresholds de entropia conforme seu código-base
# (edite a função entropy_check no script)

# 3. Revise achados "LOW" em lote antes de priorizar
jq '.findings[] | select(.severity=="LOW")' report.json | less

# 4. Mantenha a base de IOC atualizada
# Domínios e padrões evoluem rapidamente
```

### 🧪 Validação Manual Recomendada
Sempre valide manualmente achados **CRITICAL** e **HIGH**:
```bash
# Exemplo: verificar contexto de um child_process
grep -B5 -A5 "execSync" node_modules/pacote/index.js

# Verificar se segredo é fake/mock
grep -r "EXAMPLE\|fake\|dummy\|placeholder" .
```

---

## 🤝 Contribuindo

Contribuições são bem-vindas! 🎉

### 🐞 Reportando Bugs
1. Verifique se o issue já não foi reportado
2. Inclua: versão do script, sistema operacional, comando executado e output completo
3. Se possível, anexe um `report.json` sanitizado

### 💡 Sugestões de Melhoria
- Novos padrões de IOC ou domínios maliciosos
- Suporte a novos lockfiles (bun.lockb, etc.)
- Integração com ferramentas de segurança (Trivy, Grype, etc.)
- Melhorias na UI do relatório HTML

### 🔄 Pull Requests
```bash
# Fork e clone
git clone https://github.com/mvdiogo/tanstack_detection.git
cd tanstack_detection

# Crie branch para sua feature
git checkout -b feature/nova-deteccao

# Faça suas alterações e teste
./analyzer.sh -v -d ./test-project

# Commit e push
git commit -m "feat: adiciona detecção de novo padrão X"
git push origin feature/nova-deteccao
```

### 👥 Mantenedores
- [@mvdiogo](https://github.com/mvdiogo)

---

## 📜 Licença

Distribuído sob a licença **MIT**. Veja [`LICENSE`](LICENSE) para mais informações.

```
MIT License

Copyright (c) 2024 TanStack Supply Chain Analyzer Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🔐 Aviso de Segurança

> ⚠️ **Esta ferramenta é para uso educacional e de auditoria autorizada.**  
> 
> - Execute apenas em repositórios que você possui ou tem permissão explícita para auditar  
> - Não utilize para atacar, explorar ou comprometer sistemas de terceiros  
> - Achados devem ser tratados com confidencialidade e reportados responsavelmente  
> - O autor não se responsabiliza por uso indevido ou danos decorrentes da utilização desta ferramenta  
> 
> 🎓 *Use com responsabilidade. Segurança é um processo, não um produto.*

---

## 🙏 Agradecimentos

- Comunidade [TanStack](https://tanstack.com/) pelas ferramentas incríveis
- Pesquisadores de segurança que mantêm bases de IOC públicas

