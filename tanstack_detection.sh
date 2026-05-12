#!/usr/bin/env bash
###############################################################################
# Advanced TanStack / Mini Shai-Hulud Supply Chain Analyzer v2.0
# 
# Auditoria de segurança para supply chain de pacotes Node.js/TanStack
# Recursos: IOC scanner, análise de dependências, detecção de ofuscação,
#           verificação de segredos, análise de CI/CD, relatório estruturado
#
# Uso: ./analyzer.sh [-d DIR] [-o OUTPUT_DIR] [-q] [-v] [-h]
###############################################################################

set -Eeuo pipefail
shopt -s nullglob globstar

############################
# CONFIGURAÇÃO & PARÂMETROS
############################

readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"

# Defaults
TARGET_DIR="${TARGET_DIR:-.}"
OUTPUT_DIR="${OUTPUT_DIR:-./tanstack_audit}"
VERBOSE=0
QUIET=0
MAX_FILE_SIZE=5242880  # 5MB
MAX_FILES=10000
TIMEOUT_CMD=30

# Parse arguments
while getopts "d:o:qvh" opt; do
    case "$opt" in
        d) TARGET_DIR="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        q) QUIET=1 ;;
        v) VERBOSE=1 ;;
        h) 
            cat << EOF
Uso: $SCRIPT_NAME [OPÇÕES]

Opções:
  -d DIR      Diretório alvo para análise (padrão: .)
  -o DIR      Diretório de saída dos relatórios (padrão: ./tanstack_audit)
  -q          Modo silencioso (apenas erros)
  -v          Modo verboso (detalhes extras)
  -h          Mostrar esta ajuda

Saída:
  report.txt  - Relatório em texto puro
  report.json - Relatório estruturado em JSON
  report.html - Relatório visual em HTML

Códigos de saída:
  0 - Sem achados críticos
  1 - Achados de alta severidade
  2 - Erro na execução
EOF
            exit 0
            ;;
        *) exit 2 ;;
    esac
done

# Paths de saída
mkdir -p "${OUTPUT_DIR}"
readonly TEXT_REPORT="${OUTPUT_DIR}/report.txt"
readonly JSON_REPORT="${OUTPUT_DIR}/report.json"
readonly HTML_REPORT="${OUTPUT_DIR}/report.html"
readonly JSON_TMP="${OUTPUT_DIR}/.findings.json"

# Inicializa JSON de achados
echo '[]' > "$JSON_TMP"

############################
# CORES & FORMATAÇÃO
############################

readonly RED="\033[1;31m"
readonly GREEN="\033[1;32m"
readonly YELLOW="\033[1;33m"
readonly BLUE="\033[1;34m"
readonly CYAN="\033[1;36m"
readonly MAGENTA="\033[1;35m"
readonly NC="\033[0m"
readonly BOLD="\033[1m"

log() { [[ $QUIET -eq 0 ]] && echo -e "$1" | tee -a "$TEXT_REPORT"; }
log_raw() { echo -e "$1" >> "$TEXT_REPORT"; }
debug() { [[ $VERBOSE -eq 1 ]] && log "${MAGENTA}[DEBUG]${NC} $1" || true; }

section() {
    echo "" | tee -a "$TEXT_REPORT"
    log "${CYAN}════════════════════════════════════════${NC}"
    log "${CYAN}${BOLD}$1${NC}"
    log "${CYAN}════════════════════════════════════════${NC}"
}

############################
# CONTADORES & SEVERIDADE
############################

declare -A SEVERITY_COUNT=( [LOW]=0 [MEDIUM]=0 [HIGH]=0 [CRITICAL]=0 )
declare -a FINDINGS=()

add_finding() {
    local severity="$1"
    local category="$2"
    local message="$3"
    local file="${4:-}"
    local line="${5:-}"
    local remediation="${6:-}"
    
    SEVERITY_COUNT[$severity]=$((SEVERITY_COUNT[$severity] + 1))
    
    local finding=$(cat <<EOF
{
  "severity": "$severity",
  "category": "$category",
  "message": "$(echo "$message" | jq -Rs .)",
  "file": "$(echo "$file" | jq -Rs .)",
  "line": $line,
  "remediation": "$(echo "$remediation" | jq -Rs .)",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    FINDINGS+=("$finding")
    
    case "$severity" in
        CRITICAL|HIGH) alert_high "$message" ;;
        MEDIUM) alert_warn "$message" ;;
        LOW) alert_info "$message" ;;
    esac
}

alert_high()     { log "${RED}[${BOLD}HIGH${NC}${RED}]${NC} $1"; }
alert_warn()     { log "${YELLOW}[WARN]${NC} $1"; }
alert_info()     { log "${BLUE}[INFO]${NC} $1"; }
alert_critical() { log "${RED}[${BOLD}CRITICAL${NC}${RED}]${NC} $1"; }

############################
# BASE DE CONHECIMENTO - IOC
############################

# Domínios maliciosos conhecidos (atualizável via arquivo externo)
readonly -a IOC_DOMAINS=(
    "getsession.org" "filev2.getsession.org" "seed*.getsession.org"
    "pastebin.com/raw/[a-zA-Z0-9]+" "raw.githubusercontent.com/.*/.*/main/.*\.sh"
    "ipinfo.io/ip" "api.ipify.org" "discord.com/api/webhooks"
    "telemetry.*\.js" "analytics-tracker"
)

# Padrões de código suspeito (regex)
readonly -a IOC_PATTERNS=(
    # Execução de código/comandos
    'child_process\.(exec|execSync|spawn|spawnSync|fork)'
    'eval\s*\(' 'Function\s*\(' 'setTimeout\s*\(\s*["\x27][^"\x27]*eval'
    'new\s+Function\s*\(' 'vm\.runInContext'
    
    # Exfiltração de dados
    'curl\s+.*-d\s*@' 'wget\s+.*--post-file' 'fetch\s*\([^)]*method\s*:\s*["\x27]POST'
    'XMLHttpRequest.*\.send.*process\.env'
    
    # Ofuscação/encoding
    'Buffer\.from\s*\([^)]+\)\.toString\s*\(\s*["\x27]base64["\x27]\s*\)'
    'atob\s*\(' 'btoa\s*\(' 'String\.fromCharCode\s*\('
    '\$[a-zA-Z0-9_]{20,}'  # Variáveis ofuscadas
    
    # Acesso a segredos
    'process\.env\.[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)'
    'require\s*\(\s*["\x27]fs["\x27]\s*\).*readFileSync.*\.ssh'
    
    # Persistência/evassão
    'crontab\s+-l' 'systemd.*service' 'launchd.*plist'
    'nohup\s+' 'setsid\s+' 'disown\s+'
)

# Hooks de lifecycle perigosos
readonly -a DANGEROUS_HOOKS=(
    "preinstall" "install" "postinstall" "prepare" "prepublish" "prepublishOnly"
)

# Padrões de segredos (regex para detecção)
readonly -a SECRET_PATTERNS=(
    'AKIA[0-9A-Z]{16}'                      # AWS Access Key
    'gh[pousr]_[A-Za-z0-9_]{36,}'           # GitHub Token
    'npm_[A-Za-z0-9]{36}'                   # NPM Token
    'sg\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}' # SendGrid
    '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    'AIza[0-9A-Za-z\-_]{35}'                # Google API Key
    'sk_live_[0-9a-zA-Z]{24,}'              # Stripe
    'glpat-[0-9a-zA-Z\-]{20}'               # GitLab Token
)

############################
# UTILITÁRIOS
############################

# Hash seguro de arquivo
hash_file() {
    local file="$1"
    if [[ -f "$file" && -r "$file" ]]; then
        sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "ERROR"
    else
        echo "UNREADABLE"
    fi
}

# Verifica se arquivo é binário
is_binary() {
    local file="$1"
    file -b --mime-type "$file" 2>/dev/null | grep -qvE '^text/|^application/(json|javascript|x-javascript)$'
}

# Limita tamanho de arquivo para análise
is_file_safe_to_scan() {
    local file="$1"
    [[ -f "$file" && -r "$file" ]] || return 1
    local size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    [[ $size -le $MAX_FILE_SIZE ]]
}

# Entropia de Shannon (implementação pura em bash para portabilidade)
entropy_check() {
    local file="$1"
    is_binary "$file" && return 0
    is_file_safe_to_scan "$file" || return 0
    
    # Usa 'ent' se disponível, fallback para estimativa simples
    if command -v ent &>/dev/null; then
        local entropy
        entropy=$(timeout 5 ent "$file" 2>/dev/null | grep "Entropy" | awk '{print $3}')
        if [[ -n "$entropy" ]]; then
            if awk "BEGIN {exit !($entropy > 7.5)}"; then
                add_finding "MEDIUM" "OBFUSCATION" "Alta entropia detectada (possível ofuscação): $entropy" "$file" "" "Revise o conteúdo do arquivo para código ofuscado ou dados embarcados"
            fi
        fi
    else
        # Fallback: conta diversidade de bytes como proxy de entropia
        local unique_bytes
        unique_bytes=$(timeout 2 cat "$file" 2>/dev/null | fold -w1 | sort -u | wc -l)
        local total_bytes
        total_bytes=$(timeout 2 wc -c < "$file" 2>/dev/null || echo 0)
        if [[ $total_bytes -gt 1000 ]]; then
            local ratio=$((unique_bytes * 100 / total_bytes))
            if [[ $ratio -gt 85 ]]; then
                add_finding "LOW" "OBFUSCATION" "Alta diversidade de bytes em $file (possível ofuscação)" "$file" "" "Verifique se o arquivo contém dados codificados ou ofuscados"
            fi
        fi
    fi
}

# Busca padrões em arquivo com tratamento seguro
search_in_file() {
    local file="$1"
    local patterns_ref="$2"
    local -n patterns_arr="$patterns_ref"
    
    is_file_safe_to_scan "$file" || return 0
    is_binary "$file" && return 0
    
    for pattern in "${patterns_arr[@]}"; do
        # Usa grep com -P para PCRE quando disponível, fallback para -E
        if grep -qP "$pattern" "$file" 2>/dev/null || grep -qE "$pattern" "$file" 2>/dev/null; then
            local context
            context=$(grep -nE "$pattern" "$file" 2>/dev/null | head -1 | cut -d: -f1,2)
            local line_num="${context%%:*}"
            add_finding "HIGH" "IOC_PATTERN" "Padrão suspeito '$pattern' encontrado" "$file" "${line_num:-?}" "Revise esta ocorrência para confirmar se é maliciosa ou falso positivo"
        fi
    done
}

# Busca domínios IOC
search_domains() {
    local file="$1"
    is_file_safe_to_scan "$file" || return 0
    is_binary "$file" && return 0
    
    for domain in "${IOC_DOMAINS[@]}"; do
        if grep -qiE "$domain" "$file" 2>/dev/null; then
            add_finding "CRITICAL" "IOC_DOMAIN" "Domínio malicioso conhecido detectado: $domain" "$file" "" "Bloqueie este domínio e investigue a origem da requisição"
        fi
    done
}

############################
# MÓDULOS DE ANÁLISE
############################

analyze_packages() {
    section "📦 ANÁLISE DE PACOTES"
    
    local pkg_files=("package.json" "package-lock.json" "pnpm-lock.yaml" "yarn.lock")
    local found=0
    
    for file in "${pkg_files[@]}"; do
        [[ -f "${TARGET_DIR}/${file}" ]] || continue
        found=1
        local filepath="${TARGET_DIR}/${file}"
        debug "Analisando: $filepath"
        
        # Verifica lifecycle hooks perigosos
        for hook in "${DANGEROUS_HOOKS[@]}"; do
            if grep -q "\"$hook\"" "$filepath" 2>/dev/null; then
                add_finding "MEDIUM" "LIFECYCLE_HOOK" "Lifecycle hook potencialmente perigoso: $hook" "$filepath" "" "Revise os scripts deste hook para comandos suspeitos"
            fi
        done
        
        # Verifica dependências @tanstack
        if grep -qi "@tanstack" "$filepath" 2>/dev/null; then
            add_finding "LOW" "DEPENDENCY" "Pacote @tanstack detectado - verifique versões e integridade" "$filepath" "" "Use npm audit ou snyk para verificar vulnerabilidades conhecidas"
        fi
        
        # Busca padrões IOC
        search_in_file "$filepath" IOC_PATTERNS
        search_domains "$filepath"
        
        # Verifica versionamento inseguro
        if [[ "$file" == "package.json" ]]; then
            if grep -qE '"[^"]+"\s*:\s*"[^~^0-9]' "$filepath" 2>/dev/null; then
                add_finding "LOW" "VERSION_PINNING" "Dependência sem pinning de versão adequado" "$filepath" "" "Use ^ ou ~ para versionamento semântico seguro"
            fi
        fi
    done
    
    [[ $found -eq 0 ]] && alert_info "Nenhum arquivo de pacote encontrado em ${TARGET_DIR}"
}

analyze_node_modules() {
    section "🗂️ ANÁLISE DE node_modules"
    
    local nm_dir="${TARGET_DIR}/node_modules"
    [[ -d "$nm_dir" ]] || { alert_info "node_modules não encontrado"; return; }
    
    local count=0
    local -a js_files=()
    
    # Coleta arquivos JS com limite
    while IFS= read -r -d '' file; do
        js_files+=("$file")
        count=$((count + 1))
        [[ $count -ge $MAX_FILES ]] && break
    done < <(find "$nm_dir" -type f \( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" \) -print0 2>/dev/null)
    
    alert_info "Analisando ${#js_files[@]} arquivos JavaScript (limite: $MAX_FILES)"
    
    # Processa em paralelo se possível
    if command -v parallel &>/dev/null && [[ ${#js_files[@]} -gt 50 ]]; then
        printf '%s\n' "${js_files[@]}" | parallel -j4 -q bash -c '
            source "'"$0"'"
            search_in_file "{}" IOC_PATTERNS
            search_domains "{}"
            entropy_check "{}"
        ' 2>/dev/null || true
    else
        for file in "${js_files[@]}"; do
            search_in_file "$file" IOC_PATTERNS
            search_domains "$file"
            entropy_check "$file"
            
            # Detecção específica para child_process
            if grep -qE 'child_process\.(exec|spawn)' "$file" 2>/dev/null; then
                local hash
                hash=$(hash_file "$file")
                add_finding "HIGH" "DANGEROUS_API" "Uso de child_process com hash: ${hash:0:16}..." "$file" "" "Valide se a execução de comandos é necessária e segura"
            fi
        done
    fi
}

analyze_github_actions() {
    section "🔄 ANÁLISE DE GITHUB ACTIONS"
    
    local workflows_dir="${TARGET_DIR}/.github/workflows"
    [[ -d "$workflows_dir" ]] || { debug "Sem diretório .github/workflows"; return; }
    
    # Padrões de risco em workflows
    local -a workflow_patterns=(
        'pull_request_target'
        'workflow_run'
        'ACTIONS_RUNTIME_TOKEN'
        'npm publish'
        'permissions:\s*write-all'
        'checkout.*fetch-depth:\s*0'
    )
    
    for wf in "$workflows_dir"/*.yml "$workflows_dir"/*.yaml; do
        [[ -f "$wf" ]] || continue
        debug "Analisando workflow: $wf"
        
        for pattern in "${workflow_patterns[@]}"; do
            if grep -qE "$pattern" "$wf" 2>/dev/null; then
                add_finding "MEDIUM" "CI_RISK" "Padrão de risco em CI/CD: $pattern" "$wf" "" "Revise as permissões e gatilhos deste workflow"
            fi
        done
        
        # Verifica segredos expostos no workflow
        if grep -qE '\$\{\{.*secret.*\}\}' "$wf" 2>/dev/null; then
            add_finding "LOW" "SECRET_USAGE" "Uso de secrets detectado - valide a segurança" "$wf" "" "Certifique-se que secrets não são vazados em logs"
        fi
    done
}

analyze_environment() {
    section "🔐 VARIÁVEIS DE AMBIENTE & SECRETS"
    
    # Verifica segredos no código-fonte
    local found_secrets=0
    for pattern in "${SECRET_PATTERNS[@]}"; do
        while IFS=: read -r file line content; do
            [[ -z "$file" ]] && continue
            # Ignora arquivos de exemplo/configuração legítimos
            [[ "$file" =~ \.(example|template|dist|lock)$ ]] && continue
            add_finding "CRITICAL" "SECRET_LEAK" "Segredo potencial detectado: ${content:0:50}..." "$file" "$line" "Remova imediatamente e rotacione a credencial"
            found_secrets=1
        done < <(grep -rnE --include=\*.{js,ts,json,yaml,yml,env,sh} "$pattern" "${TARGET_DIR}" 2>/dev/null | head -20)
    done
    
    [[ $found_secrets -eq 0 ]] && alert_info "Nenhum segredo óbvio detectado no código"
    
    # Verifica .env e arquivos de configuração
    for envfile in ".env" ".env.local" ".npmrc" ".yarnrc" ".pypirc"; do
        [[ -f "${TARGET_DIR}/${envfile}" ]] || continue
        if grep -qE '(password|secret|token|key)\s*=' "${TARGET_DIR}/${envfile}" 2>/dev/null; then
            add_finding "HIGH" "CONFIG_SECRET" "Arquivo de configuração pode conter segredos: $envfile" "${TARGET_DIR}/${envfile}" "" "Use variáveis de ambiente ou vault para segredos"
        fi
    done
}

analyze_network_persistence() {
    section "🌐 CONEXÕES & PERSISTÊNCIA"
    
    # Verifica cron jobs (apenas se executando como usuário com permissão)
    if command -v crontab &>/dev/null; then
        local cron_content
        cron_content=$(crontab -l 2>/dev/null || true)
        if [[ -n "$cron_content" ]]; then
            if echo "$cron_content" | grep -qiE 'curl|wget|bash|node|npm|/tmp'; then
                add_finding "HIGH" "PERSISTENCE" "Cron job suspeito detectado" "crontab" "" "Revise tarefas agendadas para comandos maliciosos"
            fi
        fi
    fi
    
    # Verifica systemd/user services
    if [[ -d ~/.config/systemd/user ]] 2>/dev/null; then
        find ~/.config/systemd/user -name "*.service" -type f 2>/dev/null | while read -r svc; do
            if grep -qiE 'ExecStart=.*(curl|wget|bash|/tmp)' "$svc" 2>/dev/null; then
                add_finding "HIGH" "PERSISTENCE" "Serviço systemd suspeito: $svc" "$svc" ""
            fi
        done
    fi
    
    # Conexões de rede ativas (informacional)
    if command -v ss &>/dev/null; then
        debug "Coletando conexões de rede..."
        ss -plant 2>/dev/null | grep -E 'ESTAB|LISTEN' | head -20 | tee -a "$TEXT_REPORT" || true
    fi
}

analyze_ssh_keys() {
    section "🔑 ANÁLISE DE CHAVES SSH"
    
    local ssh_dir="${HOME}/.ssh"
    [[ -d "$ssh_dir" ]] || { debug "Sem diretório ~/.ssh"; return; }
    
    find "$ssh_dir" -type f 2>/dev/null | while read -r keyfile; do
        # Verifica permissões
        local perms
        perms=$(stat -c %a "$keyfile" 2>/dev/null || stat -f %Lp "$keyfile" 2>/dev/null)
        if [[ "$keyfile" == *.pub ]]; then
            [[ "$perms" != "644" ]] && add_finding "LOW" "SSH_PERM" "Permissão não ideal para chave pública: $perms" "$keyfile" "" "Use 644 para chaves públicas"
        else
            [[ "$perms" != "600" ]] && add_finding "MEDIUM" "SSH_PERM" "Permissão insegura para chave privada: $perms" "$keyfile" "" "Use 600 para chaves privadas"
        fi
        
        # Verifica se chave privada está no repositório
        if [[ "$keyfile" != *.pub && ! "$keyfile" =~ \.pub$ ]]; then
            if git -C "$TARGET_DIR" check-ignore "$keyfile" &>/dev/null; then
                add_finding "CRITICAL" "SSH_EXPOSURE" "Chave privada pode estar versionada: $keyfile" "$keyfile" "" "Adicione ao .gitignore imediatamente e rotacione a chave"
            fi
        fi
    done
}

analyze_binaries() {
    section "⚙️ BINÁRIOS SUSPEITOS"
    
    # Encontra executáveis com permissão de escrita suspeita
    find "${TARGET_DIR}" -type f -perm -111 ! -path "*/node_modules/.bin/*" ! -name "*.sh" 2>/dev/null | while read -r bin; do
        # Verifica se é ELF/Mach-O/PE
        local magic
        magic=$(head -c 4 "$bin" 2>/dev/null | xxd -p || echo "")
        case "$magic" in
            7f454c46) add_finding "MEDIUM" "BINARY" "Binário ELF detectado: $bin" "$bin" "" "Valide a origem deste executável" ;;
            cfeedfac|cffaedfe) add_finding "MEDIUM" "BINARY" "Binário Mach-O detectado: $bin" "$bin" "" ;;
            4d5a9000) add_finding "HIGH" "BINARY" "Binário PE (Windows) em ambiente Unix: $bin" "$bin" "" ;;
        esac
    done
}

############################
# RELATÓRIOS
############################

generate_json_report() {
    debug "Gerando relatório JSON..."
    
    local findings_json
    findings_json=$(printf '%s\n' "${FINDINGS[@]}" | jq -s '.' 2>/dev/null || echo '[]')
    
    cat > "$JSON_REPORT" <<EOF
{
  "analyzer": {
    "name": "TanStack Supply Chain Analyzer",
    "version": "${VERSION}",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "target": "${TARGET_DIR}",
    "config": {
      "max_file_size": ${MAX_FILE_SIZE},
      "max_files": ${MAX_FILES},
      "timeout": ${TIMEOUT_CMD}
    }
  },
  "summary": {
    "total_findings": ${#FINDINGS[@]},
    "by_severity": {
      "critical": ${SEVERITY_COUNT[CRITICAL]},
      "high": ${SEVERITY_COUNT[HIGH]},
      "medium": ${SEVERITY_COUNT[MEDIUM]},
      "low": ${SEVERITY_COUNT[LOW]}
    }
  },
  "findings": ${findings_json}
}
EOF
}

generate_html_report() {
    debug "Gerando relatório HTML..."
    
    # Calcula cor de status
    local status_color="green"
    local status_text="✅ Limpo"
    if [[ ${SEVERITY_COUNT[CRITICAL]} -gt 0 ]]; then
        status_color="red"; status_text="🚨 Crítico"
    elif [[ ${SEVERITY_COUNT[HIGH]} -gt 0 ]]; then
        status_color="orange"; status_text="⚠️ Alto Risco"
    elif [[ ${#FINDINGS[@]} -gt 0 ]]; then
        status_color="yellow"; status_text="⚡ Atenção"
    fi
    
    cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🔍 Supply Chain Audit Report</title>
  <style>
    :root { --bg: #0f0f1a; --card: #1a1a2e; --text: #e0e0ff; --accent: #00d4aa; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; margin: 0; padding: 20px; }
    .header { text-align: center; padding: 20px; border-bottom: 2px solid var(--accent); margin-bottom: 20px; }
    .status { font-size: 1.5em; font-weight: bold; color: ${status_color}; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 20px 0; }
    .card { background: var(--card); padding: 15px; border-radius: 8px; text-align: center; }
    .card.critical { border-left: 4px solid #ff4444; }
    .card.high { border-left: 4px solid #ff8800; }
    .card.medium { border-left: 4px solid #ffbb00; }
    .card.low { border-left: 4px solid #00d4aa; }
    .finding { background: var(--card); margin: 10px 0; padding: 15px; border-radius: 6px; border-left: 4px solid #555; }
    .finding.critical { border-left-color: #ff4444; }
    .finding.high { border-left-color: #ff8800; }
    .finding.medium { border-left-color: #ffbb00; }
    .finding.low { border-left-color: #00d4aa; }
    .meta { font-size: 0.85em; color: #888; margin-top: 8px; }
    .remediation { background: rgba(0,212,170,0.1); padding: 8px; border-radius: 4px; margin-top: 8px; font-size: 0.9em; }
    pre { background: #0a0a14; padding: 10px; border-radius: 4px; overflow-x: auto; }
    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.9em; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔍 TanStack Supply Chain Audit</h1>
    <p>Alvo: <code>${TARGET_DIR}</code> | Data: $(date '+%Y-%m-%d %H:%M')</p>
    <div class="status">${status_text}</div>
  </div>
  
  <div class="summary">
    <div class="card critical"><h3>🚨 Crítico</h3><p>${SEVERITY_COUNT[CRITICAL]}</p></div>
    <div class="card high"><h3>⚠️ Alto</h3><p>${SEVERITY_COUNT[HIGH]}</p></div>
    <div class="card medium"><h3>⚡ Médio</h3><p>${SEVERITY_COUNT[MEDIUM]}</p></div>
    <div class="card low"><h3>ℹ️ Baixo</h3><p>${SEVERITY_COUNT[LOW]}</p></div>
  </div>
  
  <h2>📋 Achados Detalhados</h2>
EOF

    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        echo '  <p style="text-align:center; padding:20px;">✨ Nenhum achado de segurança detectado!</p>' >> "$HTML_REPORT"
    else
        for finding in "${FINDINGS[@]}"; do
            local sev msg file line rem
            sev=$(echo "$finding" | jq -r '.severity')
            msg=$(echo "$finding" | jq -r '.message')
            file=$(echo "$finding" | jq -r '.file // "N/A"')
            line=$(echo "$finding" | jq -r '.line // "?"')
            rem=$(echo "$finding" | jq -r '.remediation // ""')
            
            cat >> "$HTML_REPORT" <<EOF
  <div class="finding ${sev,,}">
    <strong>[${sev^^}]</strong> ${msg}<br>
    <div class="meta">📁 ${file}:${line}</div>
    ${rem:+<div class="remediation">💡 $rem</div>}
  </div>
EOF
        done
    fi
    
    cat >> "$HTML_REPORT" <<EOF
  
  <div class="footer">
    <p>Gerado por <strong>TanStack Supply Chain Analyzer v${VERSION}</strong></p>
    <p>⚠️ Este relatório é informativo. Valide manualmente os achados antes de tomar ações.</p>
  </div>
</body>
</html>
EOF
}

############################
# EXECUÇÃO PRINCIPAL
############################

main() {
    echo "" > "$TEXT_REPORT"
    
    section "🚀 INICIANDO ANÁLISE v${VERSION}"
    log "${GREEN}[INFO]${NC} Alvo: ${BOLD}${TARGET_DIR}${NC}"
    log "${GREEN}[INFO]${NC} Saída: ${BOLD}${OUTPUT_DIR}${NC}"
    log "${GREEN}[INFO]${NC} Config: max_file=${MAX_FILE_SIZE}B, max_files=${MAX_FILES}, timeout=${TIMEOUT_CMD}s"
    
    # Valida diretório alvo
    [[ -d "$TARGET_DIR" ]] || { log "${RED}[ERRO]${NC} Diretório inválido: $TARGET_DIR"; exit 2; }
    
    # Executa módulos de análise
    analyze_packages
    analyze_node_modules
    analyze_github_actions
    analyze_environment
    analyze_network_persistence
    analyze_ssh_keys
    analyze_binaries
    
    # Gera relatórios
    generate_json_report
    generate_html_report
    
    # Resumo final
    section "📊 RESUMO"
    log "Total de achados: ${BOLD}${#FINDINGS[@]}${NC}"
    log "  🚨 Crítico: ${RED}${SEVERITY_COUNT[CRITICAL]}${NC}"
    log "  ⚠️  Alto:    ${RED}${SEVERITY_COUNT[HIGH]}${NC}"
    log "  ⚡ Médio:   ${YELLOW}${SEVERITY_COUNT[MEDIUM]}${NC}"
    log "  ℹ️  Baixo:   ${BLUE}${SEVERITY_COUNT[LOW]}${NC}"
    
    log ""
    log "${GREEN}[✓]${NC} Relatórios gerados:"
    log "  • Texto: ${TEXT_REPORT}"
    log "  • JSON : ${JSON_REPORT}"
    log "  • HTML : ${HTML_REPORT}"
    
    # Código de saída para CI/CD
    if [[ ${SEVERITY_COUNT[CRITICAL]} -gt 0 || ${SEVERITY_COUNT[HIGH]} -gt 0 ]]; then
        log ""
        log "${RED}[!]${NC} Achados críticos/altos detectados - revise antes de prosseguir!"
        rm -f "$JSON_TMP"
        exit 1
    fi
    
    rm -f "$JSON_TMP"
    exit 0
}

# Trap para limpeza em caso de erro
cleanup() {
    rm -f "$JSON_TMP" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Executa
main "$@"
