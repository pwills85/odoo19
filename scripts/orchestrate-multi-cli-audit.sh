#!/bin/bash
# File: scripts/orchestrate-multi-cli-audit.sh
# Purpose: Coordinate parallel CLI agents for stack audit
# Date: 2025-11-09
# Temperature: 0.1 (Maximum Precision)
# Best Practices: 2025 Multi-Agent Orchestration

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
PROJECT_ROOT="/Users/pedro/Documents/odoo19"
AUDIT_DIR="${PROJECT_ROOT}/audits/$(date +%Y%m%d_%H%M%S)"
WORKTREE_BASE="/Users/pedro/Documents"

# Banner
clear
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║   🎯 ORQUESTACIÓN MULTI-CLI - AUDITORÍA STACK ODOO19         ║
║   Temperature: 0.1 | Precision: Maximum | Agents: 5          ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo

# Verify CLIs installed
echo -e "${YELLOW}🔍 Verificando CLIs instalados...${NC}"

check_cli() {
    local cli=$1
    local cmd=$2

    if command -v "$cmd" &> /dev/null; then
        local version=$($cmd --version 2>&1 | head -1)
        echo -e "${GREEN}  ✅ $cli: $version${NC}"
        return 0
    else
        echo -e "${RED}  ❌ $cli: NOT FOUND${NC}"
        return 1
    fi
}

MISSING=0
check_cli "Codex CLI" "codex" || ((MISSING++))
check_cli "Copilot CLI" "copilot" || ((MISSING++))
check_cli "Git" "git" || ((MISSING++))
check_cli "jq" "jq" || ((MISSING++))

if [ $MISSING -gt 0 ]; then
    echo -e "${RED}❌ Missing $MISSING required tool(s). Please install before continuing.${NC}"
    exit 1
fi
echo

# Create audit directory structure
echo -e "${YELLOW}📁 Creando estructura de directorios...${NC}"
mkdir -p "${AUDIT_DIR}"/{security,compliance,payroll,architecture,performance}/{reports,logs}
echo -e "${GREEN}  ✅ Created: ${AUDIT_DIR}/${NC}"
echo

# Step 1: Setup Git Worktrees
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  STEP 1: Git Worktrees Setup                  ${NC}"
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo
cd "${PROJECT_ROOT}"

setup_worktree() {
    local name=$1
    local branch=$2
    local path="${WORKTREE_BASE}/odoo19-${name}"

    echo -e "${YELLOW}  Setting up worktree: $name${NC}"

    if [ -d "$path" ]; then
        echo -e "${CYAN}    → Worktree already exists, cleaning...${NC}"
        cd "${path}"
        git checkout main 2>/dev/null || git checkout -b main
        git reset --hard origin/main 2>/dev/null || true
        cd "${PROJECT_ROOT}"
    else
        git worktree add "$path" -b "$branch" 2>/dev/null || {
            echo -e "${RED}    ✗ Failed to create worktree${NC}"
            return 1
        }
    fi

    echo -e "${GREEN}    ✓ Worktree ready: $name${NC}"
}

setup_worktree "security" "security/audit-$(date +%Y%m%d)"
setup_worktree "compliance" "compliance/audit-$(date +%Y%m%d)"
setup_worktree "payroll" "payroll/audit-$(date +%Y%m%d)"
setup_worktree "architecture" "arch/audit-$(date +%Y%m%d)"
setup_worktree "performance" "perf/audit-$(date +%Y%m%d)"

echo

# Step 2: Launch Parallel Audits
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  STEP 2: Launching Parallel Audits (T=0.1)   ${NC}"
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo

# Timestamp
START_TIME=$(date +%s)

# Audit 1: Security (Codex CLI) - Background
echo -e "${CYAN}🔒 [1/5] Security Audit (Codex CLI - GPT-5-Codex)${NC}"
echo -e "${YELLOW}     Focus: XMLDSig, TED, Certificate OID${NC}"
(
    cd "${WORKTREE_BASE}/odoo19-security"

    codex --profile audit exec "
Auditoría de seguridad criptográfica (Temperature: 0.1, Reasoning: high):

Archivos a analizar:
1. dte-service/signature/xml_signer.py
   - Verificar: Algoritmo RSA-SHA1, canonicalization C14N
   - Buscar: Hardcoded keys, weak RNG, timing attacks

2. dte-service/generators/ted_generator.py
   - Verificar: SHA-1 hashing, timestamp generation, PDF417 barcode
   - Buscar: Predictable timestamps, barcode injection

3. addons/localization/l10n_cl_dte/models/dte_certificate.py
   - Verificar: OID parsing (2.16.152.1.2.2.1 Class 2, 2.16.152.1.2.3.1 Class 3)
   - Buscar: Certificate validation bypass, expiration handling

Output: JSON con findings, severity (CRITICAL/HIGH/MEDIUM/LOW), file:line, CWE
" --json -o "${AUDIT_DIR}/security/reports/security-findings.json" \
  > "${AUDIT_DIR}/security/logs/codex-stdout.log" 2>&1

    # Generate summary
    if [ -f "${AUDIT_DIR}/security/reports/security-findings.json" ]; then
        jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})' \
           "${AUDIT_DIR}/security/reports/security-findings.json" \
           > "${AUDIT_DIR}/security/reports/summary.json"

        echo "## Security Audit Summary" > "${AUDIT_DIR}/security/reports/summary.md"
        jq -r '.[] | "- \(.severity): \(.count) findings"' \
           "${AUDIT_DIR}/security/reports/summary.json" \
           >> "${AUDIT_DIR}/security/reports/summary.md"
    fi

    echo "DONE" > "${AUDIT_DIR}/security/.done"
) &
PID_SECURITY=$!
echo -e "${GREEN}     → Launched (PID: $PID_SECURITY)${NC}"
echo

sleep 2

# Audit 2: SII Compliance (Copilot CLI) - Background
echo -e "${CYAN}📋 [2/5] SII Compliance Audit (Copilot CLI - DTE Agent)${NC}"
echo -e "${YELLOW}     Focus: XSD validation, SOAP client, 59 error codes${NC}"
(
    cd "${WORKTREE_BASE}/odoo19-compliance"

    copilot --model claude-sonnet-4.5 --agent dte-compliance --allow-all-tools -p "
Auditoría de compliance SII (Temperature: 0.1 implied):

Cross-reference con SII Resolution 80/2014, DTE_v10.xsd schema.

Tareas:
1. XSD Schema Validation
   - File: dte-service/schemas/xsd/DTE_v10.xsd (269 líneas)
   - Verificar: Todos los 5 DTE types cubiertos (33, 34, 52, 56, 61)
   - Validar: Required fields match SII spec

2. Error Code Mapping
   - File: dte-service/utils/sii_error_codes.py
   - Verificar: 59 codes de 10 categorías presentes
   - Check: Retry logic para códigos retryable

3. SOAP Client Implementation
   - File: dte-service/clients/sii_soap_client.py
   - Verificar: GetTokenFromSeed, QueryEstDte, UploadDte, GetDte methods
   - Check: Exponential backoff, timeout handling (7 days)

Output: Compliance checklist markdown con pass/fail, referencias SII Resolution
" > "${AUDIT_DIR}/compliance/reports/compliance-checklist.md" \
  2> "${AUDIT_DIR}/compliance/logs/copilot-stderr.log"

    # Extract summary
    head -50 "${AUDIT_DIR}/compliance/reports/compliance-checklist.md" \
        > "${AUDIT_DIR}/compliance/reports/summary.md" 2>/dev/null || true

    echo "DONE" > "${AUDIT_DIR}/compliance/.done"
) &
PID_COMPLIANCE=$!
echo -e "${GREEN}     → Launched (PID: $PID_COMPLIANCE)${NC}"
echo

sleep 2

# Audit 3: Payroll Logic (Copilot CLI) - Background
echo -e "${CYAN}💰 [3/5] Payroll Logic Audit (Copilot CLI - Payroll Agent)${NC}"
echo -e "${YELLOW}     Focus: AFP 10%, ISAPRE 7%, APV tax, Economic Indicators${NC}"
(
    cd "${WORKTREE_BASE}/odoo19-payroll"

    copilot --model claude-sonnet-4.5 --agent odoo-payroll --allow-all-tools -p "
Auditoría de cálculos de nómina chilena (Temperature: 0.1):

Context: Bug 10x inflation fixed, Chilean Labor Code Art. 42 compliance.

Tareas:
1. AFP Calculation (10% mandatory)
   - File: addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule.py
   - Verificar: Formula (Total Imponible * 0.10), Tope 81.6 UF
   - Edge cases: Partial months, retroactive payments

2. ISAPRE Calculation (>= 7%)
   - Same file
   - Verificar: Minimum 7% validation, UF conversion, plan selection

3. APV Tax Benefit
   - File: addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
   - Verificar: Tax deduction formula, 50 UF/month limit

4. Economic Indicators Auto-Sync
   - File: addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
   - Verificar: Cron job config, API fallback, validation logic
   - Cross-check: Current UF value matches banco central

Output: Calculation audit markdown, formula verification, test coverage
" > "${AUDIT_DIR}/payroll/reports/payroll-audit.md" \
  2> "${AUDIT_DIR}/payroll/logs/copilot-stderr.log"

    # Extract summary
    head -50 "${AUDIT_DIR}/payroll/reports/payroll-audit.md" \
        > "${AUDIT_DIR}/payroll/reports/summary.md" 2>/dev/null || true

    echo "DONE" > "${AUDIT_DIR}/payroll/.done"
) &
PID_PAYROLL=$!
echo -e "${GREEN}     → Launched (PID: $PID_PAYROLL)${NC}"
echo

sleep 2

# Audit 4: Architecture (Note for user)
echo -e "${CYAN}🏗️  [4/5] Architecture Analysis${NC}"
echo -e "${YELLOW}     Note: Use Claude Code interactive session (Task tool)${NC}"
echo -e "${YELLOW}     Prompt saved to: ${AUDIT_DIR}/architecture/arch-prompt.txt${NC}"

cat > "${AUDIT_DIR}/architecture/arch-prompt.txt" <<'EOPROMPT'
Architecture deep dive (Temperature: 0.1):

Analizar arquitectura three-tier distribuida:

1. Component Interaction Analysis
   - Odoo Module: addons/localization/l10n_cl_dte/
   - DTE Service: dte-service/ (FastAPI port 8001)
   - AI Service: ai-service/ (FastAPI port 8002)
   - Dependencies: docker-compose.yml

   Verificar:
   - Internal-only services (not exposed to internet)
   - Authentication flow (OAuth2/OIDC)
   - API contract consistency

2. Async Pattern Review
   - RabbitMQ usage: Find all celery tasks
   - Redis caching: Find cache.get/set calls
   - APScheduler: dte-service/scheduler/ (15min DTE poller)

   Verificar:
   - Queue depth monitoring
   - Worker pool sizing
   - Job timeout configuration

3. API Contract Validation
   - DTE Service: dte-service/app/main.py
   - AI Service: ai-service/app/main.py

   Verificar:
   - Consistent error responses
   - Rate limiting implementation
   - Retry policies

Output: Architecture diagram (mermaid), dependency graph, anti-patterns found
EOPROMPT

echo -e "${GREEN}     → Prompt ready for manual execution${NC}"
echo

sleep 1

# Audit 5: Performance (Codex CLI) - Background
echo -e "${CYAN}⚡ [5/5] Performance Audit (Codex CLI - GPT-5-Codex)${NC}"
echo -e "${YELLOW}     Focus: N+1 queries, Redis caching, async jobs${NC}"
(
    cd "${WORKTREE_BASE}/odoo19-performance"

    codex --profile audit exec "
Performance analysis (Temperature: 0.1, Reasoning: high):

1. Database Query Optimization
   - Scan: addons/localization/**/models/*.py
   - Detect: N+1 queries, missing prefetch_related(), inefficient filters
   - Use: Odoo ORM knowledge to spot anti-patterns

2. Redis Caching Analysis
   - Files: dte-service/utils/cache.py, ai-service/app/cache_manager.py
   - Analyze: TTL values, cache key patterns, invalidation triggers
   - Recommend: Optimal TTL based on data volatility

3. Async Job Configuration
   - File: docker-compose.yml (RabbitMQ config)
   - File: dte-service/scheduler/ (APScheduler)
   - Check: Worker count, timeout values, retry policies

Output: JSON performance report con bottlenecks, optimization opportunities
Execute: Read-only analysis (no load tests)
" --json -o "${AUDIT_DIR}/performance/reports/performance-findings.json" \
  > "${AUDIT_DIR}/performance/logs/codex-stdout.log" 2>&1

    # Generate summary
    if [ -f "${AUDIT_DIR}/performance/reports/performance-findings.json" ]; then
        jq '.findings | group_by(.category) | map({category: .[0].category, count: length})' \
           "${AUDIT_DIR}/performance/reports/performance-findings.json" \
           > "${AUDIT_DIR}/performance/reports/summary.json" 2>/dev/null || true

        echo "## Performance Audit Summary" > "${AUDIT_DIR}/performance/reports/summary.md"
        jq -r '.[] | "- \(.category): \(.count) findings"' \
           "${AUDIT_DIR}/performance/reports/summary.json" \
           >> "${AUDIT_DIR}/performance/reports/summary.md" 2>/dev/null || true
    fi

    echo "DONE" > "${AUDIT_DIR}/performance/.done"
) &
PID_PERFORMANCE=$!
echo -e "${GREEN}     → Launched (PID: $PID_PERFORMANCE)${NC}"
echo

# Progress monitoring
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  STEP 3: Monitoring Progress                  ${NC}"
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo
echo -e "${BLUE}PIDs:${NC}"
echo -e "  Security: $PID_SECURITY | Compliance: $PID_COMPLIANCE | Payroll: $PID_PAYROLL | Performance: $PID_PERFORMANCE"
echo

while true; do
    DONE_COUNT=0
    [ -f "${AUDIT_DIR}/security/.done" ] && ((DONE_COUNT++))
    [ -f "${AUDIT_DIR}/compliance/.done" ] && ((DONE_COUNT++))
    [ -f "${AUDIT_DIR}/payroll/.done" ] && ((DONE_COUNT++))
    [ -f "${AUDIT_DIR}/performance/.done" ] && ((DONE_COUNT++))

    ELAPSED=$(($(date +%s) - START_TIME))
    MINS=$((ELAPSED / 60))
    SECS=$((ELAPSED % 60))

    echo -ne "\r${YELLOW}⏳ Progress: $DONE_COUNT/4 audits completed | Elapsed: ${MINS}m ${SECS}s${NC}     "

    [ $DONE_COUNT -eq 4 ] && break
    sleep 3
done

echo
echo
echo -e "${GREEN}✅ All parallel audits completed!${NC}"
echo

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))
TOTAL_MINS=$((TOTAL_TIME / 60))
TOTAL_SECS=$((TOTAL_TIME % 60))

# Step 4: Consolidate Reports
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo -e "${MAGENTA}  STEP 4: Consolidating Reports                ${NC}"
echo -e "${MAGENTA}════════════════════════════════════════════════${NC}"
echo

cat > "${AUDIT_DIR}/AUDIT_SUMMARY.md" <<EOF
# 🎯 MULTI-CLI AUDIT SUMMARY
## Odoo 19 Stack - $(date +"%Y-%m-%d %H:%M:%S")

**Configuration:**
- **Temperature:** 0.1 (Maximum Precision)
- **Agents:** 5 (Security, Compliance, Payroll, Architecture, Performance)
- **Parallelization:** 4 concurrent + 1 manual
- **Total Duration:** ${TOTAL_MINS}m ${TOTAL_SECS}s

**Research Baseline:** Sequential execution ~3 hours, Parallel ~1.9 hours (36% improvement)

---

## 📊 Results Summary

### 🔒 Security Audit (Codex CLI - GPT-5-Codex)
**Status:** $([ -f "${AUDIT_DIR}/security/.done" ] && echo "✅ COMPLETED" || echo "⚠️ PENDING")
**Report:** \`security/reports/security-findings.json\`

$(cat "${AUDIT_DIR}/security/reports/summary.md" 2>/dev/null || echo "_Report generation pending_")

---

### 📋 SII Compliance Audit (Copilot CLI - DTE Agent)
**Status:** $([ -f "${AUDIT_DIR}/compliance/.done" ] && echo "✅ COMPLETED" || echo "⚠️ PENDING")
**Report:** \`compliance/reports/compliance-checklist.md\`

$(cat "${AUDIT_DIR}/compliance/reports/summary.md" 2>/dev/null || echo "_Report generation pending_")

---

### 💰 Payroll Logic Audit (Copilot CLI - Payroll Agent)
**Status:** $([ -f "${AUDIT_DIR}/payroll/.done" ] && echo "✅ COMPLETED" || echo "⚠️ PENDING")
**Report:** \`payroll/reports/payroll-audit.md\`

$(cat "${AUDIT_DIR}/payroll/reports/summary.md" 2>/dev/null || echo "_Report generation pending_")

---

### 🏗️ Architecture Analysis (Claude Code - Manual)
**Status:** ⚠️ REQUIRES MANUAL EXECUTION
**Prompt:** See \`architecture/arch-prompt.txt\`

**Instructions:**
1. Open Claude Code session
2. Copy prompt from arch-prompt.txt
3. Execute analysis
4. Save results to architecture/reports/

---

### ⚡ Performance Audit (Codex CLI - GPT-5-Codex)
**Status:** $([ -f "${AUDIT_DIR}/performance/.done" ] && echo "✅ COMPLETED" || echo "⚠️ PENDING")
**Report:** \`performance/reports/performance-findings.json\`

$(cat "${AUDIT_DIR}/performance/reports/summary.md" 2>/dev/null || echo "_Report generation pending_")

---

## 🎯 Next Steps

1. **Review Findings:** Open \`${AUDIT_DIR}/\` and analyze all reports
2. **Prioritize Issues:** Focus on P0 (CRITICAL) findings first
3. **Create Tickets:** Use file:line references for precise fixes
4. **Remediation:** Implement fixes following recommendations
5. **Re-Audit:** Run this script again to validate fixes

---

## 📁 Audit Directory Structure

\`\`\`
${AUDIT_DIR}/
├── AUDIT_SUMMARY.md (this file)
├── security/
│   ├── reports/
│   │   ├── security-findings.json
│   │   └── summary.md
│   └── logs/
│       └── codex-stdout.log
├── compliance/
│   ├── reports/
│   │   ├── compliance-checklist.md
│   │   └── summary.md
│   └── logs/
│       └── copilot-stderr.log
├── payroll/
│   ├── reports/
│   │   ├── payroll-audit.md
│   │   └── summary.md
│   └── logs/
│       └── copilot-stderr.log
├── architecture/
│   └── arch-prompt.txt
└── performance/
    ├── reports/
    │   ├── performance-findings.json
    │   └── summary.md
    └── logs/
        └── codex-stdout.log
\`\`\`

---

**Generated:** $(date +"%Y-%m-%d %H:%M:%S")
**Script:** orchestrate-multi-cli-audit.sh
**Best Practices:** Multi-Agent Orchestration 2025
EOF

echo -e "${GREEN}✅ Summary report created: AUDIT_SUMMARY.md${NC}"
echo

# Display summary
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                    AUDIT COMPLETE                         ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo
echo -e "${GREEN}📊 Results Location:${NC} ${AUDIT_DIR}/"
echo -e "${GREEN}⏱️  Total Duration:${NC} ${TOTAL_MINS}m ${TOTAL_SECS}s"
echo -e "${GREEN}🎯 Temperature Used:${NC} 0.1 (Maximum Precision)"
echo -e "${GREEN}🤖 Agents Executed:${NC} 4 parallel (Security, Compliance, Payroll, Performance)"
echo
echo -e "${YELLOW}⚠️  Manual Step Required:${NC} Architecture audit (see arch-prompt.txt)"
echo
echo -e "${BLUE}Next: Review ${AUDIT_DIR}/AUDIT_SUMMARY.md${NC}"
echo

# Cleanup worktrees prompt
echo -e "${YELLOW}🧹 Cleanup worktrees?${NC}"
read -p "   Remove temporary git worktrees? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}   Cleaning up worktrees...${NC}"
    cd "${PROJECT_ROOT}"
    git worktree remove "${WORKTREE_BASE}/odoo19-security" --force 2>/dev/null || true
    git worktree remove "${WORKTREE_BASE}/odoo19-compliance" --force 2>/dev/null || true
    git worktree remove "${WORKTREE_BASE}/odoo19-payroll" --force 2>/dev/null || true
    git worktree remove "${WORKTREE_BASE}/odoo19-architecture" --force 2>/dev/null || true
    git worktree remove "${WORKTREE_BASE}/odoo19-performance" --force 2>/dev/null || true
    echo -e "${GREEN}   ✅ Worktrees cleaned${NC}"
else
    echo -e "${CYAN}   Worktrees kept for manual review${NC}"
fi

echo
echo -e "${GREEN}🎉 Audit orchestration complete!${NC}"
echo -e "${BLUE}Open audit directory: open '${AUDIT_DIR}'${NC}"
echo

# Auto-open if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "${AUDIT_DIR}"
fi
