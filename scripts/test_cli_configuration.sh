#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CLI CONFIGURATION - COMPREHENSIVE TEST SUITE
# ══════════════════════════════════════════════════════════════════════════════
# Purpose: Validate all 3 CLIs (Copilot, Codex, Gemini) deployment intelligence
# Date: 2025-11-10
# Author: EERGYGROUP Engineering Team
# ══════════════════════════════════════════════════════════════════════════════

set -e

PASS=0
FAIL=0
WARN=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "══════════════════════════════════════════════════════════════"
echo "🧪 CLI CONFIGURATION - COMPREHENSIVE TEST SUITE"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 1: FILE EXISTENCE & STRUCTURE
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📁 TEST SUITE 1: File Existence & Structure${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 1.1: Copilot instructions
echo -n "Test 1.1: GitHub Copilot instructions file exists... "
if [ -f "/Users/pedro/Documents/odoo19/.github/copilot-instructions.md" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 1.2: Codex config
echo -n "Test 1.2: Codex CLI config file exists... "
if [ -f "$HOME/.codex/config.toml" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 1.3: Gemini config
echo -n "Test 1.3: Gemini project config file exists... "
if [ -f "/Users/pedro/Documents/odoo19/.gemini_project_config.json" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 1.4: Deployment guide
echo -n "Test 1.4: Deployment environment guide exists... "
if [ -f "/Users/pedro/Documents/odoo19/.github/agents/knowledge/deployment_environment.md" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 1.5: Summary report
echo -n "Test 1.5: CLI configuration report exists... "
if [ -f "/Users/pedro/Documents/odoo19/CLI_CONFIGURATION_COMPLETE_REPORT.md" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 2: CONTENT VALIDATION - DOCKER AWARENESS
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🐳 TEST SUITE 2: Content Validation - Docker Awareness${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 2.1: Copilot has Docker section
echo -n "Test 2.1: Copilot instructions contain Docker section... "
if grep -q "Docker & Deployment Context" "/Users/pedro/Documents/odoo19/.github/copilot-instructions.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 2.2: Copilot has docker compose commands
echo -n "Test 2.2: Copilot has docker compose examples... "
if grep -q "docker compose exec odoo" "/Users/pedro/Documents/odoo19/.github/copilot-instructions.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 2.3: Codex has deployment context
echo -n "Test 2.3: Codex config has deployment section... "
if grep -q 'projects."/Users/pedro/Documents/odoo19".deployment' "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 2.4: Codex has service definitions
echo -n "Test 2.4: Codex has service definitions... "
if grep -q "odoo19_app" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 2.5: Gemini has deployment type
echo -n "Test 2.5: Gemini config has deployment type... "
if grep -q '"type": "docker-compose"' "/Users/pedro/Documents/odoo19/.gemini_project_config.json"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 3: COMMAND TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}⚙️  TEST SUITE 3: Command Templates${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 3.1: Codex has odoo_update_module template
echo -n "Test 3.1: Codex has odoo_update_module command... "
if grep -q "odoo_update_module.*docker compose exec odoo odoo-bin" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 3.2: Codex has python_script with .venv
echo -n "Test 3.2: Codex python_script uses .venv... "
if grep -q "python_script.*\.venv/bin/python" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 3.3: Gemini has commands section
echo -n "Test 3.3: Gemini has commands section... "
if grep -q '"commands"' "/Users/pedro/Documents/odoo19/.gemini_project_config.json"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 3.4: Deployment guide has 50+ commands
echo -n "Test 3.4: Deployment guide has extensive commands... "
CMD_COUNT=$(grep -c "docker compose" "/Users/pedro/Documents/odoo19/.github/agents/knowledge/deployment_environment.md" 2>/dev/null || echo 0)
if [ "$CMD_COUNT" -ge 50 ]; then
    echo -e "${GREEN}✓ PASS${NC} (found $CMD_COUNT commands)"
    ((PASS++))
else
    echo -e "${YELLOW}⚠ WARN${NC} (found $CMD_COUNT commands, expected 50+)"
    ((WARN++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 4: SAFETY GUIDELINES
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🛡️  TEST SUITE 4: Safety Guidelines${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 4.1: Codex has never_suggest guidelines
echo -n "Test 4.1: Codex has never_suggest_host_odoo_bin... "
if grep -q "never_suggest_host_odoo_bin = true" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 4.2: Codex enforces venv usage
echo -n "Test 4.2: Codex enforces always_use_venv... "
if grep -q "always_use_venv = true" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 4.3: Copilot warns against host commands
echo -n "Test 4.3: Copilot has NEVER suggest section... "
if grep -q "NEVER suggest" "/Users/pedro/Documents/odoo19/.github/copilot-instructions.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 4.4: Gemini has guidelines
echo -n "Test 4.4: Gemini has guidelines section... "
if grep -q '"guidelines"' "/Users/pedro/Documents/odoo19/.gemini_project_config.json"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 4.5: Deployment guide has security section
echo -n "Test 4.5: Deployment guide has security rules... "
if grep -q "Critical Rules for AI Agents" "/Users/pedro/Documents/odoo19/.github/agents/knowledge/deployment_environment.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 5: MODEL OPTIMIZATION
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🤖 TEST SUITE 5: Model Optimization${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 5.1: Codex has 8 profiles
echo -n "Test 5.1: Codex has 8 specialized profiles... "
PROFILE_COUNT=$(grep -c "^\[profiles\." "$HOME/.codex/config.toml")
if [ "$PROFILE_COUNT" -eq 8 ]; then
    echo -e "${GREEN}✓ PASS${NC} ($PROFILE_COUNT profiles)"
    ((PASS++))
else
    echo -e "${YELLOW}⚠ WARN${NC} (found $PROFILE_COUNT, expected 8)"
    ((WARN++))
fi

# Test 5.2: Codex uses o1-preview for critical tasks
echo -n "Test 5.2: Codex uses o1-preview for compliance... "
if grep -q "model = \"o1-preview\"" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 5.3: Codex has temperature optimization
echo -n "Test 5.3: Codex has temperature range 0.05-0.4... "
if grep -q "model_temperature = 0.05" "$HOME/.codex/config.toml" && \
   grep -q "model_temperature = 0.4" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 5.4: Gemini has models section
echo -n "Test 5.4: Gemini has models configuration... "
if grep -q '"models"' "/Users/pedro/Documents/odoo19/.gemini_project_config.json"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 5.5: Gemini uses thinking model
echo -n "Test 5.5: Gemini uses thinking model for critical tasks... "
if grep -q "gemini-2.0-flash-thinking" "/Users/pedro/Documents/odoo19/.gemini_project_config.json"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 6: KNOWLEDGE BASE INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📚 TEST SUITE 6: Knowledge Base Integration${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 6.1: Codex references knowledge files
echo -n "Test 6.1: Codex has knowledge_base section... "
if grep -q "knowledge_base" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 6.2: Copilot references deployment guide
echo -n "Test 6.2: Copilot references deployment_environment.md... "
if grep -q "deployment_environment.md" "/Users/pedro/Documents/odoo19/.github/copilot-instructions.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 6.3: All knowledge files exist
echo -n "Test 6.3: All 5 knowledge base files exist... "
KB_DIR="/Users/pedro/Documents/odoo19/.github/agents/knowledge"
if [ -f "$KB_DIR/deployment_environment.md" ] && \
   [ -f "$KB_DIR/project_architecture.md" ] && \
   [ -f "$KB_DIR/odoo19_patterns.md" ] && \
   [ -f "$KB_DIR/sii_regulatory_context.md" ] && \
   [ -f "$KB_DIR/chilean_payroll_regulations.md" ]; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 7: ENVIRONMENT AWARENESS
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🖥️  TEST SUITE 7: Environment Awareness${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 7.1: Codex knows architecture
echo -n "Test 7.1: Codex aware of ARM64 architecture... "
if grep -q "linux/arm64" "$HOME/.codex/config.toml"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 7.2: Copilot mentions macOS M3
echo -n "Test 7.2: Copilot aware of macOS M3... "
if grep -q "M3" "/Users/pedro/Documents/odoo19/.github/copilot-instructions.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${YELLOW}⚠ WARN${NC}"
    ((WARN++))
fi

# Test 7.3: Deployment guide has host specs
echo -n "Test 7.3: Deployment guide has host environment... "
if grep -q "MacBook Pro M3" "/Users/pedro/Documents/odoo19/.github/agents/knowledge/deployment_environment.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 7.4: Deployment guide mentions Python 3.14
echo -n "Test 7.4: Deployment guide aware of Python 3.14... "
if grep -q "Python 3.14" "/Users/pedro/Documents/odoo19/.github/agents/knowledge/deployment_environment.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITE 8: CUSTOM IMAGES
# ══════════════════════════════════════════════════════════════════════════════
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🏗️  TEST SUITE 8: Custom Docker Images${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 8.1: Copilot mentions custom Odoo image
echo -n "Test 8.1: Copilot aware of custom Odoo image... "
if grep -q "eergygroup/odoo19:chile-1.0.5" "/Users/pedro/Documents/odoo19/.github/copilot-instructions.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 8.2: Deployment guide details custom images
echo -n "Test 8.2: Deployment guide has image specifications... "
if grep -q "Multi-stage" "/Users/pedro/Documents/odoo19/.github/agents/knowledge/deployment_environment.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

# Test 8.3: Mentions Chilean dependencies
echo -n "Test 8.3: Documents mention Chilean dependencies... "
if grep -q "lxml 5.3.0" "/Users/pedro/Documents/odoo19/.github/agents/knowledge/deployment_environment.md"; then
    echo -e "${GREEN}✓ PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}✗ FAIL${NC}"
    ((FAIL++))
fi

echo ""

# ══════════════════════════════════════════════════════════════════════════════
# RESULTS SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
echo "══════════════════════════════════════════════════════════════"
echo "📊 TEST RESULTS SUMMARY"
echo "══════════════════════════════════════════════════════════════"
echo ""

TOTAL=$((PASS + FAIL + WARN))
PASS_RATE=$((PASS * 100 / TOTAL))

echo -e "${GREEN}✓ PASSED:${NC} $PASS tests"
echo -e "${RED}✗ FAILED:${NC} $FAIL tests"
echo -e "${YELLOW}⚠ WARNINGS:${NC} $WARN tests"
echo "TOTAL: $TOTAL tests"
echo ""
echo "Pass Rate: $PASS_RATE%"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🎉 ALL CRITICAL TESTS PASSED!${NC}"
    echo -e "${GREEN}✅ Configuration is production-ready${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    exit 0
elif [ $FAIL -le 3 ]; then
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}⚠️  MINOR ISSUES DETECTED${NC}"
    echo -e "${YELLOW}Configuration mostly complete, review failures${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    exit 1
else
    echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}❌ CRITICAL FAILURES DETECTED${NC}"
    echo -e "${RED}Configuration needs fixes before use${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
    exit 2
fi
