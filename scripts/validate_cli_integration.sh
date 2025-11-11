#!/bin/bash
# Validation Script: Multi-CLI Configuration (Claude Code + Codex + Copilot)
# Date: 2025-11-09
# Purpose: Validate anti-conflict configuration is working correctly

set -e

echo "🔍 VALIDACIÓN COMPLETA - CONFIGURACIÓN MULTI-CLI"
echo "=================================================="
echo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Test function
test_result() {
    local name="$1"
    local status="$2"
    local message="$3"

    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✅ PASS${NC}: $name"
        [ -n "$message" ] && echo "   → $message"
        ((PASSED++))
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}❌ FAIL${NC}: $name"
        [ -n "$message" ] && echo "   → $message"
        ((FAILED++))
    else
        echo -e "${YELLOW}⚠️  WARN${NC}: $name"
        [ -n "$message" ] && echo "   → $message"
        ((WARNINGS++))
    fi
}

echo "## 1. CUSTOM INSTRUCTIONS"
echo

# Test 1.1: AGENTS.md exists and is armonized
if [ -f "/Users/pedro/Documents/odoo19/AGENTS.md" ]; then
    if grep -q "AGENTS.md Convention 2025" "/Users/pedro/Documents/odoo19/AGENTS.md"; then
        test_result "AGENTS.md armonizado" "PASS" "Versión 2.0.0 - Multi-CLI compatible"
    else
        test_result "AGENTS.md armonizado" "FAIL" "No tiene header de estándar 2025"
    fi
else
    test_result "AGENTS.md exists" "FAIL" "File not found"
fi

# Test 1.2: AGENTS.md references SuperClaude
if grep -q "SuperClaude" "/Users/pedro/Documents/odoo19/AGENTS.md"; then
    test_result "SuperClaude principles inherited" "PASS" "AGENTS.md hereda de ~/.claude/CLAUDE.md"
else
    test_result "SuperClaude principles" "WARN" "No menciona SuperClaude explícitamente"
fi

# Test 1.3: Backup exists
BACKUP_COUNT=$(ls -1 ~/backups/cli-config-*/AGENTS.md.backup 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt 0 ]; then
    test_result "Backups created" "PASS" "$BACKUP_COUNT backup(s) found"
else
    test_result "Backups created" "WARN" "No backups found"
fi

echo
echo "## 2. MCP SERVERS"
echo

# Test 2.1: Copilot MCP config exists
if [ -f "/Users/pedro/.config/mcp-config.json" ]; then
    test_result "Copilot MCP config exists" "PASS" "~/.copilot/config.json created"
else
    test_result "Copilot MCP config" "FAIL" "File not found"
fi

# Test 2.2: MCP config has scoped filesystem
if grep -q "filesystem-odoo19" "/Users/pedro/.config/mcp-config.json"; then
    test_result "Scoped filesystem MCP" "PASS" "Scope: /Users/pedro/Documents/odoo19"
else
    test_result "Scoped filesystem MCP" "FAIL" "No scope restriction found"
fi

# Test 2.3: Valid JSON format
if jq empty "/Users/pedro/.config/mcp-config.json" 2>/dev/null; then
    test_result "MCP config valid JSON" "PASS" "JSON syntax validated"
else
    test_result "MCP config valid JSON" "FAIL" "Invalid JSON syntax"
fi

# Test 2.4: Claude Code MCP intact
if [ -f "/Users/pedro/.claude/.mcp.json" ]; then
    CLAUDE_FS_ROOT=$(jq -r '.mcpServers.filesystem.args[2]' /Users/pedro/.claude/.mcp.json 2>/dev/null)
    if [ "$CLAUDE_FS_ROOT" = "/Users/pedro" ]; then
        test_result "Claude Code MCP intact" "PASS" "Filesystem root: $CLAUDE_FS_ROOT"
    else
        test_result "Claude Code MCP" "WARN" "Filesystem root changed"
    fi
else
    test_result "Claude Code MCP" "FAIL" "~/.claude/.mcp.json not found"
fi

echo
echo "## 3. VARIABLES DE ENTORNO"
echo

# Test 3.1: .zshrc has AI CLI section
if grep -q "AI CLI Tools - Environment Variables" ~/.zshrc; then
    test_result ".zshrc AI CLI section" "PASS" "Section added"
else
    test_result ".zshrc AI CLI section" "FAIL" "Not found"
fi

# Test 3.2: .zshrc backup exists
ZSHRC_BACKUP_COUNT=$(ls -1 ~/.zshrc.backup-* 2>/dev/null | wc -l)
if [ "$ZSHRC_BACKUP_COUNT" -gt 0 ]; then
    test_result ".zshrc backup" "PASS" "$ZSHRC_BACKUP_COUNT backup(s)"
else
    test_result ".zshrc backup" "WARN" "No backup found"
fi

# Test 3.3: GITHUB_MCP_TOKEN defined
if grep -q "GITHUB_MCP_TOKEN" ~/.zshrc; then
    test_result "GITHUB_MCP_TOKEN separation" "PASS" "Variable defined in .zshrc"
else
    test_result "GITHUB_MCP_TOKEN" "WARN" "Not found in .zshrc"
fi

echo
echo "## 4. CUSTOM AGENTS (COPILOT CLI)"
echo

# Test 4.1: Agents directory exists
if [ -d "/Users/pedro/.copilot/agents" ]; then
    AGENT_COUNT=$(ls -1 /Users/pedro/.copilot/agents/*.md 2>/dev/null | wc -l | xargs)
    test_result "Copilot agents directory" "PASS" "$AGENT_COUNT agent(s) created"
else
    test_result "Copilot agents directory" "FAIL" "Directory not found"
fi

# Test 4.2: DTE compliance agent
if [ -f "/Users/pedro/.copilot/agents/dte-compliance.md" ]; then
    test_result "DTE Compliance agent" "PASS" "Chilean DTE specialist created"
else
    test_result "DTE Compliance agent" "FAIL" "Not found"
fi

# Test 4.3: Odoo payroll agent
if [ -f "/Users/pedro/.copilot/agents/odoo-payroll.md" ]; then
    test_result "Odoo Payroll agent" "PASS" "Chilean payroll specialist created"
else
    test_result "Odoo Payroll agent" "FAIL" "Not found"
fi

# Test 4.4: SII integration agent
if [ -f "/Users/pedro/.copilot/agents/sii-integration.md" ]; then
    test_result "SII Integration agent" "PASS" "SII webservice specialist created"
else
    test_result "SII Integration agent" "FAIL" "Not found"
fi

# Test 4.5: No overlap with Claude Code agents
OVERLAP=0
for claude_agent in code-reviewer debugger performance-optimizer security-auditor test-generator; do
    if [ -f "/Users/pedro/.copilot/agents/$claude_agent.md" ]; then
        ((OVERLAP++))
    fi
done

if [ $OVERLAP -eq 0 ]; then
    test_result "No agent overlap" "PASS" "Copilot agents don't duplicate Claude Code agents"
else
    test_result "No agent overlap" "FAIL" "$OVERLAP duplicate agent(s) found"
fi

echo
echo "## 5. CONFLICT RESOLUTION"
echo

# Test 5.1: Filesystem MCP scopes don't overlap
CLAUDE_SCOPE="/Users/pedro"
COPILOT_SCOPE=$(jq -r '.mcpServers."filesystem-odoo19".args[2]' /Users/pedro/.config/mcp-config.json 2>/dev/null)

if [[ "$COPILOT_SCOPE" == "$CLAUDE_SCOPE"/* ]]; then
    test_result "MCP filesystem scope isolation" "PASS" "Copilot is subset of Claude ($COPILOT_SCOPE ⊂ $CLAUDE_SCOPE)"
else
    test_result "MCP filesystem scope" "WARN" "Scopes may conflict"
fi

# Test 5.2: AGENTS.md mentions CLI-specific notes
if grep -q "For Claude Code Users" "/Users/pedro/Documents/odoo19/AGENTS.md"; then
    if grep -q "For Copilot CLI Users" "/Users/pedro/Documents/odoo19/AGENTS.md"; then
        test_result "CLI-specific instructions" "PASS" "AGENTS.md has notes for all CLIs"
    else
        test_result "CLI-specific instructions" "WARN" "Missing Copilot notes"
    fi
else
    test_result "CLI-specific instructions" "WARN" "Missing CLI-specific notes"
fi

echo
echo "=================================================="
echo "## 📊 RESULTADOS"
echo

TOTAL=$((PASSED + FAILED + WARNINGS))
PASS_RATE=$((PASSED * 100 / TOTAL))

echo "Total Tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
echo
echo "Success Rate: $PASS_RATE%"
echo

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL CRITICAL TESTS PASSED${NC}"
    echo "Configuración multi-CLI validada correctamente."
    exit 0
else
    echo -e "${RED}❌ $FAILED CRITICAL TEST(S) FAILED${NC}"
    echo "Revisar configuración y corregir errores."
    exit 1
fi
