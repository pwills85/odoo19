#!/bin/bash
# Master test runner for all Claude Code improvements
# Runs all validation tests and generates comprehensive report

set -e

CLAUDE_DIR="/Users/pedro/Documents/odoo19/.claude"
TEST_DIR="$CLAUDE_DIR/tests"
FINAL_REPORT="$TEST_DIR/comprehensive_test_report.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}"
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║         CLAUDE CODE IMPROVEMENTS - COMPREHENSIVE TEST SUITE                ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Create final report
mkdir -p "$TEST_DIR"
echo "Claude Code Improvements - Comprehensive Test Report" > "$FINAL_REPORT"
echo "=====================================================" >> "$FINAL_REPORT"
echo "Date: $(date)" >> "$FINAL_REPORT"
echo "" >> "$FINAL_REPORT"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_WARN=0

# Test 1: Extended Thinking
echo -e "\n${BOLD}Running Test Suite 1: Extended Thinking${NC}"
echo "═══════════════════════════════════════════════════"
if bash "$TEST_DIR/test_extended_thinking.sh"; then
    echo -e "${GREEN}✅ Extended Thinking tests PASSED${NC}"
    echo "✅ Extended Thinking: PASSED" >> "$FINAL_REPORT"
    ((TOTAL_PASS++))
else
    echo -e "${RED}❌ Extended Thinking tests FAILED${NC}"
    echo "❌ Extended Thinking: FAILED" >> "$FINAL_REPORT"
    ((TOTAL_FAIL++))
fi

# Test 2: MCP Servers
echo -e "\n${BOLD}Running Test Suite 2: MCP Servers${NC}"
echo "═══════════════════════════════════════════════════"
if bash "$TEST_DIR/test_mcp_servers.sh"; then
    echo -e "${GREEN}✅ MCP Servers tests PASSED${NC}"
    echo "✅ MCP Servers: PASSED" >> "$FINAL_REPORT"
    ((TOTAL_PASS++))
else
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${YELLOW}⚠️  MCP Servers tests PASSED WITH WARNINGS${NC}"
        echo "⚠️  MCP Servers: PASSED WITH WARNINGS" >> "$FINAL_REPORT"
        ((TOTAL_WARN++))
    else
        echo -e "${RED}❌ MCP Servers tests FAILED${NC}"
        echo "❌ MCP Servers: FAILED" >> "$FINAL_REPORT"
        ((TOTAL_FAIL++))
    fi
fi

# Test 3: Haiku Agents
echo -e "\n${BOLD}Running Test Suite 3: Haiku Agents${NC}"
echo "═══════════════════════════════════════════════════"
if bash "$TEST_DIR/test_haiku_agents.sh"; then
    echo -e "${GREEN}✅ Haiku Agents tests PASSED${NC}"
    echo "✅ Haiku Agents: PASSED" >> "$FINAL_REPORT"
    ((TOTAL_PASS++))
else
    echo -e "${RED}❌ Haiku Agents tests FAILED${NC}"
    echo "❌ Haiku Agents: FAILED" >> "$FINAL_REPORT"
    ((TOTAL_FAIL++))
fi

# Test 4: Python Validation Suite
echo -e "\n${BOLD}Running Test Suite 4: Python Validation${NC}"
echo "═══════════════════════════════════════════════════"
if python3 "$TEST_DIR/validate_improvements.py"; then
    echo -e "${GREEN}✅ Python validation PASSED${NC}"
    echo "✅ Python Validation: PASSED" >> "$FINAL_REPORT"
    ((TOTAL_PASS++))
else
    echo -e "${RED}❌ Python validation FAILED${NC}"
    echo "❌ Python Validation: FAILED" >> "$FINAL_REPORT"
    ((TOTAL_FAIL++))
fi

# Generate summary
echo "" >> "$FINAL_REPORT"
echo "OVERALL SUMMARY" >> "$FINAL_REPORT"
echo "===============" >> "$FINAL_REPORT"
echo "Test Suites Passed: $TOTAL_PASS" >> "$FINAL_REPORT"
echo "Test Suites Failed: $TOTAL_FAIL" >> "$FINAL_REPORT"
echo "Test Suites With Warnings: $TOTAL_WARN" >> "$FINAL_REPORT"

TOTAL_SUITES=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_WARN))
if [ $TOTAL_SUITES -gt 0 ]; then
    SUCCESS_RATE=$((TOTAL_PASS * 100 / TOTAL_SUITES))
    echo "Success Rate: $SUCCESS_RATE%" >> "$FINAL_REPORT"
fi

# Display final results
echo -e "\n${BOLD}${BLUE}"
echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                           FINAL TEST RESULTS                               ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}✅ Test Suites Passed:${NC} $TOTAL_PASS"
echo -e "${YELLOW}⚠️  Test Suites With Warnings:${NC} $TOTAL_WARN"
echo -e "${RED}❌ Test Suites Failed:${NC} $TOTAL_FAIL"

if [ $TOTAL_SUITES -gt 0 ]; then
    echo -e "\n${BOLD}Success Rate: $SUCCESS_RATE%${NC}"
fi

echo -e "\n${BLUE}📄 Comprehensive report saved to:${NC}"
echo "   $FINAL_REPORT"

# Additional reports
echo -e "\n${BLUE}📊 Individual test results:${NC}"
ls -lh "$TEST_DIR"/*_test_results.* 2>/dev/null || echo "   (No individual reports found)"

# Exit code
if [ $TOTAL_FAIL -gt 0 ]; then
    echo -e "\n${RED}${BOLD}❌ VALIDATION FAILED - SOME TESTS DID NOT PASS${NC}"
    exit 1
elif [ $TOTAL_WARN -gt 0 ]; then
    echo -e "\n${YELLOW}${BOLD}⚠️  VALIDATION PASSED WITH WARNINGS${NC}"
    exit 0
else
    echo -e "\n${GREEN}${BOLD}✅ ALL VALIDATIONS PASSED SUCCESSFULLY${NC}"
    exit 0
fi
