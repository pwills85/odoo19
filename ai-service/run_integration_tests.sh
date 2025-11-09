#!/bin/bash

# Integration Tests Runner for AI Microservice (PHASE 1)
# ====================================================
# Runs comprehensive integration tests for:
# - Prompt Caching
# - Streaming SSE
# - Token Pre-counting
#
# Usage:
#   ./run_integration_tests.sh              # Run all tests
#   ./run_integration_tests.sh caching      # Run only caching tests
#   ./run_integration_tests.sh streaming    # Run only streaming tests
#   ./run_integration_tests.sh precounting  # Run only precounting tests
#   ./run_integration_tests.sh coverage     # Run with coverage report
#
# Author: EERGYGROUP - Test Automation Sprint 2025-11-09

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
TEST_DIR="$PROJECT_ROOT/tests/integration"

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}❌ pytest not found. Install with: pip install pytest pytest-asyncio${NC}"
    exit 1
fi

# Print header
echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  AI Microservice Integration Tests (PHASE 1) ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

# Parse arguments
TEST_TYPE="${1:-all}"
VERBOSE="${2:--v}"

# Change to project root
cd "$PROJECT_ROOT"

# Function to print section header
print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo ""
}

# Function to run test suite
run_tests() {
    local test_file="$1"
    local description="$2"

    print_header "$description"

    if pytest "$TEST_DIR/$test_file" -m integration $VERBOSE; then
        echo -e "${GREEN}✅ $description PASSED${NC}"
        return 0
    else
        echo -e "${RED}❌ $description FAILED${NC}"
        return 1
    fi
}

# Track results
PASSED=0
FAILED=0

# Run tests based on argument
case "$TEST_TYPE" in
    caching)
        if run_tests "test_prompt_caching.py" "Prompt Caching Tests"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
        ;;

    streaming)
        if run_tests "test_streaming_sse.py" "Streaming SSE Tests"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
        ;;

    precounting)
        if run_tests "test_token_precounting.py" "Token Pre-counting Tests"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
        ;;

    coverage)
        print_header "Running Integration Tests with Coverage"

        pytest \
            tests/integration/ \
            -m integration \
            --cov=clients/anthropic_client \
            --cov=chat/engine \
            --cov=main \
            --cov-report=html \
            --cov-report=term-missing \
            $VERBOSE

        echo ""
        echo -e "${GREEN}📊 Coverage report generated: htmlcov/index.html${NC}"
        ;;

    all|*)
        # Run all three test suites
        if run_tests "test_prompt_caching.py" "Prompt Caching Tests"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi

        if run_tests "test_streaming_sse.py" "Streaming SSE Tests"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi

        if run_tests "test_token_precounting.py" "Token Pre-counting Tests"; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
        ;;
esac

# Print summary
echo ""
print_header "Test Summary"

echo -e "${BLUE}Test Suites:${NC}"
echo "  - test_prompt_caching.py: 8 tests"
echo "  - test_streaming_sse.py: 10 tests"
echo "  - test_token_precounting.py: 15 tests"
echo ""
echo -e "${BLUE}Total: 33 integration tests${NC}"
echo ""

if [ "$TEST_TYPE" == "all" ]; then
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}✅ All test suites PASSED${NC}"
        exit 0
    else
        echo -e "${RED}❌ Some test suites FAILED${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}Run Options:${NC}"
echo "  ./run_integration_tests.sh             - Run all tests"
echo "  ./run_integration_tests.sh caching     - Run caching tests only"
echo "  ./run_integration_tests.sh streaming   - Run streaming tests only"
echo "  ./run_integration_tests.sh precounting - Run precounting tests only"
echo "  ./run_integration_tests.sh coverage    - Run with coverage report"
echo ""
echo -e "${BLUE}Additional Options:${NC}"
echo "  -v                                     - Verbose output (default)"
echo "  -vv                                    - Very verbose output"
echo "  -q                                     - Quiet output"
echo ""
echo -e "${BLUE}Examples:${NC}"
echo "  ./run_integration_tests.sh caching -vv         - Caching tests, very verbose"
echo "  ./run_integration_tests.sh streaming -q        - Streaming tests, quiet"
echo "  ./run_integration_tests.sh coverage            - All tests with coverage"
echo ""

print_header "Documentation"
echo -e "${BLUE}For more information, see:${NC}"
echo "  - INTEGRATION_TESTS_GUIDE.md: Complete test documentation"
echo "  - tests/integration/conftest.py: Shared fixtures"
echo "  - tests/integration/test_*.py: Test implementations"
echo ""
