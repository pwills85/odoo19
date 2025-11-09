#!/bin/bash
# -*- coding: utf-8 -*-
"""
Test Runner Script - l10n_cl_dte_eergygroup
============================================

Helper script to run tests with various configurations.

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
"""

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ODOO_BIN="./odoo-bin"
CONFIG_FILE="config/odoo.conf"
TEST_DB="test_eergygroup"
MODULE="l10n_cl_dte_eergygroup"

# Banner
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         EERGYGROUP DTE TEST RUNNER                         ║"
echo "║         Module: l10n_cl_dte_eergygroup                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Parse arguments
TEST_TYPE="${1:-all}"

case "$TEST_TYPE" in
    all)
        echo -e "${YELLOW}Running ALL tests (78 tests)...${NC}"
        $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --stop-after-init \
            -i $MODULE
        ;;

    smoke)
        echo -e "${YELLOW}Running SMOKE tests only (quick validation)...${NC}"
        $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --test-tags=eergygroup_smoke \
            --stop-after-init \
            -i $MODULE
        ;;

    integration)
        echo -e "${YELLOW}Running INTEGRATION tests only...${NC}"
        $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --test-tags=eergygroup_integration \
            --stop-after-init \
            -i $MODULE
        ;;

    account_move)
        echo -e "${YELLOW}Running account.move tests only (25 tests)...${NC}"
        $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --test-tags=+eergygroup/test_account_move \
            --stop-after-init \
            -i $MODULE
        ;;

    reference)
        echo -e "${YELLOW}Running account.move.reference tests only (25 tests)...${NC}"
        $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --test-tags=+eergygroup/test_account_move_reference \
            --stop-after-init \
            -i $MODULE
        ;;

    company)
        echo -e "${YELLOW}Running res.company tests only (28 tests)...${NC}"
        $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --test-tags=+eergygroup/test_res_company \
            --stop-after-init \
            -i $MODULE
        ;;

    coverage)
        echo -e "${YELLOW}Running tests with coverage report...${NC}"

        # Check if coverage is installed
        if ! command -v coverage &> /dev/null; then
            echo -e "${RED}Error: coverage not installed. Run: pip install coverage${NC}"
            exit 1
        fi

        # Run with coverage
        coverage run --source=addons/localization/$MODULE \
            --omit="*/tests/*" \
            $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --stop-after-init \
            -i $MODULE

        echo -e "${GREEN}Generating coverage report...${NC}"
        coverage report -m

        echo -e "${GREEN}Generating HTML coverage report...${NC}"
        coverage html

        echo -e "${GREEN}Coverage report saved to: htmlcov/index.html${NC}"
        ;;

    debug)
        echo -e "${YELLOW}Running tests with DEBUG logging...${NC}"
        $ODOO_BIN -c $CONFIG_FILE \
            -d $TEST_DB \
            --test-enable \
            --log-level=test:DEBUG \
            --stop-after-init \
            -i $MODULE
        ;;

    clean)
        echo -e "${YELLOW}Cleaning test database...${NC}"
        dropdb --if-exists $TEST_DB
        echo -e "${GREEN}Test database dropped.${NC}"
        ;;

    help|--help|-h)
        echo "Usage: ./run_tests.sh [option]"
        echo ""
        echo "Options:"
        echo "  all          Run all tests (default) - 78 tests"
        echo "  smoke        Run smoke tests only - quick validation"
        echo "  integration  Run integration tests only"
        echo "  account_move Run account.move tests - 25 tests"
        echo "  reference    Run reference tests - 25 tests"
        echo "  company      Run company tests - 28 tests"
        echo "  coverage     Run tests with coverage report (≥80%)"
        echo "  debug        Run tests with DEBUG logging"
        echo "  clean        Drop test database"
        echo "  help         Show this help message"
        echo ""
        echo "Examples:"
        echo "  ./run_tests.sh              # Run all tests"
        echo "  ./run_tests.sh smoke        # Quick smoke tests"
        echo "  ./run_tests.sh coverage     # With coverage report"
        exit 0
        ;;

    *)
        echo -e "${RED}Error: Unknown option '$TEST_TYPE'${NC}"
        echo "Run './run_tests.sh help' for usage information"
        exit 1
        ;;
esac

# Check exit code
if [ $? -eq 0 ]; then
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  TESTS PASSED ✅                          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    exit 0
else
    echo -e "${RED}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                  TESTS FAILED ❌                          ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    exit 1
fi
