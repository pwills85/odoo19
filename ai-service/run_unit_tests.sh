#!/bin/bash
# Run unit tests for anthropic_client.py and chat/engine.py
# Generates coverage report

set -e

echo "===================================================================================="
echo "AI SERVICE UNIT TESTS - anthropic_client.py & chat/engine.py"
echo "===================================================================================="
echo ""
echo "Starting pytest with coverage..."
echo ""

cd /Users/pedro/Documents/odoo19/ai-service

# Run pytest with markers and coverage
python -m pytest \
    -m unit \
    tests/unit/test_anthropic_client.py \
    tests/unit/test_chat_engine.py \
    -v \
    --tb=short \
    --cov=clients/anthropic_client \
    --cov=chat/engine \
    --cov-report=term-missing \
    --cov-report=html:htmlcov \
    --cov-report=json:.coverage.json \
    -p no:warnings

echo ""
echo "===================================================================================="
echo "COVERAGE REPORT"
echo "===================================================================================="
echo ""

# Show coverage summary
python -m coverage report --include="clients/anthropic_client.py,chat/engine.py"

echo ""
echo "===================================================================================="
echo "TEST SUMMARY"
echo "===================================================================================="
echo ""

# Count tests
TOTAL_TESTS=$(python -m pytest tests/unit/test_anthropic_client.py tests/unit/test_chat_engine.py --collect-only -q 2>/dev/null | tail -1 | awk '{print $1}')

echo "Total Unit Tests Created: $TOTAL_TESTS"
echo ""
echo "anthropic_client.py: 25 tests"
echo "chat/engine.py: 26 tests"
echo ""
echo "HTML Coverage Report: /Users/pedro/Documents/odoo19/ai-service/htmlcov/index.html"
echo "JSON Coverage Report: /Users/pedro/Documents/odoo19/ai-service/.coverage.json"
echo ""
echo "===================================================================================="
