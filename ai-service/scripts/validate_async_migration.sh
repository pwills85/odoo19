#!/bin/bash
# Validation Script: Async Migration - ProjectMatcherClaude
# Date: 2025-11-11
# Purpose: Validate that async migration is working correctly

set -e

echo "=========================================="
echo "Async Migration Validation"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counter
TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Check AsyncAnthropic client
echo -n "Test 1: Verify AsyncAnthropic client initialization... "
RESULT=$(docker compose exec -T ai-service python3 -c "
from analytics.project_matcher_claude import ProjectMatcherClaude
import os
matcher = ProjectMatcherClaude(anthropic_api_key='test-key')
assert type(matcher.client).__name__ == 'AsyncAnthropic', 'Client is not AsyncAnthropic'
print('OK')
" 2>&1 | tail -1)

if [ "$RESULT" == "OK" ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: $RESULT"
    ((TESTS_FAILED++))
fi

# Test 2: Check suggest_project_sync doesn't exist
echo -n "Test 2: Verify suggest_project_sync removed... "
RESULT=$(docker compose exec -T ai-service python3 -c "
from analytics.project_matcher_claude import ProjectMatcherClaude
import os
matcher = ProjectMatcherClaude(anthropic_api_key='test-key')
assert not hasattr(matcher, 'suggest_project_sync'), 'suggest_project_sync still exists'
print('OK')
" 2>&1 | tail -1)

if [ "$RESULT" == "OK" ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: $RESULT"
    ((TESTS_FAILED++))
fi

# Test 3: Check suggest_project is async
echo -n "Test 3: Verify suggest_project is async... "
RESULT=$(docker compose exec -T ai-service python3 -c "
from analytics.project_matcher_claude import ProjectMatcherClaude
import inspect
import os
matcher = ProjectMatcherClaude(anthropic_api_key='test-key')
assert inspect.iscoroutinefunction(matcher.suggest_project), 'suggest_project is not async'
print('OK')
" 2>&1 | tail -1)

if [ "$RESULT" == "OK" ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: $RESULT"
    ((TESTS_FAILED++))
fi

# Test 4: Run unit tests
echo -n "Test 4: Run async unit tests... "
RESULT=$(docker compose exec -T ai-service pytest tests/unit/test_project_matcher_async.py -v -m unit --tb=no -q 2>&1 | tail -1)

if echo "$RESULT" | grep -q "10 passed"; then
    echo -e "${GREEN}✓ PASSED${NC} (10/10 tests)"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: $RESULT"
    ((TESTS_FAILED++))
fi

# Test 5: Check routes/analytics.py uses await
echo -n "Test 5: Verify endpoint uses await... "
RESULT=$(docker compose exec -T ai-service grep -q "await matcher.suggest_project" /app/routes/analytics.py && echo "OK" || echo "FAIL")

if [ "$RESULT" == "OK" ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: Endpoint doesn't use await"
    ((TESTS_FAILED++))
fi

# Test 6: Check no event loop creation
echo -n "Test 6: Verify no event loop creation... "
RESULT=$(docker compose exec -T ai-service grep -q "asyncio.new_event_loop\|asyncio.set_event_loop" /app/analytics/project_matcher_claude.py && echo "FAIL" || echo "OK")

if [ "$RESULT" == "OK" ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: Event loop creation found (anti-pattern)"
    ((TESTS_FAILED++))
fi

# Test 7: Check retry decorator exists
echo -n "Test 7: Verify retry decorator on suggest_project... "
RESULT=$(docker compose exec -T ai-service grep -B 5 "async def suggest_project" /app/analytics/project_matcher_claude.py | grep -q "@retry" && echo "OK" || echo "FAIL")

if [ "$RESULT" == "OK" ]; then
    echo -e "${GREEN}✓ PASSED${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ FAILED${NC}"
    echo "  Error: Retry decorator not found"
    ((TESTS_FAILED++))
fi

# Summary
echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
echo -e "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests Failed: ${RED}${TESTS_FAILED}${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED - Async migration successful!${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED - Migration incomplete${NC}"
    exit 1
fi
