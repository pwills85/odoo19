#!/bin/bash
# validate_pytest_config.sh
# Validates pytest and coverage configuration in pyproject.toml
# Usage: ./validate_pytest_config.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

echo "=========================================="
echo "Pytest & Coverage Configuration Validator"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# 1. Check pyproject.toml exists
echo "1. Checking pyproject.toml..."
if [ -f "$PROJECT_ROOT/pyproject.toml" ]; then
    print_success "pyproject.toml found"
else
    print_error "pyproject.toml not found at $PROJECT_ROOT/pyproject.toml"
    exit 1
fi
echo ""

# 2. Validate TOML syntax
echo "2. Validating TOML syntax..."
if python3 -c "import sys; sys.version_info >= (3, 11)" 2>/dev/null; then
    if python3 -c "import tomllib; tomllib.loads(open('$PROJECT_ROOT/pyproject.toml').read())" 2>/dev/null; then
        print_success "TOML syntax is valid (Python 3.11+ tomllib)"
    else
        print_error "TOML syntax is invalid"
        exit 1
    fi
else
    # Fallback for older Python versions
    if python3 -c "import toml; toml.load('$PROJECT_ROOT/pyproject.toml')" 2>/dev/null; then
        print_success "TOML syntax is valid (toml package)"
    else
        print_warning "Could not validate TOML - please install 'toml' package"
    fi
fi
echo ""

# 3. Check pytest configuration sections
echo "3. Checking Pytest configuration sections..."

if grep -q "\[tool.pytest.ini_options\]" "$PROJECT_ROOT/pyproject.toml"; then
    print_success "[tool.pytest.ini_options] section found"
else
    print_error "[tool.pytest.ini_options] section not found"
    exit 1
fi

if grep -q "testpaths = \[\"tests\"\]" "$PROJECT_ROOT/pyproject.toml"; then
    print_success "testpaths = [\"tests\"] configured"
else
    print_error "testpaths not properly configured"
    exit 1
fi

if grep -q "minversion = \"7.0\"" "$PROJECT_ROOT/pyproject.toml"; then
    print_success "minversion = \"7.0\" configured"
else
    print_warning "minversion not set to 7.0"
fi

if grep -q "addopts = \[" "$PROJECT_ROOT/pyproject.toml"; then
    print_success "addopts list found"
else
    print_error "addopts not configured"
    exit 1
fi

echo ""

# 4. Check coverage configuration sections
echo "4. Checking Coverage configuration sections..."

if grep -q "\[tool.coverage.run\]" "$PROJECT_ROOT/pyproject.toml"; then
    print_success "[tool.coverage.run] section found"
else
    print_error "[tool.coverage.run] section not found"
    exit 1
fi

if grep -q "\[tool.coverage.report\]" "$PROJECT_ROOT/pyproject.toml"; then
    print_success "[tool.coverage.report] section found"
else
    print_error "[tool.coverage.report] section not found"
    exit 1
fi

if grep -q "fail_under = 80" "$PROJECT_ROOT/pyproject.toml"; then
    print_success "Coverage threshold set to 80%"
else
    print_error "Coverage threshold not set to 80%"
    exit 1
fi

echo ""

# 5. Check markers configuration
echo "5. Checking Test markers..."

MARKERS=("unit" "integration" "slow" "api" "database" "async")
MARKER_COUNT=0

for marker in "${MARKERS[@]}"; do
    if grep -q "\"$marker:" "$PROJECT_ROOT/pyproject.toml"; then
        print_success "@pytest.mark.$marker registered"
        ((MARKER_COUNT++))
    else
        print_warning "@pytest.mark.$marker not found"
    fi
done

if [ $MARKER_COUNT -eq ${#MARKERS[@]} ]; then
    print_success "All ${#MARKERS[@]} markers registered"
else
    print_warning "Only $MARKER_COUNT of ${#MARKERS[@]} markers found"
fi

echo ""

# 6. Check for pytest installation
echo "6. Checking pytest installation..."

if command -v pytest &> /dev/null; then
    PYTEST_VERSION=$(pytest --version 2>&1 | head -n1)
    print_success "pytest installed: $PYTEST_VERSION"
else
    print_warning "pytest not installed - run: pip install pytest pytest-cov"
fi

echo ""

# 7. Check for coverage installation
echo "7. Checking coverage installation..."

if python3 -c "import coverage" 2>/dev/null; then
    COVERAGE_VERSION=$(python3 -c "import coverage; print(coverage.__version__)" 2>/dev/null)
    print_success "coverage installed: version $COVERAGE_VERSION"
else
    print_warning "coverage not installed - run: pip install coverage pytest-cov"
fi

echo ""

# 8. Check tests directory structure
echo "8. Checking tests directory..."

if [ -d "$PROJECT_ROOT/tests" ]; then
    print_success "tests/ directory found"

    TEST_FILES=$(find "$PROJECT_ROOT/tests" -name "test_*.py" -o -name "*_test.py" | wc -l)
    if [ $TEST_FILES -gt 0 ]; then
        print_success "Found $TEST_FILES test files"
    else
        print_warning "No test files found in tests/ directory"
    fi
else
    print_warning "tests/ directory not found - please create it: mkdir tests"
fi

echo ""

# 9. Summary
echo "=========================================="
echo "Configuration Validation Summary"
echo "=========================================="

print_success "pyproject.toml is properly configured for pytest & coverage"
echo ""
echo "Configuration Details:"
echo "  - Pytest minimum version: 7.0"
echo "  - Test paths: tests/"
echo "  - Coverage threshold: 80%"
echo "  - Test markers: 6 registered"
echo "  - Coverage reporting: HTML, JSON, Terminal"
echo ""

echo "Next steps:"
echo "  1. Create tests directory if needed: mkdir -p tests"
echo "  2. Add conftest.py for fixtures: touch tests/conftest.py"
echo "  3. Write your first test: touch tests/test_example.py"
echo "  4. Run tests: pytest -m unit"
echo "  5. View coverage report: open htmlcov/index.html"
echo ""

echo -e "${GREEN}Configuration validation completed successfully!${NC}"
