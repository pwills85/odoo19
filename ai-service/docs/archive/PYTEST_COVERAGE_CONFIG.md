# Pytest & Coverage Configuration Report

**Date:** 2025-11-09
**Service:** AI Microservice
**Status:** CONFIGURED
**Coverage Threshold:** 80%

---

## Configuration Summary

Enterprise-grade pytest and coverage configuration has been successfully added to `pyproject.toml`.

### Files Modified
- `/Users/pedro/Documents/odoo19/ai-service/pyproject.toml` (UPDATED)

---

## Pytest Configuration

### Section: `[tool.pytest.ini_options]`

**Key Settings:**
| Setting | Value | Purpose |
|---------|-------|---------|
| `minversion` | 7.0 | Minimum pytest version required |
| `testpaths` | ["tests"] | Test discovery directory |
| `python_files` | ["test_*.py", "*_test.py"] | Test file naming convention |
| `python_classes` | ["Test*"] | Test class naming convention |
| `python_functions` | ["test_*"] | Test function naming convention |

### Coverage Options in addopts

```toml
addopts = [
    "--cov=.",                              # Coverage for all files
    "--cov-report=html",                    # HTML report generation
    "--cov-report=term-missing:skip-covered", # Terminal report
    "--cov-report=json",                    # JSON report for CI/CD
    "--cov-fail-under=80",                  # FAIL if coverage < 80%
    "-v",                                   # Verbose output
    "--strict-markers",                     # Enforce marker registration
    "--tb=short",                           # Short traceback format
    "--capture=no",                         # No output capturing
]
```

---

## Test Markers Configuration

### Registered Markers (6 total)

```
unit
  Unit tests for individual functions/classes

integration
  Integration tests for service interactions

slow
  Slow running tests (>1s execution time)

api
  API endpoint tests

database
  Database interaction tests

async
  Asynchronous tests
```

### Usage Examples

```bash
# Run only unit tests
pytest -m unit

# Run integration tests
pytest -m integration

# Run everything except slow tests
pytest -m "not slow"

# Run API tests (combined markers)
pytest -m "api or integration"
```

---

## Coverage Configuration

### Section: `[tool.coverage.run]`

**Key Settings:**
```toml
source = ["."]                    # Measure all code in current directory
branch = true                     # Track branch coverage
parallel = true                   # Support parallel test execution
```

**Omit Patterns:**
- `tests/*` - Test files themselves
- `**/__pycache__/*` - Cache directories
- `**/.venv/*` - Virtual environment
- `venv/*` - Alternative venv location
- `*/site-packages/*` - Installed packages
- `**/conftest.py` - Pytest configuration
- `setup.py` - Setup configuration

### Section: `[tool.coverage.report]`

**Key Settings:**
| Setting | Value | Purpose |
|---------|-------|---------|
| `fail_under` | 80 | FAIL if coverage below 80% |
| `show_missing` | true | Display uncovered lines |
| `precision` | 2 | Show coverage to 2 decimals |
| `skip_empty` | true | Skip empty files |
| `skip_covered` | false | Show all files in report |

**Excluded from Coverage:**
- Lines with `# pragma: no cover` comment
- `__repr__` methods
- Assertion errors
- NotImplementedError raises
- `if __name__ == "__main__":`
- TYPE_CHECKING blocks
- Protocol class definitions
- Abstract method definitions

### Output Formats

| Format | Location | Purpose |
|--------|----------|---------|
| HTML Report | `htmlcov/` | Visual coverage analysis |
| JSON Report | `.coverage.json` | CI/CD integration |
| Terminal | stdout | Quick feedback during test runs |

---

## Verification Commands

### 1. Verify Pytest Installation

```bash
cd /Users/pedro/Documents/odoo19/ai-service
pytest --version
```

**Expected Output:**
```
pytest 7.x.x or higher
```

### 2. List Registered Markers

```bash
cd /Users/pedro/Documents/odoo19/ai-service
pytest --markers | grep "custom mark"
```

**Expected Output:**
```
@pytest.mark.unit
@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.api
@pytest.mark.database
@pytest.mark.async
```

### 3. Validate TOML Syntax

```bash
cd /Users/pedro/Documents/odoo19/ai-service
python -m tomllib pyproject.toml  # Python 3.11+
# OR
pip install toml && python -c "import toml; toml.load('pyproject.toml')"
```

### 4. Run Tests with Coverage

```bash
cd /Users/pedro/Documents/odoo19/ai-service
pytest --cov=. --cov-report=html --cov-report=term-missing
```

**Expected Behavior:**
- Tests execute from `tests/` directory
- Coverage report generated in `htmlcov/`
- Terminal shows coverage percentage
- FAILS if coverage < 80%

### 5. Run Specific Test Categories

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run everything except slow tests
pytest -m "not slow"

# Run API tests with verbose output
pytest -m api -v
```

---

## Enterprise Standards Applied

### Quality Gates
- ✅ Minimum pytest version enforced (7.0+)
- ✅ Strict marker enforcement enabled
- ✅ Coverage floor at 80%
- ✅ Branch coverage tracking enabled
- ✅ Parallel test execution support

### Reporting
- ✅ HTML reports for visual analysis
- ✅ JSON reports for CI/CD pipelines
- ✅ Terminal reports for quick feedback
- ✅ Missing line identification
- ✅ 2-decimal precision

### Test Organization
- ✅ 6 categorical markers for test organization
- ✅ Standard naming conventions defined
- ✅ Clear test discovery patterns
- ✅ Support for async and slow tests

---

## Integration with CI/CD

The configuration is ready for GitHub Actions, GitLab CI, or similar pipelines:

```yaml
# Example GitHub Actions step
- name: Run Tests with Coverage
  run: |
    cd ai-service
    pytest --cov=. --cov-report=json --cov-report=html

- name: Upload Coverage Report
  uses: codecov/codecov-action@v3
  with:
    files: ./ai-service/.coverage.json
    fail_ci_if_error: true
    minimum_coverage: 80
```

---

## Next Steps

1. Create `tests/` directory if not exists
2. Add `conftest.py` for pytest fixtures
3. Write first test with marker: `@pytest.mark.unit`
4. Run: `pytest -m unit` to verify configuration
5. Check `htmlcov/index.html` for coverage report

---

## Configuration Files

**Primary Configuration:**
- `/Users/pedro/Documents/odoo19/ai-service/pyproject.toml`

**Generated Files (after first test run):**
- `htmlcov/` - HTML coverage report
- `.coverage` - Binary coverage database
- `.coverage.json` - JSON coverage data
- `.pytest_cache/` - Pytest cache

**Recommended .gitignore entries:**
```
htmlcov/
.coverage
.coverage.json
.pytest_cache/
__pycache__/
```

---

## Enterprise Compliance

This configuration follows:
- pytest best practices (v7.0+)
- coverage.py standards
- Python 3.11 compatibility
- PEP 517/518 pyproject.toml standards
- Industry coverage benchmarks (80%+ target)

Configuration Status: **PRODUCTION READY**
