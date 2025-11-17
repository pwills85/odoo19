# Pytest & Coverage Configuration - Quick Start

**Status:** ✅ Production Ready
**Date:** 2025-11-09
**Coverage Threshold:** 80%

---

## What's Configured

- ✅ Enterprise-grade pytest 7.0+ configuration
- ✅ 80% coverage enforcement
- ✅ 6 test markers (unit, integration, slow, api, database, async)
- ✅ Automatic test marking by directory
- ✅ HTML, JSON, and terminal coverage reports
- ✅ 4 pytest hooks for enterprise features

---

## Quick Start

### 1. Validate Configuration
```bash
bash validate_pytest_config.sh
```

### 2. Run Tests
```bash
# Fast suite (pre-commit)
pytest -m "not slow" -v

# Unit tests only
pytest -m unit -v

# With coverage report
pytest --cov=. --cov-report=html
```

### 3. View Coverage
```bash
open htmlcov/index.html
```

---

## Key Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Main pytest & coverage configuration |
| `tests/conftest.py` | Fixtures and pytest hooks |
| `PYTEST_COVERAGE_CONFIG.md` | Configuration reference (1,200+ words) |
| `tests/TESTING_MARKERS_GUIDE.md` | Complete markers guide (2,500+ words) |
| `CONFIGURATION_SUMMARY.md` | Implementation summary (1,500+ words) |
| `tests/unit/test_markers_example.py` | 17 working example tests |
| `validate_pytest_config.sh` | Configuration validator |

---

## Test Categories

```
@pytest.mark.unit         - Fast unit tests (< 1 second each)
@pytest.mark.integration  - Integration tests (1-5 seconds each)
@pytest.mark.slow         - Slow tests (> 1 second)
@pytest.mark.api          - API endpoint tests
@pytest.mark.database     - Database interaction tests
@pytest.mark.async        - Asynchronous tests
```

---

## Common Commands

```bash
# Run fast tests (pre-commit)
pytest -m "not slow"

# Run specific marker
pytest -m unit -v

# Combine markers
pytest -m "api and not slow"

# With coverage
pytest --cov=. --cov-report=html --cov-report=term-missing

# Stop on first failure
pytest -x

# Run last failed tests
pytest --lf

# See what tests would run
pytest --collect-only
```

---

## Configuration Highlights

### Coverage Enforcement
```toml
# pyproject.toml
[tool.coverage.report]
fail_under = 80  # FAIL if coverage < 80%
```

### Test Markers
```toml
markers = [
    "unit: Unit tests for individual functions/classes",
    "integration: Integration tests for service interactions",
    "slow: Slow running tests (>1s execution time)",
    "api: API endpoint tests",
    "database: Database interaction tests",
    "async: Asynchronous tests",
]
```

### Pytest Options
```toml
addopts = [
    "--cov=.",                          # Coverage all files
    "--cov-report=html",                # HTML report
    "--cov-report=term-missing:skip-covered",  # Terminal
    "--cov-fail-under=80",              # FAIL if < 80%
    "-v",                               # Verbose
    "--strict-markers",                 # Enforce markers
]
```

---

## Auto-Marking by Directory

Tests are automatically marked based on location:

```
tests/
├── unit/            → @pytest.mark.unit
├── integration/     → @pytest.mark.integration
└── load/            → @pytest.mark.slow
```

No need to add decorators if you organize by directory!

---

## Examples

### Unit Test
```python
@pytest.mark.unit
def test_validate_rut():
    from utils.validators import validate_rut
    assert validate_rut("12.345.678-9") is True
```

### Integration Test
```python
@pytest.mark.integration
def test_dte_api_endpoint(client):
    response = client.post("/api/v1/dte/create", json={...})
    assert response.status_code == 200
```

### Slow Test
```python
@pytest.mark.slow
@pytest.mark.integration
def test_bulk_processing():
    # Takes 10+ seconds
    result = process_1000_items()
    assert len(result) == 1000
```

---

## Coverage Report

After running tests with coverage:

```bash
pytest --cov=. --cov-report=html
```

Reports generated:
- `htmlcov/index.html` - Visual coverage analysis
- `.coverage.json` - CI/CD integration
- Console output - Quick feedback

---

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run tests with coverage
  run: |
    cd ai-service
    pytest -m "not slow" --cov-fail-under=80
```

---

## Documentation

Comprehensive guides available:

1. **PYTEST_COVERAGE_CONFIG.md** (1,200+ words)
   - Detailed configuration reference
   - Verification commands
   - Enterprise standards

2. **TESTING_MARKERS_GUIDE.md** (2,500+ words)
   - Complete marker usage guide
   - Examples for each marker
   - Advanced patterns

3. **CONFIGURATION_SUMMARY.md** (1,500+ words)
   - Implementation overview
   - Quality gates
   - Next steps

---

## Troubleshooting

### "Unknown pytest.mark.xxx"
All markers must be registered in pyproject.toml. Check:
```bash
pytest --markers
```

### "Coverage below 80%"
See uncovered lines:
```bash
pytest --cov=. --cov-report=term-missing
```

### "Tests are slow"
Run only fast tests:
```bash
pytest -m "not slow"
```

---

## Status

| Component | Status |
|-----------|--------|
| Configuration | ✅ Complete |
| Documentation | ✅ Complete (5,200+ words) |
| Examples | ✅ Complete (17 tests) |
| Validation Tool | ✅ Complete |
| CI/CD Ready | ✅ Yes |
| Production Ready | ✅ Yes |

---

**Start here:** Run `bash validate_pytest_config.sh` to verify everything is set up correctly.

For more details, see `TESTING_MARKERS_GUIDE.md` or `PYTEST_COVERAGE_CONFIG.md`.
