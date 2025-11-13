# Testing Markers Guide - AI Service

**Last Updated:** 2025-11-09
**Configuration Version:** Enterprise-grade pytest + coverage

---

## Overview

The AI Service test suite uses pytest markers to categorize and run tests selectively. All markers are defined in `pyproject.toml` and automatically enforced with `--strict-markers`.

---

## Available Markers

### 1. `@pytest.mark.unit`
**Purpose:** Unit tests for individual functions/classes
**Use case:** Testing business logic in isolation
**Scope:** Fast execution (< 1 second per test)
**Database:** No database access
**External APIs:** Mocked

**Example:**
```python
import pytest

@pytest.mark.unit
def test_validate_rut():
    """Test RUT validation algorithm"""
    from utils.validators import validate_rut
    assert validate_rut("12.345.678-9") is True
    assert validate_rut("12.345.678-0") is False
```

**Run unit tests only:**
```bash
pytest -m unit
```

---

### 2. `@pytest.mark.integration`
**Purpose:** Integration tests for service interactions
**Use case:** Testing multiple components working together
**Scope:** Moderate execution (1-5 seconds per test)
**Database:** May use test database
**External APIs:** Partially mocked or using test services

**Example:**
```python
import pytest

@pytest.mark.integration
def test_create_dte_invoice(client, auth_headers, sample_dte_data):
    """Test DTE creation via API"""
    response = client.post(
        "/api/v1/dte/create",
        json=sample_dte_data,
        headers=auth_headers
    )
    assert response.status_code == 200
    assert "dte_id" in response.json()
```

**Run integration tests only:**
```bash
pytest -m integration
```

---

### 3. `@pytest.mark.slow`
**Purpose:** Slow running tests (> 1 second execution time)
**Use case:** Performance tests, load tests, heavy processing
**Scope:** May take several seconds
**Database:** May access production-like database
**External APIs:** May call real services

**Example:**
```python
import pytest
import time

@pytest.mark.slow
def test_bulk_dte_processing():
    """Test processing 1000 DTEs"""
    # This test takes ~10 seconds
    result = process_bulk_dtes(count=1000)
    assert len(result) == 1000
```

**Run only slow tests:**
```bash
pytest -m slow
```

**Run everything EXCEPT slow tests (fast suite):**
```bash
pytest -m "not slow"
```

---

### 4. `@pytest.mark.api`
**Purpose:** API endpoint tests
**Use case:** Testing HTTP endpoints, request/response handling
**Scope:** Fast to moderate execution
**Database:** Test database only
**External APIs:** Mocked

**Example:**
```python
import pytest

@pytest.mark.api
def test_health_check_endpoint(client):
    """Test /health endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

@pytest.mark.api
def test_dte_validation_endpoint(client, sample_dte_data):
    """Test DTE validation endpoint"""
    response = client.post(
        "/api/v1/dte/validate",
        json=sample_dte_data
    )
    assert response.status_code == 200
```

**Run API tests:**
```bash
pytest -m api
```

---

### 5. `@pytest.mark.database`
**Purpose:** Database interaction tests
**Use case:** Testing ORM queries, migrations, data persistence
**Scope:** Moderate execution (1-3 seconds)
**Database:** Uses test database with transactions
**External APIs:** None

**Example:**
```python
import pytest

@pytest.mark.database
def test_save_dte_to_database(db_session):
    """Test saving DTE to database"""
    dte = DTE(
        tipo_dte=33,
        folio=12345,
        rut_emisor="12.345.678-9"
    )
    db_session.add(dte)
    db_session.commit()

    # Verify saved
    saved = db_session.query(DTE).filter_by(folio=12345).first()
    assert saved is not None
    assert saved.tipo_dte == 33
```

**Run database tests:**
```bash
pytest -m database
```

---

### 6. `@pytest.mark.async`
**Purpose:** Asynchronous tests
**Use case:** Testing async functions, async endpoints, concurrent operations
**Scope:** Varies by operation
**Database:** May use test database
**External APIs:** May call services

**Example:**
```python
import pytest

@pytest.mark.async
@pytest.mark.asyncio
async def test_async_dte_generation():
    """Test asynchronous DTE generation"""
    result = await generate_dte_async(
        tipo_dte=33,
        folio=12345
    )
    assert result["status"] == "success"
    assert result["dte_id"] > 0
```

**Run async tests:**
```bash
pytest -m async
```

---

## Test Organization Structure

```
tests/
├── __init__.py
├── conftest.py                    # Fixtures, hooks, configuration
├── pytest.ini                     # Pytest configuration (legacy)
├── TESTING_MARKERS_GUIDE.md      # This file
│
├── unit/                          # Unit tests (auto-marked)
│   ├── __init__.py
│   ├── test_validators.py         # RUT, email validators
│   ├── test_cost_tracker.py       # Cost tracking logic
│   ├── test_llm_helpers.py        # LLM utilities
│   └── test_plugin_system.py      # Plugin registration
│
├── integration/                   # Integration tests (auto-marked)
│   ├── __init__.py
│   ├── test_critical_endpoints.py # API integration
│   └── test_dte_regression.py     # DTE workflow
│
└── load/                          # Load tests (auto-marked as slow)
    ├── __init__.py
    ├── locustfile.py              # Locust load testing
    └── README.md
```

**Note:** Tests are automatically marked based on directory location:
- Files in `unit/` → `@pytest.mark.unit`
- Files in `integration/` → `@pytest.mark.integration`
- Files in `load/` → `@pytest.mark.slow`

---

## Common Test Combinations

### 1. Fast Test Suite (Ideal for CI/CD pre-commit)
```bash
# Run all tests EXCEPT slow ones
pytest -m "not slow" -v

# Expected execution time: < 30 seconds
```

### 2. Unit Tests Only (For rapid feedback during development)
```bash
# Run only unit tests
pytest -m unit -v

# Expected execution time: < 10 seconds
```

### 3. API Integration Tests
```bash
# Run API and integration tests
pytest -m "api or integration" -v

# Expected execution time: 15-30 seconds
```

### 4. Database Tests Only
```bash
# Test database interactions
pytest -m database -v

# Expected execution time: 10-20 seconds
```

### 5. Full Suite (CI/CD nightly builds)
```bash
# Run everything including slow tests
pytest -v

# Expected execution time: 2-5 minutes
```

### 6. Async Tests
```bash
# Run async operations
pytest -m async -v

# Expected execution time: Varies
```

---

## Running Tests with Coverage

### Generate Coverage Report
```bash
# Run all tests with coverage
pytest --cov=. --cov-report=html --cov-report=term-missing

# Check coverage is >= 80% (enforced)
# HTML report saved to: htmlcov/index.html
```

### Coverage by Test Category
```bash
# Coverage for unit tests only
pytest -m unit --cov=. --cov-report=term-missing

# Coverage for integration tests only
pytest -m integration --cov=. --cov-report=term-missing
```

### View Coverage Reports
```bash
# Open HTML coverage report in browser
open htmlcov/index.html

# Or view JSON coverage data
cat .coverage.json
```

---

## Advanced Marker Usage

### Combine Multiple Markers
```bash
# Run unit OR integration tests (both)
pytest -m "unit or integration"

# Run API tests that are NOT slow
pytest -m "api and not slow"

# Run (unit OR integration) AND NOT slow
pytest -m "(unit or integration) and not slow"
```

### Exclude Specific Markers
```bash
# Run everything EXCEPT slow tests
pytest -m "not slow"

# Run everything EXCEPT database tests
pytest -m "not database"

# Run everything EXCEPT async tests
pytest -m "not async"
```

### Check Available Markers
```bash
# List all registered markers
pytest --markers

# Expected output:
# @pytest.mark.unit: Unit tests for individual functions/classes
# @pytest.mark.integration: Integration tests for service interactions
# @pytest.mark.slow: Slow running tests (>1s execution time)
# @pytest.mark.api: API endpoint tests
# @pytest.mark.database: Database interaction tests
# @pytest.mark.async: Asynchronous tests
```

---

## Test Example Files

### Example 1: Unit Test
**File:** `tests/unit/test_validators.py`
```python
import pytest
from utils.validators import validate_rut

@pytest.mark.unit
def test_validate_rut_correct_format():
    """Test valid RUT format"""
    assert validate_rut("12.345.678-9") is True

@pytest.mark.unit
def test_validate_rut_incorrect_check_digit():
    """Test RUT with incorrect check digit"""
    assert validate_rut("12.345.678-0") is False

@pytest.mark.unit
def test_validate_rut_missing_dash():
    """Test RUT without dash"""
    assert validate_rut("123456789") is False
```

**Run:**
```bash
pytest tests/unit/test_validators.py -v
pytest tests/unit/test_validators.py::test_validate_rut_correct_format
pytest -m unit tests/unit/test_validators.py
```

---

### Example 2: Integration Test
**File:** `tests/integration/test_critical_endpoints.py`
```python
import pytest

@pytest.mark.integration
def test_dte_creation_workflow(client, auth_headers, sample_dte_data):
    """Test complete DTE creation workflow"""
    # 1. Create DTE
    response = client.post(
        "/api/v1/dte/create",
        json=sample_dte_data,
        headers=auth_headers
    )
    assert response.status_code == 200
    dte_id = response.json()["dte_id"]

    # 2. Get DTE
    response = client.get(
        f"/api/v1/dte/{dte_id}",
        headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["id"] == dte_id

    # 3. Validate DTE
    response = client.post(
        f"/api/v1/dte/{dte_id}/validate",
        headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True

@pytest.mark.integration
@pytest.mark.slow
def test_bulk_dte_processing(client, auth_headers):
    """Test bulk DTE processing (slow operation)"""
    # Process 100 DTEs
    dtes = [create_sample_dte(i) for i in range(100)]
    response = client.post(
        "/api/v1/dte/bulk-process",
        json={"dtes": dtes},
        headers=auth_headers
    )
    assert response.status_code == 200
    assert len(response.json()["processed"]) == 100
```

**Run:**
```bash
pytest tests/integration/ -v
pytest -m integration tests/integration/
pytest -m "integration and not slow"
```

---

### Example 3: API Test with Markers
**File:** `tests/test_api_health.py`
```python
import pytest

@pytest.mark.unit
@pytest.mark.api
def test_health_endpoint_unit(client):
    """Unit test for health endpoint"""
    response = client.get("/health")
    assert response.status_code == 200

@pytest.mark.integration
@pytest.mark.api
def test_health_endpoint_integration(client, auth_headers):
    """Integration test with auth headers"""
    response = client.get("/health", headers=auth_headers)
    assert response.status_code == 200
    assert "timestamp" in response.json()
```

---

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r tests/requirements-test.txt

      - name: Run fast tests (pre-commit)
        run: cd ai-service && pytest -m "not slow" -v

      - name: Generate coverage report
        run: cd ai-service && pytest --cov=. --cov-report=json

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./ai-service/.coverage.json
          fail_ci_if_error: true

      - name: Run full test suite (nightly)
        if: github.event_name == 'schedule'
        run: cd ai-service && pytest -v
```

---

## Best Practices

### 1. Always Mark Your Tests
```python
# GOOD
@pytest.mark.unit
def test_my_function():
    pass

# BAD - Test won't be marked or categorized
def test_my_function():
    pass
```

### 2. Use Appropriate Marker for Your Test
```python
# GOOD - Unit test for a function
@pytest.mark.unit
def test_rut_validator():
    assert validate_rut("12.345.678-9") is True

# GOOD - Integration test for API
@pytest.mark.integration
def test_dte_api_endpoint(client):
    response = client.post("/api/v1/dte/create", json={...})
    assert response.status_code == 200

# AVOID - Wrong marker for test type
@pytest.mark.integration  # <-- Unit tests shouldn't be integration
def test_simple_math():
    assert 2 + 2 == 4
```

### 3. Use Multiple Markers When Needed
```python
# GOOD - Test is both API and slow
@pytest.mark.api
@pytest.mark.slow
def test_bulk_dte_processing():
    pass

# GOOD - Test is unit, but specifically for API-related logic
@pytest.mark.unit
@pytest.mark.api
def test_api_request_validation():
    pass
```

### 4. Run Fast Tests Frequently
```bash
# During development - run fast tests only
pytest -m "not slow" -v

# After major changes - run full suite
pytest -v

# Before commit - run fast tests + coverage check
pytest -m "not slow" --cov=. --cov-report=term-missing
```

### 5. Use Fixtures for Common Setup
```python
# conftest.py already provides:
# - client: FastAPI TestClient
# - auth_headers: Authorization headers
# - sample_dte_data: Sample DTE document
# - sample_chat_message: Sample chat message

# Use them in your tests:
@pytest.mark.api
def test_with_fixtures(client, auth_headers, sample_dte_data):
    response = client.post(
        "/api/v1/dte/create",
        json=sample_dte_data,
        headers=auth_headers
    )
    assert response.status_code == 200
```

---

## Troubleshooting

### "Unknown pytest.mark.xxx" Error
**Cause:** Marker not registered in pyproject.toml
**Solution:**
```bash
# Check registered markers
pytest --markers

# Add to pyproject.toml:
# [tool.pytest.ini_options]
# markers = [
#     "mymarker: My custom marker"
# ]
```

### "--strict-markers" Enforcement
**Cause:** Using undefined markers
**Solution:** All markers must be in `pyproject.toml`
```python
# This will FAIL with --strict-markers:
@pytest.mark.undefined_marker  # Not in pyproject.toml
def test_something():
    pass

# This will PASS:
@pytest.mark.unit  # Defined in pyproject.toml
def test_something():
    pass
```

### Coverage Below 80%
**Cause:** Not enough tests written
**Solution:**
```bash
# See which lines aren't covered
pytest --cov=. --cov-report=term-missing

# View HTML report
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

---

## Summary

| Marker | Purpose | Speed | Database | When to Use |
|--------|---------|-------|----------|-------------|
| `unit` | Test individual functions | Fast | No | Core business logic |
| `integration` | Test multiple components | Medium | Maybe | Service interactions |
| `slow` | Performance/load tests | Slow | Maybe | Heavy processing |
| `api` | HTTP endpoint tests | Fast-Medium | No | REST endpoints |
| `database` | DB interaction tests | Medium | Yes | ORM/persistence |
| `async` | Async function tests | Varies | Maybe | Concurrent operations |

---

**Configuration Ready:** ✅ All markers configured in `pyproject.toml`
**Coverage Threshold:** ✅ 80% minimum enforced
**CI/CD Ready:** ✅ Production-grade configuration
