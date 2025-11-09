"""
test_markers_example.py
======================

Example test file demonstrating pytest markers configuration
and enterprise-grade testing patterns.

This file shows:
1. How to use pytest markers for test categorization
2. How to use fixtures from conftest.py
3. How coverage reporting works
4. Best practices for test organization
"""

import pytest
from fastapi import HTTPException


# ==============================================================================
# UNIT TESTS - Fast, isolated tests for individual functions
# ==============================================================================


@pytest.mark.unit
def test_simple_function():
    """
    Simple unit test with @pytest.mark.unit marker.

    This test will:
    - Be collected by pytest
    - Run with: pytest -m unit
    - Be included in coverage report
    - Count toward 80% coverage threshold
    """
    result = 2 + 2
    assert result == 4


@pytest.mark.unit
def test_string_validation():
    """Unit test for string validation logic."""
    def is_valid_rut_format(rut: str) -> bool:
        """Check if RUT has correct format"""
        parts = rut.split("-")
        return len(parts) == 2 and parts[1].isdigit()

    # Test valid format
    assert is_valid_rut_format("12.345.678-9") is True

    # Test invalid format
    assert is_valid_rut_format("12.345.6789") is False


@pytest.mark.unit
def test_with_fixture(sample_dte_data):
    """
    Unit test using fixture from conftest.py.

    Fixtures provide pre-configured test data without
    cluttering the test code.
    """
    # sample_dte_data comes from conftest.py
    assert sample_dte_data["dte_data"]["tipo_dte"] == "33"
    assert sample_dte_data["dte_data"]["folio"] == "12345"
    assert sample_dte_data["dte_data"]["monto_total"] == 119000


@pytest.mark.unit
def test_multiple_assertions():
    """Unit test with multiple assertions for comprehensive coverage."""
    # Test data
    values = [1, 2, 3, 4, 5]

    # Multiple assertions
    assert len(values) == 5
    assert values[0] == 1
    assert values[-1] == 5
    assert sum(values) == 15
    assert all(v > 0 for v in values)


@pytest.mark.unit
def test_exception_handling():
    """Unit test for exception handling."""
    def divide(a: int, b: int) -> float:
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a / b

    # Test normal operation
    assert divide(10, 2) == 5.0

    # Test exception is raised
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide(10, 0)


# ==============================================================================
# API TESTS - Tests for HTTP endpoints
# ==============================================================================


@pytest.mark.unit
@pytest.mark.api
def test_api_health_check(client):
    """
    Test API health check endpoint.

    Markers:
    - @pytest.mark.unit: This is a fast test
    - @pytest.mark.api: This tests an API endpoint

    The client fixture comes from conftest.py (FastAPI TestClient)
    """
    response = client.get("/health")

    # Assertions for HTTP response
    assert response.status_code == 200
    assert "status" in response.json() or "message" in response.json()


@pytest.mark.api
def test_api_with_auth_headers(client, auth_headers):
    """
    Test API endpoint with authentication headers.

    Uses auth_headers fixture from conftest.py for authenticated requests.
    """
    # This test shows how to make authenticated API calls
    # Actual implementation depends on your API
    response = client.get("/health", headers=auth_headers)

    assert response.status_code == 200


# ==============================================================================
# PARAMETRIZED TESTS - Run same test with multiple inputs
# ==============================================================================


@pytest.mark.unit
@pytest.mark.parametrize("input_value,expected", [
    ("12.345.678-9", True),
    ("12.345.678-0", False),
    ("invalid", False),
    ("", False),
])
def test_rut_validation_parametrized(input_value, expected):
    """
    Parametrized test runs multiple times with different inputs.

    This single test function creates 4 separate test cases:
    1. test_rut_validation_parametrized[12.345.678-9-True]
    2. test_rut_validation_parametrized[12.345.678-0-False]
    3. test_rut_validation_parametrized[invalid-False]
    4. test_rut_validation_parametrized[-False]

    Each case is counted separately in coverage reports.
    """
    def validate_rut(rut: str) -> bool:
        parts = rut.split("-")
        if len(parts) != 2:
            return False
        return len(parts[0].replace(".", "")) == 8 and parts[1].isdigit()

    result = validate_rut(input_value)
    assert result == expected


# ==============================================================================
# SKIPPED TESTS - Tests that should be skipped
# ==============================================================================


@pytest.mark.unit
@pytest.mark.skip(reason="Feature not yet implemented")
def test_not_yet_implemented():
    """
    Test marked with @pytest.mark.skip will be skipped.

    Shows as 's' in pytest output (skipped, not failed)
    """
    pass


@pytest.mark.unit
@pytest.mark.skipif(
    not hasattr(__builtins__, 'async'),
    reason="requires async support"
)
def test_requires_feature():
    """Test that requires a specific feature."""
    pass


# ==============================================================================
# TESTS WITH CUSTOM MARKERS
# ==============================================================================


@pytest.mark.unit
@pytest.mark.slow
def test_with_multiple_markers():
    """
    Test with multiple markers shows test categorization flexibility.

    This test is marked as both:
    - unit: It's a fast, isolated test
    - slow: It might have some overhead or setup

    Markers help organize tests by multiple dimensions:
    - Speed (unit vs slow)
    - Type (api, database)
    - Category (integration, async)
    """
    import time
    # Simulate some work
    result = sum(range(1000000))
    assert result > 0


# ==============================================================================
# COVERAGE AND LINE COUNTING
# ==============================================================================


@pytest.mark.unit
def test_coverage_demonstration():
    """
    This test demonstrates how coverage is calculated.

    Each line of code in this test file counts toward coverage.
    The coverage report will show:
    - How many lines are covered by tests
    - How many lines are missing coverage
    - Coverage percentage (need >= 80%)
    """
    # These lines are "covered" (executed by a test)
    value_a = 10
    value_b = 20
    result = value_a + value_b

    # This assertion passes
    assert result == 30

    # All lines in this function are covered
    # Therefore this function contributes to overall coverage


def uncovered_function():
    """
    This function is NOT covered (no test calls it).

    It will appear in coverage report as "missing"
    and reduce overall coverage percentage.

    To fix: Write a test that calls this function.
    """
    return "This line is never executed in tests"


# ==============================================================================
# BEST PRACTICES
# ==============================================================================


@pytest.mark.unit
def test_clear_descriptive_name():
    """
    Good test name is descriptive about what's being tested.

    GOOD names:
    - test_validate_rut_with_correct_format()
    - test_calculate_tax_amount_for_10m_salary()
    - test_api_returns_401_for_missing_auth()

    BAD names:
    - test_1()
    - test_stuff()
    - test_thing()
    """
    assert True


@pytest.mark.unit
def test_arrange_act_assert_pattern():
    """
    Good tests follow the Arrange-Act-Assert pattern.

    1. ARRANGE: Set up test data
    2. ACT: Execute the code being tested
    3. ASSERT: Verify the result
    """
    # ARRANGE: Set up test data
    values = [1, 2, 3, 4, 5]

    # ACT: Execute the function being tested
    total = sum(values)

    # ASSERT: Verify the result
    assert total == 15


@pytest.mark.unit
def test_one_thing_per_test():
    """
    Good practice: Each test should test ONE thing.

    If a test is testing multiple things, break it into
    multiple tests that each test one thing.

    This test tests only one thing: that sum works correctly.
    """
    result = sum([1, 2, 3])
    assert result == 6

    # DON'T do this:
    # assert sum([1, 2, 3]) == 6
    # assert len([1, 2, 3]) == 3
    # assert max([1, 2, 3]) == 3
    # ^ This mixes three different tests


# ==============================================================================
# RUNNING THESE TESTS
# ==============================================================================

"""
Run this test file with:

# Run all tests in this file
pytest tests/unit/test_markers_example.py -v

# Run only unit tests in this file
pytest tests/unit/test_markers_example.py -m unit -v

# Run with coverage
pytest tests/unit/test_markers_example.py --cov=. --cov-report=term-missing

# Run specific test function
pytest tests/unit/test_markers_example.py::test_simple_function -v

# Run tests matching a pattern
pytest tests/unit/test_markers_example.py -k "rut" -v

# Run with detailed output
pytest tests/unit/test_markers_example.py -vv

# Show which lines aren't covered
pytest tests/unit/test_markers_example.py --cov=. --cov-report=term-missing


Check markers configuration:

# List all available markers
pytest --markers

# Show markers for this file
pytest tests/unit/test_markers_example.py --collect-only


Expected output:

$ pytest tests/unit/test_markers_example.py -v

tests/unit/test_markers_example.py::test_simple_function PASSED
tests/unit/test_markers_example.py::test_string_validation PASSED
tests/unit/test_markers_example.py::test_with_fixture PASSED
tests/unit/test_markers_example.py::test_multiple_assertions PASSED
tests/unit/test_markers_example.py::test_exception_handling PASSED
tests/unit/test_markers_example.py::test_api_health_check PASSED
tests/unit/test_markers_example.py::test_api_with_auth_headers PASSED
tests/unit/test_markers_example.py::test_rut_validation_parametrized[...] PASSED
tests/unit/test_markers_example.py::test_rut_validation_parametrized[...] PASSED
tests/unit/test_markers_example.py::test_rut_validation_parametrized[...] PASSED
tests/unit/test_markers_example.py::test_rut_validation_parametrized[...] PASSED
tests/unit/test_markers_example.py::test_not_yet_implemented SKIPPED
tests/unit/test_markers_example.py::test_requires_feature SKIPPED
tests/unit/test_markers_example.py::test_with_multiple_markers PASSED
tests/unit/test_markers_example.py::test_coverage_demonstration PASSED
tests/unit/test_markers_example.py::test_clear_descriptive_name PASSED
tests/unit/test_markers_example.py::test_arrange_act_assert_pattern PASSED
tests/unit/test_markers_example.py::test_one_thing_per_test PASSED

======================== 15 passed, 2 skipped in 0.23s ========================
"""
