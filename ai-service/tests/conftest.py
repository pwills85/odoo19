# -*- coding: utf-8 -*-
"""
Pytest Configuration and Fixtures

This file contains pytest configuration, fixtures, and hooks
for the AI Service test suite.

Pytest automatically loads this file before running tests.

Enterprise-grade testing configuration with:
- Custom markers for test categorization (unit, integration, slow, api, database, async)
- Coverage enforcement (80% minimum)
- FastAPI test client for API testing
- Sample fixtures for DTE and chat testing
"""
import pytest
from fastapi.testclient import TestClient
import os
import sys
from typing import Generator, Any

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import app
from config import settings


@pytest.fixture
def client():
    """FastAPI test client"""
    return TestClient(app)


@pytest.fixture
def valid_api_key():
    """Valid API key for testing"""
    return settings.api_key


@pytest.fixture
def auth_headers(valid_api_key):
    """Authentication headers"""
    return {"Authorization": f"Bearer {valid_api_key}"}


@pytest.fixture
def sample_dte_data():
    """Sample DTE data for testing"""
    return {
        "dte_data": {
            "tipo_dte": "33",
            "folio": "12345",
            "fecha_emision": "2025-10-22",
            "rut_emisor": "12345678-9",
            "rut_receptor": "98765432-1",
            "monto_total": 119000,
            "monto_neto": 100000,
            "monto_iva": 19000,
            "items": [
                {
                    "nombre": "Producto Test",
                    "cantidad": 1,
                    "precio_unitario": 100000
                }
            ]
        },
        "company_id": 1,
        "history": []
    }


@pytest.fixture
def sample_chat_message():
    """Sample chat message for testing"""
    return {
        "message": "¿Cómo genero un DTE 33?",
        "user_context": {
            "company_name": "Test Company SpA",
            "company_rut": "12345678-9",
            "user_role": "Contador",
            "environment": "Sandbox",
            "module": "l10n_cl_dte"
        }
    }


# ==============================================================================
# PYTEST HOOKS: Custom test execution behavior and collection
# ==============================================================================


def pytest_configure(config: Any) -> None:
    """
    Configure pytest with custom settings during session startup.

    Called once at the beginning of test session.
    Additional markers can be registered here beyond those in pyproject.toml.
    """
    # Additional custom markers can be added here if needed
    config.addinivalue_line(
        "markers",
        "skip_on_ci: mark test to skip when running in CI environment",
    )
    config.addinivalue_line(
        "markers",
        "api: mark test as API endpoint test",
    )


def pytest_collection_modifyitems(config: Any, items: list) -> None:
    """
    Modify test collection to automatically mark tests based on location.

    This automatically marks tests with categories based on their file paths:
    - Tests in 'unit/' get @pytest.mark.unit
    - Tests in 'integration/' get @pytest.mark.integration
    """
    for item in items:
        # Auto-mark tests based on directory location
        if "integration" in str(item.fspath):
            if "integration" not in [marker.name for marker in item.iter_markers()]:
                item.add_marker(pytest.mark.integration)
        elif "unit" in str(item.fspath):
            if "unit" not in [marker.name for marker in item.iter_markers()]:
                item.add_marker(pytest.mark.unit)

        # Mark slow tests that might need timeout
        if "slow" in item.nodeid.lower() or "load" in str(item.fspath):
            if "slow" not in [marker.name for marker in item.iter_markers()]:
                item.add_marker(pytest.mark.slow)


def pytest_runtest_setup(item: Any) -> None:
    """
    Set up individual test execution before each test runs.

    Called before each test function is executed.
    Handles skipping tests based on certain conditions.
    """
    # Skip tests marked with skip_on_ci when CI environment is detected
    skip_on_ci = item.get_closest_marker("skip_on_ci")
    if skip_on_ci:
        if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
            pytest.skip("Skipped in CI environment")


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any) -> Generator:
    """
    Customize test reports with additional information.

    Called after each test completes.
    Adds marker information to the test report.
    """
    outcome = yield

    # Add custom properties to test report
    rep = outcome.get_result()
    if rep.when == "call":
        # Capture marker information for reporting
        markers = [marker.name for marker in item.iter_markers()]
        rep.markers = markers
