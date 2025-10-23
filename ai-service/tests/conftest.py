# -*- coding: utf-8 -*-
"""
Pytest Configuration and Fixtures
"""
import pytest
from fastapi.testclient import TestClient
import os
import sys

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
