# -*- coding: utf-8 -*-
"""
Configuración pytest para DTE Service
Enhanced with comprehensive fixtures for testing
"""

import pytest
import sys
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock

# Agregar path del DTE service al PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ═══════════════════════════════════════════════════════════
# PYTEST CONFIGURATION
# ═══════════════════════════════════════════════════════════

def pytest_configure(config):
    """Configure pytest with custom settings"""
    os.environ['TESTING'] = 'true'
    os.environ['SII_ENVIRONMENT'] = 'sandbox'


# ═══════════════════════════════════════════════════════════
# SAMPLE DATA FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def sample_dte_xml():
    """XML de prueba para tests"""
    return """<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
    <Documento>
        <Encabezado>
            <IdDoc>
                <TipoDTE>33</TipoDTE>
                <Folio>1</Folio>
                <FchEmis>2025-10-21</FchEmis>
            </IdDoc>
            <Emisor>
                <RUTEmisor>76123456-K</RUTEmisor>
                <RznSoc>Test Company</RznSoc>
            </Emisor>
            <Receptor>
                <RUTRecep>12345678-5</RUTRecep>
                <RznSocRecep>Test Client</RznSocRecep>
            </Receptor>
            <Totales>
                <MntTotal>119000</MntTotal>
            </Totales>
        </Encabezado>
        <TED>
            <DD>
                <RE>76123456-K</RE>
                <TD>33</TD>
                <F>1</F>
                <FE>2025-10-21</FE>
                <RR>12345678-5</RR>
                <RSR>Test Client</RSR>
                <MNT>119000</MNT>
                <IT1>Test Item</IT1>
                <CAF>
                    <DA></DA>
                    <FRMA></FRMA>
                </CAF>
                <TSTED>2025-10-21T10:00:00</TSTED>
            </DD>
            <FRMT algoritmo="SHA1withRSA"></FRMT>
        </TED>
    </Documento>
</DTE>
"""


@pytest.fixture
def sample_invoice_data():
    """Datos de factura de prueba"""
    return {
        "dte_type": "33",
        "invoice_data": {
            "folio": 1,
            "fecha_emision": "2025-10-21",
            "emisor": {
                "rut": "76123456-K",
                "razon_social": "Test Company",
                "giro": "Servicios",
            },
            "receptor": {
                "rut": "12345678-5",
                "razon_social": "Test Client",
            },
            "totales": {
                "monto_neto": 100000,
                "iva": 19000,
                "monto_total": 119000,
            },
        },
    }


@pytest.fixture
def sample_caf_xml():
    """Sample CAF XML for testing"""
    return """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
    <CAF version="1.0">
        <DA>
            <RE>76123456-K</RE>
            <RS>TEST COMPANY SPA</RS>
            <TD>33</TD>
            <RNG><D>1</D><H>1000</H></RNG>
            <FA>2025-01-01</FA>
        </DA>
        <FRMA>signature_data_here</FRMA>
    </CAF>
</AUTORIZACION>"""


# ═══════════════════════════════════════════════════════════
# MOCK FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def mock_sii_client():
    """Mock SII SOAP client"""
    client = Mock()
    client.send_dte = Mock(return_value={
        'success': True,
        'track_id': 'TEST_TRACK_123',
        'status': 'sent',
        'response_xml': '<SII>OK</SII>',
        'duration_ms': 1234
    })
    client.query_status = Mock(return_value={
        'success': True,
        'track_id': 'TEST_TRACK_123',
        'status': 'accepted',
        'response_xml': '<SII>ACCEPTED</SII>'
    })
    return client


@pytest.fixture
def mock_redis_client():
    """Mock Redis client"""
    redis = Mock()
    redis._data = {}

    def mock_get(key):
        return redis._data.get(key)
    redis.get = Mock(side_effect=mock_get)

    def mock_set(key, value, ex=None):
        redis._data[key] = value
        return True
    redis.set = Mock(side_effect=mock_set)

    def mock_setex(key, time, value):
        redis._data[key] = value
        return True
    redis.setex = Mock(side_effect=mock_setex)

    def mock_delete(key):
        if key in redis._data:
            del redis._data[key]
        return True
    redis.delete = Mock(side_effect=mock_delete)

    def mock_keys(pattern):
        import fnmatch
        return [k for k in redis._data.keys() if fnmatch.fnmatch(k, pattern)]
    redis.keys = Mock(side_effect=mock_keys)

    return redis


@pytest.fixture
async def mock_rabbitmq_client():
    """Mock RabbitMQ client"""
    client = AsyncMock()
    client._published = []

    async def mock_publish(exchange, routing_key, message, **kwargs):
        client._published.append({
            'exchange': exchange,
            'routing_key': routing_key,
            'message': message
        })
        return True
    client.publish = AsyncMock(side_effect=mock_publish)
    client.connect = AsyncMock(return_value=True)
    client.close = AsyncMock(return_value=True)

    return client


# ═══════════════════════════════════════════════════════════
# PARAMETRIZE FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture(params=['33', '34', '52', '56', '61'])
def dte_type(request):
    """Parametrized fixture for all DTE types"""
    return request.param


# ═══════════════════════════════════════════════════════════
# UTILITY FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def freeze_time():
    """Freeze time for consistent testing"""
    return datetime(2025, 10, 21, 12, 0, 0)
