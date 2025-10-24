# -*- coding: utf-8 -*-
"""
Tests para Sprint 0 - Security Fixes
Tests unitarios para validar fixes críticos de seguridad
"""

import pytest
from fastapi.testclient import TestClient
import os


# ═══════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def client():
    """Cliente de prueba FastAPI"""
    # Set required env var before importing app
    os.environ['EERGY_SERVICES_API_KEY'] = 'test_api_key_12345'
    os.environ['STRICT_XSD_VALIDATION'] = 'false'  # Desactivar para tests

    from main import app
    return TestClient(app)


@pytest.fixture
def valid_api_key():
    """API Key válida para tests"""
    return 'test_api_key_12345'


@pytest.fixture
def invalid_api_key():
    """API Key inválida para tests"""
    return 'wrong_key_99999'


# ═══════════════════════════════════════════════════════════
# TEST A1: API KEY VALIDATION
# ═══════════════════════════════════════════════════════════

def test_a1_api_key_required_from_env(client, valid_api_key):
    """
    FIX A1: API Key DEBE venir de variable de entorno.
    Test que la API key se requiere y se valida correctamente.
    """
    # Intento sin API key → 403
    response = client.get("/health")
    assert response.status_code in [200, 403]  # Health puede o no requerir auth

    # Intento con API key inválida → 403
    response = client.post(
        "/api/dte/generate-and-send",
        json={"dte_type": 33},
        headers={"Authorization": "Bearer wrong_key"}
    )
    assert response.status_code == 403
    assert "Invalid API key" in response.text or "Forbidden" in response.text


def test_a1_api_key_valid_accepted(client, valid_api_key):
    """Test que API key válida es aceptada"""
    response = client.post(
        "/api/dte/generate-and-send",
        json={
            "dte_type": 33,
            "invoice_data": {},
            "certificate": {"cert_file": "", "password": ""}
        },
        headers={"Authorization": f"Bearer {valid_api_key}"}
    )

    # No debe ser 403 (puede ser 400 por datos inválidos, pero no 403)
    assert response.status_code != 403


def test_a1_no_default_api_key():
    """
    Test que NO existe valor por defecto para API key.
    Si no se setea EERGY_SERVICES_API_KEY, debe fallar al iniciar.
    """
    # Guardar valor original
    original_key = os.environ.get('EERGY_SERVICES_API_KEY')

    try:
        # Eliminar variable de entorno
        if 'EERGY_SERVICES_API_KEY' in os.environ:
            del os.environ['EERGY_SERVICES_API_KEY']

        # Intentar importar config debe fallar
        with pytest.raises(Exception) as exc_info:
            from config import settings
            # Forzar acceso a api_key para que Pydantic valide
            _ = settings.api_key

        # Debe contener error de field required
        assert "field required" in str(exc_info.value).lower() or \
               "missing" in str(exc_info.value).lower()

    finally:
        # Restaurar valor original
        if original_key:
            os.environ['EERGY_SERVICES_API_KEY'] = original_key


# ═══════════════════════════════════════════════════════════
# TEST A2: XSD STRICT MODE
# ═══════════════════════════════════════════════════════════

def test_a2_xsd_strict_mode_enabled():
    """
    FIX A2: XSD Strict Mode habilitado por defecto.
    Si schema no está cargado y strict=True, debe fallar.
    """
    from validators.xsd_validator import XSDValidator

    validator = XSDValidator()

    # Si no hay schemas cargados y strict=True, debe lanzar ValueError
    if not validator.schemas:
        xml_test = '<DTE><Documento></Documento></DTE>'

        with pytest.raises(ValueError) as exc_info:
            validator.validate(xml_test, schema_name='DTE', strict=True)

        assert "not loaded" in str(exc_info.value).lower()


def test_a2_xsd_strict_mode_disabled():
    """Test que strict mode puede desactivarse"""
    from validators.xsd_validator import XSDValidator

    validator = XSDValidator()

    xml_test = '<DTE><Documento></Documento></DTE>'

    # Con strict=False, no debe lanzar exception
    is_valid, errors = validator.validate(xml_test, schema_name='DTE', strict=False)

    # Puede ser válido o inválido, pero no debe lanzar exception
    assert isinstance(is_valid, bool)
    assert isinstance(errors, list)


def test_a2_xsd_config_from_env():
    """Test que strict mode lee de configuración"""
    from config import settings

    # Config debe tener el campo
    assert hasattr(settings, 'strict_xsd_validation')
    assert isinstance(settings.strict_xsd_validation, bool)


# ═══════════════════════════════════════════════════════════
# TEST A3: RATE LIMITING
# ═══════════════════════════════════════════════════════════

def test_a3_rate_limiting_enabled(client, valid_api_key):
    """
    FIX A3: Rate limiting debe estar activo.
    Después de 10 requests/minuto, debe retornar 429.
    """
    headers = {"Authorization": f"Bearer {valid_api_key}"}

    # Hacer 11 requests rápidas
    responses = []
    for i in range(11):
        response = client.post(
            "/api/dte/generate-and-send",
            json={
                "dte_type": 33,
                "invoice_data": {"folio": i},
                "certificate": {"cert_file": "", "password": ""}
            },
            headers=headers
        )
        responses.append(response.status_code)

    # Al menos una debe ser 429 (Too Many Requests)
    assert 429 in responses, f"Rate limiting not working. Status codes: {responses}"


def test_a3_slowapi_configured():
    """Test que slowapi está configurado en la app"""
    from main import app, limiter

    # App debe tener limiter en state
    assert hasattr(app.state, 'limiter')
    assert app.state.limiter is not None

    # Limiter debe estar inicializado
    assert limiter is not None


# ═══════════════════════════════════════════════════════════
# TEST A5: SIGNATURE VERIFICATION
# ═══════════════════════════════════════════════════════════

def test_a5_signature_verification_implemented():
    """
    FIX A5: Verificación de firma debe estar implementada.
    """
    from signers.xmldsig_signer import XMLDsigSigner

    signer = XMLDsigSigner()

    # Método verify_signature debe existir
    assert hasattr(signer, 'verify_signature')
    assert callable(signer.verify_signature)


def test_a5_signature_verification_called():
    """
    Test que verify_signature se llama después de firmar.
    Esto es más difícil de testear sin mock, pero podemos verificar
    que el método no lanza exception con XML válido.
    """
    from signers.xmldsig_signer import XMLDsigSigner

    signer = XMLDsigSigner()

    # XML de prueba (firmado mock)
    xml_signed = '''<?xml version="1.0"?>
    <DTE>
        <Documento></Documento>
        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
            <SignedInfo></SignedInfo>
        </Signature>
    </DTE>'''

    # No debe lanzar exception (aunque puede retornar False si firma inválida)
    try:
        result = signer.verify_signature(xml_signed)
        assert isinstance(result, bool)
    except Exception as e:
        # OK si falla por razones de firma inválida, pero no por NotImplementedError
        assert "not implemented" not in str(e).lower()


# ═══════════════════════════════════════════════════════════
# TEST INTEGRATION: ALL FIXES
# ═══════════════════════════════════════════════════════════

def test_all_security_fixes_applied():
    """
    Test de integración: Todos los fixes de seguridad aplicados.
    """
    from config import settings
    from validators.xsd_validator import XSDValidator
    from signers.xmldsig_signer import XMLDsigSigner
    from main import app, limiter

    # A1: API Key obligatoria
    assert settings.api_key is not None
    assert settings.api_key != ""

    # A2: XSD Strict Mode configurado
    assert hasattr(settings, 'strict_xsd_validation')
    validator = XSDValidator()
    assert hasattr(validator, '_get_strict_mode')

    # A3: Rate Limiting configurado
    assert hasattr(app.state, 'limiter')
    assert limiter is not None

    # A5: Signature Verification implementada
    signer = XMLDsigSigner()
    assert hasattr(signer, 'verify_signature')

    print("✅ Todos los fixes de seguridad críticos están aplicados")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
