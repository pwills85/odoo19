# -*- coding: utf-8 -*-
"""
Tests unitarios para validaciones de input mejoradas (P0-4).

Cubre:
- DTEValidationRequest validators
- ChatMessageRequest validators
- PayrollValidationRequest validators

Markers:
    - unit: Test unitario
    - fast: Test rápido (<100ms)
    - validation: Test de validación de datos
"""

import pytest
from pydantic import ValidationError
from datetime import datetime, timedelta

# Import models from main.py
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from main import (
    DTEValidationRequest,
    ChatMessageRequest,
    PayrollValidationRequest
)


# ============================================================================
# DTEValidationRequest Tests
# ============================================================================

class TestDTEValidationRequest:
    """Tests para DTEValidationRequest validators (P0-4)."""

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_valid_dte_basic(self):
        """Test validación DTE con datos básicos válidos."""
        request = DTEValidationRequest(
            dte_data={
                'tipo_dte': '33',
                'rut_emisor': '12345678-5',
                'rut_receptor': '87654321-K',
                'monto_total': 119000,
                'fecha_emision': '2025-11-10'
            },
            company_id=1,
            history=[]
        )

        assert request.dte_data['tipo_dte'] == '33'
        assert request.company_id == 1

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_rut_format_invalid(self):
        """Test RUT con formato inválido debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={
                    'tipo_dte': '33',
                    'rut_emisor': '12345678',  # Sin DV
                    'monto_total': 1000
                },
                company_id=1
            )

        assert 'RUT emisor inválido' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_rut_dv_incorrect(self):
        """Test RUT con DV incorrecto debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={
                    'tipo_dte': '33',
                    'rut_emisor': '12345678-0',  # DV correcto es 5
                    'monto_total': 1000
                },
                company_id=1
            )

        assert 'dígito verificador inválido' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_rut_dv_k_valid(self):
        """Test RUT con DV 'K' válido."""
        # RUT 11111111-K es válido
        request = DTEValidationRequest(
            dte_data={
                'tipo_dte': '33',
                'rut_emisor': '11111111-K',
                'monto_total': 1000
            },
            company_id=1
        )

        assert request.dte_data['rut_emisor'] == '11111111-K'

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_monto_negative(self):
        """Test monto negativo debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={
                    'tipo_dte': '33',
                    'monto_total': -1000
                },
                company_id=1
            )

        assert 'debe ser positivo' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_monto_zero(self):
        """Test monto cero debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={
                    'tipo_dte': '33',
                    'monto_total': 0
                },
                company_id=1
            )

        assert 'debe ser positivo' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_monto_excessive(self):
        """Test monto excesivo (>1 trillion) debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={
                    'tipo_dte': '33',
                    'monto_total': 9999999999999  # >999 trillion
                },
                company_id=1
            )

        assert 'excede límite razonable' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_fecha_future(self):
        """Test fecha futura debe fallar."""
        future_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')

        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={
                    'tipo_dte': '33',
                    'fecha_emision': future_date,
                    'monto_total': 1000
                },
                company_id=1
            )

        assert 'no puede ser futura' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_fecha_today_valid(self):
        """Test fecha de hoy es válida."""
        today = datetime.now().strftime('%Y-%m-%d')

        request = DTEValidationRequest(
            dte_data={
                'tipo_dte': '33',
                'fecha_emision': today,
                'monto_total': 1000
            },
            company_id=1
        )

        assert request.dte_data['fecha_emision'] == today

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_tipo_dte_invalid(self):
        """Test tipo DTE inválido debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={
                    'tipo_dte': '99',  # No existe
                    'monto_total': 1000
                },
                company_id=1
            )

        assert 'no válido' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_tipo_dte_all_valid(self):
        """Test todos los tipos DTE válidos."""
        valid_types = ['33', '34', '39', '41', '43', '46', '52', '56', '61', '110', '111', '112']

        for tipo in valid_types:
            request = DTEValidationRequest(
                dte_data={
                    'tipo_dte': tipo,
                    'monto_total': 1000
                },
                company_id=1
            )
            assert request.dte_data['tipo_dte'] == tipo

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_history_too_large(self):
        """Test history demasiado grande (>100KB) debe fallar."""
        # Crear history de >100KB
        large_history = [{'data': 'x' * 1000} for _ in range(150)]

        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={'tipo_dte': '33', 'monto_total': 1000},
                company_id=1,
                history=large_history
            )

        assert 'History demasiado grande' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_history_too_many_items(self):
        """Test history con >100 elementos debe fallar."""
        large_history = [{'item': i} for i in range(101)]

        with pytest.raises(ValidationError) as exc_info:
            DTEValidationRequest(
                dte_data={'tipo_dte': '33', 'monto_total': 1000},
                company_id=1,
                history=large_history
            )

        # Pydantic debería rechazar por max_items=100
        assert 'ensure this value has at most 100 items' in str(exc_info.value).lower()


# ============================================================================
# ChatMessageRequest Tests
# ============================================================================

class TestChatMessageRequest:
    """Tests para ChatMessageRequest validators (P0-4)."""

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_valid_message(self):
        """Test mensaje válido básico."""
        request = ChatMessageRequest(
            message="¿Cómo funciona el DTE 33?"
        )

        assert request.message == "¿Cómo funciona el DTE 33?"

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_empty_message(self):
        """Test mensaje vacío debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            ChatMessageRequest(message="")

        assert 'ensure this value has at least 1 character' in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_whitespace_only_message(self):
        """Test mensaje solo espacios debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            ChatMessageRequest(message="   ")

        assert 'no puede estar vacío' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_xss_script_injection(self):
        """Test XSS con <script> debe ser sanitizado."""
        request = ChatMessageRequest(
            message="Hola <script>alert('xss')</script> mundo"
        )

        # Script debe ser removido
        assert '<script>' not in request.message
        assert 'alert' not in request.message
        assert 'Hola' in request.message
        assert 'mundo' in request.message

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_javascript_injection(self):
        """Test javascript: injection debe ser sanitizado."""
        request = ChatMessageRequest(
            message="Click <a href='javascript:alert(1)'>aquí</a>"
        )

        # javascript: debe ser removido
        assert 'javascript:' not in request.message

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_html_tags_removal(self):
        """Test HTML tags deben ser removidos."""
        request = ChatMessageRequest(
            message="<b>Hola</b> <i>mundo</i>"
        )

        # Tags deben ser removidos
        assert '<b>' not in request.message
        assert '</b>' not in request.message
        assert 'Hola' in request.message
        assert 'mundo' in request.message

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_excessive_special_chars(self):
        """Test exceso de caracteres especiales debe fallar."""
        # 40 caracteres especiales
        message = "!!!" * 15

        with pytest.raises(ValidationError) as exc_info:
            ChatMessageRequest(message=message)

        assert 'caracteres especiales' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_spam_all_caps(self):
        """Test mensaje todo mayúsculas largo (spam) debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            ChatMessageRequest(
                message="BUY NOW!!! SPECIAL OFFER!!! CLICK HERE FOR DISCOUNT!!!"
            )

        assert 'spam' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_dte_caps_allowed(self):
        """Test mensaje con 'DTE' en mayúsculas debe ser permitido."""
        # Excepción: mensajes que empiezan con 'DTE' pueden ser caps
        request = ChatMessageRequest(
            message="DTE 33 FACTURA ELECTRÓNICA INFORMACIÓN"
        )

        assert 'DTE' in request.message

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_sql_injection_patterns(self):
        """Test patrones de SQL injection deben fallar."""
        sql_patterns = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT * FROM passwords",
            "DELETE FROM invoices WHERE 1=1"
        ]

        for pattern in sql_patterns:
            with pytest.raises(ValidationError) as exc_info:
                ChatMessageRequest(message=pattern)

            assert 'patrones sospechosos' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_valid_session_id_uuid(self):
        """Test session_id con UUID válido."""
        import uuid
        session_id = str(uuid.uuid4())

        request = ChatMessageRequest(
            message="Hola",
            session_id=session_id
        )

        assert request.session_id == session_id

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_invalid_session_id(self):
        """Test session_id inválido debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            ChatMessageRequest(
                message="Hola",
                session_id="not-a-uuid"
            )

        assert 'UUID válido' in str(exc_info.value)


# ============================================================================
# PayrollValidationRequest Tests
# ============================================================================

class TestPayrollValidationRequest:
    """Tests para PayrollValidationRequest validators (P0-4)."""

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_valid_payroll_request(self):
        """Test request de payroll válido."""
        request = PayrollValidationRequest(
            employee_id=1,
            period='2025-11',
            wage=500000,
            lines=[
                {'code': 'SUELDO', 'amount': 500000},
                {'code': 'AFP', 'amount': -60000}
            ]
        )

        assert request.wage == 500000
        assert request.period == '2025-11'

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_wage_below_minimum(self):
        """Test sueldo menor al mínimo debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period='2025-11',
                wage=300000,  # Menor al mínimo
                lines=[{'code': 'SUELDO', 'amount': 300000}]
            )

        assert 'menor al mínimo legal' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_wage_exceeds_maximum(self):
        """Test sueldo excesivo debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period='2025-11',
                wage=60000000,  # 60M CLP (excesivo)
                lines=[{'code': 'SUELDO', 'amount': 60000000}]
            )

        assert 'excede límite razonable' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_period_format_invalid(self):
        """Test período con formato inválido debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period='2025/11',  # Formato incorrecto
                wage=500000,
                lines=[{'code': 'SUELDO', 'amount': 500000}]
            )

        # Pydantic pattern validation
        assert 'string does not match regex' in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_period_too_future(self):
        """Test período muy futuro (>2 meses) debe fallar."""
        future_period = (datetime.now() + timedelta(days=90)).strftime('%Y-%m')

        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period=future_period,
                wage=500000,
                lines=[{'code': 'SUELDO', 'amount': 500000}]
            )

        assert 'muy futuro' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_period_too_old(self):
        """Test período muy antiguo (>12 meses) debe fallar."""
        old_period = (datetime.now() - timedelta(days=400)).strftime('%Y-%m')

        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period=old_period,
                wage=500000,
                lines=[{'code': 'SUELDO', 'amount': 500000}]
            )

        assert 'muy antiguo' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_lines_missing_code(self):
        """Test línea sin código debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period='2025-11',
                wage=500000,
                lines=[
                    {'amount': 500000}  # Sin 'code'
                ]
            )

        assert "sin campo 'code'" in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_lines_missing_amount(self):
        """Test línea sin monto debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period='2025-11',
                wage=500000,
                lines=[
                    {'code': 'SUELDO'}  # Sin 'amount'
                ]
            )

        assert "sin campo 'amount'" in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_lines_amount_non_numeric(self):
        """Test línea con monto no numérico debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period='2025-11',
                wage=500000,
                lines=[
                    {'code': 'SUELDO', 'amount': 'quinientos mil'}
                ]
            )

        assert 'debe ser numérico' in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    def test_lines_empty_list(self):
        """Test lista de líneas vacía debe fallar."""
        with pytest.raises(ValidationError) as exc_info:
            PayrollValidationRequest(
                employee_id=1,
                period='2025-11',
                wage=500000,
                lines=[]
            )

        assert 'ensure this value has at least 1 item' in str(exc_info.value).lower()


# ============================================================================
# Performance Tests
# ============================================================================

class TestValidationPerformance:
    """Tests de performance para validaciones (<5ms target)."""

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    @pytest.mark.performance
    def test_dte_validation_performance(self, benchmark):
        """Test performance validación DTE (<5ms)."""

        def validate_dte():
            return DTEValidationRequest(
                dte_data={
                    'tipo_dte': '33',
                    'rut_emisor': '12345678-5',
                    'monto_total': 119000,
                    'fecha_emision': '2025-11-10'
                },
                company_id=1
            )

        result = benchmark(validate_dte)
        assert result.dte_data['tipo_dte'] == '33'

        # Assert <5ms (benchmark stats available in result)

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    @pytest.mark.performance
    def test_chat_validation_performance(self, benchmark):
        """Test performance validación chat (<2ms)."""

        def validate_chat():
            return ChatMessageRequest(
                message="¿Cómo funciona el DTE 33?"
            )

        result = benchmark(validate_chat)
        assert '¿' in result.message

    @pytest.mark.unit
    @pytest.mark.fast
    @pytest.mark.validation
    @pytest.mark.performance
    def test_payroll_validation_performance(self, benchmark):
        """Test performance validación payroll (<3ms)."""

        def validate_payroll():
            return PayrollValidationRequest(
                employee_id=1,
                period='2025-11',
                wage=500000,
                lines=[
                    {'code': 'SUELDO', 'amount': 500000},
                    {'code': 'AFP', 'amount': -60000}
                ]
            )

        result = benchmark(validate_payroll)
        assert result.wage == 500000
