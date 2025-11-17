# -*- coding: utf-8 -*-
"""
Tests para GAP-002: Integración Legal Caps con Economic Indicators

Valida que topes AFP/AFC se obtienen de tabla l10n_cl.legal.caps
sin valores hardcoded en hr_economic_indicators.py

Fix: 2025-11-09 GAP-002
Brecha identificada: Línea 225 hr_economic_indicators.py tenía fallback hardcoded 87.8 UF
Solución: Método _get_afp_cap_from_legal_table() consulta tabla exclusivamente

Referencias:
- HR-GAP-002: Eliminar hardcoding tope AFP
- Ley 20.255 Art. 17 (Tope AFP 83.1 UF 2025)
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError
from datetime import date
from unittest.mock import patch, MagicMock


@tagged('post_install', '-at_install', 'gap002', 'payroll_integration')
class TestGAP002LegalCapsIntegration(TransactionCase):
    """Test GAP-002: Integración Legal Caps con Economic Indicators"""

    def setUp(self):
        super().setUp()
        self.LegalCaps = self.env['l10n_cl.legal.caps']
        self.Indicators = self.env['hr.economic.indicators']

    # ═══════════════════════════════════════════════════════════
    # CORE GAP-002 TESTS: Eliminación de valores hardcoded
    # ═══════════════════════════════════════════════════════════

    def test_gap002_afp_cap_from_legal_table_not_hardcoded(self):
        """
        GAP-002: Tope AFP se obtiene de tabla legal.caps, NO hardcoded.

        Verifica que si se cambia el valor en la tabla legal.caps,
        el indicador creado refleja el nuevo valor (sin fallback 87.8).
        """
        # 1. Crear cap custom (90 UF para test)
        test_cap = self.LegalCaps.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 90.0,  # Valor diferente a 83.1 y 87.8
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
            'valid_until': False,
        })

        # 2. Mock AI-Service response (solo datos base, SIN afp_tope_uf)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                # NOTE: NO incluye 'afp_tope_uf' intencionalmente
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # 3. Llamar fetch_from_ai_service con mock
        with patch('requests.get', return_value=mock_response):
            indicator = self.Indicators.fetch_from_ai_service(2025, 1)

        # 4. Assert: debe usar 90.0 UF de la tabla, NO 87.8 hardcoded
        self.assertEqual(
            indicator.afp_limit,
            90.0,
            "GAP-002: Debe usar tope de tabla legal.caps (90.0), "
            "NO valor hardcoded (87.8)"
        )

    def test_gap002_error_if_cap_not_exists(self):
        """
        GAP-002: ValidationError si tope AFP no existe en legal.caps.

        Verifica que el método _get_afp_cap_from_legal_table() lanza
        error descriptivo si no encuentra cap configurado.
        """
        # Borrar todos los caps AFP
        self.LegalCaps.search([
            ('code', '=', 'AFP_IMPONIBLE_CAP')
        ]).unlink()

        # Mock AI-Service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # Intentar fetch → debe fallar
        with patch('requests.get', return_value=mock_response):
            with self.assertRaises(ValidationError) as context:
                self.Indicators.fetch_from_ai_service(2025, 1)

        # Verificar mensaje de error descriptivo
        error_msg = str(context.exception)
        self.assertIn('Tope AFP no configurado', error_msg)
        self.assertIn('AFP_IMPONIBLE_CAP', error_msg)

    def test_gap002_validation_unit_must_be_uf(self):
        """
        GAP-002: ValidationError si tope AFP no está en UF.

        Previene configuración incorrecta de topes en unidades incorrectas.
        """
        # Crear cap con unidad incorrecta (utm en vez de uf)
        self.LegalCaps.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 83.1,
            'unit': 'utm',  # ❌ Incorrecto (debe ser 'uf')
            'valid_from': date(2025, 1, 1),
            'valid_until': False,
        })

        # Mock AI-Service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # Intentar fetch → debe fallar
        with patch('requests.get', return_value=mock_response):
            with self.assertRaises(ValidationError) as context:
                self.Indicators.fetch_from_ai_service(2025, 1)

        # Verificar mensaje de error
        error_msg = str(context.exception)
        self.assertIn('Tope AFP debe estar en UF', error_msg)
        self.assertIn('utm', error_msg)

    # ═══════════════════════════════════════════════════════════
    # INTEGRATION TESTS: Múltiples períodos de vigencia
    # ═══════════════════════════════════════════════════════════

    def test_gap002_multiple_validity_periods_correct_cap(self):
        """
        GAP-002: Obtener tope correcto según período de vigencia.

        Simula múltiples topes AFP con vigencias diferentes y verifica
        que se use el correcto según la fecha del indicador.
        """
        # Crear topes para diferentes períodos
        cap_2025 = self.LegalCaps.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 83.1,
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
            'valid_until': date(2025, 12, 31),
        })

        cap_2026 = self.LegalCaps.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 85.0,  # Simulación valor futuro
            'unit': 'uf',
            'valid_from': date(2026, 1, 1),
            'valid_until': False,
        })

        # Mock AI-Service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # Test 1: Fetch para enero 2025 → debe usar cap_2025 (83.1)
        with patch('requests.get', return_value=mock_response):
            indicator_2025 = self.Indicators.fetch_from_ai_service(2025, 1)

        self.assertEqual(
            indicator_2025.afp_limit,
            83.1,
            "Enero 2025 debe usar cap 83.1 UF"
        )

        # Test 2: Fetch para enero 2026 → debe usar cap_2026 (85.0)
        with patch('requests.get', return_value=mock_response):
            indicator_2026 = self.Indicators.fetch_from_ai_service(2026, 1)

        self.assertEqual(
            indicator_2026.afp_limit,
            85.0,
            "Enero 2026 debe usar cap 85.0 UF"
        )

    # ═══════════════════════════════════════════════════════════
    # REGRESSION TESTS: Compatibilidad con data XML existente
    # ═══════════════════════════════════════════════════════════

    def test_gap002_xml_data_loads_correctly(self):
        """
        GAP-002: Verificar que data/l10n_cl_legal_caps_2025.xml carga.

        Confirma que el tope AFP 83.1 UF está disponible desde data XML.
        """
        afp_cap = self.LegalCaps.search([
            ('code', '=', 'AFP_IMPONIBLE_CAP'),
            ('valid_from', '=', date(2025, 1, 1))
        ], limit=1)

        self.assertTrue(afp_cap, "Debe existir cap AFP desde XML data")
        self.assertEqual(afp_cap.amount, 83.1)
        self.assertEqual(afp_cap.unit, 'uf')

    def test_gap002_fetch_uses_xml_cap_by_default(self):
        """
        GAP-002: fetch_from_ai_service usa cap 83.1 UF desde XML.

        Verifica integración completa: al llamar fetch sin crear cap custom,
        debe usar el valor 83.1 UF cargado desde data XML.
        """
        # Mock AI-Service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # Fetch para 2025
        with patch('requests.get', return_value=mock_response):
            indicator = self.Indicators.fetch_from_ai_service(2025, 6)

        # Debe usar cap desde XML (83.1)
        self.assertEqual(
            indicator.afp_limit,
            83.1,
            "Debe usar cap 83.1 UF desde data XML por defecto"
        )

    # ═══════════════════════════════════════════════════════════
    # AUDIT LOG TESTS: Trazabilidad cambios
    # ═══════════════════════════════════════════════════════════

    def test_gap002_indicator_logs_afp_cap_used(self):
        """
        GAP-002: Verificar que se loguea el valor de AFP cap usado.

        Valida que el log contiene el valor exacto del tope AFP utilizado
        para trazabilidad en auditorías.
        """
        # Crear cap
        self.LegalCaps.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 83.1,
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
            'valid_until': False,
        })

        # Mock AI-Service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # Capturar logs
        import logging
        with self.assertLogs('odoo.addons.l10n_cl_hr_payroll.models.hr_economic_indicators', level='INFO') as log:
            with patch('requests.get', return_value=mock_response):
                indicator = self.Indicators.fetch_from_ai_service(2025, 1)

        # Verificar que log contiene valor AFP cap usado
        log_output = '\n'.join(log.output)
        self.assertIn('AFP cap: 83.1', log_output, "Log debe incluir valor AFP cap usado")

    # ═══════════════════════════════════════════════════════════
    # EDGE CASES: Casos límite
    # ═══════════════════════════════════════════════════════════

    def test_gap002_cap_with_exact_validity_boundary(self):
        """
        GAP-002: Tope válido en fecha exacta de inicio de vigencia.

        Verifica que un indicador creado justo en valid_from usa el cap.
        """
        # Crear cap válido desde 2025-06-01
        self.LegalCaps.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 83.1,
            'unit': 'uf',
            'valid_from': date(2025, 6, 1),
            'valid_until': False,
        })

        # Mock AI-Service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # Fetch para 2025-06 (inicio exacto de vigencia)
        with patch('requests.get', return_value=mock_response):
            indicator = self.Indicators.fetch_from_ai_service(2025, 6)

        self.assertEqual(
            indicator.afp_limit,
            83.1,
            "Debe usar cap en fecha exacta de inicio de vigencia"
        )

    def test_gap002_cap_before_validity_raises_error(self):
        """
        GAP-002: Error si cap aún no está vigente.

        Verifica que fetch falla si se intenta obtener cap para fecha
        anterior a valid_from.
        """
        # Crear cap válido solo desde 2025-06-01
        self.LegalCaps.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 83.1,
            'unit': 'uf',
            'valid_from': date(2025, 6, 1),
            'valid_until': False,
        })

        # Mock AI-Service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 37000.0,
                'utm': 65000.0,
                'uta': 780000.0,
                'sueldo_minimo': 460000.0,
                'asig_fam_tramo_1': 15000.0,
                'asig_fam_tramo_2': 10000.0,
                'asig_fam_tramo_3': 5000.0,
            }
        }

        # Intentar fetch para 2025-01 (antes de valid_from) → debe fallar
        with patch('requests.get', return_value=mock_response):
            with self.assertRaises(ValidationError) as context:
                self.Indicators.fetch_from_ai_service(2025, 1)

        error_msg = str(context.exception)
        self.assertIn('Tope AFP no configurado', error_msg)
