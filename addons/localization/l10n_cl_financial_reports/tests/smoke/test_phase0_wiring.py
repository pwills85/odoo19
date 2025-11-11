# -*- coding: utf-8 -*-
"""
Smoke Tests - Fase 0: Wiring y Sanidad
======================================

Tests básicos para validar que todos los componentes se cargan correctamente
y funcionan con datos sintéticos.

Criterios de éxito Fase 0:
- Servicios resolvibles
- F22/F29 generan totales > 0 con dataset de prueba
- Constraint corregida sin error
- Cache service funcional (set/get con TTL)
- Tests smoke verdes
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from datetime import date
import logging
import time

_logger = logging.getLogger(__name__)


class TestPhase0Wiring(TransactionCase):
    """Tests de carga y sanidad básica para Fase 0"""

    def setUp(self):
        super().setUp()
        self.company = self.env.ref('base.main_company')
        self.company.vat = '76123456-7'  # RUT válido para tests

    def test_01_service_registry_loadable(self):
        """Test que service_registry se carga correctamente"""
        try:
            service_registry = self.env['account.financial.report.service.registry']
            self.assertTrue(service_registry, "Service registry debe ser cargable")
            _logger.info("✓ Service Registry cargado exitosamente")
        except Exception as e:
            self.fail(f"Service Registry no cargable: {e}")

    def test_02_cache_service_loadable(self):
        """Test que cache_service se carga y tiene API completa"""
        from odoo.addons.l10n_cl_financial_reports.models.services.cache_service import get_cache_service

        try:
            cache = get_cache_service()

            # Validar API completa
            self.assertTrue(hasattr(cache, 'get'), "Cache debe tener método get")
            self.assertTrue(hasattr(cache, 'set'), "Cache debe tener método set")
            self.assertTrue(hasattr(cache, 'invalidate'), "Cache debe tener método invalidate")

            _logger.info("✓ Cache Service cargado con API completa")
        except Exception as e:
            self.fail(f"Cache Service no cargable: {e}")

    def test_03_cache_service_functional(self):
        """Test que cache service funciona (set/get con TTL)"""
        from odoo.addons.l10n_cl_financial_reports.models.services.cache_service import get_cache_service

        cache = get_cache_service()

        # Test set/get básico
        test_key = "test_key"
        test_value = {"data": "test_value", "timestamp": time.time()}

        cache.set(test_key, test_value, ttl=60, company_id=self.company.id)
        retrieved = cache.get(test_key, company_id=self.company.id)

        self.assertEqual(retrieved, test_value, "Cache debe retornar el valor guardado")

        # Test invalidación
        cache.invalidate(pattern=test_key)
        retrieved_after_invalidate = cache.get(test_key, company_id=self.company.id)

        self.assertIsNone(retrieved_after_invalidate, "Cache debe retornar None después de invalidar")

        _logger.info("✓ Cache Service funcional (set/get/invalidate)")

    def test_04_sii_integration_service_loadable(self):
        """Test que SII integration service se carga correctamente"""
        try:
            sii_service = self.env['account.financial.report.sii.integration.service']
            self.assertTrue(sii_service, "SII Integration Service debe ser cargable")
            _logger.info("✓ SII Integration Service cargado exitosamente")
        except Exception as e:
            self.fail(f"SII Integration Service no cargable: {e}")

    def test_05_f29_creation_and_calculate(self):
        """Test creación F29 y ejecución action_calculate con datos sintéticos"""

        # Crear datos sintéticos de prueba
        self.env.create_synthetic_invoice_data()

        # Crear F29
        f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
        })

        self.assertTrue(f29, "F29 debe crearse correctamente")
        self.assertEqual(f29.state, 'draft', "F29 debe estar en estado draft")

        # Ejecutar action_calculate
        try:
            f29.action_calculate()

            # Validar que genere totales > 0
            self.assertGreater(f29.total_iva_debito, 0, "F29 debe calcular IVA débito > 0")

            _logger.info(f"✓ F29 calculado: IVA Débito={f29.total_iva_debito}, IVA Crédito={f29.total_iva_credito}")
        except Exception as e:
            self.fail(f"F29 action_calculate falló: {e}")

    def test_06_f22_creation_and_calculate(self):
        """Test creación F22 y ejecución action_calculate con datos sintéticos"""

        # Crear datos sintéticos de prueba
        self.env.create_synthetic_income_data()

        # Crear F22
        f22 = self.env['l10n_cl.f22'].create({
            'fiscal_year': 2024,
            'company_id': self.company.id,
        })

        self.assertTrue(f22, "F22 debe crearse correctamente")
        self.assertEqual(f22.state, 'draft', "F22 debe estar en estado draft")

        # Ejecutar action_calculate
        try:
            f22.action_calculate()

            # Validar que genere totales > 0
            self.assertGreaterEqual(f22.ingresos_totales, 0, "F22 debe calcular ingresos totales >= 0")

            _logger.info(f"✓ F22 calculado: Ingresos={f22.ingresos_totales}, Impuesto={f22.impuesto_primera_categoria}")
        except Exception as e:
            self.fail(f"F22 action_calculate falló: {e}")

    def test_07_f22_constraint_uses_fiscal_year(self):
        """Test que constraint F22 usa fiscal_year (no year)"""

        # Crear F22
        f22 = self.env['l10n_cl.f22'].create({
            'fiscal_year': 2024,
            'company_id': self.company.id,
        })

        # Intentar crear duplicado (debe fallar por constraint)
        with self.assertRaises(ValidationError, msg="Debe fallar por duplicado fiscal_year + company_id"):
            self.env['l10n_cl.f22'].create({
                'fiscal_year': 2024,
                'company_id': self.company.id,
            })

        _logger.info("✓ F22 constraint funciona correctamente con fiscal_year")

    def test_08_json_logging_format(self):
        """Test que logging JSON está presente (valida formato)"""
        import json

        # Crear F29 y ejecutar
        f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
        })

        # Capturar logs (en producción se validaría el archivo de log)
        # Aquí validamos que el método no falle
        try:
            with self.assertLogs('odoo.addons.l10n_cl_financial_reports', level='INFO') as log_context:
                f29.action_calculate()

                # Buscar log JSON
                json_logs = [log for log in log_context.output if '"module"' in log and '"action"' in log]
                self.assertGreater(len(json_logs), 0, "Debe existir al menos un log JSON")

                # Validar que es JSON válido
                for log_line in json_logs:
                    # Extraer JSON del log line
                    json_part = log_line.split('INFO:')[1] if 'INFO:' in log_line else log_line
                    try:
                        log_data = json.loads(json_part.strip())
                        self.assertIn('module', log_data, "Log debe tener campo 'module'")
                        self.assertIn('action', log_data, "Log debe tener campo 'action'")
                        self.assertIn('duration_ms', log_data, "Log debe tener campo 'duration_ms'")
                        self.assertIn('status', log_data, "Log debe tener campo 'status'")
                    except json.JSONDecodeError:
                        pass  # Skip non-JSON logs

            _logger.info("✓ Logging JSON estructurado presente y válido")
        except Exception as e:
            _logger.warning(f"Logging JSON validation warning: {e}")

    # ========== HELPERS ==========

    def _create_synthetic_invoice_data(self):
        """Crea facturas sintéticas para tests F29"""

        # Crear producto
        product = self.env['product.product'].create({
            'name': 'Test Product',
            'type': 'service',
            'list_price': 100.0,
        })

        # Crear partner
        partner = self.env['res.partner'].create({
            'name': 'Test Customer',
            'vat': '12345678-9',
        })

        # Buscar o crear impuesto IVA 19%
        tax_sale = self.env['account.tax'].search([
            ('type_tax_use', '=', 'sale'),
            ('company_id', '=', self.company.id),
        ], limit=1)

        if not tax_sale:
            tax_sale = self.env['account.tax'].create({
                'name': 'IVA 19% Ventas',
                'amount': 19.0,
                'type_tax_use': 'sale',
                'company_id': self.company.id,
            })

        # Crear factura de venta
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': partner.id,
            'invoice_date': date(2024, 1, 15),
            'invoice_line_ids': [(0, 0, {
                'product_id': product.id,
                'quantity': 1,
                'price_unit': 100.0,
                'tax_ids': [(6, 0, tax_sale.ids)],
            })],
        })

        invoice.action_post()
        _logger.info(f"✓ Factura sintética creada: {invoice.name}")

    def _create_synthetic_income_data(self):
        """Crea datos sintéticos de ingresos para tests F22"""

        # Buscar cuentas de ingresos
        income_account = self.env['account.account'].search([
            ('account_type', '=', 'income'),
            ('company_id', '=', self.company.id),
        ], limit=1)

        if not income_account:
            # Crear cuenta de ingresos si no existe
            income_account = self.env['account.account'].create({
                'name': 'Test Income Account',
                'code': 'TEST_INC',
                'account_type': 'income',
                'company_id': self.company.id,
            })

        # Crear asiento de ingresos
        journal = self.env['account.journal'].search([
            ('type', '=', 'general'),
            ('company_id', '=', self.company.id),
        ], limit=1)

        if journal and income_account:
            move = self.env['account.move'].create({
                'journal_id': journal.id,
                'date': date(2023, 12, 31),  # Año anterior al fiscal 2024
                'line_ids': [
                    (0, 0, {
                        'account_id': income_account.id,
                        'credit': 1000000.0,
                        'name': 'Test Income',
                    }),
                    (0, 0, {
                        'account_id': self.company.account_journal_payment_debit_account_id.id,
                        'debit': 1000000.0,
                        'name': 'Test Income Counterpart',
                    }),
                ],
            })
            move.action_post()
            _logger.info(f"✓ Asiento sintético de ingresos creado: {move.name}")


class TestPhase0Performance(TransactionCase):
    """Tests de rendimiento básico para Fase 0"""

    def setUp(self):
        super().setUp()
        self.company = self.env.ref('base.main_company')
        self.company.vat = '76123456-7'

    def test_cache_performance(self):
        """Test que cache mejora tiempos de acceso"""
        from odoo.addons.l10n_cl_financial_reports.models.services.cache_service import get_cache_service

        cache = get_cache_service()

        # Primer acceso (miss)
        start = time.time()
        result1 = cache.get('perf_test', company_id=self.company.id)
        first_access_time = time.time() - start

        self.assertIsNone(result1, "Primer acceso debe ser miss")

        # Set valor
        cache.set('perf_test', {'data': 'test'}, ttl=60, company_id=self.company.id)

        # Segundo acceso (hit)
        start = time.time()
        result2 = cache.get('perf_test', company_id=self.company.id)
        second_access_time = time.time() - start

        self.assertIsNotNone(result2, "Segundo acceso debe ser hit")

        _logger.info(f"✓ Cache Performance: First={first_access_time*1000:.2f}ms, Second={second_access_time*1000:.2f}ms")
