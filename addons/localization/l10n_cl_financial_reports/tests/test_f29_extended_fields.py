# -*- coding: utf-8 -*-
"""
Tests para Extensión F29 - FASE 1
==================================

Tests para validar:
1. Campos nuevos se guardan y leen correctamente
2. Constraints de coherencia funcionan como esperado
3. Cálculos computed son correctos

Referencias:
- Odoo Testing Framework: https://www.odoo.com/documentation/19.0/developer/reference/backend/testing.html
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


class TestF29ExtendedFields(TransactionCase):
    """Tests para campos extendidos del F29"""

    def setUp(self):
        super().setUp()
        self.company = self.env.ref('base.main_company')
        self.company.vat = '76123456-7'

        # Crear F29 de prueba
        self.f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
        })

    def test_01_nuevos_campos_debito_fiscal(self):
        """Test que los campos de débito fiscal se guardan correctamente"""
        self.f29.write({
            'ventas_afectas': 1000000.0,
            'ventas_exentas': 500000.0,
            'ventas_exportacion': 200000.0,
            'debito_remanente_mes_anterior': 50000.0,
            'creditos_especiales': 10000.0,
        })

        # Validar que se guardaron
        self.assertEqual(self.f29.ventas_afectas, 1000000.0)
        self.assertEqual(self.f29.ventas_exentas, 500000.0)
        self.assertEqual(self.f29.ventas_exportacion, 200000.0)
        self.assertEqual(self.f29.debito_remanente_mes_anterior, 50000.0)
        self.assertEqual(self.f29.creditos_especiales, 10000.0)

        # Validar cálculo automático débito fiscal (19% de ventas afectas)
        expected_debito = 1000000.0 * 0.19
        self.assertAlmostEqual(self.f29.debito_fiscal, expected_debito, places=2)

        _logger.info(f"✓ Campos débito fiscal guardados y calculados correctamente")

    def test_02_nuevos_campos_credito_fiscal(self):
        """Test que los campos de crédito fiscal se guardan correctamente"""
        self.f29.write({
            'compras_afectas': 800000.0,
            'compras_exentas': 300000.0,
            'compras_activo_fijo': 200000.0,
            'remanente_credito_mes_anterior': 30000.0,
        })

        # Validar que se guardaron
        self.assertEqual(self.f29.compras_afectas, 800000.0)
        self.assertEqual(self.f29.compras_exentas, 300000.0)
        self.assertEqual(self.f29.compras_activo_fijo, 200000.0)
        self.assertEqual(self.f29.remanente_credito_mes_anterior, 30000.0)

        # Validar cálculo automático crédito fiscal (19% de compras afectas + activo fijo)
        expected_credito = (800000.0 + 200000.0) * 0.19
        self.assertAlmostEqual(self.f29.credito_fiscal, expected_credito, places=2)

        _logger.info(f"✓ Campos crédito fiscal guardados y calculados correctamente")

    def test_03_campos_ppm_y_retenciones(self):
        """Test que los campos de PPM y retenciones se guardan correctamente"""
        self.f29.write({
            'ppm_mes': 150000.0,
            'ppm_voluntario': 50000.0,
            'iva_retenido': 20000.0,
        })

        # Validar que se guardaron
        self.assertEqual(self.f29.ppm_mes, 150000.0)
        self.assertEqual(self.f29.ppm_voluntario, 50000.0)
        self.assertEqual(self.f29.iva_retenido, 20000.0)

        _logger.info(f"✓ Campos PPM y retenciones guardados correctamente")

    def test_04_tipo_declaracion_y_rectificacion(self):
        """Test que tipo_declaracion y numero_rectificacion funcionan"""
        # Por defecto debe ser original
        self.assertEqual(self.f29.tipo_declaracion, 'original')

        # Cambiar a rectificatoria
        self.f29.write({
            'tipo_declaracion': 'rectificatoria',
            'numero_rectificacion': 1,
        })

        self.assertEqual(self.f29.tipo_declaracion, 'rectificatoria')
        self.assertEqual(self.f29.numero_rectificacion, 1)

        _logger.info(f"✓ Tipo declaración y número rectificación funcionan correctamente")

    def test_05_calculo_iva_determinado(self):
        """Test que el cálculo de IVA determinado es correcto"""
        self.f29.write({
            'ventas_afectas': 1000000.0,  # Genera débito de 190,000
            'compras_afectas': 500000.0,  # Genera crédito de 95,000
            'debito_remanente_mes_anterior': 20000.0,
            'remanente_credito_mes_anterior': 10000.0,
            'creditos_especiales': 5000.0,
        })

        # IVA Determinado = (Débito + Remanente Débito - Créditos Especiales) - (Crédito + Remanente Crédito)
        # = (190,000 + 20,000 - 5,000) - (95,000 + 10,000)
        # = 205,000 - 105,000 = 100,000

        expected_iva_determinado = 100000.0
        self.assertAlmostEqual(self.f29.iva_determinado, expected_iva_determinado, delta=1.0)

        _logger.info(f"✓ Cálculo IVA determinado correcto: {self.f29.iva_determinado}")

    def test_06_calculo_resultado_final_a_pagar(self):
        """Test que el cálculo del resultado final (a pagar) es correcto"""
        self.f29.write({
            'ventas_afectas': 1000000.0,  # Débito 190,000
            'compras_afectas': 500000.0,  # Crédito 95,000
            'ppm_mes': 50000.0,
            'iva_retenido': 10000.0,
        })

        # IVA Determinado = 190,000 - 95,000 = 95,000
        # IVA a Pagar = 95,000 - 50,000 - 10,000 = 35,000

        expected_iva_a_pagar = 35000.0
        self.assertAlmostEqual(self.f29.iva_a_pagar, expected_iva_a_pagar, delta=1.0)
        self.assertEqual(self.f29.saldo_favor, 0.0)
        self.assertEqual(self.f29.remanente_mes_siguiente, 0.0)

        _logger.info(f"✓ Cálculo resultado final (a pagar) correcto: {self.f29.iva_a_pagar}")

    def test_07_calculo_resultado_final_saldo_favor(self):
        """Test que el cálculo del saldo a favor es correcto"""
        self.f29.write({
            'ventas_afectas': 500000.0,  # Débito 95,000
            'compras_afectas': 1000000.0,  # Crédito 190,000
            'ppm_mes': 10000.0,
        })

        # IVA Determinado = 95,000 - 190,000 = -95,000
        # Después de PPM = -95,000 - 10,000 = -105,000
        # Saldo a Favor = 105,000

        expected_saldo_favor = 105000.0
        self.assertAlmostEqual(self.f29.saldo_favor, expected_saldo_favor, delta=1.0)
        self.assertEqual(self.f29.iva_a_pagar, 0.0)
        self.assertAlmostEqual(self.f29.remanente_mes_siguiente, expected_saldo_favor, delta=1.0)

        _logger.info(f"✓ Cálculo saldo a favor correcto: {self.f29.saldo_favor}")

    def test_08_campos_legacy_backward_compatibility(self):
        """Test que los campos legacy mantienen backward compatibility"""
        self.f29.write({
            'ventas_afectas': 1000000.0,
            'compras_afectas': 500000.0,
        })

        # Los campos legacy deben reflejar los valores nuevos
        self.assertEqual(self.f29.total_ventas, self.f29.ventas_afectas)
        self.assertEqual(self.f29.total_compras, self.f29.compras_afectas)
        self.assertEqual(self.f29.total_iva_debito, self.f29.debito_fiscal)
        self.assertEqual(self.f29.total_iva_credito, self.f29.credito_fiscal)

        _logger.info(f"✓ Campos legacy mantienen backward compatibility")


class TestF29Constraints(TransactionCase):
    """Tests para constraints de coherencia del F29"""

    def setUp(self):
        super().setUp()
        self.company = self.env.ref('base.main_company')
        self.company.vat = '76123456-7'

        # Crear F29 de prueba
        self.f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
        })

    def test_01_constraint_debito_fiscal_coherence_pass(self):
        """Test que constraint débito fiscal pasa cuando es coherente"""
        # Débito coherente (19% de ventas)
        self.f29.write({
            'ventas_afectas': 1000000.0,
            # debito_fiscal se calcula automáticamente como 190,000
        })

        # No debe levantar excepción
        try:
            self.f29._check_debito_fiscal_coherence()
            _logger.info(f"✓ Constraint débito fiscal coherente (PASS)")
        except ValidationError:
            self.fail("Constraint débito fiscal falló cuando debía pasar")

    def test_02_constraint_debito_fiscal_coherence_fail(self):
        """Test que constraint débito fiscal falla cuando es incoherente"""
        # Crear F29 con datos incoherentes (forzar valor incorrecto)
        # Nota: Como debito_fiscal es computed, necesitamos hacer bypass del compute temporalmente
        # Para este test, vamos a validar que el constraint se activa correctamente

        with self.assertRaises(ValidationError, msg="Debe fallar por débito fiscal incoherente"):
            # Intentar crear con valores que provocarían incoherencia
            # Simulamos modificando directamente con SQL para bypass del compute
            self.env.cr.execute(
                "UPDATE l10n_cl_f29 SET ventas_afectas = %s, debito_fiscal = %s WHERE id = %s",
                (1000000.0, 100000.0, self.f29.id)  # 100k es incorrecto, debería ser 190k
            )
            self.env.cache.invalidate()
            self.f29.refresh()
            # Forzar validación
            self.f29._check_debito_fiscal_coherence()

        _logger.info(f"✓ Constraint débito fiscal incoherente (FAIL como esperado)")

    def test_03_constraint_credito_fiscal_coherence_pass(self):
        """Test que constraint crédito fiscal pasa cuando es coherente"""
        # Crédito coherente (19% de compras)
        self.f29.write({
            'compras_afectas': 1000000.0,
            'compras_activo_fijo': 500000.0,
            # credito_fiscal se calcula automáticamente como (1000000 + 500000) * 0.19 = 285,000
        })

        # No debe levantar excepción
        try:
            self.f29._check_credito_fiscal_coherence()
            _logger.info(f"✓ Constraint crédito fiscal coherente (PASS)")
        except ValidationError:
            self.fail("Constraint crédito fiscal falló cuando debía pasar")

    def test_04_constraint_credito_fiscal_coherence_fail(self):
        """Test que constraint crédito fiscal falla cuando es incoherente"""
        with self.assertRaises(ValidationError, msg="Debe fallar por crédito fiscal incoherente"):
            # Simular incoherencia
            self.env.cr.execute(
                "UPDATE l10n_cl_f29 SET compras_afectas = %s, compras_activo_fijo = %s, credito_fiscal = %s WHERE id = %s",
                (1000000.0, 500000.0, 100000.0, self.f29.id)  # 100k es incorrecto, debería ser 285k
            )
            self.env.cache.invalidate()
            self.f29.refresh()
            self.f29._check_credito_fiscal_coherence()

        _logger.info(f"✓ Constraint crédito fiscal incoherente (FAIL como esperado)")

    def test_05_constraint_unique_declaration_pass(self):
        """Test que constraint unicidad pasa cuando no hay duplicados"""
        # Crear segundo F29 para período diferente (debe pasar)
        f29_2 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 2, 1),  # Mes diferente
            'company_id': self.company.id,
        })

        # No debe levantar excepción
        try:
            f29_2._check_unique_declaration()
            _logger.info(f"✓ Constraint unicidad sin duplicados (PASS)")
        except ValidationError:
            self.fail("Constraint unicidad falló cuando debía pasar")

    def test_06_constraint_unique_declaration_fail(self):
        """Test que constraint unicidad falla cuando hay duplicados"""
        # Crear F29 duplicado para mismo período (debe fallar)
        with self.assertRaises(ValidationError, msg="Debe fallar por declaración duplicada"):
            self.env['l10n_cl.f29'].create({
                'period_date': date(2024, 1, 1),  # Mismo mes que self.f29
                'company_id': self.company.id,
                'tipo_declaracion': 'original',  # Misma tipo
            })

        _logger.info(f"✓ Constraint unicidad con duplicados (FAIL como esperado)")

    def test_07_constraint_unique_declaration_rectificatoria_allowed(self):
        """Test que rectificatorias NO están sujetas al constraint de unicidad"""
        # Crear rectificatoria para mismo período (debe pasar)
        f29_rect = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),  # Mismo mes que self.f29
            'company_id': self.company.id,
            'tipo_declaracion': 'rectificatoria',  # Tipo diferente
            'numero_rectificacion': 1,
        })

        # No debe levantar excepción
        self.assertTrue(f29_rect.id, "Rectificatoria debe permitir crear para mismo período")
        _logger.info(f"✓ Rectificatorias permitidas para mismo período")


class TestF29ComputedFields(TransactionCase):
    """Tests específicos para campos computed del F29"""

    def setUp(self):
        super().setUp()
        self.company = self.env.ref('base.main_company')
        self.company.vat = '76123456-7'

    def test_01_compute_iva_amounts(self):
        """Test del método _compute_iva_amounts"""
        f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
            'ventas_afectas': 1000000.0,
            'compras_afectas': 600000.0,
            'compras_activo_fijo': 400000.0,
        })

        # Validar débito fiscal (19% de ventas)
        self.assertAlmostEqual(f29.debito_fiscal, 190000.0, delta=1.0)

        # Validar crédito fiscal (19% de compras + activo fijo)
        self.assertAlmostEqual(f29.credito_fiscal, 190000.0, delta=1.0)

        _logger.info(f"✓ _compute_iva_amounts funciona correctamente")

    def test_02_compute_iva_determinado(self):
        """Test del método _compute_iva_determinado"""
        f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
            'ventas_afectas': 2000000.0,  # Débito: 380,000
            'compras_afectas': 1000000.0,  # Crédito: 190,000
            'debito_remanente_mes_anterior': 50000.0,
            'remanente_credito_mes_anterior': 30000.0,
            'creditos_especiales': 10000.0,
        })

        # IVA Determinado = (380k + 50k - 10k) - (190k + 30k) = 420k - 220k = 200k
        expected = 200000.0
        self.assertAlmostEqual(f29.iva_determinado, expected, delta=1.0)

        _logger.info(f"✓ _compute_iva_determinado funciona correctamente")

    def test_03_compute_resultado_final(self):
        """Test del método _compute_resultado_final"""
        f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
            'ventas_afectas': 2000000.0,  # Débito: 380,000
            'compras_afectas': 1000000.0,  # Crédito: 190,000
            'ppm_mes': 100000.0,
            'iva_retenido': 20000.0,
        })

        # IVA Determinado = 380k - 190k = 190k
        # Resultado = 190k - 100k - 20k = 70k a pagar

        self.assertAlmostEqual(f29.iva_a_pagar, 70000.0, delta=1.0)
        self.assertEqual(f29.saldo_favor, 0.0)

        _logger.info(f"✓ _compute_resultado_final funciona correctamente")

    def test_04_compute_legacy_fields(self):
        """Test del método _compute_legacy_fields"""
        f29 = self.env['l10n_cl.f29'].create({
            'period_date': date(2024, 1, 1),
            'company_id': self.company.id,
            'ventas_afectas': 1000000.0,
            'compras_afectas': 500000.0,
        })

        # Legacy fields deben ser iguales a los nuevos
        self.assertEqual(f29.total_ventas, f29.ventas_afectas)
        self.assertEqual(f29.total_compras, f29.compras_afectas)
        self.assertEqual(f29.total_iva_debito, f29.debito_fiscal)
        self.assertEqual(f29.total_iva_credito, f29.credito_fiscal)

        _logger.info(f"✓ _compute_legacy_fields funciona correctamente")
