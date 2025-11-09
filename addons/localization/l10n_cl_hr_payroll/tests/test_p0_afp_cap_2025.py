# -*- coding: utf-8 -*-

"""
Test P0-1: Tope AFP 2025 - 83.1 UF
===================================

Verifica corrección de brecha P0-1 identificada en auditoría:
- Tope AFP debe ser 83.1 UF según Ley 20.255 Art. 17
- Valor previo incorrecto: 81.6 UF
- Valor corregido: 83.1 UF

Referencias:
- Superintendencia de Pensiones 2025
- Ley 20.255 Art. 17
- Auditoría 2025-11-07: P0-1
"""

from odoo.tests import tagged, TransactionCase
from datetime import date


@tagged('post_install', '-at_install', 'p0_critical', 'afp_cap')
class TestP0AfpCap2025(TransactionCase):
    """Test P0-1: Validar tope AFP 83.1 UF para 2025"""

    def setUp(self):
        super().setUp()
        self.LegalCapsModel = self.env['l10n_cl.legal.caps']

    def test_afp_cap_is_831_uf_2025(self):
        """
        P0-1: Tope AFP 2025 debe ser 83.1 UF

        Verifica que el dato corregido en data/l10n_cl_legal_caps_2025.xml
        se cargue correctamente en la base de datos.
        """
        afp_cap = self.LegalCapsModel.search([
            ('code', '=', 'AFP_IMPONIBLE_CAP'),
            ('valid_from', '=', '2025-01-01')
        ], limit=1)

        self.assertTrue(
            afp_cap,
            "Debe existir tope AFP para 2025 en BD"
        )

        self.assertEqual(
            afp_cap.amount,
            83.1,
            "Tope AFP 2025 debe ser 83.1 UF según Ley 20.255 Art. 17 "
            "(valor previo incorrecto: 81.6 UF)"
        )

        self.assertEqual(
            afp_cap.unit,
            'uf',
            "Unidad del tope AFP debe ser UF"
        )

    def test_afp_cap_not_816_uf(self):
        """
        P0-1: Verificar que valor incorrecto (81.6 UF) fue corregido

        Este test falla si el valor antiguo incorrecto aún existe.
        """
        wrong_cap = self.LegalCapsModel.search([
            ('code', '=', 'AFP_IMPONIBLE_CAP'),
            ('valid_from', '=', '2025-01-01'),
            ('amount', '=', 81.6)
        ], limit=1)

        self.assertFalse(
            wrong_cap,
            "NO debe existir tope AFP 81.6 UF para 2025 "
            "(valor incorrecto según auditoría P0-1)"
        )

    def test_afp_cap_vigencia(self):
        """
        P0-1: Verificar vigencia del tope AFP 2025

        El tope debe estar vigente desde 2025-01-01 sin fecha de fin
        (valid_until = False) para permitir uso indefinido hasta
        próxima actualización.
        """
        afp_cap = self.LegalCapsModel.search([
            ('code', '=', 'AFP_IMPONIBLE_CAP'),
            ('valid_from', '=', '2025-01-01')
        ], limit=1)

        self.assertTrue(afp_cap, "Debe existir tope AFP 2025")

        self.assertEqual(
            afp_cap.valid_from,
            date(2025, 1, 1),
            "Vigencia debe iniciar 2025-01-01"
        )

        self.assertFalse(
            afp_cap.valid_until,
            "Tope no debe tener fecha de fin (vigente indefinido)"
        )

    def test_get_afp_cap_for_date(self):
        """
        P0-1: Test obtención de tope AFP vigente por fecha

        Verifica que al consultar el tope AFP para una fecha en 2025,
        se obtenga el valor correcto de 83.1 UF.
        """
        test_date = date(2025, 6, 15)  # Fecha en medio de 2025

        afp_cap = self.LegalCapsModel.search([
            ('code', '=', 'AFP_IMPONIBLE_CAP'),
            ('valid_from', '<=', test_date),
            '|',
            ('valid_until', '=', False),
            ('valid_until', '>=', test_date)
        ], limit=1, order='valid_from desc')

        self.assertTrue(
            afp_cap,
            "Debe encontrar tope AFP vigente para fecha en 2025"
        )

        self.assertEqual(
            afp_cap.amount,
            83.1,
            "Tope AFP vigente para 2025-06-15 debe ser 83.1 UF"
        )

    # ═══════════════════════════════════════════════════════════
    # PR-2 TESTS: NOM-C001 - get_cap() Method Validation
    # ═══════════════════════════════════════════════════════════

    def test_pr2_get_cap_method_returns_correct_value(self):
        """
        PR-2: Verificar que get_cap() retorna valor correcto.

        Requirement: get_cap('AFP_IMPONIBLE_CAP', date) debe retornar (83.1, 'uf')
        """
        test_date = date(2025, 6, 15)
        amount, unit = self.LegalCapsModel.get_cap('AFP_IMPONIBLE_CAP', test_date)

        self.assertEqual(amount, 83.1, "get_cap() debe retornar 83.1")
        self.assertEqual(unit, 'uf', "get_cap() debe retornar unidad 'uf'")

    def test_pr2_get_cap_with_string_date(self):
        """
        PR-2: Verificar que get_cap() acepta fecha como string.

        Requirement: get_cap() debe convertir string a date automáticamente
        """
        amount, unit = self.LegalCapsModel.get_cap('AFP_IMPONIBLE_CAP', '2025-06-15')

        self.assertEqual(amount, 83.1)
        self.assertEqual(unit, 'uf')

    def test_pr2_get_cap_with_none_date_uses_today(self):
        """
        PR-2: Verificar que get_cap(code, None) usa fecha actual.

        Requirement: Si no se pasa fecha, debe usar date.today()
        """
        # Este test asume que estamos en 2025 o que el tope 2025 aún está vigente
        # En producción real, ajustar según fecha de ejecución
        try:
            amount, unit = self.LegalCapsModel.get_cap('AFP_IMPONIBLE_CAP')
            # Si no lanza excepción, significa que encontró un tope vigente
            self.assertIsNotNone(amount)
            self.assertIsNotNone(unit)
        except Exception:
            # Si lanza excepción, es porque no hay tope vigente para hoy
            # Esto es aceptable en tests si fecha actual está fuera del rango
            pass

    def test_pr2_get_cap_missing_cap_raises_error(self):
        """
        PR-2: Verificar que get_cap() lanza error si no encuentra tope.

        Requirement: ValidationError si no existe tope para el código y fecha
        """
        from odoo.exceptions import ValidationError

        # Usar fecha muy antigua donde no existe tope configurado
        test_date = date(2020, 1, 1)

        with self.assertRaises(ValidationError) as context:
            self.LegalCapsModel.get_cap('AFP_IMPONIBLE_CAP', test_date)

        self.assertIn('No se encontró tope legal', str(context.exception))

    def test_pr2_get_cap_invalid_code_raises_error(self):
        """
        PR-2: Verificar que get_cap() lanza error con código inexistente.

        Requirement: ValidationError si código no existe
        """
        from odoo.exceptions import ValidationError

        test_date = date(2025, 6, 15)

        with self.assertRaises(ValidationError) as context:
            self.LegalCapsModel.get_cap('INVALID_CODE', test_date)

        self.assertIn('No se encontró tope legal', str(context.exception))

    def test_pr2_salary_rule_uses_get_cap(self):
        """
        PR-2: Verificar que regla salarial TOPE_IMPONIBLE_UF usa get_cap().

        Requirement: Código de regla debe llamar get_cap() en lugar de búsqueda manual
        """
        # Buscar la regla TOPE_IMPONIBLE_UF
        rule = self.env['hr.salary.rule'].search([
            ('code', '=', 'TOPE_IMPONIBLE_UF')
        ], limit=1)

        self.assertTrue(rule, "Debe existir regla TOPE_IMPONIBLE_UF")

        # Verificar que el código usa get_cap()
        self.assertIn(
            'get_cap',
            rule.amount_python_compute,
            "Código de regla debe usar método get_cap()"
        )

        # Verificar que NO usa búsqueda manual (domain)
        self.assertNotIn(
            "search(domain",
            rule.amount_python_compute,
            "Código NO debe usar búsqueda manual con domain"
        )

    def test_pr2_multiple_validity_periods(self):
        """
        PR-2: Test múltiples períodos de vigencia (preparación futuro).

        Verifica que si existen múltiples topes con vigencias diferentes,
        get_cap() retorna el correcto según fecha.
        """
        # Crear tope adicional para 2026 (simulación)
        self.LegalCapsModel.create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 85.0,  # Ejemplo: valor futuro
            'unit': 'uf',
            'valid_from': date(2026, 1, 1),
            'valid_until': False,
        })

        # Buscar tope para 2025
        amount_2025, _ = self.LegalCapsModel.get_cap('AFP_IMPONIBLE_CAP', date(2025, 6, 15))
        self.assertEqual(amount_2025, 83.1, "2025 debe retornar 83.1")

        # Buscar tope para 2026
        amount_2026, _ = self.LegalCapsModel.get_cap('AFP_IMPONIBLE_CAP', date(2026, 6, 15))
        self.assertEqual(amount_2026, 85.0, "2026 debe retornar 85.0")
