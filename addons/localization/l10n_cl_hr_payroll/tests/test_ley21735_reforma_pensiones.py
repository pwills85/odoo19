# -*- coding: utf-8 -*-
"""
Tests Ley 21.735 - Reforma del Sistema de Pensiones

Valida implementación completa aporte empleador 1% (0.1% + 0.9%)
vigente desde 01 agosto 2025.

Normativa:
- Ley 21.735 "Reforma del Sistema de Pensiones"
- Vigencia: 01-08-2025
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from datetime import date


class TestLey21735ReformaPensiones(TransactionCase):
    """Test suite Ley 21.735 - Reforma Sistema Pensiones"""

    def setUp(self):
        super().setUp()

        # Company
        self.company = self.env.ref('base.main_company')

        # Employee
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee Ley 21.735',
            'company_id': self.company.id
        })

        # AFP (para otros cálculos)
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Cuprum',
            'code': 'CUPRUM',
            'rate': 11.44,
            'sis_rate': 1.57
        })

        # Indicadores económicos para todos los períodos de tests
        # Julio 2025 (antes vigencia Ley 21.735)
        self.env['hr.economic.indicators'].create({
            'period': date(2025, 7, 1),
            'uf': 37500.00,
            'utm': 65000.00,
            'uta': 780000.00,
            'minimum_wage': 500000.00
        })
        # Agosto 2025 (vigencia Ley 21.735)
        self.env['hr.economic.indicators'].create({
            'period': date(2025, 8, 1),
            'uf': 37500.00,
            'utm': 65000.00,
            'uta': 780000.00,
            'minimum_wage': 500000.00
        })
        # Septiembre 2025
        self.env['hr.economic.indicators'].create({
            'period': date(2025, 9, 1),
            'uf': 37500.00,
            'utm': 65000.00,
            'uta': 780000.00,
            'minimum_wage': 500000.00
        })
        # Enero 2026 (períodos futuros)
        self.env['hr.economic.indicators'].create({
            'period': date(2026, 1, 1),
            'uf': 38000.00,
            'utm': 66000.00,
            'uta': 792000.00,
            'minimum_wage': 510000.00
        })

        # Estructura salarial
        self.struct = self.env.ref('l10n_cl_hr_payroll.structure_base_cl',
                                   raise_if_not_found=False)
        if not self.struct:
            self.struct = self.env['hr.payroll.structure'].create({
                'name': 'Estructura Chile',
                'code': 'CL_BASE'
            })

    # ===== VIGENCIA LEY 21.735 =====

    def test_01_no_aplica_antes_agosto_2025(self):
        """No debe aplicar Ley 21.735 en períodos anteriores a 01-08-2025"""

        # Contrato vigente antes de agosto 2025
        contract = self.env['hr.contract'].create({
            'name': 'Contrato Pre-Ley',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': date(2024, 1, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        # Nómina julio 2025 (antes vigencia)
        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Julio 2025',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 7, 1),
            'date_to': date(2025, 7, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Validaciones
        self.assertFalse(
            payslip.aplica_ley21735,
            "No debe aplicar Ley 21.735 en julio 2025"
        )
        self.assertEqual(
            payslip.employer_cuenta_individual_ley21735, 0,
            "Cuenta Individual debe ser 0 antes vigencia"
        )
        self.assertEqual(
            payslip.employer_seguro_social_ley21735, 0,
            "Seguro Social debe ser 0 antes vigencia"
        )
        self.assertEqual(
            payslip.employer_total_ley21735, 0,
            "Total Ley 21.735 debe ser 0 antes vigencia"
        )

    def test_02_aplica_desde_agosto_2025(self):
        """Debe aplicar Ley 21.735 desde 01-08-2025"""

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Post-Ley',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        # Nómina agosto 2025 (inicio vigencia)
        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Agosto 2025',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Validaciones
        self.assertTrue(
            payslip.aplica_ley21735,
            "Debe aplicar Ley 21.735 desde agosto 2025"
        )
        self.assertGreater(
            payslip.employer_total_ley21735, 0,
            "Total Ley 21.735 debe ser > 0"
        )

    # ===== CÁLCULOS LEY 21.735 =====

    def test_03_calculo_cuenta_individual_01_percent(self):
        """Cuenta Individual debe ser exactamente 0.1%"""

        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Test 0.1%',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Test 0.1%',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # 0.1% de $2.000.000 = $2.000
        expected = wage * 0.001

        self.assertEqual(
            payslip.employer_cuenta_individual_ley21735, expected,
            f"Cuenta Individual debe ser 0.1% de ${wage:,} = ${expected:,}"
        )

    def test_04_calculo_seguro_social_09_percent(self):
        """Seguro Social debe ser exactamente 0.9%"""

        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Test 0.9%',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Test 0.9%',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # 0.9% de $2.000.000 = $18.000
        expected = wage * 0.009

        self.assertEqual(
            payslip.employer_seguro_social_ley21735, expected,
            f"Seguro Social debe ser 0.9% de ${wage:,} = ${expected:,}"
        )

    def test_05_total_es_suma_01_mas_09(self):
        """Total debe ser suma de 0.1% + 0.9% = 1%"""

        wage = 1800000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Test Total',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Test Total 1%',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 9, 1),
            'date_to': date(2025, 9, 30),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Validar suma
        suma_componentes = (
            payslip.employer_cuenta_individual_ley21735 +
            payslip.employer_seguro_social_ley21735
        )

        self.assertEqual(
            payslip.employer_total_ley21735, suma_componentes,
            "Total debe ser suma de componentes"
        )

        # Validar es exactamente 1%
        expected_total = wage * 0.01

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total debe ser exactamente 1% de ${wage:,} = ${expected_total:,}"
        )

    # ===== VALIDACIONES =====

    def test_06_validation_blocks_missing_aporte(self):
        """Validación debe bloquear confirmación si falta aporte"""

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Test Validación',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Test Validación',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        # Forzar aplica_ley21735 = True pero total = 0 (simular bug)
        payslip.write({
            'aplica_ley21735': True,
            'employer_total_ley21735': 0
        })

        # Intentar confirmar (debe fallar)
        with self.assertRaises(ValidationError) as cm:
            payslip.write({'state': 'done'})

        self.assertIn('Ley 21.735', str(cm.exception))
        self.assertIn('aporte empleador', str(cm.exception).lower())

    # ===== CASOS EDGE =====

    def test_07_multiples_salarios_precision(self):
        """Validar precisión con múltiples niveles salariales"""

        test_cases = [
            (500000, 500, 4500, 5000),      # Sueldo bajo
            (1000000, 1000, 9000, 10000),   # Sueldo medio
            (2500000, 2500, 22500, 25000),  # Sueldo alto
            (5000000, 5000, 45000, 50000),  # Sueldo muy alto
        ]

        for wage, exp_cuenta, exp_seguro, exp_total in test_cases:
            with self.subTest(wage=wage):
                contract = self.env['hr.contract'].create({
                    'name': f'Contrato ${wage:,}',
                    'employee_id': self.employee.id,
                    'wage': wage,
                    'date_start': date(2025, 8, 1),
                    'state': 'open',
                    'afp_id': self.afp.id
                })

                payslip = self.env['hr.payslip'].create({
                    'name': f'Payslip ${wage:,}',
                    'employee_id': self.employee.id,
                    'contract_id': contract.id,
                    'date_from': date(2025, 10, 1),
                    'date_to': date(2025, 10, 31),
                    'struct_id': self.struct.id
                })

                payslip.compute_sheet()

                self.assertEqual(
                    payslip.employer_cuenta_individual_ley21735, exp_cuenta,
                    f"Cuenta Individual ${wage:,}"
                )
                self.assertEqual(
                    payslip.employer_seguro_social_ley21735, exp_seguro,
                    f"Seguro Social ${wage:,}"
                )
                self.assertEqual(
                    payslip.employer_total_ley21735, exp_total,
                    f"Total ${wage:,}"
                )

    def test_08_contratos_anteriores_agosto_vigentes_post_agosto(self):
        """Contratos anteriores a agosto 2025 pero nóminas post-agosto deben aplicar"""

        # Contrato iniciado antes de agosto 2025
        contract = self.env['hr.contract'].create({
            'name': 'Contrato Abril 2025',
            'employee_id': self.employee.id,
            'wage': 1200000,
            'date_start': date(2025, 4, 1),  # Antes vigencia
            'state': 'open',
            'afp_id': self.afp.id
        })

        # Nómina agosto 2025 (post vigencia)
        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Agosto 2025 - Contrato Antiguo',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Debe aplicar (es el PERÍODO el que determina aplicación, no inicio contrato)
        self.assertTrue(
            payslip.aplica_ley21735,
            "Debe aplicar Ley 21.735 si período es post 01-08-2025, "
            "independiente de fecha inicio contrato"
        )

        expected_total = contract.wage * 0.01
        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            "Total debe ser 1% incluso en contratos pre-agosto"
        )

    def test_09_wage_cero_no_genera_aporte(self):
        """Wage 0 o negativo no debe generar aporte"""

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Sin Sueldo',
            'employee_id': self.employee.id,
            'wage': 0,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Sin Sueldo',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Aplica la ley pero aporte es 0
        self.assertTrue(payslip.aplica_ley21735, "Aplica ley (período válido)")
        self.assertEqual(
            payslip.employer_total_ley21735, 0,
            "Aporte debe ser 0 si wage es 0"
        )

    def test_10_periodos_futuros_2026_aplican(self):
        """Períodos futuros (2026+) deben seguir aplicando Ley 21.735"""

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2026',
            'employee_id': self.employee.id,
            'wage': 3000000,
            'date_start': date(2026, 1, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Enero 2026',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2026, 1, 1),
            'date_to': date(2026, 1, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        self.assertTrue(
            payslip.aplica_ley21735,
            "Ley 21.735 debe aplicar en 2026 y siguientes"
        )

        expected_total = 3000000 * 0.01
        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            "Cálculo debe ser correcto en períodos futuros"
        )
