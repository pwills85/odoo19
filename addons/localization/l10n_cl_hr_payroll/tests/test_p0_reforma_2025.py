# -*- coding: utf-8 -*-

"""
Test P0-1: Reforma Previsional 2025 (Ley 21.419)
================================================

Verifica implementación de aporte empleador 1% adicional:
- 0.5% APV (Ahorro Pensión Voluntaria)
- 0.5% Seguro Cesantía

Solo aplica a contratos iniciados desde 2025-01-01.
No aplica retroactivamente a contratos anteriores.

Referencias:
- Ley 21.419 (Reforma Previsional 2025)
- Superintendencia de Pensiones
- Previred - Circular Reforma 2025
- Auditoría 2025-11-07: P0-1
"""

from odoo.tests import tagged, TransactionCase
from datetime import date


@tagged('post_install', '-at_install', 'p0_critical', 'reforma_2025')
class TestP0Reforma2025(TransactionCase):
    """Test P0-1: Validar Reforma Previsional 2025"""

    def setUp(self):
        super().setUp()

        # Crear empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee Reforma'
        })

        # Crear AFP (para contratos)
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Cuprum',
            'code': 'CUPRUM',
            'rate': 11.44
        })

        # Contrato pre-2025 (NO aplica reforma)
        self.contract_2024 = self.env['hr.contract'].create({
            'name': 'Contrato 2024',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'date_start': date(2024, 6, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        # Contrato 2025 (SÍ aplica reforma)
        self.contract_2025 = self.env['hr.contract'].create({
            'name': 'Contrato 2025',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': date(2025, 1, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        # Estructura salarial
        self.struct = self.env.ref('l10n_cl_hr_payroll.structure_base_cl',
                                   raise_if_not_found=False)
        if not self.struct:
            # Crear estructura si no existe
            self.struct = self.env['hr.payroll.structure'].create({
                'name': 'Estructura Chile',
                'code': 'CL_BASE'
            })

    def test_reforma_no_aplica_contratos_2024(self):
        """
        P0-1: Contratos pre-2025 NO deben tener aporte reforma

        Validar que contratos iniciados antes del 2025-01-01
        NO tienen el aporte empleador del 1% adicional.
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Liquidación Test 2024',
            'employee_id': self.employee.id,
            'contract_id': self.contract_2024.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False
        })

        # Computar campos
        payslip._compute_employer_reforma_2025()

        self.assertEqual(
            payslip.employer_reforma_2025,
            0,
            "Contrato 2024 NO debe tener aporte reforma 2025"
        )
        self.assertEqual(
            payslip.employer_apv_2025,
            0,
            "Contrato 2024 NO debe tener APV empleador"
        )
        self.assertEqual(
            payslip.employer_cesantia_2025,
            0,
            "Contrato 2024 NO debe tener Cesantía empleador"
        )

    def test_reforma_aplica_contratos_2025(self):
        """
        P0-1: Contratos desde 2025 deben tener 1% adicional

        Validar que contratos iniciados desde 2025-01-01
        tienen el aporte empleador del 1% (0.5% APV + 0.5% Cesantía).
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Liquidación Test 2025',
            'employee_id': self.employee.id,
            'contract_id': self.contract_2025.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False
        })

        # Computar campos
        payslip._compute_employer_reforma_2025()

        # Validar cálculos
        # 1% de $1.500.000 = $15.000
        expected_total = 1500000 * 0.01  # $15.000
        expected_apv = 1500000 * 0.005   # $7.500
        expected_ces = 1500000 * 0.005   # $7.500

        self.assertEqual(
            payslip.employer_reforma_2025,
            expected_total,
            f"Aporte total debe ser 1% de sueldo (${expected_total:,.0f})"
        )
        self.assertEqual(
            payslip.employer_apv_2025,
            expected_apv,
            f"APV debe ser 0.5% de sueldo (${expected_apv:,.0f})"
        )
        self.assertEqual(
            payslip.employer_cesantia_2025,
            expected_ces,
            f"Cesantía debe ser 0.5% de sueldo (${expected_ces:,.0f})"
        )

    def test_reforma_calculo_correcto_distintos_sueldos(self):
        """
        P0-1: Validar cálculo correcto con diferentes sueldos

        Probar que el cálculo del 1% se aplica correctamente
        a diferentes rangos de sueldo.
        """
        test_cases = [
            (500000, 5000, 2500, 2500),     # Sueldo mínimo
            (1000000, 10000, 5000, 5000),   # Sueldo promedio
            (2000000, 20000, 10000, 10000), # Sueldo alto
            (3500000, 35000, 17500, 17500), # Sueldo muy alto
        ]

        for wage, expected_total, expected_apv, expected_ces in test_cases:
            with self.subTest(wage=wage):
                contract = self.env['hr.contract'].create({
                    'name': f'Contrato ${wage:,.0f}',
                    'employee_id': self.employee.id,
                    'wage': wage,
                    'date_start': date(2025, 1, 1),
                    'state': 'open',
                    'afp_id': self.afp.id
                })

                payslip = self.env['hr.payslip'].create({
                    'name': f'Test ${wage:,.0f}',
                    'employee_id': self.employee.id,
                    'contract_id': contract.id,
                    'date_from': date(2025, 1, 1),
                    'date_to': date(2025, 1, 31),
                    'struct_id': self.struct.id if self.struct else False
                })

                payslip._compute_employer_reforma_2025()

                self.assertEqual(
                    payslip.employer_reforma_2025,
                    expected_total,
                    f"Sueldo ${wage:,.0f}: Total debe ser ${expected_total:,.0f}"
                )
                self.assertEqual(
                    payslip.employer_apv_2025,
                    expected_apv,
                    f"Sueldo ${wage:,.0f}: APV debe ser ${expected_apv:,.0f}"
                )
                self.assertEqual(
                    payslip.employer_cesantia_2025,
                    expected_ces,
                    f"Sueldo ${wage:,.0f}: Cesantía debe ser ${expected_ces:,.0f}"
                )

    def test_reforma_fecha_limite_exacta(self):
        """
        P0-1: Validar fecha límite exacta 2025-01-01

        Contratos con fecha 2024-12-31 NO aplican.
        Contratos con fecha 2025-01-01 SÍ aplican.
        """
        # Contrato 31/12/2024 (NO aplica)
        contract_ultimo_dia_2024 = self.env['hr.contract'].create({
            'name': 'Contrato 31/12/2024',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'date_start': date(2024, 12, 31),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip_2024 = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': contract_ultimo_dia_2024.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False
        })

        payslip_2024._compute_employer_reforma_2025()

        self.assertEqual(
            payslip_2024.employer_reforma_2025,
            0,
            "Contrato 31/12/2024 NO debe tener reforma"
        )

        # Contrato 01/01/2025 (SÍ aplica)
        contract_primer_dia_2025 = self.env['hr.contract'].create({
            'name': 'Contrato 01/01/2025',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'date_start': date(2025, 1, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip_2025 = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': contract_primer_dia_2025.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False
        })

        payslip_2025._compute_employer_reforma_2025()

        self.assertEqual(
            payslip_2025.employer_reforma_2025,
            10000,  # 1% de $1.000.000
            "Contrato 01/01/2025 debe tener reforma ($10.000)"
        )

    def test_reforma_sin_contrato_no_falla(self):
        """
        P0-1: Validar que payslip sin contrato no causa error

        Edge case: payslip sin contract_id debe retornar 0
        sin lanzar excepción.
        """
        payslip_sin_contrato = self.env['hr.payslip'].create({
            'name': 'Test sin contrato',
            'employee_id': self.employee.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False
        })

        # No debe lanzar excepción
        payslip_sin_contrato._compute_employer_reforma_2025()

        self.assertEqual(
            payslip_sin_contrato.employer_reforma_2025,
            0,
            "Payslip sin contrato debe retornar 0"
        )

    def test_reforma_percentage_accuracy(self):
        """
        P0-1: Validar precisión de porcentajes

        Verificar que los cálculos usan exactamente 0.5% (no 0.005001 ni 0.004999)
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Precisión',
            'employee_id': self.employee.id,
            'contract_id': self.contract_2025.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False
        })

        payslip._compute_employer_reforma_2025()

        # Validar que APV + Cesantía = Total
        sum_components = payslip.employer_apv_2025 + payslip.employer_cesantia_2025

        self.assertEqual(
            sum_components,
            payslip.employer_reforma_2025,
            "Suma de componentes debe ser igual al total"
        )

        # Validar que cada componente es exactamente 0.5%
        expected_apv = self.contract_2025.wage * 0.005
        expected_ces = self.contract_2025.wage * 0.005

        self.assertAlmostEqual(
            payslip.employer_apv_2025,
            expected_apv,
            places=2,
            msg="APV debe ser exactamente 0.5% del sueldo"
        )

        self.assertAlmostEqual(
            payslip.employer_cesantia_2025,
            expected_ces,
            places=2,
            msg="Cesantía debe ser exactamente 0.5% del sueldo"
        )
