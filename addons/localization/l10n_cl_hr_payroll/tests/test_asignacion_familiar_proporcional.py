# -*- coding: utf-8 -*-

"""
Tests para GAP-001: Proporcionalidad Asignación Familiar

Normativa: DFL 150 Art. 1° - Proporcionalidad obligatoria
Fix: 2025-11-09 GAP-001

Valida cálculo de asignación familiar proporcional por días trabajados
considerando fechas de ingreso y egreso del trabajador.

Tests:
- Ingreso mid-mes (día 15, mes 30 días)
- Egreso mid-mes (día 10, mes 31 días)
- Mes completo sin proporcionalidad (100%)
- Febrero bisiesto edge case (15 días de 29 disponibles)
- Múltiples cargas + proporcionalidad (2 simples + factor)
"""

from odoo.tests import tagged, TransactionCase
from datetime import date
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'payroll_gap001')
class TestAsignacionFamiliarProporcional(TransactionCase):
    """
    Tests para proporcionalidad Asignación Familiar

    Técnica: TransactionCase de Odoo 19 CE
    Fixture: Empleado + Contrato + Indicadores (setUp)
    """

    def setUp(self):
        super().setUp()

        # ═══════════════════════════════════════════════════════════
        # SETUP: Crear indicadores económicos base
        # ═══════════════════════════════════════════════════════════

        self.indicators = self.env['hr.economic.indicators'].create({
            'period': date(2025, 10, 1),
            'uf': 39383.07,
            'utm': 68647,
            'uta': 823764,
            'minimum_wage': 500000.00,
            'afp_limit': 87.8,
        })

        # ═══════════════════════════════════════════════════════════
        # SETUP: Crear AFP (requerido para contrato)
        # ═══════════════════════════════════════════════════════════

        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Capital',
            'code': 'CAPITAL',
            'rate': 11.44,
        })

        # ═══════════════════════════════════════════════════════════
        # SETUP: Crear empleado base (sin fechas ingreso/egreso)
        # ═══════════════════════════════════════════════════════════

        self.employee_base = self.env['hr.employee'].create({
            'name': 'Base Employee Proporcional',
            'identification_id': '12345678-9',
        })

        # ═══════════════════════════════════════════════════════════
        # SETUP: Crear contrato Tramo A (ingreso bajo) con 1 carga simple
        # ═══════════════════════════════════════════════════════════

        self.contract = self.env['hr.contract'].create({
            'name': 'Test Contract Proportional',
            'employee_id': self.employee_base.id,
            'wage': 400000,  # Tramo A (≤ $434,162)
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'family_allowance_simple': 1,  # 1 carga simple
            'family_allowance_maternal': 0,
            'state': 'open',
            'date_start': date(2025, 1, 1),
        })

        # ═══════════════════════════════════════════════════════════
        # SETUP: Obtener estructura salarial
        # ═══════════════════════════════════════════════════════════

        self.struct = self.env.ref('l10n_cl_hr_payroll.structure_base_cl',
                                   raise_if_not_found=False)
        if not self.struct:
            self.struct = self.env['hr.payroll.structure'].create({
                'name': 'Estructura Chile',
                'code': 'CL_BASE'
            })

    # ═══════════════════════════════════════════════════════════════════
    # TEST 1: INGRESO DÍA 15, MES 30 DÍAS
    # ═══════════════════════════════════════════════════════════════════

    def test_ingreso_dia_15_mes_30_dias(self):
        """
        Trabajador ingresa día 15 de mes de 30 días

        Datos:
        - Período: 2025-10-01 al 2025-10-30 (30 días)
        - Ingreso: 2025-10-15 (día 15)
        - Días trabajados: 16 (del 15 al 30, inclusivo)
        - Factor proporcional: 16/30 = 0.5333
        - Asignación base: $13,193 (1 carga simple, Tramo A)
        - Asignación proporcional: $13,193 × 0.5333 = ~$7,033
        """
        # Setup: Crear empleado con fecha ingreso día 15
        employee = self.env['hr.employee'].create({
            'name': 'Test Ingreso 15 Octubre',
            'identification_id': '11111111-1',
            'date_start': date(2025, 10, 15),  # INGRESO DÍA 15
        })

        # Crear contrato para este empleado
        contract = self.env['hr.contract'].create({
            'name': 'Contract Ingreso 15',
            'employee_id': employee.id,
            'wage': 400000,  # Tramo A
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'family_allowance_simple': 1,  # 1 carga simple
            'family_allowance_maternal': 0,
            'state': 'open',
            'date_start': date(2025, 10, 15),  # Coincide con empleado
        })

        # Execute: Crear payslip para octubre
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip Ingreso 15',
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 30),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        # Execute: Computar campos
        payslip.compute_sheet()

        # ═══════════════════════════════════════════════════════════
        # ASSERT 1: Días trabajados = 16 (15 al 30, inclusivo)
        # ═══════════════════════════════════════════════════════════

        self.assertEqual(
            payslip.asignacion_familiar_dias_trabajados,
            16,
            f"Días trabajados debe ser 16 (15 al 30, inclusivo), "
            f"obtuvo {payslip.asignacion_familiar_dias_trabajados}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 2: Factor proporcional = 16/30 = 0.5333
        # ═══════════════════════════════════════════════════════════

        expected_factor = 16 / 30  # 0.5333...
        self.assertAlmostEqual(
            payslip.asignacion_familiar_factor_proporcional,
            expected_factor,
            places=4,
            msg=f"Factor proporcional debe ser {expected_factor:.4f} (16/30), "
            f"obtuvo {payslip.asignacion_familiar_factor_proporcional:.4f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 3: Total base = $13,193 (Tramo A, 1 carga simple)
        # ═══════════════════════════════════════════════════════════

        expected_base = 13193  # Monto Tramo A × 1 carga
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total_base,
            expected_base,
            places=0,
            msg=f"Total base debe ser ${expected_base:,.0f} "
            f"(Tramo A, 1 carga simple), "
            f"obtuvo ${payslip.asignacion_familiar_total_base:,.0f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 4: Total proporcional = $13,193 × 0.5333 = ~$7,033
        # ═══════════════════════════════════════════════════════════

        expected_proporcional = expected_base * expected_factor  # 13193 × 0.5333 ≈ 7033
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total,
            expected_proporcional,
            places=0,
            msg=f"Asignación proporcional debe ser ~${expected_proporcional:,.0f} "
            f"(${expected_base:,.0f} × {expected_factor:.4f}), "
            f"obtuvo ${payslip.asignacion_familiar_total:,.0f}"
        )

        _logger.info(
            f"✓ TEST 1 PASS: Ingreso día 15/30 → "
            f"{payslip.asignacion_familiar_dias_trabajados} días, "
            f"factor {payslip.asignacion_familiar_factor_proporcional:.4f}, "
            f"total ${payslip.asignacion_familiar_total:,.0f}"
        )

    # ═══════════════════════════════════════════════════════════════════
    # TEST 2: EGRESO DÍA 10, MES 31 DÍAS
    # ═══════════════════════════════════════════════════════════════════

    def test_egreso_dia_10_mes_31_dias(self):
        """
        Trabajador egresa día 10 de mes de 31 días

        Datos:
        - Período: 2025-12-01 al 2025-12-31 (31 días)
        - Egreso: 2025-12-10 (día 10)
        - Días trabajados: 10 (del 1 al 10, inclusivo)
        - Factor proporcional: 10/31 = 0.3226
        - Asignación base: $13,193 (1 carga simple, Tramo A)
        - Asignación proporcional: $13,193 × 0.3226 = ~$4,254
        """
        # Setup: Crear empleado con fecha egreso día 10
        employee = self.env['hr.employee'].create({
            'name': 'Test Egreso 10 Diciembre',
            'identification_id': '22222222-2',
            'date_start': date(2024, 1, 1),  # Contratado hace tiempo
            'date_end': date(2025, 12, 10),  # EGRESO DÍA 10 DICIEMBRE
        })

        # Crear contrato para este empleado
        contract = self.env['hr.contract'].create({
            'name': 'Contract Egreso 10',
            'employee_id': employee.id,
            'wage': 400000,  # Tramo A
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'family_allowance_simple': 1,  # 1 carga simple
            'family_allowance_maternal': 0,
            'state': 'open',
            'date_start': date(2024, 1, 1),
            'date_end': date(2025, 12, 10),  # Coincide con empleado
        })

        # Execute: Crear payslip para diciembre
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip Egreso 10',
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 12, 1),
            'date_to': date(2025, 12, 31),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        # Execute: Computar campos
        payslip.compute_sheet()

        # ═══════════════════════════════════════════════════════════
        # ASSERT 1: Días trabajados = 10 (1 al 10, inclusivo)
        # ═══════════════════════════════════════════════════════════

        self.assertEqual(
            payslip.asignacion_familiar_dias_trabajados,
            10,
            f"Días trabajados debe ser 10 (1 al 10, inclusivo), "
            f"obtuvo {payslip.asignacion_familiar_dias_trabajados}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 2: Factor proporcional = 10/31 = 0.3226
        # ═══════════════════════════════════════════════════════════

        expected_factor = 10 / 31  # 0.3226...
        self.assertAlmostEqual(
            payslip.asignacion_familiar_factor_proporcional,
            expected_factor,
            places=4,
            msg=f"Factor proporcional debe ser {expected_factor:.4f} (10/31), "
            f"obtuvo {payslip.asignacion_familiar_factor_proporcional:.4f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 3: Total base = $13,193 (Tramo A, 1 carga simple)
        # ═══════════════════════════════════════════════════════════

        expected_base = 13193  # Monto Tramo A × 1 carga
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total_base,
            expected_base,
            places=0,
            msg=f"Total base debe ser ${expected_base:,.0f}, "
            f"obtuvo ${payslip.asignacion_familiar_total_base:,.0f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 4: Total proporcional = $13,193 × 0.3226 = ~$4,254
        # ═══════════════════════════════════════════════════════════

        expected_proporcional = expected_base * expected_factor  # 13193 × 0.3226 ≈ 4254
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total,
            expected_proporcional,
            places=0,
            msg=f"Asignación proporcional debe ser ~${expected_proporcional:,.0f} "
            f"(${expected_base:,.0f} × {expected_factor:.4f}), "
            f"obtuvo ${payslip.asignacion_familiar_total:,.0f}"
        )

        _logger.info(
            f"✓ TEST 2 PASS: Egreso día 10/31 → "
            f"{payslip.asignacion_familiar_dias_trabajados} días, "
            f"factor {payslip.asignacion_familiar_factor_proporcional:.4f}, "
            f"total ${payslip.asignacion_familiar_total:,.0f}"
        )

    # ═══════════════════════════════════════════════════════════════════
    # TEST 3: MES COMPLETO SIN PROPORCIONALIDAD (100%)
    # ═══════════════════════════════════════════════════════════════════

    def test_mes_completo_sin_proporcionalidad(self):
        """
        Trabajador mes completo (sin fecha ingreso/egreso en período)

        Datos:
        - Período: 2025-10-01 al 2025-10-30 (30 días)
        - Sin ingreso en período (fecha_start anterior a período)
        - Sin egreso en período (fecha_end posterior a período o no existe)
        - Días trabajados: 30
        - Factor proporcional: 30/30 = 1.0 (100%)
        - Asignación base: $13,193 (1 carga simple, Tramo A)
        - Asignación total: $13,193 × 1.0 = $13,193 (SIN DESCUENTO)
        """
        # Setup: Crear empleado sin restricciones en período
        employee = self.env['hr.employee'].create({
            'name': 'Test Mes Completo',
            'identification_id': '33333333-3',
            'date_start': date(2025, 1, 1),  # ANTERIOR al período
            # Sin date_end (activo indefinidamente)
        })

        # Crear contrato
        contract = self.env['hr.contract'].create({
            'name': 'Contract Mes Completo',
            'employee_id': employee.id,
            'wage': 400000,  # Tramo A
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'family_allowance_simple': 1,  # 1 carga simple
            'family_allowance_maternal': 0,
            'state': 'open',
            'date_start': date(2025, 1, 1),
        })

        # Execute: Crear payslip para octubre
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip Mes Completo',
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 10, 1),
            'date_to': date(2025, 10, 30),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        # Execute: Computar campos
        payslip.compute_sheet()

        # ═══════════════════════════════════════════════════════════
        # ASSERT 1: Días trabajados = 30 (mes completo)
        # ═══════════════════════════════════════════════════════════

        self.assertEqual(
            payslip.asignacion_familiar_dias_trabajados,
            30,
            f"Días trabajados debe ser 30 (mes completo), "
            f"obtuvo {payslip.asignacion_familiar_dias_trabajados}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 2: Factor proporcional = 30/30 = 1.0 (100%)
        # ═══════════════════════════════════════════════════════════

        expected_factor = 1.0
        self.assertAlmostEqual(
            payslip.asignacion_familiar_factor_proporcional,
            expected_factor,
            places=4,
            msg=f"Factor proporcional debe ser 1.0 (100%), "
            f"obtuvo {payslip.asignacion_familiar_factor_proporcional:.4f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 3: Total base = $13,193 (1 carga simple, Tramo A)
        # ═══════════════════════════════════════════════════════════

        expected_base = 13193
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total_base,
            expected_base,
            places=0,
            msg=f"Total base debe ser ${expected_base:,.0f}, "
            f"obtuvo ${payslip.asignacion_familiar_total_base:,.0f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 4: Total = $13,193 (sin descuento, factor 1.0)
        # ═══════════════════════════════════════════════════════════

        expected_total = 13193  # Sin proporcionalidad
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total,
            expected_total,
            places=0,
            msg=f"Asignación debe ser ${expected_total:,.0f} "
            f"(100% sin descuento por proporcionalidad), "
            f"obtuvo ${payslip.asignacion_familiar_total:,.0f}"
        )

        _logger.info(
            f"✓ TEST 3 PASS: Mes completo → "
            f"{payslip.asignacion_familiar_dias_trabajados} días, "
            f"factor {payslip.asignacion_familiar_factor_proporcional:.4f}, "
            f"total ${payslip.asignacion_familiar_total:,.0f}"
        )

    # ═══════════════════════════════════════════════════════════════════
    # TEST 4: FEBRERO BISIESTO 29 DÍAS (EDGE CASE)
    # ═══════════════════════════════════════════════════════════════════

    def test_febrero_bisiesto_29_dias(self):
        """
        Edge case: Febrero bisiesto (2024)

        Datos:
        - Período: 2024-02-01 al 2024-02-29 (bisiesto, 29 días)
        - Ingreso: 2024-02-15 (día 15)
        - Días trabajados: 15 (del 15 al 29, inclusivo)
        - Factor proporcional: 15/29 = 0.5172
        - Asignación base: $13,193 (1 carga simple, Tramo A)
        - Asignación proporcional: $13,193 × 0.5172 = ~$6,821
        """
        # Setup: Crear empleado con ingreso día 15 febrero
        employee = self.env['hr.employee'].create({
            'name': 'Test Febrero Bisiesto',
            'identification_id': '44444444-4',
            'date_start': date(2024, 2, 15),  # INGRESO DÍA 15 FEBRERO BISIESTO
        })

        # Crear contrato
        contract = self.env['hr.contract'].create({
            'name': 'Contract Febrero Bisiesto',
            'employee_id': employee.id,
            'wage': 400000,  # Tramo A
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'family_allowance_simple': 1,  # 1 carga simple
            'family_allowance_maternal': 0,
            'state': 'open',
            'date_start': date(2024, 2, 15),  # Coincide con empleado
        })

        # Execute: Crear payslip para febrero (bisiesto)
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip Febrero Bisiesto',
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': date(2024, 2, 1),
            'date_to': date(2024, 2, 29),  # Febrero bisiesto = 29 días
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        # Execute: Computar campos
        payslip.compute_sheet()

        # ═══════════════════════════════════════════════════════════
        # ASSERT 1: Días trabajados = 15 (15 al 29, inclusivo)
        # ═══════════════════════════════════════════════════════════

        self.assertEqual(
            payslip.asignacion_familiar_dias_trabajados,
            15,
            f"Días trabajados debe ser 15 (15 al 29 febrero bisiesto), "
            f"obtuvo {payslip.asignacion_familiar_dias_trabajados}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 2: Factor proporcional = 15/29 = 0.5172
        # ═══════════════════════════════════════════════════════════

        expected_factor = 15 / 29  # 0.5172...
        self.assertAlmostEqual(
            payslip.asignacion_familiar_factor_proporcional,
            expected_factor,
            places=4,
            msg=f"Factor proporcional debe ser {expected_factor:.4f} (15/29), "
            f"obtuvo {payslip.asignacion_familiar_factor_proporcional:.4f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 3: Total base = $13,193 (Tramo A, 1 carga simple)
        # ═══════════════════════════════════════════════════════════

        expected_base = 13193
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total_base,
            expected_base,
            places=0,
            msg=f"Total base debe ser ${expected_base:,.0f}, "
            f"obtuvo ${payslip.asignacion_familiar_total_base:,.0f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 4: Total proporcional = $13,193 × 0.5172 = ~$6,821
        # ═══════════════════════════════════════════════════════════

        expected_proporcional = expected_base * expected_factor  # 13193 × 0.5172 ≈ 6821
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total,
            expected_proporcional,
            places=0,
            msg=f"Asignación proporcional debe ser ~${expected_proporcional:,.0f} "
            f"(${expected_base:,.0f} × {expected_factor:.4f}), "
            f"obtuvo ${payslip.asignacion_familiar_total:,.0f}"
        )

        _logger.info(
            f"✓ TEST 4 PASS: Febrero bisiesto (15/29) → "
            f"{payslip.asignacion_familiar_dias_trabajados} días, "
            f"factor {payslip.asignacion_familiar_factor_proporcional:.4f}, "
            f"total ${payslip.asignacion_familiar_total:,.0f}"
        )

    # ═══════════════════════════════════════════════════════════════════
    # TEST 5: MÚLTIPLES CARGAS + PROPORCIONALIDAD
    # ═══════════════════════════════════════════════════════════════════

    def test_multiple_cargas_proporcional(self):
        """
        2 cargas simples + proporcionalidad

        Datos:
        - Período: 2025-11-01 al 2025-11-30 (30 días)
        - Ingreso: 2025-11-20 (día 20)
        - Días trabajados: 11 (del 20 al 30, inclusivo)
        - Factor proporcional: 11/30 = 0.3667
        - Asignación base: $13,193 × 2 = $26,386 (Tramo A, 2 cargas simples)
        - Asignación proporcional: $26,386 × 0.3667 = ~$9,677
        """
        # Setup: Crear empleado con ingreso día 20 noviembre
        employee = self.env['hr.employee'].create({
            'name': 'Test Múltiples Cargas',
            'identification_id': '55555555-5',
            'date_start': date(2025, 11, 20),  # INGRESO DÍA 20 NOVIEMBRE
        })

        # Crear contrato CON 2 CARGAS SIMPLES
        contract = self.env['hr.contract'].create({
            'name': 'Contract Múltiples Cargas',
            'employee_id': employee.id,
            'wage': 400000,  # Tramo A
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'family_allowance_simple': 2,  # 2 CARGAS SIMPLES
            'family_allowance_maternal': 0,
            'state': 'open',
            'date_start': date(2025, 11, 20),  # Coincide con empleado
        })

        # Execute: Crear payslip para noviembre
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip Múltiples Cargas',
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 11, 1),
            'date_to': date(2025, 11, 30),
            'indicadores_id': self.indicators.id,
            'struct_id': self.struct.id,
        })

        # Execute: Computar campos
        payslip.compute_sheet()

        # ═══════════════════════════════════════════════════════════
        # ASSERT 1: Días trabajados = 11 (20 al 30, inclusivo)
        # ═══════════════════════════════════════════════════════════

        self.assertEqual(
            payslip.asignacion_familiar_dias_trabajados,
            11,
            f"Días trabajados debe ser 11 (20 al 30, inclusivo), "
            f"obtuvo {payslip.asignacion_familiar_dias_trabajados}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 2: Factor proporcional = 11/30 = 0.3667
        # ═══════════════════════════════════════════════════════════

        expected_factor = 11 / 30  # 0.3667...
        self.assertAlmostEqual(
            payslip.asignacion_familiar_factor_proporcional,
            expected_factor,
            places=4,
            msg=f"Factor proporcional debe ser {expected_factor:.4f} (11/30), "
            f"obtuvo {payslip.asignacion_familiar_factor_proporcional:.4f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 3: Total base = $13,193 × 2 = $26,386 (Tramo A, 2 cargas)
        # ═══════════════════════════════════════════════════════════

        expected_base = 13193 * 2  # $26,386 (2 cargas simples)
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total_base,
            expected_base,
            places=0,
            msg=f"Total base debe ser ${expected_base:,.0f} "
            f"(${13193:,.0f} × 2 cargas), "
            f"obtuvo ${payslip.asignacion_familiar_total_base:,.0f}"
        )

        # ═══════════════════════════════════════════════════════════
        # ASSERT 4: Total proporcional = $26,386 × 0.3667 = ~$9,677
        # ═══════════════════════════════════════════════════════════

        expected_proporcional = expected_base * expected_factor  # 26386 × 0.3667 ≈ 9677
        self.assertAlmostEqual(
            payslip.asignacion_familiar_total,
            expected_proporcional,
            places=0,
            msg=f"Asignación proporcional debe ser ~${expected_proporcional:,.0f} "
            f"(${expected_base:,.0f} × {expected_factor:.4f}), "
            f"obtuvo ${payslip.asignacion_familiar_total:,.0f}"
        )

        _logger.info(
            f"✓ TEST 5 PASS: Múltiples cargas (2) + proporcionalidad → "
            f"{payslip.asignacion_familiar_dias_trabajados} días, "
            f"factor {payslip.asignacion_familiar_factor_proporcional:.4f}, "
            f"base ${payslip.asignacion_familiar_total_base:,.0f}, "
            f"total ${payslip.asignacion_familiar_total:,.0f}"
        )
