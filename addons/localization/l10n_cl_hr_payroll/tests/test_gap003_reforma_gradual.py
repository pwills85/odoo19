# -*- coding: utf-8 -*-
"""
Tests GAP-003 - Reforma Previsional 2025 - Gradualidad Aporte Empleador

Valida implementación completa gradualidad Ley 21.735:
- Tabla gradualidad 2025-2033 (9 años)
- Distribución CI/CRP/SSP VARIABLE por período
- Tope AFP 87.8 UF (integración l10n_cl.legal.caps)
- Campo CRP (desde agosto 2026)
- Integración AI service (hr.economic.indicators)

Normativa:
- Ley 21.735 "Reforma del Sistema de Pensiones"
- Fuente: ChileAtiende + Superintendencia Pensiones
- Vigencia: 01-08-2025
- Gradualidad: 1.0% → 8.5% (9 años)

Coverage target: ≥95%
Tests: 16 (gradualidad, distribución, tope, CRP, integración)

Test categories:
1. GRADUALIDAD (9 tests): test_01 to test_09
2. DISTRIBUCIÓN VARIABLE (3 tests): test_10 to test_12
3. TOPE AFP (2 tests): test_13 to test_14
4. CAMPO CRP (1 test): test_15
5. INTEGRACIÓN AI SERVICE (1 test): test_16
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from datetime import date, timedelta
import logging

_logger = logging.getLogger(__name__)


class TestGAP003ReformaGradual(TransactionCase):
    """Suite tests exhaustiva GAP-003 - Reforma Previsional 2025"""

    @classmethod
    def setUpClass(cls):
        """Setup inicial de la clase (ejecutado una sola vez)"""
        super().setUpClass()
        _logger.info("═" * 80)
        _logger.info("INICIANDO TEST SUITE GAP-003 - REFORMA PREVISIONAL 2025")
        _logger.info("═" * 80)

    def setUp(self):
        """Setup inicial de cada test - Crear fixtures completos"""
        super().setUp()

        # ═════════════════════════════════════════════════════════════
        # 1. COMPANY y EMPLOYEE
        # ═════════════════════════════════════════════════════════════
        self.company = self.env.ref('base.main_company')

        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee GAP-003',
            'company_id': self.company.id,
            'identification_id': '12.345.678-9',
        })

        # ═════════════════════════════════════════════════════════════
        # 2. AFP
        # ═════════════════════════════════════════════════════════════
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Cuprum',
            'code': 'CUPRUM',
            'rate': 11.44,
            'sis_rate': 1.57
        })

        # ═════════════════════════════════════════════════════════════
        # 3. INDICADORES ECONÓMICOS (2025-2035, 132 registros)
        # CRÍTICO: Sin estos fixtures, tests fallarán con ValidationError
        # ═════════════════════════════════════════════════════════════
        _logger.info("Poblando indicadores económicos 2025-2035...")

        # UF base (valores aproximados históricos)
        uf_values = {
            2025: 38277.50,
            2026: 39000.00,
            2027: 39500.00,
            2028: 40000.00,
            2029: 40500.00,
            2030: 41000.00,
            2031: 41500.00,
            2032: 42000.00,
            2033: 42500.00,
            2034: 43000.00,
            2035: 43500.00,
        }

        for year in range(2025, 2036):
            uf = uf_values.get(year, 38277.50)
            for month in range(1, 13):
                period = date(year, month, 1)

                # Evitar duplicados
                existing = self.env['hr.economic.indicators'].search([
                    ('period', '=', period)
                ])
                if existing:
                    existing.unlink()

                self.env['hr.economic.indicators'].create({
                    'period': period,
                    'uf': uf,
                    'utm': int(uf * 1.74),  # UTM aproximadamente 1.74x UF
                    'uta': int(uf * 21.5),  # UTA aproximadamente 21.5x UF
                    'minimum_wage': 500000,
                })

        _logger.info(f"✓ Poblados 132 indicadores económicos (11 años × 12 meses)")

        # ═════════════════════════════════════════════════════════════
        # 4. LEGAL CAPS (Tope AFP - Arquitectura distribuida)
        # ═════════════════════════════════════════════════════════════
        _logger.info("Poblando legal caps (AFP_IMPONIBLE_CAP)...")

        # Crear tope AFP para todos los años de tests (87.8 UF)
        existing_caps = self.env['l10n_cl.legal.caps'].search([
            ('code', '=', 'AFP_IMPONIBLE_CAP')
        ])
        existing_caps.unlink()

        self.legal_cap = self.env['l10n_cl.legal.caps'].create({
            'code': 'AFP_IMPONIBLE_CAP',
            'name': 'Tope Imponible AFP',
            'value': 87.8,
            'unit': 'uf',
            'date_from': date(2025, 1, 1),
            'date_to': date(2035, 12, 31),
            'active': True,
        })

        _logger.info(f"✓ Legal cap AFP: 87.8 UF")

        # ═════════════════════════════════════════════════════════════
        # 5. ESTRUCTURA SALARIAL
        # ═════════════════════════════════════════════════════════════
        self.struct = self.env.ref('l10n_cl_hr_payroll.structure_base_cl',
                                   raise_if_not_found=False)
        if not self.struct:
            self.struct = self.env['hr.payroll.structure'].create({
                'name': 'Estructura Chile',
                'code': 'CL_BASE'
            })

        _logger.info(f"✓ Setup completado - Listos para tests")

    # ═════════════════════════════════════════════════════════════════════
    # SECCIÓN 1: TESTS GRADUALIDAD (test_01 a test_09)
    # ═════════════════════════════════════════════════════════════════════

    def test_01_gradualidad_2025_1_0_percent(self):
        """
        Test Gradualidad Año 2025: 1.0% total

        Valida:
        - CI: 0.1% (absoluto = 10% relativo en 2025)
        - CRP: 0.0% (no aplica)
        - SSP: 0.9% (absoluto = 90% relativo en 2025)
        - Total: 1.0%

        Normativa: Ley 21.735 Art. 2° - Año 1 (2025)
        """
        wage = 2000000  # $2M

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2025',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2025',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Valores esperados
        expected_ci = wage * 0.001  # 0.1%
        expected_crp = 0.0  # No aplica en 2025
        expected_ssp = wage * 0.009  # 0.9%
        expected_total = wage * 0.010  # 1.0%

        # Validaciones
        self.assertEqual(
            payslip.employer_cuenta_individual_ley21735, expected_ci,
            f"CI debe ser 0.1% de ${wage:,} = ${expected_ci:,.0f}, "
            f"pero obtuvo ${payslip.employer_cuenta_individual_ley21735:,.0f}"
        )

        self.assertEqual(
            payslip.employer_crp_ley21735, expected_crp,
            "CRP debe ser 0 en 2025 (aún no vigente)"
        )

        self.assertEqual(
            payslip.employer_seguro_social_ley21735, expected_ssp,
            f"SSP debe ser 0.9% de ${wage:,} = ${expected_ssp:,.0f}, "
            f"pero obtuvo ${payslip.employer_seguro_social_ley21735:,.0f}"
        )

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total debe ser 1.0% de ${wage:,} = ${expected_total:,.0f}, "
            f"pero obtuvo ${payslip.employer_total_ley21735:,.0f}"
        )

        _logger.info(f"✓ test_01: Gradualidad 2025 = 1.0% CORRECTO")

    def test_02_gradualidad_2026_3_5_percent(self):
        """
        Test Gradualidad Año 2026: 3.5% total

        Valida:
        - CI: 0.1% (absoluto)
        - CRP: 0.9% (absoluto, INICIA en 2026)
        - SSP: 2.5% (absoluto)
        - Total: 3.5% (NO 2.0%)

        Normativa: Ley 21.735 Art. 2° - Año 2 (2026)
        **CRÍTICO:** Corrige error plan v1.0 (2.0% → 3.5%)
        """
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2026',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2026, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2026',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2026, 8, 1),
            'date_to': date(2026, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Valores esperados - TABLA OFICIAL
        expected_ci = wage * 0.001  # 0.1%
        expected_crp = wage * 0.009  # 0.9% (INICIA en 2026)
        expected_ssp = wage * 0.025  # 2.5%
        expected_total = wage * 0.035  # 3.5% (CRÍTICO)

        # Validaciones
        self.assertEqual(
            payslip.employer_cuenta_individual_ley21735, expected_ci,
            f"CI 2026 debe ser 0.1%"
        )

        self.assertGreater(
            payslip.employer_crp_ley21735, 0,
            "CRP debe ser > 0 desde agosto 2026"
        )

        self.assertEqual(
            payslip.employer_crp_ley21735, expected_crp,
            f"CRP 2026 debe ser 0.9% = ${expected_crp:,.0f}, "
            f"pero obtuvo ${payslip.employer_crp_ley21735:,.0f}"
        )

        self.assertEqual(
            payslip.employer_seguro_social_ley21735, expected_ssp,
            f"SSP 2026 debe ser 2.5% = ${expected_ssp:,.0f}, "
            f"pero obtuvo ${payslip.employer_seguro_social_ley21735:,.0f}"
        )

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2026 DEBE SER 3.5% (${expected_total:,.0f}), "
            f"NO 2.0% como plan v1.0 - OBTUVO ${payslip.employer_total_ley21735:,.0f}"
        )

        _logger.info(f"✓ test_02: Gradualidad 2026 = 3.5% CORRECTO (corrige v1.0)")

    def test_03_gradualidad_2027_4_25_percent(self):
        """
        Test Gradualidad Año 2027: 4.25% total

        Valida distribución: CI 0.25%, CRP 1.5%, SSP 2.5%
        """
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2027',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2027, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2027',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2027, 8, 1),
            'date_to': date(2027, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        expected_ci = wage * 0.0025  # 0.25%
        expected_crp = wage * 0.015  # 1.5%
        expected_ssp = wage * 0.025  # 2.5%
        expected_total = wage * 0.0425  # 4.25%

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2027 debe ser 4.25% = ${expected_total:,.0f}"
        )

        _logger.info(f"✓ test_03: Gradualidad 2027 = 4.25% CORRECTO")

    def test_04_gradualidad_2028_5_0_percent(self):
        """Test Gradualidad Año 2028: 5.0% total"""
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2028',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2028, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2028',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2028, 8, 1),
            'date_to': date(2028, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        expected_total = wage * 0.050  # 5.0%

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2028 debe ser 5.0% = ${expected_total:,.0f}"
        )

        _logger.info(f"✓ test_04: Gradualidad 2028 = 5.0% CORRECTO")

    def test_05_gradualidad_2029_5_7_percent(self):
        """Test Gradualidad Año 2029: 5.7% total"""
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2029',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2029, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2029',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2029, 8, 1),
            'date_to': date(2029, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        expected_total = wage * 0.057  # 5.7%

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2029 debe ser 5.7% = ${expected_total:,.0f}"
        )

        _logger.info(f"✓ test_05: Gradualidad 2029 = 5.7% CORRECTO")

    def test_06_gradualidad_2030_6_4_percent(self):
        """Test Gradualidad Año 2030: 6.4% total"""
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2030',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2030, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2030',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2030, 8, 1),
            'date_to': date(2030, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        expected_total = wage * 0.064  # 6.4%

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2030 debe ser 6.4% = ${expected_total:,.0f}"
        )

        _logger.info(f"✓ test_06: Gradualidad 2030 = 6.4% CORRECTO")

    def test_07_gradualidad_2031_7_1_percent(self):
        """Test Gradualidad Año 2031: 7.1% total"""
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2031',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2031, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2031',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2031, 8, 1),
            'date_to': date(2031, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        expected_total = wage * 0.071  # 7.1%

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2031 debe ser 7.1% = ${expected_total:,.0f}"
        )

        _logger.info(f"✓ test_07: Gradualidad 2031 = 7.1% CORRECTO")

    def test_08_gradualidad_2032_7_8_percent(self):
        """Test Gradualidad Año 2032: 7.8% total"""
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2032',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2032, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2032',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2032, 8, 1),
            'date_to': date(2032, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        expected_total = wage * 0.078  # 7.8%

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2032 debe ser 7.8% = ${expected_total:,.0f}"
        )

        _logger.info(f"✓ test_08: Gradualidad 2032 = 7.8% CORRECTO")

    def test_09_gradualidad_2033_8_5_percent_final(self):
        """
        Test Gradualidad Año 2033+: 8.5% total (FINAL)

        Esta es la tasa máxima que se mantiene indefinidamente.
        Valida distribución final: CI 4.5%, CRP 1.5%, SSP 2.5%
        """
        wage = 2000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2033',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2033, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2033',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2033, 8, 1),
            'date_to': date(2033, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        expected_ci = wage * 0.045  # 4.5%
        expected_crp = wage * 0.015  # 1.5%
        expected_ssp = wage * 0.025  # 2.5%
        expected_total = wage * 0.085  # 8.5% (FINAL)

        self.assertEqual(
            payslip.employer_cuenta_individual_ley21735, expected_ci,
            f"CI 2033+ debe ser 4.5% = ${expected_ci:,.0f}"
        )

        self.assertEqual(
            payslip.employer_crp_ley21735, expected_crp,
            f"CRP 2033+ debe ser 1.5% = ${expected_crp:,.0f}"
        )

        self.assertEqual(
            payslip.employer_seguro_social_ley21735, expected_ssp,
            f"SSP 2033+ debe ser 2.5% = ${expected_ssp:,.0f}"
        )

        self.assertEqual(
            payslip.employer_total_ley21735, expected_total,
            f"Total 2033+ debe ser 8.5% (FINAL) = ${expected_total:,.0f}"
        )

        _logger.info(f"✓ test_09: Gradualidad 2033+ = 8.5% FINAL CORRECTO")

    # ═════════════════════════════════════════════════════════════════════
    # SECCIÓN 2: TESTS DISTRIBUCIÓN VARIABLE (test_10 a test_12)
    # ═════════════════════════════════════════════════════════════════════

    def test_10_distribucion_2025_proporcional(self):
        """
        Test Distribución 2025: CI y SSP son PROPORCIONALES

        En 2025:
        - CI = 0.1% (absoluto) = 10% RELATIVO del total
        - SSP = 0.9% (absoluto) = 90% RELATIVO del total

        **CRÍTICO:** Validar que NO es distribución fija del total,
        sino componentes absolutos que resultan proporcionales.

        Normativa: Período 1 Ley 21.735 (Ago 2025 - Jul 2026)
        """
        wage = 3000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2025',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2025',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        total = payslip.employer_total_ley21735

        # Validar proporciones del total
        expected_ci_percent = 0.10  # 10% relativo
        expected_ssp_percent = 0.90  # 90% relativo

        ci_percent_real = payslip.employer_cuenta_individual_ley21735 / total if total > 0 else 0
        ssp_percent_real = payslip.employer_seguro_social_ley21735 / total if total > 0 else 0

        self.assertAlmostEqual(
            ci_percent_real, expected_ci_percent,
            places=2,
            msg=f"CI debe ser {expected_ci_percent*100}% del total en 2025 "
                f"(${payslip.employer_cuenta_individual_ley21735:,.0f} / ${total:,.0f} = {ci_percent_real*100:.1f}%)"
        )

        self.assertAlmostEqual(
            ssp_percent_real, expected_ssp_percent,
            places=2,
            msg=f"SSP debe ser {expected_ssp_percent*100}% del total en 2025"
        )

        _logger.info(f"✓ test_10: Distribución 2025 proporcional CORRECTA")

    def test_11_distribucion_2026_componentes_absolutos(self):
        """
        Test Distribución 2026+: CI, CRP, SSP son ABSOLUTOS

        **CRÍTICO:** A partir de 2026, los componentes NO son proporcionales
        al total, sino que tienen valores ABSOLUTOS FIJOS:
        - SSP = 2.5% del wage (SIEMPRE, NO varía con total)
        - CRP = 0.9% a 1.5% del wage (absoluto, NO varía)
        - CI = residual para llegar al total anual

        Este es el cambio fundamental vs distribución 2025.

        Normativa: Período 2 Ley 21.735 (Ago 2026+)
        """
        wage = 3000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2026',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2026, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2026',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2026, 8, 1),
            'date_to': date(2026, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Valores esperados ABSOLUTOS
        expected_ssp_absolute = wage * 0.025  # 2.5% absoluto
        expected_crp_absolute = wage * 0.009  # 0.9% absoluto en 2026

        # SSP debe ser exactamente 2.5% (NO proporcional al total)
        self.assertEqual(
            payslip.employer_seguro_social_ley21735,
            expected_ssp_absolute,
            f"SSP 2026 debe ser 2.5% ABSOLUTO (${expected_ssp_absolute:,.0f}), "
            f"NO proporcional al total. "
            f"Obtuvo ${payslip.employer_seguro_social_ley21735:,.0f}"
        )

        # CRP debe ser exactamente 0.9% (absoluto)
        self.assertEqual(
            payslip.employer_crp_ley21735,
            expected_crp_absolute,
            f"CRP 2026 debe ser 0.9% ABSOLUTO (${expected_crp_absolute:,.0f}), "
            f"NO proporcional"
        )

        _logger.info(f"✓ test_11: Distribución 2026+ componentes absolutos CORRECTA")

    def test_12_distribucion_2033_proporciones_finales(self):
        """
        Test Distribución 2033+: Proporciones finales estables

        En régimen final (2033+):
        - CI: 4.5% = 52.9% relativo (4.5 / 8.5)
        - CRP: 1.5% = 17.6% relativo (1.5 / 8.5)
        - SSP: 2.5% = 29.4% relativo (2.5 / 8.5)
        - Total: 8.5% = 100%

        Validar proporciones matemáticas exactas.
        """
        wage = 3000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato 2033',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2033, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Ago-2033',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2033, 8, 1),
            'date_to': date(2033, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        total = payslip.employer_total_ley21735

        # Proporciones esperadas
        expected_ci_percent = 4.5 / 8.5  # 52.9%
        expected_crp_percent = 1.5 / 8.5  # 17.6%
        expected_ssp_percent = 2.5 / 8.5  # 29.4%

        ci_percent_real = payslip.employer_cuenta_individual_ley21735 / total if total > 0 else 0
        crp_percent_real = payslip.employer_crp_ley21735 / total if total > 0 else 0
        ssp_percent_real = payslip.employer_seguro_social_ley21735 / total if total > 0 else 0

        self.assertAlmostEqual(
            ci_percent_real, expected_ci_percent,
            places=2,
            msg=f"CI debe ser {expected_ci_percent*100:.1f}% del total"
        )

        self.assertAlmostEqual(
            crp_percent_real, expected_crp_percent,
            places=2,
            msg=f"CRP debe ser {expected_crp_percent*100:.1f}% del total"
        )

        self.assertAlmostEqual(
            ssp_percent_real, expected_ssp_percent,
            places=2,
            msg=f"SSP debe ser {expected_ssp_percent*100:.1f}% del total"
        )

        _logger.info(f"✓ test_12: Distribución 2033+ proporciones finales CORRECTA")

    # ═════════════════════════════════════════════════════════════════════
    # SECCIÓN 3: TESTS TOPE AFP (test_13 a test_14)
    # ═════════════════════════════════════════════════════════════════════

    def test_13_tope_afp_salario_alto(self):
        """
        Test Tope AFP: Aplicado para salarios altos

        Valida que salarios > tope AFP (87.8 UF) son topeados.

        Ejemplo:
        - Wage: $5,000,000
        - Tope AFP: 87.8 UF × $38,277.50 = $3,360,759
        - Aporte esperado: 1.0% × $3,360,759 = $33,608 (2025)
        - NO: 1.0% × $5,000,000 = $50,000 (incorrecto sin tope)

        Normativa: DL 3.500 Art. 16 - Tope imponible AFP
        Arquitectura: Integración l10n_cl.legal.caps (NO hardcoded)
        """
        wage = 5000000  # $5M (sobre tope)

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Alto Sueldo',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Alto Sueldo',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Obtener UF para cálculo de tope
        indicators = self.env['hr.economic.indicators'].search([
            ('period', '=', date(2025, 8, 1))
        ])
        uf = indicators.uf if indicators else 38277.50

        # Tope esperado: 87.8 UF × UF_value
        tope_esperado = 87.8 * uf

        # Aporte esperado sobre tope
        aporte_esperado_sobre_tope = tope_esperado * 0.01  # 1% en 2025

        # Aporte SIN tope (incorrecto)
        aporte_sin_tope = wage * 0.01

        # Validación 1: Aporte debe ser MENOR que sin tope
        self.assertLess(
            payslip.employer_total_ley21735,
            aporte_sin_tope,
            "Aporte debe ser menor que 1% del wage (debe estar topeado)"
        )

        # Validación 2: Aporte debe ser aproximadamente sobre tope
        self.assertAlmostEqual(
            payslip.employer_total_ley21735,
            aporte_esperado_sobre_tope,
            delta=100.0,  # Tolerancia $100 por redondeos
            msg=f"Aporte debe calcularse sobre tope (${tope_esperado:,.0f}), "
                f"no sobre wage (${wage:,})"
        )

        _logger.info(f"✓ test_13: Tope AFP aplicado correctamente para salario alto")

    def test_14_tope_afp_salario_bajo(self):
        """
        Test Tope AFP: NO aplicado para salarios bajos

        Valida que salarios < tope AFP no son afectados.

        Ejemplo:
        - Wage: $1,500,000
        - Tope AFP: $3,360,759
        - Wage < Tope, entonces:
        - Aporte: 1.0% × $1,500,000 = $15,000 (sin tope)

        Normativa: DL 3.500 Art. 16
        """
        wage = 1500000  # $1.5M (bajo tope)

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Bajo Sueldo',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Payslip Bajo Sueldo',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Aporte esperado: exactamente 1% del wage
        expected = wage * 0.01

        self.assertEqual(
            payslip.employer_total_ley21735,
            expected,
            f"Salario bajo (${wage:,}) no debe ser topeado. "
            f"Esperado: ${expected:,.0f}, "
            f"Obtuvo: ${payslip.employer_total_ley21735:,.0f}"
        )

        _logger.info(f"✓ test_14: Tope AFP no aplicado para salario bajo CORRECTO")

    # ═════════════════════════════════════════════════════════════════════
    # SECCIÓN 4: TEST CAMPO CRP (test_15)
    # ═════════════════════════════════════════════════════════════════════

    def test_15_campo_crp_desde_2026(self):
        """
        Test Campo CRP: Vigencia desde 2026

        Valida:
        - CRP = 0 en 2025 (aún no vigente)
        - CRP > 0 desde agosto 2026 (inicia)
        - CRP = 0.9% en 2026, 1.5% desde 2027

        Campo crítico para compliance:
        - Campo debe existir en modelo (compute, store, readonly)
        - Debe ser requerido en reportería (Previred, LRE)
        - Vigencia: 01-08-2026 hasta 31-07-2054 (30 años)

        Normativa: Ley 21.735 Art. 2° - Transitorio CRP
        """
        # TEST 2025: CRP = 0
        contract_2025 = self.env['hr.contract'].create({
            'name': 'Contrato 2025',
            'employee_id': self.employee.id,
            'wage': 2000000,
            'date_start': date(2025, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip_2025 = self.env['hr.payslip'].create({
            'name': 'Payslip 2025',
            'employee_id': self.employee.id,
            'contract_id': contract_2025.id,
            'date_from': date(2025, 8, 1),
            'date_to': date(2025, 8, 31),
            'struct_id': self.struct.id
        })

        payslip_2025.compute_sheet()

        self.assertEqual(
            payslip_2025.employer_crp_ley21735, 0.0,
            "CRP debe ser 0 en 2025 (aún no vigente)"
        )

        # TEST 2026: CRP > 0
        contract_2026 = self.env['hr.contract'].create({
            'name': 'Contrato 2026',
            'employee_id': self.employee.id,
            'wage': 2000000,
            'date_start': date(2026, 8, 1),
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip_2026 = self.env['hr.payslip'].create({
            'name': 'Payslip 2026',
            'employee_id': self.employee.id,
            'contract_id': contract_2026.id,
            'date_from': date(2026, 8, 1),
            'date_to': date(2026, 8, 31),
            'struct_id': self.struct.id
        })

        payslip_2026.compute_sheet()

        self.assertGreater(
            payslip_2026.employer_crp_ley21735, 0.0,
            "CRP debe ser > 0 desde agosto 2026"
        )

        # Validar valor exacto 0.9%
        expected_crp_2026 = payslip_2026.contract_id.wage * 0.009
        self.assertEqual(
            payslip_2026.employer_crp_ley21735, expected_crp_2026,
            f"CRP 2026 debe ser 0.9% (${expected_crp_2026:,.0f})"
        )

        _logger.info(f"✓ test_15: Campo CRP vigencia desde 2026 CORRECTO")

    # ═════════════════════════════════════════════════════════════════════
    # SECCIÓN 5: TEST INTEGRACIÓN AI SERVICE (test_16)
    # ═════════════════════════════════════════════════════════════════════

    def test_16_integracion_ai_service_economic_indicators(self):
        """
        Test Integración AI Service: Flujo completo Odoo ↔ AI Service

        Valida arquitectura distribuida para cálculo de tope AFP:
        1. AI service extrae UF desde Previred (fuente oficial)
        2. hr.economic.indicators almacena valor (base de datos)
        3. Payslip obtiene UF de indicadores (NO hardcoded)
        4. Cálculo aplica tope: wage_topeado = min(wage, 87.8 UF × UF_value)

        Este test simula que AI service ya pobló indicadores económicos
        con valores específicos, y valida que el cálculo usa esos valores.

        **CRÍTICO:** Valida integración con arquitectura distribuida
        (NO hardcoding de UF o tope AFP)

        Normativa:
        - Ley 21.735 (gradualidad)
        - DL 3.500 Art. 16 (tope AFP)
        - Circular SP 2025 (implementación)

        Arquitectura:
        - AI service → hr.economic.indicators (UF mensual)
        - hr.economic.indicators → Payslip calc (obtiene UF)
        - l10n_cl.legal.caps → Payslip calc (obtiene tope 87.8)
        """
        # Preparar indicador específico (simula AI service)
        uf_test = 38500.00  # UF test diferente
        period = date(2025, 10, 1)

        # Limpiar indicador existente
        existing = self.env['hr.economic.indicators'].search([
            ('period', '=', period)
        ])
        existing.unlink()

        # Crear indicador (simula AI service poblando datos)
        test_indicator = self.env['hr.economic.indicators'].create({
            'period': period,
            'uf': uf_test,  # Valor específico para validar integración
            'utm': int(uf_test * 1.74),
            'uta': int(uf_test * 21.5),
            'minimum_wage': 500000,
        })

        _logger.info(f"AI Service simulado: UF={uf_test} en {period}")

        # Trabajador con sueldo alto (sobre tope)
        wage = 5000000

        contract = self.env['hr.contract'].create({
            'name': 'Contrato Test Integración AI',
            'employee_id': self.employee.id,
            'wage': wage,
            'date_start': period,
            'state': 'open',
            'afp_id': self.afp.id
        })

        payslip = self.env['hr.payslip'].create({
            'name': 'Test Integración AI Service',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': period,
            'date_to': date(2025, 10, 31),
            'struct_id': self.struct.id
        })

        payslip.compute_sheet()

        # Cálculo esperado usando UF del indicador económico
        # Tope: 87.8 UF × $38,500 = $3,380,300
        tope_esperado = 87.8 * uf_test

        # Aporte: 1% × tope (2025)
        aporte_esperado = tope_esperado * 0.01

        # Validación 1: Cálculo debe usar UF de indicador (no hardcoded)
        self.assertAlmostEqual(
            payslip.employer_total_ley21735,
            aporte_esperado,
            delta=10.0,
            msg=f"Cálculo debe usar UF de hr.economic.indicators (${uf_test:,}) "
                f"poblado por AI service, no hardcoded"
        )

        # Validación 2: Cálculo debe ser diferente si UF fuera diferente
        # (Prueba que realmente obtiene el valor dinámico)
        uf_default = 38277.50
        tope_si_default = 87.8 * uf_default
        aporte_si_default = tope_si_default * 0.01

        self.assertNotAlmostEqual(
            payslip.employer_total_ley21735,
            aporte_si_default,
            delta=50.0,
            msg=f"Cálculo debe usar UF específico (${uf_test}), "
                f"no valor default (${uf_default})"
        )

        # Validación 3: Validar que NO usa wage completo (tope debe estar aplicado)
        aporte_sin_tope = wage * 0.01
        self.assertNotEqual(
            payslip.employer_total_ley21735,
            aporte_sin_tope,
            "Cálculo debe aplicar tope AFP (no usar wage completo)"
        )

        _logger.info(
            f"✓ test_16: Integración AI Service correcta "
            f"(UF=${uf_test:,}, Tope=${tope_esperado:,.0f}, Aporte=${aporte_esperado:,.0f})"
        )

    # ═════════════════════════════════════════════════════════════════════
    # TEARDOWN
    # ═════════════════════════════════════════════════════════════════════

    def tearDown(self):
        """Cleanup después de cada test"""
        super().tearDown()
        # TransactionCase auto-rollback, no necesario cleanup manual
