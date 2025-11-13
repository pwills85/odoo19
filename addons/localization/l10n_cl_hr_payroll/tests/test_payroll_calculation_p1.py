# -*- coding: utf-8 -*-

"""
Tests - Motor de Cálculo de Liquidación P1

Valida la cadena completa de cálculo de la liquidación de sueldo chilena.
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import UserError
from datetime import datetime, date
from dateutil.relativedelta import relativedelta


@tagged('post_install', '-at_install', 'payroll_calculation')
class TestPayrollCalculationP1(TransactionCase):
    """
    Tests para validar el motor de cálculo de liquidación P1
    
    Casos de prueba:
    - US 1.3.1: Empleado con sueldo bajo mínimo imponible
    - US 1.3.2: Empleado con sueldo sobre tope imponible
    - US 1.3.3: Empleado con APV (integración P0)
    - US 1.3.4: Validación de totales
    """
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Compañía
        cls.company = cls.env.ref('base.main_company')
        cls.company.vat = '76123456-7'
        
        # AFP de prueba
        cls.afp = cls.env['hr.afp'].create({
            'name': 'AFP Modelo',
            'code': 'MODELO',
            'rate': 1.44,  # 1.44% comisión
        })
        
        # Indicadores económicos enero 2025
        cls.indicators = cls.env['hr.economic.indicators'].create({
            'period': date(2025, 1, 1),
            'uf': 37800.00,
            'utm': 65967.00,
            'uta': 791604.00,
            'minimum_wage': 500000.00,
        })
        
        # Topes legales 2025 (API actualizada a Odoo 19)
        # Crear solo si no existen (evitar duplicados)
        legal_caps_data = [
            ('AFP_IMPONIBLE_CAP', 81.6),
            ('APV_CAP_MONTHLY', 50.0),
            ('APV_CAP_ANNUAL', 600.0),
        ]
        for code, amount in legal_caps_data:
            if not cls.env['l10n_cl.legal.caps'].search([
                ('code', '=', code),
                ('valid_from', '=', date(2025, 1, 1))
            ]):
                cls.env['l10n_cl.legal.caps'].create({
                    'code': code,
                    'amount': amount,
                    'unit': 'uf',
                    'valid_from': date(2025, 1, 1),
                })
        
        # Tramos impuesto 2025 (simplificado) - API actualizada a Odoo 19
        # Valores en UTM, no en CLP (UTM 2025 = 65,967)
        # Crear solo si no existen (evitar duplicados)
        tax_brackets_data = [
            (1, 0.0, 13.89, 0.0, 0.0),    # 916,380 / 65,967
            (2, 13.89, 30.85, 4.0, 0.0),  # 2,035,200 / 65,967
            (3, 30.85, 51.41, 8.0, 0.68), # 3,391,200 / 65,967; rebaja: 44,752.80 / 65,967
        ]
        for tramo, desde, hasta, tasa, rebaja in tax_brackets_data:
            if not cls.env['hr.tax.bracket'].search([
                ('tramo', '=', tramo),
                ('vigencia_desde', '=', date(2025, 1, 1))
            ]):
                cls.env['hr.tax.bracket'].create({
                    'tramo': tramo,
                    'desde': desde,
                    'hasta': hasta,
                    'tasa': tasa,
                    'rebaja': rebaja,
                    'vigencia_desde': date(2025, 1, 1),
                })
        
        # Empleados
        cls.employee_low = cls._create_employee(cls, 'Juan Pérez', '12345678-9')
        cls.employee_high = cls._create_employee(cls, 'María González', '98765432-1')
        cls.employee_apv = cls._create_employee(cls, 'Pedro López', '11223344-5')
        
        # Contratos
        cls.contract_low = cls._create_contract(
            cls, cls.employee_low, 600000, 'low'
        )
        cls.contract_high = cls._create_contract(
            cls, cls.employee_high, 4000000, 'high'
        )
        cls.contract_apv = cls._create_contract(
            cls, cls.employee_apv, 1500000, 'apv',
            apv_monto=50000, apv_regimen='A'
        )
        
        # Estructura salarial
        cls.payroll_structure = cls.env['hr.payroll.structure'].create({
            'name': 'Estructura Chile P1',
            'code': 'CL_P1',
        })
        
        # Asignar reglas salariales a la estructura
        salary_rules = cls.env['hr.salary.rule'].search([
            ('code', 'in', [
                'BASIC', 'HABERES_IMPONIBLES', 'HABERES_NO_IMPONIBLES',
                'TOTAL_IMPONIBLE', 'TOPE_IMPONIBLE_UF', 'BASE_TRIBUTABLE',
                'AFP', 'SALUD', 'AFC', 'BASE_IMPUESTO_UNICO', 'IMPUESTO_UNICO',
                'TOTAL_HABERES', 'TOTAL_DESCUENTOS', 'NET'
            ])
        ])

        if not salary_rules:
            raise ValueError(
                'No se encontraron reglas salariales. '
                'Asegúrese de que el módulo l10n_cl_hr_payroll esté instalado y los datos cargados.'
            )

        salary_rules.write({'struct_id': cls.payroll_structure.id})
    
    def _create_employee(self, name, rut):
        """Helper: crear empleado"""
        return self.env['hr.employee'].create({
            'name': name,
            'company_id': self.company.id,
        })
    
    def _create_contract(self, employee, wage, ref, apv_monto=0, apv_regimen=False):
        """Helper: crear contrato"""
        vals = {
            'name': 'Contrato %s' % ref,
            'employee_id': employee.id,
            'wage': wage,
            'state': 'open',
            'date_start': date(2025, 1, 1),
            'afp_id': self.afp.id,
            'company_id': self.company.id,
        }

        # Agregar APV solo si se especifica
        if apv_monto > 0:
            vals['l10n_cl_apv_amount'] = apv_monto
        if apv_regimen:
            vals['l10n_cl_apv_regime'] = apv_regimen

        return self.env['hr.contract'].create(vals)
    
    def _create_payslip(self, employee, contract):
        """Helper: crear y calcular liquidación"""
        payslip = self.env['hr.payslip'].create({
            'name': 'Liquidación Enero 2025 - %s' % employee.name,
            'employee_id': employee.id,
            'contract_id': contract.id,
            'struct_id': self.payroll_structure.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicators.id,
            'company_id': self.company.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        return payslip
    
    # ═══════════════════════════════════════════════════════════
    # TEST CASES
    # ═══════════════════════════════════════════════════════════
    
    def test_01_empleado_sueldo_bajo(self):
        """
        US 1.3.1: Empleado con sueldo $600,000 (bajo mínimo)
        
        Validar:
        - Cálculo correcto de AFP (10% + 1.44% comisión)
        - Cálculo correcto de Salud (7%)
        - Cálculo correcto de AFC (0.6%)
        - Base tributable correcta
        - Impuesto Único = 0 (bajo tramo exento)
        - Alcance líquido correcto
        """
        payslip = self.env.create_payslip(self.employee_low, self.contract_low)

        # Obtener líneas
        lines = {line.code: line.total for line in payslip.line_ids}

        # Validaciones
        sueldo_base = 600000
        
        # Haberes
        self.assertEqual(lines.get('BASIC'), sueldo_base,
                        'Sueldo base debe ser $600,000')
        self.assertEqual(lines.get('HABERES_IMPONIBLES'), sueldo_base,
                        'Total imponible debe ser igual al sueldo base')
        
        # Base tributable (sin tope)
        self.assertEqual(lines.get('BASE_TRIBUTABLE'), sueldo_base,
                        'Base tributable debe ser igual al sueldo (sin tope)')
        
        # AFP: 10% + 1.44% = 11.44%
        afp_esperado = -(sueldo_base * 0.1144)
        self.assertAlmostEqual(lines.get('AFP'), afp_esperado, delta=1,
                              msg='AFP debe ser 11.44% del sueldo')
        
        # Salud: 7%
        salud_esperado = -(sueldo_base * 0.07)
        self.assertAlmostEqual(lines.get('SALUD'), salud_esperado, delta=1,
                              msg='Salud debe ser 7% del sueldo')
        
        # AFC: 0.6%
        afc_esperado = -(sueldo_base * 0.006)
        self.assertAlmostEqual(lines.get('AFC'), afc_esperado, delta=1,
                              msg='AFC debe ser 0.6% del sueldo')
        
        # Base impuesto
        base_impuesto = sueldo_base - abs(lines.get('AFP')) - abs(lines.get('SALUD')) - abs(lines.get('AFC'))
        self.assertAlmostEqual(lines.get('BASE_IMPUESTO_UNICO'), base_impuesto, delta=1,
                              msg='Base impuesto = sueldo - previsionales')
        
        # Impuesto Único (debe ser 0, está en tramo exento)
        self.assertEqual(lines.get('IMPUESTO_UNICO'), 0,
                        'Impuesto debe ser 0 (tramo exento)')
        
        # Líquido
        liquido_esperado = sueldo_base + lines.get('TOTAL_DESCUENTOS')
        self.assertAlmostEqual(lines.get('NET'), liquido_esperado, delta=1,
                              msg='Líquido = haberes + descuentos (desc negativos)')
    
    # def test_02_empleado_sueldo_alto_con_tope(self):
    #     """
    #     US 1.3.2: Empleado con sueldo $4,000,000 (sobre tope)
        
    #     Validar:
    #     - Aplicación correcta del tope imponible (81.6 UF)
    #     - Base tributable limitada al tope
    #     - Descuentos previsionales sobre base con tope
    #     - Impuesto Único sobre renta alta
    #     """
    #     payslip = self.env.create_payslip(self.employee_high, self.contract_high)
        
    #     # Obtener líneas
    #     lines = {line.code: line.total for line in payslip.line_ids}
        
    #     # Tope imponible en CLP
    #     tope_clp = 81.6 * 37800  # 81.6 UF * valor UF
        
    #     # Validaciones
    #     sueldo_base = 4000000
        
    #     self.assertEqual(lines.get('BASIC'), sueldo_base,
    #                     'Sueldo base debe ser $4,000,000')
        
    #     # Base tributable debe estar limitada al tope
    #     self.assertAlmostEqual(lines.get('BASE_TRIBUTABLE'), tope_clp, delta=100,
    #                           msg='Base tributable debe estar limitada al tope 81.6 UF')
        
    #     # AFP se calcula sobre base con tope
    #     afp_esperado = -(tope_clp * 0.1144)
    #     self.assertAlmostEqual(lines.get('AFP'), afp_esperado, delta=10,
    #                           msg='AFP debe calcularse sobre base con tope')
        
    #     # Salud sobre base con tope
    #     salud_esperado = -(tope_clp * 0.07)
    #     self.assertAlmostEqual(lines.get('SALUD'), salud_esperado, delta=10,
    #                           msg='Salud debe calcularse sobre base con tope')
        
    #     # Impuesto Único (debe aplicar, renta alta)
    #     self.assertLess(lines.get('IMPUESTO_UNICO'), 0,
    #                    'Debe haber impuesto único para renta alta')
    
    # def test_03_empleado_con_apv(self):
    #     """
    #     US 1.3.3: Empleado con APV $50,000 Régimen A
        
    #     Validar:
    #     - Integración con cálculo APV de P0
    #     - Descuento APV presente en liquidación
    #     - Total descuentos incluye APV
    #     - Líquido refleja descuento APV
    #     """
    #     payslip = self.env.create_payslip(self.employee_apv, self.contract_apv)
        
    #     # Obtener líneas
    #     lines = {line.code: line.total for line in payslip.line_ids}
        
    #     # Validar que existe línea APV
    #     apv_line = payslip.line_ids.filtered(lambda l: l.code == 'APV')
    #     self.assertTrue(apv_line, 'Debe existir línea APV en la liquidación')
        
    #     # APV debe ser $50,000 (negativo)
    #     self.assertEqual(apv_line.total, -50000,
    #                     'APV debe ser -$50,000')
        
    #     # Total descuentos debe incluir APV
    #     total_desc = abs(lines.get('TOTAL_DESCUENTOS'))
    #     self.assertGreater(total_desc, 50000,
    #                       'Total descuentos debe incluir APV')
    
    def test_04_totales_consistencia(self):
        """
        US 1.3.4: Validación de consistencia de totales
        
        Validar:
        - Total Haberes = suma de líneas positivas
        - Total Descuentos = suma de líneas negativas
        - Líquido = Haberes - Descuentos
        """
        payslip = self.env.create_payslip(self.employee_low, self.contract_low)
        
        # Calcular manualmente
        haberes_manual = sum([l.total for l in payslip.line_ids if l.total > 0])
        descuentos_manual = abs(sum([l.total for l in payslip.line_ids if l.total < 0]))
        liquido_manual = haberes_manual - descuentos_manual
        
        # Comparar con campos computed
        self.assertEqual(payslip.gross_wage, haberes_manual,
                        'Total haberes debe coincidir con suma manual')
        self.assertEqual(payslip.total_deductions, descuentos_manual,
                        'Total descuentos debe coincidir con suma manual')
        self.assertEqual(payslip.net_wage, liquido_manual,
                        'Líquido debe coincidir con haberes - descuentos')
    
    def test_05_validacion_fechas(self):
        """Validar que las fechas sean consistentes"""
        with self.assertRaises(Exception):
            self.env['hr.payslip'].create({
                'name': 'Test Fechas Inválidas',
                'employee_id': self.employee_low.id,
                'contract_id': self.contract_low.id,
                'date_from': date(2025, 1, 31),
                'date_to': date(2025, 1, 1),  # Inválido
                'company_id': self.company.id,
            })
    
    def test_06_numero_secuencial(self):
        """Validar que se asigne número secuencial automático"""
        payslip1 = self.env['hr.payslip'].create({
            'name': 'Test Secuencia 1',
            'employee_id': self.employee_low.id,
            'contract_id': self.contract_low.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'company_id': self.company.id,
        })
        
        payslip2 = self.env['hr.payslip'].create({
            'name': 'Test Secuencia 2',
            'employee_id': self.employee_high.id,
            'contract_id': self.contract_high.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'company_id': self.company.id,
        })
        
        self.assertNotEqual(payslip1.number, payslip2.number,
                           'Los números deben ser únicos')
        self.assertNotEqual(payslip1.number, '/',
                           'Debe asignarse número automático')
