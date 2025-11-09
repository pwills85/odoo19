# -*- coding: utf-8 -*-

"""
Tests - Generación Libro de Remuneraciones Electrónico (LRE)

Valida la generación correcta del archivo LRE para la Dirección del Trabajo.
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import UserError
from datetime import date
import base64


@tagged('post_install', '-at_install', 'lre')
class TestLREGeneration(TransactionCase):
    """Tests para validar la generación del LRE"""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Compañía
        cls.company = cls.env.ref('base.main_company')
        cls.company.vat = '76123456-7'
        
        # AFP
        cls.afp = cls.env['hr.afp'].create({
            'name': 'AFP Habitat',
            'code': 'HABITAT',
            'rate': 1.27,
        })
        
        # Indicadores
        cls.indicators = cls.env['hr.economic.indicators'].create({
            'month': 1,
            'year': 2025,
            'uf': 37800.00,
            'utm': 65967.00,
            'uta': 791604.00,
            'minimum_wage': 500000.00,
        })
        
        # Empleados
        cls.employee1 = cls.env['hr.employee'].create({
            'name': 'Juan Pérez Silva',
            'firstname': 'Juan',
            'lastname': 'Pérez',
            'mothers_name': 'Silva',
            'identification_id': '12345678-9',
            'company_id': cls.company.id,
        })
        
        cls.employee2 = cls.env['hr.employee'].create({
            'name': 'María González López',
            'firstname': 'María',
            'lastname': 'González',
            'mothers_name': 'López',
            'identification_id': '98765432-1',
            'company_id': cls.company.id,
        })
        
        # Contratos
        cls.contract1 = cls.env['hr.contract'].create({
            'name': 'Contrato Juan',
            'employee_id': cls.employee1.id,
            'wage': 800000,
            'state': 'open',
            'date_start': date(2025, 1, 1),
            'afp_id': cls.afp.id,
            'company_id': cls.company.id,
        })
        
        cls.contract2 = cls.env['hr.contract'].create({
            'name': 'Contrato María',
            'employee_id': cls.employee2.id,
            'wage': 1200000,
            'state': 'open',
            'date_start': date(2025, 1, 1),
            'afp_id': cls.afp.id,
            'company_id': cls.company.id,
        })
        
        # Estructura salarial
        cls.payroll_structure = cls.env['hr.payroll.structure'].create({
            'name': 'Estructura LRE',
            'code': 'LRE_TEST',
        })
        
        # Liquidaciones
        cls.payslip1 = cls._create_payslip(cls, cls.employee1, cls.contract1)
        cls.payslip2 = cls._create_payslip(cls, cls.employee2, cls.contract2)
        
        # Marcar como pagadas
        cls.payslip1.state = 'done'
        cls.payslip2.state = 'done'
    
    def _create_payslip(self, employee, contract):
        """Helper: crear liquidación"""
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
        
        # Agregar líneas manuales para el test
        self.env['hr.payslip.line'].create({
            'slip_id': payslip.id,
            'code': 'BASIC',
            'name': 'Sueldo Base',
            'sequence': 1,
            'category_id': self.env.ref('l10n_cl_hr_payroll.category_base').id,
            'quantity': 1,
            'rate': 100,
            'amount': contract.wage,
            'total': contract.wage,
        })
        
        self.env['hr.payslip.line'].create({
            'slip_id': payslip.id,
            'code': 'AFP',
            'name': 'AFP',
            'sequence': 10,
            'category_id': self.env.ref('l10n_cl_hr_payroll.category_afp_sopa').id,
            'quantity': 1,
            'rate': -11.27,
            'amount': contract.wage,
            'total': -(contract.wage * 0.1127),
        })
        
        self.env['hr.payslip.line'].create({
            'slip_id': payslip.id,
            'code': 'NET',
            'name': 'Líquido',
            'sequence': 100,
            'category_id': self.env.ref('l10n_cl_hr_payroll.category_net').id,
            'quantity': 1,
            'rate': 100,
            'amount': contract.wage * 0.8873,
            'total': contract.wage * 0.8873,
        })
        
        return payslip
    
    # ═══════════════════════════════════════════════════════════
    # TEST CASES
    # ═══════════════════════════════════════════════════════════
    
    def test_01_wizard_creation(self):
        """Validar creación del wizard"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '1',
            'period_year': 2025,
            'company_id': self.company.id,
        })
        
        self.assertEqual(wizard.state, 'draft')
        self.assertEqual(wizard.period_month, '1')
        self.assertEqual(wizard.period_year, 2025)
    
    def test_02_generate_lre_success(self):
        """Validar generación exitosa del LRE"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '1',
            'period_year': 2025,
            'company_id': self.company.id,
        })
        
        # Generar
        wizard.action_generate_lre()
        
        # Validaciones
        self.assertEqual(wizard.state, 'done')
        self.assertTrue(wizard.lre_file, 'Debe generar archivo')
        self.assertTrue(wizard.lre_filename, 'Debe tener nombre de archivo')
        self.assertEqual(wizard.total_payslips, 2, 'Debe procesar 2 liquidaciones')
        self.assertEqual(wizard.total_employees, 2, 'Debe contar 2 empleados')
    
    def test_03_lre_content_structure(self):
        """Validar estructura del contenido CSV"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '1',
            'period_year': 2025,
            'company_id': self.company.id,
        })
        
        wizard.action_generate_lre()
        
        # Decodificar CSV
        csv_content = base64.b64decode(wizard.lre_file).decode('utf-8')
        lines = csv_content.split('\n')
        
        # Validar estructura
        self.assertGreaterEqual(len(lines), 3, 'Debe tener header + 2 empleados')
        
        # Validar header
        header = lines[0]
        self.assertIn('RUT_EMPLEADOR', header)
        self.assertIn('PERIODO', header)
        self.assertIn('RUT_TRABAJADOR', header)
        self.assertIn('SUELDO_BASE', header)
        self.assertIn('ALCANCE_LIQUIDO', header)
        
        # Validar datos
        data_line1 = lines[1]
        self.assertIn('76123456-7', data_line1)  # RUT empleador
        self.assertIn('202501', data_line1)  # Período
        self.assertIn('12345678', data_line1)  # RUT empleado 1
    
    def test_04_lre_totals_match(self):
        """Validar que los totales del LRE coincidan con las liquidaciones"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '1',
            'period_year': 2025,
            'company_id': self.company.id,
        })
        
        wizard.action_generate_lre()
        
        # Total remuneraciones del wizard
        total_wizard = wizard.total_remuneraciones
        
        # Total de las liquidaciones
        total_payslips = sum(self.payslip1.gross_wage + self.payslip2.gross_wage)
        
        self.assertAlmostEqual(total_wizard, total_payslips, delta=100,
                              msg='Totales deben coincidir')
    
    def test_05_no_payslips_error(self):
        """Validar error cuando no hay liquidaciones"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '12',  # Mes sin liquidaciones
            'period_year': 2024,
            'company_id': self.company.id,
        })
        
        with self.assertRaises(UserError):
            wizard.action_generate_lre()
    
    def test_06_filename_format(self):
        """Validar formato del nombre de archivo"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '1',
            'period_year': 2025,
            'company_id': self.company.id,
        })
        
        wizard.action_generate_lre()
        
        # Formato esperado: LRE_RUT_YYYY_MM.csv
        expected = 'LRE_76123456-7_2025_01.csv'
        self.assertEqual(wizard.lre_filename, expected)
    
    def test_07_rut_splitting(self):
        """Validar separación correcta de RUT"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '1',
            'period_year': 2025,
            'company_id': self.company.id,
        })
        
        # Test split RUT
        rut_parts = wizard._split_rut('12345678-9')
        self.assertEqual(rut_parts['rut'], '12345678')
        self.assertEqual(rut_parts['dv'], '9')
        
        # RUT sin formato
        rut_parts2 = wizard._split_rut('123456789')
        self.assertEqual(rut_parts2['rut'], '12345678')
        self.assertEqual(rut_parts2['dv'], '9')
    
    def test_08_working_days_calculation(self):
        """Validar cálculo de días trabajados"""
        wizard = self.env['hr.lre.wizard'].create({
            'period_month': '1',
            'period_year': 2025,
            'company_id': self.company.id,
        })
        
        days = wizard._get_working_days(self.payslip1)
        self.assertEqual(days, 31, 'Enero tiene 31 días')
