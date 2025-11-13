# -*- coding: utf-8 -*-
"""
🚀 FASE 3.2: Test de Integración AFR + l10n_cl_payroll
Costos laborales en reportes financieros

Siguiendo protocolo PROMPT_AGENT_IA.md:
🏆 NIVEL 1: Documentación Oficial Odoo 18 - TransactionCase con @tagged
🎯 NIVEL 2: Arquitectura y patrones internos
🔍 NIVEL 3: Validación MCP aplicada

Flujo de Integración:
1. l10n_cl_payroll: Genera costos laborales (sueldos, leyes sociales)
2. account_financial_report: Incluye estos costos en reportes financieros
3. Verificar que reportes reflejan correctamente estructura de costos chilena
"""

import logging
from datetime import date

from odoo.tests.common import TransactionCase, tagged

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'l10n_cl', 'integration', 'financial_reports')
class TestFinancialReportsPayrollIntegration(TransactionCase):
    """
    Test de integración: AFR + l10n_cl_payroll
    Verificar que reportes financieros incluyen correctamente costos laborales chilenos
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Company chilena
        cls.company_cl = cls.env['res.company'].create({
            'name': 'Test Company Chile Financial',
            'country_id': cls.env.ref('base.cl').id,
            'currency_id': cls.env.ref('base.CLP').id,
            'vat': '76987654-3',
        })
        
        # Plan contable chileno
        cls._setup_chart_of_accounts()
        
        # Empleados para testing
        cls.employee1 = cls.env['hr.employee'].create({
            'name': 'María González',
            'company_id': cls.company_cl.id,
        })
        
        cls.employee2 = cls.env['hr.employee'].create({
            'name': 'Carlos Silva',
            'company_id': cls.company_cl.id,
        })
        
        # Período de testing
        cls.test_date = date(2025, 1, 15)
        cls.period_start = date(2025, 1, 1)
        cls.period_end = date(2025, 1, 31)

    @classmethod
    def _setup_chart_of_accounts(cls):
        """Setup plan contable chileno para testing"""
        # Cuentas principales para costos laborales
        cls.account_salaries = cls.env['account.account'].create({
            'name': 'Sueldos y Salarios',
            'code': '611001',
            'account_type': 'expense',
            'company_id': cls.company_cl.id,
        })
        
        cls.account_social_charges = cls.env['account.account'].create({
            'name': 'Leyes Sociales',
            'code': '611002', 
            'account_type': 'expense',
            'company_id': cls.company_cl.id,
        })
        
        cls.account_provisions = cls.env['account.account'].create({
            'name': 'Provisiones Personal',
            'code': '215001',
            'account_type': 'liability_current',
            'company_id': cls.company_cl.id,
        })

    def setUp(self):
        super().setUp()
        self.env.user.company_id = self.company_cl

    def test_payroll_costs_appear_in_financial_reports(self):
        """
        Test principal: Costos de nómina aparecen correctamente en reportes financieros
        """
        # === SETUP: Crear nóminas con costos laborales ===
        payslip1 = self.env.create_payslip_with_full_costs(
            self.employee1, base_salary=1000000
        )
        payslip2 = self.env.create_payslip_with_full_costs(
            self.employee2, base_salary=800000
        )
        
        payslip1.action_payslip_done()
        payslip2.action_payslip_done()
        
        # === VERIFICAR: Asientos contables generados ===
        moves = self.env['account.move'].search([
            ('ref', 'in', [payslip1.name, payslip2.name]),
            ('company_id', '=', self.company_cl.id)
        ])
        
        self.assertTrue(moves, "Deben generarse asientos contables de nómina")
        
        # === ACCIÓN: Generar reporte financiero ===
        report_data = self._generate_financial_report()
        
        # === VERIFICACIONES ===
        
        # 1. Costos de sueldos deben aparecer en el reporte
        salary_line = self._find_report_line(report_data, self.account_salaries.code)
        self.assertTrue(salary_line, "Sueldos deben aparecer en reporte financiero")
        
        expected_salaries = 1000000 + 800000  # Suma de sueldos base
        self.assertAlmostEqual(
            salary_line['balance'], 
            expected_salaries,
            delta=1000,
            msg="Total sueldos en reporte debe coincidir con nómina"
        )
        
        # 2. Leyes sociales deben aparecer
        social_charges_line = self._find_report_line(report_data, self.account_social_charges.code)
        self.assertTrue(social_charges_line, "Leyes sociales deben aparecer en reporte")
        
        # Calcular leyes sociales esperadas (aproximadamente 25% del sueldo base)
        expected_social_charges = (1000000 + 800000) * 0.25
        self.assertAlmostEqual(
            social_charges_line['balance'],
            expected_social_charges,
            delta=10000,
            msg="Leyes sociales deben reflejar cálculo correcto"
        )
        
        # 3. Provisiones deben aparecer en pasivos
        provisions_line = self._find_report_line(report_data, self.account_provisions.code)
        self.assertTrue(provisions_line, "Provisiones deben aparecer en reporte")

    def test_payroll_hierarchy_in_reports(self):
        """Test: Jerarquía de costos laborales en reportes"""
        # Crear nómina
        payslip = self.env.create_payslip_with_full_costs(self.employee1, 1200000)
        payslip.action_payslip_done()
        
        # Generar reporte con detalle
        report_data = self._generate_detailed_financial_report()
        
        # Verificar estructura jerárquica de costos
        cost_section = self._find_report_section(report_data, 'COSTOS DE PERSONAL')
        self.assertTrue(cost_section, "Debe existir sección de costos de personal")
        
        # Subsecciones esperadas
        expected_subsections = [
            'Sueldos y Salarios',
            'Gratificaciones',
            'Leyes Sociales',
            'Provisiones'
        ]
        
        for subsection in expected_subsections:
            found = self._find_report_subsection(cost_section, subsection)
            self.assertTrue(found, f"Debe existir subsección: {subsection}")

    def test_comparative_financial_reports_with_payroll(self):
        """Test: Reportes comparativos incluyen evolución de costos laborales"""
        # Crear nóminas en dos períodos diferentes
        
        # Período 1 (Enero)
        payslip_jan = self.env.create_payslip_with_full_costs(
            self.employee1, 1000000, 
            period_start=date(2025, 1, 1), period_end=date(2025, 1, 31)
        )
        payslip_jan.action_payslip_done()
        
        # Período 2 (Febrero) - aumento salarial
        payslip_feb = self.env.create_payslip_with_full_costs(
            self.employee1, 1100000,  # Aumento 10%
            period_start=date(2025, 2, 1), period_end=date(2025, 2, 28)
        )
        payslip_feb.action_payslip_done()
        
        # Generar reporte comparativo
        comparative_data = self._generate_comparative_report(
            date_from_1=date(2025, 1, 1), date_to_1=date(2025, 1, 31),
            date_from_2=date(2025, 2, 1), date_to_2=date(2025, 2, 28)
        )
        
        # Verificar evolución de costos
        salary_comparison = self._find_comparative_line(
            comparative_data, self.account_salaries.code
        )
        
        self.assertTrue(salary_comparison, "Debe existir comparación de sueldos")
        
        # Verificar cálculo de variación
        expected_variation = ((1100000 - 1000000) / 1000000) * 100  # 10%
        self.assertAlmostEqual(
            salary_comparison['variation_percent'],
            expected_variation,
            delta=0.1,
            msg="Variación porcentual debe calcularse correctamente"
        )

    def test_payroll_integration_with_cost_centers(self):
        """Test: Integración con centros de costo"""
        # Crear centros de costo
        cost_center_admin = self.env['account.analytic.account'].create({
            'name': 'Administración',
            'company_id': self.company_cl.id,
        })
        
        cost_center_sales = self.env['account.analytic.account'].create({
            'name': 'Ventas',
            'company_id': self.company_cl.id,
        })
        
        # Asignar empleados a centros de costo
        contract1 = self.env.create_contract_with_cost_center(
            self.employee1, cost_center_admin, 1000000
        )
        contract2 = self.env.create_contract_with_cost_center(
            self.employee2, cost_center_sales, 900000
        )
        
        # Generar nóminas
        payslip1 = self.env.create_payslip_from_contract(contract1)
        payslip2 = self.env.create_payslip_from_contract(contract2)
        
        payslip1.action_payslip_done()
        payslip2.action_payslip_done()
        
        # Generar reporte por centros de costo
        analytic_report = self._generate_analytic_report()
        
        # Verificar distribución por centro de costo
        admin_costs = self._find_analytic_line(analytic_report, cost_center_admin.id)
        sales_costs = self._find_analytic_line(analytic_report, cost_center_sales.id)
        
        self.assertTrue(admin_costs, "Costos de administración deben aparecer")
        self.assertTrue(sales_costs, "Costos de ventas deben aparecer")
        
        self.assertAlmostEqual(admin_costs['amount'], 1000000, delta=1000)
        self.assertAlmostEqual(sales_costs['amount'], 900000, delta=1000)

    def test_year_end_provisions_in_financial_reports(self):
        """Test: Provisiones de fin de año en reportes"""
        # Crear empleado con antigüedad para provisiones
        employee_senior = self.env['hr.employee'].create({
            'name': 'Pedro Veterano',
            'company_id': self.company_cl.id,
        })
        
        # Contrato con fecha de inicio anterior para generar provisiones
        contract = self.env['hr.contract'].create({
            'name': 'Contrato Senior',
            'employee_id': employee_senior.id,
            'wage': 1500000,
            'date_start': date(2024, 1, 1),  # 1 año de antigüedad
        })
        
        # Crear nómina que genere provisiones
        payslip = self.env.create_payslip_with_provisions(contract)
        payslip.action_payslip_done()
        
        # Generar reporte de balance
        balance_report = self._generate_balance_report()
        
        # Verificar provisiones en pasivos corrientes
        provisions_section = self._find_report_section(balance_report, 'PASIVOS CORRIENTES')
        self.assertTrue(provisions_section, "Debe existir sección de pasivos corrientes")
        
        # Provisiones específicas esperadas
        expected_provisions = [
            'Provisión Vacaciones',
            'Provisión Gratificación',
            'Provisión Indemnización'
        ]
        
        for provision in expected_provisions:
            provision_line = self._find_provision_line(provisions_section, provision)
            self.assertTrue(provision_line, f"Debe existir provisión: {provision}")
            self.assertGreater(provision_line['balance'], 0, f"{provision} debe tener saldo")

    # === MÉTODOS AUXILIARES ===
    
    def _create_payslip_with_full_costs(self, employee, base_salary, 
                                       period_start=None, period_end=None):
        """Crear nómina con estructura completa de costos chilenos"""
        if period_start is None:
            period_start = self.period_start
        if period_end is None:
            period_end = self.period_end
            
        # Crear contrato
        contract = self.env['hr.contract'].create({
            'name': f'Contrato {employee.name}',
            'employee_id': employee.id,
            'wage': base_salary,
            'date_start': period_start,
        })
        
        # Crear nómina
        payslip = self.env['hr.payslip'].create({
            'name': f'Nómina {employee.name} {period_start.strftime("%Y-%m")}',
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': period_start,
            'date_to': period_end,
        })
        
        # Calcular nómina
        payslip.compute_sheet()
        
        # Agregar líneas específicas chilenas para testing
        self._add_chilean_payroll_lines(payslip, base_salary)
        
        return payslip
    
    def _add_chilean_payroll_lines(self, payslip, base_salary):
        """Agregar líneas específicas de nómina chilena"""
        lines_data = [
            # Haberes
            ('SUELDO', 'Sueldo Base', base_salary),
            ('GRATIF', 'Gratificación', base_salary / 12),  # 1/12 anual
            
            # Descuentos
            ('AFP', 'AFP (10%)', -base_salary * 0.10),
            ('SALUD', 'Salud (7%)', -base_salary * 0.07),
            
            # Aportes patronales
            ('MUTUAL', 'Mutual (0.95%)', base_salary * 0.0095),
            ('SIS', 'SIS (0.6%)', base_salary * 0.006),
        ]
        
        for code, name, amount in lines_data:
            self.env['hr.payslip.line'].create({
                'payslip_id': payslip.id,
                'name': name,
                'code': code,
                'amount': amount,
                'total': amount,
            })
    
    def _generate_financial_report(self):
        """Generar reporte financiero básico"""
        report_wizard = self.env['financial.report.wizard'].create({
            'date_from': self.period_start,
            'date_to': self.period_end,
            'company_id': self.company_cl.id,
            'report_type': 'profit_loss',
        })
        
        return report_wizard.generate_report()
    
    def _generate_detailed_financial_report(self):
        """Generar reporte financiero detallado"""
        report_wizard = self.env['financial.report.wizard'].create({
            'date_from': self.period_start,
            'date_to': self.period_end,
            'company_id': self.company_cl.id,
            'report_type': 'profit_loss',
            'detail_level': 'detailed',
        })
        
        return report_wizard.generate_report()
    
    def _generate_comparative_report(self, date_from_1, date_to_1, date_from_2, date_to_2):
        """Generar reporte comparativo"""
        report_wizard = self.env['financial.report.comparative.wizard'].create({
            'date_from_1': date_from_1,
            'date_to_1': date_to_1,
            'date_from_2': date_from_2,
            'date_to_2': date_to_2,
            'company_id': self.company_cl.id,
        })
        
        return report_wizard.generate_comparative_report()
    
    def _generate_analytic_report(self):
        """Generar reporte analítico por centros de costo"""
        report_wizard = self.env['analytic.report.wizard'].create({
            'date_from': self.period_start,
            'date_to': self.period_end,
            'company_id': self.company_cl.id,
        })
        
        return report_wizard.generate_analytic_report()
    
    def _generate_balance_report(self):
        """Generar reporte de balance"""
        report_wizard = self.env['financial.report.wizard'].create({
            'date_from': self.period_start,
            'date_to': self.period_end,
            'company_id': self.company_cl.id,
            'report_type': 'balance_sheet',
        })
        
        return report_wizard.generate_report()
    
    def _find_report_line(self, report_data, account_code):
        """Encontrar línea específica en reporte por código de cuenta"""
        for line in report_data.get('lines', []):
            if line.get('account_code') == account_code:
                return line
        return None
    
    def _find_report_section(self, report_data, section_name):
        """Encontrar sección específica en reporte"""
        for section in report_data.get('sections', []):
            if section_name.upper() in section.get('name', '').upper():
                return section
        return None
    
    def _find_report_subsection(self, section, subsection_name):
        """Encontrar subsección dentro de una sección"""
        for subsection in section.get('subsections', []):
            if subsection_name.upper() in subsection.get('name', '').upper():
                return subsection
        return None
    
    def _find_comparative_line(self, comparative_data, account_code):
        """Encontrar línea en reporte comparativo"""
        for line in comparative_data.get('comparative_lines', []):
            if line.get('account_code') == account_code:
                return line
        return None
    
    def _find_analytic_line(self, analytic_data, analytic_account_id):
        """Encontrar línea analítica específica"""
        for line in analytic_data.get('analytic_lines', []):
            if line.get('analytic_account_id') == analytic_account_id:
                return line
        return None
    
    def _find_provision_line(self, provisions_section, provision_name):
        """Encontrar línea de provisión específica"""
        for line in provisions_section.get('lines', []):
            if provision_name.upper() in line.get('name', '').upper():
                return line
        return None
    
    def _create_contract_with_cost_center(self, employee, analytic_account, wage):
        """Crear contrato con centro de costo asignado"""
        return self.env['hr.contract'].create({
            'name': f'Contrato {employee.name} - {analytic_account.name}',
            'employee_id': employee.id,
            'wage': wage,
            'date_start': self.period_start,
            'analytic_account_id': analytic_account.id,
        })
    
    def _create_payslip_from_contract(self, contract):
        """Crear nómina desde contrato existente"""
        payslip = self.env['hr.payslip'].create({
            'name': f'Nómina {contract.employee_id.name}',
            'employee_id': contract.employee_id.id,
            'contract_id': contract.id,
            'date_from': self.period_start,
            'date_to': self.period_end,
        })
        
        payslip.compute_sheet()
        return payslip
    
    def _create_payslip_with_provisions(self, contract):
        """Crear nómina con provisiones de fin de año"""
        payslip = self.env['hr.payslip'].create({
            'name': f'Nómina con Provisiones {contract.employee_id.name}',
            'employee_id': contract.employee_id.id,
            'contract_id': contract.id,
            'date_from': self.period_start,
            'date_to': self.period_end,
        })
        
        payslip.compute_sheet()
        
        # Agregar provisiones específicas
        provisions = [
            ('PROV_VAC', 'Provisión Vacaciones', contract.wage * 0.04),
            ('PROV_GRAT', 'Provisión Gratificación', contract.wage / 12),
            ('PROV_IND', 'Provisión Indemnización', contract.wage * 0.08),
        ]
        
        for code, name, amount in provisions:
            self.env['hr.payslip.line'].create({
                'payslip_id': payslip.id,
                'name': name,
                'code': code,
                'amount': amount,
                'total': amount,
            })
        
        return payslip
