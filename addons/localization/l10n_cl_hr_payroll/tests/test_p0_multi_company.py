# -*- coding: utf-8 -*-

"""
Test P0-3: Multi-Compañía Isolation
====================================

Verifica corrección de brecha P0-3 identificada en auditoría:
- Implementar ir.rule para aislamiento de datos entre compañías
- Proteger datos sensibles de nómina según Ley 19.628

Modelos con aislamiento:
- hr.payslip (liquidaciones)
- hr.payslip.run (lotes)
- hr.payslip.line (líneas detalle)
- hr.payslip.input (inputs adicionales)
- hr.contract (heredado de Odoo base)

Referencias:
- Ley 19.628 Protección de Datos Personales
- Auditoría 2025-11-07: P0-3
- security/multi_company_rules.xml
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import AccessError
from datetime import date


@tagged('post_install', '-at_install', 'p0_critical', 'multi_company')
class TestP0MultiCompany(TransactionCase):
    """Test P0-3: Validar aislamiento multi-compañía en nómina"""

    def setUp(self):
        super().setUp()

        # Modelos
        self.CompanyModel = self.env['res.company']
        self.UserModel = self.env['res.users']
        self.EmployeeModel = self.env['hr.employee']
        self.ContractModel = self.env['hr.contract']
        self.PayslipModel = self.env['hr.payslip']
        self.PayslipRunModel = self.env['hr.payslip.run']

        # Crear dos compañías para testing
        self.company_a = self.CompanyModel.create({
            'name': 'Test Company A',
            'vat': '111111111',
        })

        self.company_b = self.CompanyModel.create({
            'name': 'Test Company B',
            'vat': '222222222',
        })

        # Obtener grupos requeridos
        group_hr_user = self.env.ref('hr.group_hr_user')
        group_payroll_user = self.env.ref('l10n_cl_hr_payroll.group_hr_payroll_user')

        # Usuario con acceso solo a Company A
        self.user_company_a = self.UserModel.sudo().create({
            'name': 'User Company A',
            'login': 'user_a@test.com',
            'company_id': self.company_a.id,
            'company_ids': [(6, 0, [self.company_a.id])],
        })

        # Usuario con acceso solo a Company B
        self.user_company_b = self.UserModel.sudo().create({
            'name': 'User Company B',
            'login': 'user_b@test.com',
            'company_id': self.company_b.id,
            'company_ids': [(6, 0, [self.company_b.id])],
        })

        # Asignar grupos usando write en el grupo para añadir usuarios
        group_hr_user.sudo().write({
            'users': [(4, self.user_company_a.id), (4, self.user_company_b.id)]
        })
        group_payroll_user.sudo().write({
            'users': [(4, self.user_company_a.id), (4, self.user_company_b.id)]
        })

        # Empleado Company A (usando sudo para evitar checks de permisos en tests)
        self.employee_a = self.EmployeeModel.sudo().create({
            'name': 'Employee A',
            'company_id': self.company_a.id,
        })

        # Empleado Company B
        self.employee_b = self.EmployeeModel.sudo().create({
            'name': 'Employee B',
            'company_id': self.company_b.id,
        })

        # Contrato Company A
        self.contract_a = self.ContractModel.sudo().create({
            'name': 'Contract A',
            'employee_id': self.employee_a.id,
            'company_id': self.company_a.id,
            'wage': 1000000,
            'date_start': date(2025, 1, 1),
        })

        # Contrato Company B
        self.contract_b = self.ContractModel.sudo().create({
            'name': 'Contract B',
            'employee_id': self.employee_b.id,
            'company_id': self.company_b.id,
            'wage': 1500000,
            'date_start': date(2025, 1, 1),
        })

        # Payslip Company A
        self.payslip_a = self.PayslipModel.sudo().create({
            'name': 'Payslip A',
            'employee_id': self.employee_a.id,
            'contract_id': self.contract_a.id,
            'company_id': self.company_a.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
        })

        # Payslip Company B
        self.payslip_b = self.PayslipModel.sudo().create({
            'name': 'Payslip B',
            'employee_id': self.employee_b.id,
            'contract_id': self.contract_b.id,
            'company_id': self.company_b.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
        })

        # NOTA: Creación con sudo() para evitar AccessError en tests
        # Los tests validan ir.rules multi-company, no permisos de grupos

    def test_ir_rule_payslip_exists(self):
        """
        P0-3: Verificar que existe ir.rule para hr.payslip
        """
        rule = self.env['ir.rule'].search([
            ('model_id.model', '=', 'hr.payslip'),
            ('name', 'ilike', 'multi-company')
        ])

        self.assertTrue(
            rule,
            "Debe existir ir.rule multi-company para hr.payslip "
            "(security/multi_company_rules.xml)"
        )

    def test_ir_rule_payslip_run_exists(self):
        """
        P0-3: Verificar que existe ir.rule para hr.payslip.run
        """
        rule = self.env['ir.rule'].search([
            ('model_id.model', '=', 'hr.payslip.run'),
            ('name', 'ilike', 'multi-company')
        ])

        self.assertTrue(
            rule,
            "Debe existir ir.rule multi-company para hr.payslip.run"
        )

    def test_user_a_sees_only_company_a_payslips(self):
        """
        P0-3: Usuario Company A ve solo liquidaciones de su compañía

        Verificación Ley 19.628: Datos personales de empleados de otra
        compañía no deben ser visibles.
        """
        payslips_a = self.PayslipModel.with_user(self.user_company_a).search([])

        self.assertIn(
            self.payslip_a,
            payslips_a,
            "Usuario A debe ver payslip de Company A"
        )

        self.assertNotIn(
            self.payslip_b,
            payslips_a,
            "Usuario A NO debe ver payslip de Company B "
            "(violación Ley 19.628 si visible)"
        )

    def test_user_b_sees_only_company_b_payslips(self):
        """
        P0-3: Usuario Company B ve solo liquidaciones de su compañía
        """
        payslips_b = self.PayslipModel.with_user(self.user_company_b).search([])

        self.assertIn(
            self.payslip_b,
            payslips_b,
            "Usuario B debe ver payslip de Company B"
        )

        self.assertNotIn(
            self.payslip_a,
            payslips_b,
            "Usuario B NO debe ver payslip de Company A"
        )

    def test_user_a_cannot_read_company_b_payslip(self):
        """
        P0-3: Usuario A no puede leer directamente payslip de Company B

        Test de seguridad estricto: Intentar leer por ID directo debe fallar.
        """
        with self.assertRaises(AccessError):
            self.payslip_b.with_user(self.user_company_a).read(['name'])

    def test_user_b_cannot_write_company_a_payslip(self):
        """
        P0-3: Usuario B no puede modificar payslip de Company A
        """
        with self.assertRaises(AccessError):
            self.payslip_a.with_user(self.user_company_b).write({
                'name': 'Intento modificación cross-company'
            })

    def test_user_a_cannot_unlink_company_b_payslip(self):
        """
        P0-3: Usuario A no puede eliminar payslip de Company B
        """
        with self.assertRaises(AccessError):
            self.payslip_b.with_user(self.user_company_a).unlink()

    def test_shared_master_data_visible_to_all(self):
        """
        P0-3: Datos maestros compartidos (sin company_id) visibles para todos

        Modelos como hr.afp, hr.isapre, l10n_cl.legal.caps NO deben tener
        ir.rule porque son datos maestros compartidos entre compañías.
        """
        # Indicadores económicos (compartidos)
        indicators = self.env['hr.economic.indicators'].with_user(
            self.user_company_a
        ).search([])

        self.assertTrue(
            indicators,
            "Indicadores económicos deben ser visibles para todos los usuarios "
            "(datos maestros compartidos)"
        )

        # Topes legales (compartidos)
        caps = self.env['l10n_cl.legal.caps'].with_user(
            self.user_company_a
        ).search([])

        self.assertTrue(
            caps,
            "Topes legales deben ser visibles para todos "
            "(datos maestros compartidos)"
        )
