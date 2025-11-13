# -*- coding: utf-8 -*-

"""
Test Fixtures - FASE 0-1 Payroll Tests
======================================

Factory classes y data fixtures para tests de nómina FASE 0-1.

Proporciona:
- Test companies con configuración contable chilena
- Test employees con contratos variados
- Test payroll data (AFP, cotizaciones, retenciones)
- Test accounting accounts (contabilidad chilena)
"""

from datetime import date, timedelta
from dateutil.relativedelta import relativedelta


class CompanyFactory:
    """Factory para crear test companies con config chilena"""

    @staticmethod
    def create_test_company(env, name="Test Company Chile", vat="76.123.456-7"):
        """Crea empresa test con configuración contable"""
        Company = env['res.company']

        company = Company.search([('vat', '=', vat)], limit=1)
        if company:
            return company

        return Company.create({
            'name': name,
            'vat': vat,
            'country_id': env.ref('base.cl').id,
            'currency_id': env.ref('base.CLP').id,
            'l10n_cl_dte_resolution_number': '0000123456789',
            'l10n_cl_dte_resolution_date': date.today(),
            'l10n_cl_activity_code': '620200',  # Servicios de TI
        })


class PartnerFactory:
    """Factory para crear partners (empleados, proveedores)"""

    @staticmethod
    def create_employee_partner(env, name="Test Employee", vat="12.345.678-9"):
        """Crea partner para empleado"""
        Partner = env['res.partner']

        partner = Partner.search([('vat', '=', vat)], limit=1)
        if partner:
            return partner

        return Partner.create({
            'name': name,
            'vat': vat,
            'is_company': False,
            'country_id': env.ref('base.cl').id,
            'l10n_cl_sii_taxpayer_type': '1',  # RUT
        })

    @staticmethod
    def create_provider_partner(env, name="Test Provider", vat="76.987.654-3"):
        """Crea partner para proveedor"""
        Partner = env['res.partner']

        partner = Partner.search([('vat', '=', vat)], limit=1)
        if partner:
            return partner

        return Partner.create({
            'name': name,
            'vat': vat,
            'is_company': True,
            'supplier_rank': 1,
            'country_id': env.ref('base.cl').id,
            'l10n_cl_sii_taxpayer_type': '1',
        })


class ContractFactory:
    """Factory para crear contratos de trabajo"""

    @staticmethod
    def create_test_contract(
        env,
        employee_id,
        company_id,
        wage=2_000_000,
        contract_type='indefinite',
        afp_type='A'
    ):
        """Crea contrato de trabajo con configuración chilena"""
        Contract = env['hr.contract']

        contract = Contract.create({
            'name': f"Contrato {employee_id}",
            'employee_id': employee_id,
            'company_id': company_id,
            'contract_type_id': env.ref('hr_contract.contract_type_indefinite').id if contract_type == 'indefinite' else None,
            'wage': wage,
            'date_start': date.today() - relativedelta(months=12),
            'state': 'open',

            # Campos chilenos DFL 150
            'l10n_cl_gratification_type': 'LEGAL',  # Gratificación legal
            'l10n_cl_gratification_amount': wage * 0.083,  # 8.3% base
            'l10n_cl_afp_type': afp_type,
            'l10n_cl_afp_percentage': 10.0,
            'l10n_cl_health_insurance_type': 'FONASA',
            'l10n_cl_health_insurance_percentage': 7.0,
        })

        return contract


class PayrollDataFactory:
    """Factory para crear data de nómina (AFP, cotizaciones, etc)"""

    @staticmethod
    def get_or_create_economic_indicators(env, year=2025):
        """Obtiene o crea indicadores económicos para año (API actualizada a Odoo 19)"""
        Indicators = env['hr.economic.indicators']

        # Buscar por período (primer día del año)
        period_date = date(year, 1, 1)
        indicators = Indicators.search([
            ('period', '=', period_date),
        ], limit=1)

        if indicators:
            return indicators

        # Crear indicadores para enero del año especificado
        return Indicators.create({
            'period': period_date,
            'uf': 37000.0,  # UF enero 2025
            'utm': 70000.0,  # UTM enero 2025
            'uta': 840000.0,  # UTA anual
            'minimum_wage': 500000.0,  # Sueldo mínimo
        })

    @staticmethod
    def get_or_create_legal_caps(env, year=2025):
        """Obtiene o crea topes legales para año (API actualizada a Odoo 19)"""
        LegalCaps = env['l10n_cl.legal.caps']

        # Topes legales 2025
        caps_data = [
            ('AFP_IMPONIBLE_CAP', 83.1, 'uf'),  # Tope AFP Ley 20.255 Art. 17
            ('APV_CAP_MONTHLY', 50.0, 'uf'),  # Tope APV mensual
            ('APV_CAP_ANNUAL', 600.0, 'uf'),  # Tope APV anual
        ]

        caps = {}
        for code, amount, unit in caps_data:
            # Usar objetos date, no strings
            valid_from_date = date(year, 1, 1)
            cap = LegalCaps.search([
                ('code', '=', code),
                ('valid_from', '=', valid_from_date),
            ], limit=1)

            if not cap:
                cap = LegalCaps.create({
                    'code': code,
                    'amount': amount,
                    'unit': unit,
                    'valid_from': valid_from_date,
                    'valid_until': date(year, 12, 31),
                })

            caps[code] = cap

        return caps

    @staticmethod
    def get_or_create_afp_fund(env, name="AFP Modelo", percentage=0.8):
        """Obtiene o crea fondo AFP"""
        AFP = env['l10n_cl.afp.fund']

        afp = AFP.search([('name', '=', name)], limit=1)

        if afp:
            return afp

        return AFP.create({
            'name': name,
            'commission_percentage': percentage,
            'insurance_percentage': 1.45,
        })


class PayslipFactory:
    """Factory para crear nóminas de prueba"""

    @staticmethod
    def create_test_payslip(
        env,
        employee_id,
        contract_id,
        date_from=None,
        date_to=None,
    ):
        """Crea nómina de prueba"""
        Payslip = env['hr.payslip']

        if not date_from:
            date_from = date.today().replace(day=1)
        if not date_to:
            date_to = date_from + relativedelta(months=1) - timedelta(days=1)

        payslip = Payslip.create({
            'employee_id': employee_id,
            'contract_id': contract_id,
            'date_from': date_from,
            'date_to': date_to,
            'state': 'draft',
        })

        # Computar líneas salariales
        payslip.compute_sheet()

        return payslip


class TestDataGenerator:
    """Generator completo para test data FASE 0-1"""

    @staticmethod
    def generate_complete_test_data(env):
        """Genera suite completa de test data"""
        data = {}

        # Company
        data['company'] = CompanyFactory.create_test_company(env)
        env.company = data['company']

        # Indicators y Caps
        data['indicators'] = PayrollDataFactory.get_or_create_economic_indicators(env)
        data['caps'] = PayrollDataFactory.get_or_create_legal_caps(env)

        # AFP
        data['afp'] = PayrollDataFactory.get_or_create_afp_fund(env)

        # Partners
        data['employee_partner'] = PartnerFactory.create_employee_partner(env)
        data['provider_partner'] = PartnerFactory.create_provider_partner(env)

        # Employee
        Employee = env['hr.employee']
        data['employee'] = Employee.create({
            'name': 'Test Employee',
            'work_email': 'employee@test.com',
            'company_id': data['company'].id,
            'resource_id': env.ref('base.user_admin').id,
        })

        # Contract
        data['contract'] = ContractFactory.create_test_contract(
            env,
            data['employee'].id,
            data['company'].id,
            wage=2_000_000,
        )

        # Payslip
        data['payslip'] = PayslipFactory.create_test_payslip(
            env,
            data['employee'].id,
            data['contract'].id,
        )

        return data


# Fixtures para pytest
def pytest_generate_tests(metafunc):
    """Genera parametrized tests según markers"""
    if "test_data" in metafunc.fixturenames:
        metafunc.parametrize(
            "test_data",
            [TestDataGenerator.generate_complete_test_data],
            indirect=True,
        )
