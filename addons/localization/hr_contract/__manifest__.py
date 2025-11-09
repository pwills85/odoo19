# -*- coding: utf-8 -*-
{
    'name': 'Employee Contracts (Stub)',
    'version': '19.0.1.0.0',
    'category': 'Human Resources',
    'summary': 'Minimal stub for hr_contract compatibility',
    'description': """
Minimal stub module to provide hr_contract compatibility for l10n_cl_hr_payroll.
This is a temporary solution for Odoo 19 Community Edition.
    """,
    'author': 'EERGYGROUP',
    'website': 'https://eergygroup.cl',
    'depends': ['hr', 'mail'],
    'data': [
        'security/ir.model.access.csv',
    ],
    'installable': True,
    'application': False,
    'auto_install': False,
}
