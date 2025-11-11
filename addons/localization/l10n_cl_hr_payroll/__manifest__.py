# -*- coding: utf-8 -*-
{
    'name': 'Chilean Localization - Payroll & HR',
    'version': '19.0.1.0.0',
    'category': 'Human Resources/Payroll',
    'summary': 'Gestión de Nóminas Chilena - Previred, Finiquito, Reforma 2025',
    'description': """
Chilean Payroll & Human Resources
==================================

Módulo de nóminas para Chile según normativa vigente 2025.

Características principales:
-----------------------------
* Cálculos de nómina chilena
  - AFP (10 fondos, comisiones variables)
  - FONASA (7%) / ISAPRE (planes variables)
  - Impuesto único (7 tramos progresivos)
  - Gratificación legal (25% utilidades, tope 4.75 IMM)
  - Reforma Previsional 2025 (aporte empleador)

* Previred
  - Exportación archivo 105 campos
  - Certificado F30-1
  - Validación formato

* Finiquito (Liquidación final)
  - Sueldo proporcional
  - Vacaciones proporcionales
  - Indemnización años servicio (tope 11 años)
  - Indemnización aviso previo

* Integración con microservicios
  - Payroll Service (cálculos complejos)
  - AI Service (validaciones, optimización)

* Auditoría completa (Art. 54 CT)
  - Audit trail 7 años
  - Snapshot indicadores económicos
  - Trazabilidad completa

Integración con Odoo Base:
--------------------------
* Extiende hr.employee (empleados)
* Extiende hr.contract (contratos)
* Crea hr.payslip (liquidaciones)
* Integración contable

Requisitos:
-----------
* Payroll Microservice (FastAPI) en ejecución
* AI Service (opcional, para funciones avanzadas)
* Indicadores económicos actualizados (UF, UTM, UTA)

Autor: Eergygroup
Licencia: LGPL-3
""",
    'author': 'Eergygroup',
    'website': 'https://www.eergygroup.com',
    'license': 'LGPL-3',
    'depends': [
        'base',
        'hr',                    # ✅ CE base - RRHH
        # 'hr_contract',         # ❌ Enterprise-only in Odoo 19 - removed
        'hr_holidays',           # ✅ Time Off (Odoo 19 CE base module)
        'account',               # ✅ CE base - Contabilidad
        'l10n_cl',               # ✅ Localización Chile (plan contable, RUT)
    ],
    'external_dependencies': {
        'python': [
            'requests',          # HTTP client para microservicios
            'python-dotenv',     # ✅ Environment variables management (FIX-002)
        ],
    },
    'data': [
        # Seguridad (PRIMERO)
        'security/security_groups.xml',
        'security/multi_company_rules.xml',
        'security/ir.model.access.csv',
        
        # Views STUB (antes de datos)
        'views/hr_contract_stub_views.xml',
        
        # Datos base (SEGUNDO) - SOPA 2025
        'data/ir_sequence.xml',                      # Secuencias
        'data/ir_cron_data.xml',                     # Cron automático indicadores
        'data/hr_salary_rule_category_base.xml',     # 13 categorías base
        'data/hr_salary_rule_category_sopa.xml',     # 9 categorías SOPA
        'data/hr_tax_bracket_2025.xml',              # Tramos impuesto 2025
        'data/l10n_cl_apv_institutions.xml',         # Instituciones APV
        'data/hr_salary_rules_p1.xml',               # Reglas salariales P1
        'data/hr_salary_rules_apv.xml',              # Reglas APV (Régimen A/B)
        'data/hr_payroll_structure_data.xml',      # Estructura base
        'data/hr_salary_rules_ley21735.xml',         # Ley 21.735 Reforma Pensiones
        
        # Vistas
        'views/hr_payroll_structure_views.xml',
        'views/hr_salary_rule_views.xml',
        'views/hr_payslip_run_views.xml',
        'views/hr_contract_views.xml',              # Chilean extensions (hereda de stub)
        'views/hr_payslip_views.xml',
        'views/hr_afp_views.xml',
        'views/hr_isapre_views.xml',
        'views/hr_economic_indicators_views.xml',
        'views/menus.xml',
        
        # Wizards (commented for FASE A - test execution focus)
        # 'wizards/hr_economic_indicators_import_wizard_views.xml',
        # 'wizards/hr_lre_wizard_views.xml',
        # 'wizards/payroll_ai_validation_wizard_views.xml',
        # 'wizards/previred_validation_wizard_views.xml',
    ],
    'tests': [
        'tests/test_ai_driven_payroll.py',
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
}
