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
        'hr',                    # RRHH base Odoo
        'hr_contract',           # Contratos
        'hr_holidays',           # Vacaciones
        'account',               # Contabilidad
        'l10n_cl',               # Localización Chile (plan contable, RUT)
    ],
    'external_dependencies': {
        'python': [
            'requests',          # HTTP client para microservicios
        ],
    },
    'data': [
        # Seguridad (PRIMERO)
        'security/security_groups.xml',
        'security/ir.model.access.csv',
        
        # Datos base (SEGUNDO) - SOPA 2025
        'data/ir_sequence.xml',                      # Secuencias
        'data/ir_cron_data.xml',                     # Cron automático indicadores
        'data/hr_salary_rule_category_base.xml',     # 13 categorías base
        'data/hr_salary_rule_category_sopa.xml',     # 9 categorías SOPA
        'data/hr_tax_bracket_2025.xml',              # Tramos impuesto 2025
        'data/l10n_cl_legal_caps_2025.xml',          # Topes legales APV/AFC
        'data/l10n_cl_apv_institutions.xml',         # Instituciones APV
        
        # Vistas
        'views/hr_payroll_structure_views.xml',
        'views/hr_salary_rule_views.xml',
        'views/hr_payslip_run_views.xml',
        'views/hr_contract_views.xml',
        'views/hr_payslip_views.xml',
        'views/hr_afp_views.xml',
        'views/hr_isapre_views.xml',
        'views/hr_economic_indicators_views.xml',
        'views/menus.xml',
        
        # Wizards
        'wizards/hr_economic_indicators_import_wizard_views.xml',
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
}
