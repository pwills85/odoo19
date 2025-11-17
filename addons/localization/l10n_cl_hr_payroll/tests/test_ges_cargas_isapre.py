# -*- coding: utf-8 -*-

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError


@tagged('post_install', '-at_install', 'l10n_cl_payroll', 'ges_cargas')
class TestGESCargasIsapre(TransactionCase):
    """
    Test GES cargas (beneficiarios salud) para trabajadores con Isapre.
    
    CONTEXTO REGULATORIO:
    - Trabajadores Isapre DEBEN declarar cargas GES para LRE Previred
    - Cargas GES normalmente coinciden con cargas familiares
    - PERO pueden diferir en casos edge (ej: ingreso alto sin asignación familiar)
    
    CASOS A TESTEAR:
    1. Cargas GES se inicializan desde family_allowance_* (caso normal)
    2. Cargas GES pueden editarse independientemente (caso edge)
    3. Trabajador Fonasa no tiene cargas GES (validación)
    4. Validaciones: no negativos, máx. 1 maternal
    """
    
    def setUp(self):
        super().setUp()
        
        # Company
        self.company = self.env['res.company'].create({
            'name': 'Test Company CL'
        })
        
        # Employee
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee GES',
            'company_id': self.company.id,
        })
        
        # AFP
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Capital',
            'code': 'CAPITAL',
            'rate': 11.44,
        })
        
        # Isapre
        self.isapre = self.env['hr.isapre'].create({
            'name': 'Banmédica',
            'code': 'BANMED',
        })
    
    def test_ges_cargas_auto_initialize_from_family_allowance(self):
        """
        Test Case 1: GES cargas se inicializan automáticamente desde family_allowance_*
        
        Escenario normal: Trabajador Isapre con cargas familiares
        → GES cargas deben copiarse automáticamente
        """
        contract = self.env['hr.contract'].create({
            'name': 'Contract Test GES Auto',
            'employee_id': self.employee.id,
            'wage': 2000000,
            'date_start': '2025-01-01',
            'state': 'open',
            'afp_id': self.afp.id,
            'health_system': 'isapre',
            'isapre_id': self.isapre.id,
            'isapre_plan_uf': 5.0,
            'family_allowance_simple': 3,
            'family_allowance_maternal': 1,
            'family_allowance_invalid': 0,
        })
        
        # Forzar compute
        contract._compute_ges_cargas()
        
        # Validar que GES cargas se inicializan desde family_allowance_*
        self.assertEqual(contract.isapre_ges_cargas_simples, 3,
                        "GES cargas simples debe inicializar desde family_allowance_simple")
        self.assertEqual(contract.isapre_ges_cargas_maternales, 1,
                        "GES cargas maternales debe inicializar desde family_allowance_maternal")
        self.assertEqual(contract.isapre_ges_cargas_invalidas, 0,
                        "GES cargas inválidas debe inicializar desde family_allowance_invalid")
    
    def test_ges_cargas_editable_independently(self):
        """
        Test Case 2: GES cargas pueden editarse independientemente
        
        Escenario edge: Ejecutivo con ingreso alto (sin asignación familiar)
        pero con hijos que SÍ tienen cobertura GES
        
        → GES cargas ≠ family_allowance (ingreso > Tramo D)
        """
        contract = self.env['hr.contract'].create({
            'name': 'Contract Test GES Edge Case',
            'employee_id': self.employee.id,
            'wage': 5000000,  # Alto ingreso → Sin asignación familiar
            'date_start': '2025-01-01',
            'state': 'open',
            'afp_id': self.afp.id,
            'health_system': 'isapre',
            'isapre_id': self.isapre.id,
            'isapre_plan_uf': 6.5,
            'family_allowance_simple': 0,    # No recibe asignación (ingreso alto)
            'family_allowance_maternal': 0,  # No recibe asignación (ingreso alto)
            'family_allowance_invalid': 0,
        })
        
        # Pero SÍ tiene cargas GES (hijos con cobertura salud)
        contract.write({
            'isapre_ges_cargas_simples': 3,
            'isapre_ges_cargas_maternales': 1,
        })
        
        # Validar que GES cargas son independientes
        self.assertEqual(contract.family_allowance_simple, 0,
                        "Family allowance debe ser 0 (ingreso alto)")
        self.assertEqual(contract.isapre_ges_cargas_simples, 3,
                        "GES cargas simples debe ser 3 (beneficiarios reales)")
        self.assertEqual(contract.isapre_ges_cargas_maternales, 1,
                        "GES cargas maternales debe ser 1 (cónyuge)")
    
    def test_fonasa_no_ges_cargas(self):
        """
        Test Case 3: Trabajador FONASA no tiene cargas GES separadas
        
        FONASA maneja cargas automáticamente, no requiere declaración explícita
        """
        contract = self.env['hr.contract'].create({
            'name': 'Contract Test FONASA No GES',
            'employee_id': self.employee.id,
            'wage': 2000000,
            'date_start': '2025-01-01',
            'state': 'open',
            'afp_id': self.afp.id,
            'health_system': 'fonasa',  # ← FONASA
            'family_allowance_simple': 2,
            'family_allowance_maternal': 1,
        })
        
        # Forzar compute
        contract._compute_ges_cargas()
        
        # Validar que GES cargas son 0 (no aplican para FONASA)
        self.assertEqual(contract.isapre_ges_cargas_simples, 0,
                        "FONASA no debe tener GES cargas (se manejan automáticamente)")
        self.assertEqual(contract.isapre_ges_cargas_maternales, 0,
                        "FONASA no debe tener GES cargas maternales")
        self.assertEqual(contract.isapre_ges_cargas_invalidas, 0,
                        "FONASA no debe tener GES cargas inválidas")
    
    def test_ges_cargas_validations_non_negative(self):
        """
        Test Case 4A: Validar que GES cargas no pueden ser negativas
        """
        contract = self.env['hr.contract'].create({
            'name': 'Contract Test GES Validation',
            'employee_id': self.employee.id,
            'wage': 2000000,
            'date_start': '2025-01-01',
            'state': 'open',
            'afp_id': self.afp.id,
            'health_system': 'isapre',
            'isapre_id': self.isapre.id,
            'isapre_plan_uf': 5.0,
        })
        
        # Intentar cargas GES negativas (debe fallar)
        with self.assertRaises(ValidationError):
            contract.write({'isapre_ges_cargas_simples': -1})
        
        with self.assertRaises(ValidationError):
            contract.write({'isapre_ges_cargas_maternales': -1})
        
        with self.assertRaises(ValidationError):
            contract.write({'isapre_ges_cargas_invalidas': -1})
    
    def test_ges_cargas_maternal_max_one(self):
        """
        Test Case 4B: Validar máximo 1 carga maternal GES
        """
        contract = self.env['hr.contract'].create({
            'name': 'Contract Test GES Max Maternal',
            'employee_id': self.employee.id,
            'wage': 2000000,
            'date_start': '2025-01-01',
            'state': 'open',
            'afp_id': self.afp.id,
            'health_system': 'isapre',
            'isapre_id': self.isapre.id,
            'isapre_plan_uf': 5.0,
        })
        
        # Intentar más de 1 carga maternal GES (debe fallar)
        with self.assertRaises(ValidationError):
            contract.write({'isapre_ges_cargas_maternales': 2})
    
    def test_ges_cargas_lre_previred_scenario(self):
        """
        Test Case 5: Validar escenario completo para LRE Previred
        
        Trabajador Isapre con cargas GES → debe reportarse correctamente a Previred
        """
        contract = self.env['hr.contract'].create({
            'name': 'Contract Test LRE Previred',
            'employee_id': self.employee.id,
            'wage': 3000000,
            'date_start': '2025-01-01',
            'state': 'open',
            'afp_id': self.afp.id,
            'health_system': 'isapre',
            'isapre_id': self.isapre.id,
            'isapre_plan_uf': 5.5,
            'isapre_fun': '123456789-K',
            'family_allowance_simple': 2,
            'family_allowance_maternal': 1,
            'family_allowance_invalid': 0,
        })
        
        # Forzar compute
        contract._compute_ges_cargas()
        
        # Validar datos completos para LRE
        self.assertEqual(contract.health_system, 'isapre', "Sistema salud debe ser Isapre")
        self.assertEqual(contract.isapre_id.code, 'BANMED', "Código Isapre debe estar presente")
        self.assertEqual(contract.isapre_plan_uf, 5.5, "Plan UF debe estar presente")
        self.assertEqual(contract.isapre_ges_cargas_simples, 2, "GES cargas simples para LRE")
        self.assertEqual(contract.isapre_ges_cargas_maternales, 1, "GES cargas maternales para LRE")
        self.assertEqual(contract.isapre_ges_cargas_invalidas, 0, "GES cargas inválidas para LRE")
        
        # Simular línea LRE Previred (formato columnas 45-49)
        # BANMED|229665|2|1|0
        lre_isapre_code = contract.isapre_id.code
        lre_plan_clp = int(contract.isapre_plan_uf * 38277.50)  # UF 2025
        lre_ges_simples = contract.isapre_ges_cargas_simples
        lre_ges_maternales = contract.isapre_ges_cargas_maternales
        lre_ges_invalidas = contract.isapre_ges_cargas_invalidas
        
        lre_row = f"{lre_isapre_code}|{lre_plan_clp}|{lre_ges_simples}|{lre_ges_maternales}|{lre_ges_invalidas}"
        
        # Validar formato LRE
        self.assertEqual(lre_row, "BANMED|210526|2|1|0",
                        "Línea LRE Previred debe incluir cargas GES correctamente")
