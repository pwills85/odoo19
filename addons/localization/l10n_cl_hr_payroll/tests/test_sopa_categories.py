# -*- coding: utf-8 -*-

from odoo.tests import common, tagged
from odoo.exceptions import ValidationError


@tagged('post_install', '-at_install', 'payroll_sopa')
class TestSOPACategories(common.TransactionCase):
    """Test SOPA 2025 Categories - Odoo 19 CE"""
    
    def setUp(self):
        super(TestSOPACategories, self).setUp()
        self.Category = self.env['hr.salary.rule.category']
    
    def test_01_categories_exist(self):
        """Verificar que existen al menos 22 categorías SOPA 2025"""
        categories = self.Category.search([])
        self.assertGreaterEqual(
            len(categories), 22,
            f"Deben existir al menos 22 categorías SOPA 2025, encontradas: {len(categories)}"
        )
    
    def test_02_category_base_exists(self):
        """Verificar categoría BASE con flags correctos"""
        category = self.env.ref('l10n_cl_hr_payroll.category_base', raise_if_not_found=False)
        
        self.assertTrue(category, "Categoría BASE debe existir")
        self.assertEqual(category.code, 'BASE', "Código debe ser BASE")
        self.assertTrue(category.imponible, "BASE debe ser imponible")
        self.assertTrue(category.tributable, "BASE debe ser tributable")
        self.assertTrue(category.afecta_gratificacion, "BASE debe afectar gratificación")
        self.assertEqual(category.signo, 'positivo', "BASE debe tener signo positivo")
    
    def test_03_category_hierarchy(self):
        """Verificar jerarquía HABER → IMPO"""
        parent = self.env.ref('l10n_cl_hr_payroll.category_haberes', raise_if_not_found=False)
        child = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible', raise_if_not_found=False)
        
        self.assertTrue(parent, "Categoría HABERES debe existir")
        self.assertTrue(child, "Categoría IMPO debe existir")
        self.assertEqual(
            child.parent_id.id, parent.id,
            "IMPO debe ser hijo de HABER"
        )
    
    def test_04_imponible_flags(self):
        """Verificar flags imponibles correctos"""
        # Imponibles
        impo = self.env.ref('l10n_cl_hr_payroll.category_haber_imponible', raise_if_not_found=False)
        self.assertTrue(impo, "Categoría IMPO debe existir")
        self.assertTrue(impo.imponible, "IMPO debe tener flag imponible=True")
        
        # No imponibles
        noimpo = self.env.ref('l10n_cl_hr_payroll.category_haber_no_imponible', raise_if_not_found=False)
        self.assertTrue(noimpo, "Categoría NOIMPO debe existir")
        self.assertFalse(noimpo.imponible, "NOIMPO debe tener flag imponible=False")
    
    def test_05_code_unique_constraint(self):
        """Verificar constraint código único"""
        with self.assertRaises(Exception):  # IntegrityError o ValidationError
            self.Category.create({
                'name': 'Duplicado',
                'code': 'BASE',  # Ya existe
                'tipo': 'haber'
            })
    
    def test_06_descuentos_legales_exist(self):
        """Verificar categoría LEGAL (descuentos legales) existe"""
        legal = self.env.ref('l10n_cl_hr_payroll.category_desc_legal', raise_if_not_found=False)
        
        self.assertTrue(legal, "Categoría LEGAL debe existir")
        self.assertEqual(legal.code, 'LEGAL', "Código debe ser LEGAL")
        self.assertEqual(legal.tipo, 'descuento', "Tipo debe ser descuento")
        self.assertEqual(legal.signo, 'negativo', "Signo debe ser negativo")
    
    def test_07_totalizadores_exist(self):
        """Verificar totalizadores existen"""
        totalizadores = [
            'category_gross',           # GROSS
            'category_total_imponible', # TOTAL_IMPO
            'category_renta_tributable',# RENTA_TRIB
            'category_liquido',         # NET
        ]
        
        for total_id in totalizadores:
            total = self.env.ref(f'l10n_cl_hr_payroll.{total_id}', raise_if_not_found=False)
            self.assertTrue(
                total,
                f"Totalizador {total_id} debe existir"
            )
            self.assertEqual(
                total.tipo, 'totalizador',
                f"Categoría {total_id} debe ser tipo totalizador"
            )
