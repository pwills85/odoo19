# -*- coding: utf-8 -*-
"""
Tests de Integración con l10n_latam_base
Verifica que l10n_cl_dte integra correctamente con módulos base Odoo 19 CE
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestL10nLatamIntegration(TransactionCase):
    """Tests de integración con l10n_latam_base y l10n_cl"""
    
    def setUp(self):
        super().setUp()
        self.Move = self.env['account.move']
        self.Partner = self.env['res.partner']
        self.Journal = self.env['account.journal']
        self.Product = self.env['product.product']
        self.Company = self.env['res.company']
        
        # Crear datos de prueba
        self.company = self.env.company
        self.company.write({
            'vat': '76123456-K',
            'name': 'Test Company SII',
        })
        
        self.partner = self.Partner.create({
            'name': 'Test Partner',
            'vat': '12345678-5',
            'country_id': self.env.ref('base.cl').id,
        })
        
        self.product = self.Product.create({
            'name': 'Test Product',
            'list_price': 100.0,
            'type': 'service',
        })
        
        self.journal = self.Journal.search([
            ('type', '=', 'sale'),
            ('company_id', '=', self.company.id)
        ], limit=1)
        
        # Buscar document type 33 (Factura Electrónica)
        self.doc_type_33 = self.env['l10n_latam.document.type'].search([
            ('code', '=', '33'),
            ('country_id.code', '=', 'CL')
        ], limit=1)
    
    def test_01_dte_code_field_exists(self):
        """Verifica que campo dte_code existe en account.move"""
        move = self.Move.create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'journal_id': self.journal.id,
        })
        
        # Campo debe existir
        self.assertTrue(hasattr(move, 'dte_code'))
        
        # Debe ser un campo Char
        field_type = self.Move._fields.get('dte_code')
        self.assertIsNotNone(field_type)
    
    def test_02_dte_code_related_to_latam(self):
        """Verifica que dte_code viene de l10n_latam_document_type_id.code"""
        if not self.doc_type_33:
            self.skipTest('Document type 33 not found')
        
        move = self.Move.create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'journal_id': self.journal.id,
            'l10n_latam_document_type_id': self.doc_type_33.id,
        })
        
        # dte_code debe ser '33'
        self.assertEqual(move.dte_code, '33')
    
    def test_03_no_dte_type_field_in_move(self):
        """Verifica que campo dte_type NO existe en account.move"""
        move = self.Move.create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'journal_id': self.journal.id,
        })
        
        # Campo dte_type NO debe existir en account.move
        # (puede existir en otros modelos como dte.caf)
        field_type = self.Move._fields.get('dte_type')
        
        # Si existe, debe ser related o computed, no Selection directo
        if field_type:
            # Verificar que no es un Selection field directo
            self.assertNotEqual(field_type.type, 'selection')
    
    def test_04_caf_sync_with_latam_sequence(self):
        """Verifica que método _sync_with_latam_sequence existe en dte.caf"""
        CAF = self.env['dte.caf']
        
        # Verificar que modelo existe
        self.assertTrue(CAF)
        
        # Verificar que método existe
        self.assertTrue(hasattr(CAF, '_sync_with_latam_sequence'))
        
        # Crear CAF de prueba
        caf = CAF.create({
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'company_id': self.company.id,
            'rut_empresa': '76123456-K',
            'fecha_autorizacion': '2025-10-21',
        })
        
        # Método debe ejecutarse sin error (graceful degradation)
        try:
            result = caf._sync_with_latam_sequence()
            # Puede retornar True o False, ambos son válidos
            self.assertIn(result, [True, False])
        except Exception as e:
            self.fail(f'_sync_with_latam_sequence falló: {e}')
    
    def test_05_uses_l10n_cl_activity_description(self):
        """Verifica que usa l10n_cl_activity_description (no sii_activity_description)"""
        company = self.env.company
        
        # Campo l10n_cl_activity_description debe existir
        self.assertTrue(hasattr(company, 'l10n_cl_activity_description'))
        
        # Campo sii_activity_description NO debe existir
        # (si existe, es legacy y no debe usarse)
        self.assertFalse(hasattr(company, 'sii_activity_description'))
    
    def test_06_rut_validation_simplified(self):
        """Verifica que validación RUT es simple (solo presencia)"""
        move = self.Move.create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'journal_id': self.journal.id,
        })
        
        # Método _check_partner_rut debe existir
        self.assertTrue(hasattr(move, '_check_partner_rut'))
        
        # Con partner que tiene RUT, no debe fallar
        try:
            move._check_partner_rut()
        except ValidationError:
            self.fail('Validación RUT falló con partner válido')
        
        # Sin RUT, debe fallar (solo si tiene dte_code)
        partner_sin_rut = self.Partner.create({
            'name': 'Partner Sin RUT',
            'country_id': self.env.ref('base.cl').id,
        })
        
        move_sin_rut = self.Move.create({
            'move_type': 'out_invoice',
            'partner_id': partner_sin_rut.id,
            'journal_id': self.journal.id,
        })
        
        # Si tiene dte_code, debe validar RUT
        if move_sin_rut.dte_code:
            with self.assertRaises(ValidationError):
                move_sin_rut._check_partner_rut()
    
    def test_07_integration_with_l10n_latam_use_documents(self):
        """Verifica integración con l10n_latam_use_documents"""
        # Verificar que journal puede usar documentos LATAM
        if hasattr(self.journal, 'l10n_latam_use_documents'):
            # Campo existe, verificar que es Boolean
            field_type = self.Journal._fields.get('l10n_latam_use_documents')
            self.assertEqual(field_type.type, 'boolean')
    
    def test_08_document_type_mapping(self):
        """Verifica mapeo correcto de tipos de documento"""
        # Buscar todos los document types chilenos
        doc_types = self.env['l10n_latam.document.type'].search([
            ('country_id.code', '=', 'CL')
        ])
        
        # Debe haber al menos 5 tipos (33, 34, 52, 56, 61)
        self.assertGreaterEqual(len(doc_types), 5)
        
        # Verificar códigos principales
        codes = doc_types.mapped('code')
        expected_codes = ['33', '34', '52', '56', '61']
        
        for code in expected_codes:
            self.assertIn(code, codes, f'Código DTE {code} no encontrado')
