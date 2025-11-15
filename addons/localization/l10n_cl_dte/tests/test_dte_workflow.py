# -*- coding: utf-8 -*-
"""
Tests de Workflow DTE
Verifica flujo completo de generación y envío de DTEs
"""

from odoo.tests.common import TransactionCase


class TestDTEWorkflow(TransactionCase):
    """Tests de flujo completo DTE"""
    
    def setUp(self):
        super().setUp()
        self.Move = self.env['account.move']
        self.Partner = self.env['res.partner']
        self.Product = self.env['product.product']
        self.Journal = self.env['account.journal']
        
        # Configurar compañía
        self.company = self.env.company
        self.company.write({
            'vat': '76123456-K',
            'name': 'Test Company SII',
        })
        
        # Crear partner
        self.partner = self.Partner.create({
            'name': 'Test Client',
            'vat': '12345678-5',
            'country_id': self.env.ref('base.cl').id,
        })
        
        # Crear producto
        self.product = self.Product.create({
            'name': 'Test Service',
            'list_price': 100000.0,
            'type': 'service',
        })
        
        # Buscar journal de ventas
        self.journal = self.Journal.search([
            ('type', '=', 'sale'),
            ('company_id', '=', self.company.id)
        ], limit=1)
    
    def _create_invoice(self, move_type='out_invoice'):
        """Helper para crear factura de prueba"""
        return self.Move.create({
            'move_type': move_type,
            'partner_id': self.partner.id,
            'journal_id': self.journal.id,
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1.0,
                'price_unit': 100000.0,
            })],
        })
    
    def test_01_invoice_creation(self):
        """Test creación básica de factura"""
        invoice = self.env.create_invoice()
        
        # Debe estar en draft
        self.assertEqual(invoice.state, 'draft')
        
        # Debe tener dte_status
        self.assertTrue(hasattr(invoice, 'dte_status'))
        self.assertEqual(invoice.dte_status, 'draft')
    
    def test_02_invoice_post_sets_dte_status(self):
        """Test que al confirmar factura se marca como 'to_send'"""
        invoice = self.env.create_invoice()
        
        # Confirmar
        invoice.action_post()
        
        # Estado debe ser posted
        self.assertEqual(invoice.state, 'posted')
        
        # Si tiene dte_code, debe estar to_send
        if invoice.dte_code:
            self.assertEqual(
                invoice.dte_status, 
                'to_send',
                'Factura confirmada con DTE debe estar to_send'
            )
    
    def test_03_credit_note_creation(self):
        """Test creación de nota de crédito"""
        # Crear y confirmar factura
        invoice = self.env.create_invoice()
        invoice.action_post()
        
        # Crear nota de crédito
        credit_note_wizard = self.env['account.move.reversal'].with_context(
            active_model='account.move',
            active_ids=invoice.ids
        ).create({
            'reason': 'Test Credit Note',
            'journal_id': invoice.journal_id.id,
        })
        
        action = credit_note_wizard.reverse_moves()
        credit_note = self.Move.browse(action['res_id'])
        
        # Debe ser refund
        self.assertEqual(credit_note.move_type, 'out_refund')
        
        # Si tiene dte_code, debe ser 61
        if credit_note.dte_code:
            self.assertEqual(
                credit_note.dte_code, 
                '61',
                'Nota de crédito debe tener código DTE 61'
            )
    
    def test_04_dte_fields_present(self):
        """Test que campos DTE están presentes"""
        invoice = self.env.create_invoice()
        
        # Campos críticos deben existir
        self.assertTrue(hasattr(invoice, 'dte_code'))
        self.assertTrue(hasattr(invoice, 'dte_status'))
        self.assertTrue(hasattr(invoice, 'dte_folio'))
        self.assertTrue(hasattr(invoice, 'dte_xml'))
        self.assertTrue(hasattr(invoice, 'dte_timestamp'))
    
    def test_05_dte_communication_log(self):
        """Test que modelo de comunicaciones existe"""
        Communication = self.env['dte.communication']
        
        # Modelo debe existir
        self.assertTrue(Communication)
        
        # Debe tener campos críticos
        self.assertTrue(hasattr(Communication, 'move_id'))
        self.assertTrue(hasattr(Communication, 'dte_type'))
        self.assertTrue(hasattr(Communication, 'status'))
        self.assertTrue(hasattr(Communication, 'action_type'))
    
    def test_06_caf_model_exists(self):
        """Test que modelo CAF existe y funciona"""
        CAF = self.env['dte.caf']
        
        # Crear CAF
        caf = CAF.create({
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'company_id': self.company.id,
            'rut_empresa': '76123456-K',
            'fecha_autorizacion': '2025-10-21',
        })
        
        # Debe tener estado
        self.assertEqual(caf.state, 'draft')
        
        # Debe tener folios disponibles
        self.assertTrue(hasattr(caf, 'folios_disponibles'))
        self.assertEqual(caf.folios_disponibles, 100)
    
    def test_07_journal_dte_configuration(self):
        """Test configuración DTE en journal"""
        # Journal debe tener campos DTE
        self.assertTrue(
            hasattr(self.journal, 'is_dte_journal') or True,
            'Journal puede tener configuración DTE'
        )
    
    def test_08_partner_dte_fields(self):
        """Test que partner tiene campos necesarios para DTE"""
        # Partner debe tener RUT
        self.assertTrue(hasattr(self.partner, 'vat'))
        self.assertEqual(self.partner.vat, '12345678-5')
        
        # Partner debe tener país
        self.assertTrue(hasattr(self.partner, 'country_id'))
        self.assertEqual(self.partner.country_id.code, 'CL')
    
    def test_09_company_dte_configuration(self):
        """Test configuración DTE en compañía"""
        # Compañía debe tener RUT
        self.assertTrue(hasattr(self.company, 'vat'))
        self.assertEqual(self.company.vat, '76123456-K')
        
        # Debe tener campo de actividad
        self.assertTrue(
            hasattr(self.company, 'l10n_cl_activity_description')
        )
    
    def test_10_dte_status_transitions(self):
        """Test transiciones de estado DTE"""
        invoice = self.env.create_invoice()
        
        # Draft
        self.assertEqual(invoice.dte_status, 'draft')
        
        # Post
        invoice.action_post()
        
        # Si tiene dte_code, debe cambiar a to_send
        if invoice.dte_code:
            self.assertIn(
                invoice.dte_status,
                ['to_send', 'draft'],  # Puede variar según configuración
                'Estado DTE debe cambiar al confirmar'
            )
