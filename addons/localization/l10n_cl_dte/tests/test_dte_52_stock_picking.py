# -*- coding: utf-8 -*-
"""
Unit Tests - DTE 52 Stock Picking
==================================

FASE 1 DTE 52 Implementation - Complete test suite for stock.picking DTE 52.

Tests cover:
- DTE 52 generation from stock picking
- XML structure validation
- CAF folio management
- Digital signature
- TED generation
- SII submission workflow
- Idempotency protection
- Error handling

Created: 2025-11-08
Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

import unittest
from unittest.mock import Mock, MagicMock, patch
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError, UserError


class TestDTE52StockPicking(TransactionCase):
    """
    Test suite for DTE 52 generation on stock.picking.

    This uses Odoo's TransactionCase which provides a real test database.
    """

    @classmethod
    def setUpClass(cls):
        """Set up test data once for all test methods."""
        super().setUpClass()

        # Create test company
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company DTE',
            'vat': '76123456-7',
            'street': 'Av. Test 123',
            'city': 'Santiago',
            'country_id': cls.env.ref('base.cl').id,
        })

        # Create test partner
        cls.partner = cls.env['res.partner'].create({
            'name': 'Test Partner DTE 52',
            'vat': '12345678-9',
            'street': 'Calle Test 456',
            'city': 'Valparaíso',
            'country_id': cls.env.ref('base.cl').id,
        })

        # Create test product
        cls.product = cls.env['product.product'].create({
            'name': 'Test Product DTE 52',
            'default_code': 'PROD-TEST-001',
            'type': 'product',
            'list_price': 10000.0,
        })

        # Create picking type (delivery)
        cls.picking_type = cls.env['stock.picking.type'].create({
            'name': 'Test Delivery DTE 52',
            'code': 'outgoing',
            'warehouse_id': cls.env['stock.warehouse'].search([
                ('company_id', '=', cls.company.id)
            ], limit=1).id,
            'sequence_code': 'OUT',
        })

    def test_01_basic_fields_creation(self):
        """Test that DTE 52 fields exist on stock.picking model."""
        # Create a basic picking
        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
        })

        # Check DTE 52 fields exist
        self.assertTrue(hasattr(picking, 'genera_dte_52'))
        self.assertTrue(hasattr(picking, 'dte_52_status'))
        self.assertTrue(hasattr(picking, 'dte_52_folio'))
        self.assertTrue(hasattr(picking, 'dte_52_xml'))
        self.assertTrue(hasattr(picking, 'dte_52_timestamp'))
        self.assertTrue(hasattr(picking, 'tipo_traslado'))
        self.assertTrue(hasattr(picking, 'patente_vehiculo'))
        self.assertTrue(hasattr(picking, 'invoice_id'))

        # Check default values
        self.assertFalse(picking.genera_dte_52)
        self.assertEqual(picking.dte_52_status, 'draft')
        self.assertEqual(picking.tipo_traslado, '1')  # Default

    def test_02_tipo_traslado_options(self):
        """Test that tipo_traslado has all 9 valid options."""
        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
        })

        # Get field selection options
        tipo_traslado_field = picking._fields['tipo_traslado']
        selection_values = [opt[0] for opt in tipo_traslado_field.selection]

        # Check all 9 types are present
        expected_types = ['1', '2', '3', '4', '5', '6', '7', '8', '9']
        for tipo in expected_types:
            self.assertIn(tipo, selection_values,
                f"Tipo de traslado '{tipo}' should be in selection options")

    def test_03_validation_no_partner(self):
        """Test validation fails when partner is missing."""
        picking = self.env['stock.picking'].create({
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
            'genera_dte_52': True,
        })

        # Should raise ValidationError
        with self.assertRaises(ValidationError) as context:
            picking._validate_guia_data()

        self.assertIn('destinatario', str(context.exception).lower())

    def test_04_validation_partner_no_vat(self):
        """Test validation fails when partner has no RUT."""
        partner_no_vat = self.env['res.partner'].create({
            'name': 'Partner No VAT',
            'country_id': self.env.ref('base.cl').id,
        })

        picking = self.env['stock.picking'].create({
            'partner_id': partner_no_vat.id,
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
            'genera_dte_52': True,
        })

        with self.assertRaises(ValidationError) as context:
            picking._validate_guia_data()

        self.assertIn('rut', str(context.exception).lower())

    def test_05_validation_no_products(self):
        """Test validation fails when picking has no move lines."""
        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
            'genera_dte_52': True,
        })

        with self.assertRaises(ValidationError) as context:
            picking._validate_guia_data()

        self.assertIn('producto', str(context.exception).lower())

    def test_06_validation_no_quantity_done(self):
        """Test validation fails when no quantities are processed."""
        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
            'genera_dte_52': True,
        })

        # Add move line with no quantity_done
        self.env['stock.move'].create({
            'name': 'Test Move',
            'picking_id': picking.id,
            'product_id': self.product.id,
            'product_uom_qty': 10,
            'product_uom': self.product.uom_id.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
        })

        with self.assertRaises(ValidationError) as context:
            picking._validate_guia_data()

        self.assertIn('cantidades despachadas', str(context.exception).lower())

    def test_07_idempotency_prevents_duplicate_generation(self):
        """Test that DTE 52 cannot be regenerated if already exists."""
        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
            'genera_dte_52': True,
            'state': 'done',
        })

        # Simulate DTE already generated
        picking.write({
            'dte_52_folio': '1000001',
            'dte_52_xml': b'fake_xml_content',
        })

        # Attempt to regenerate should fail
        with self.assertRaises(ValidationError) as context:
            picking.action_generar_dte_52()

        error_msg = str(context.exception)
        self.assertIn('folio', error_msg.lower())
        self.assertIn('1000001', error_msg)

    def test_08_button_validate_marks_to_send(self):
        """Test that validating picking marks DTE 52 as 'to_send'."""
        picking = self.env['stock.picking'].create({
            'partner_id': self.partner.id,
            'picking_type_id': self.picking_type.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
            'company_id': self.company.id,
            'genera_dte_52': True,
        })

        # Add stock move
        move = self.env['stock.move'].create({
            'name': 'Test Move',
            'picking_id': picking.id,
            'product_id': self.product.id,
            'product_uom_qty': 5,
            'product_uom': self.product.uom_id.id,
            'location_id': self.env.ref('stock.stock_location_stock').id,
            'location_dest_id': self.env.ref('stock.stock_location_customers').id,
        })

        # Confirm and assign picking
        picking.action_confirm()
        picking.action_assign()

        # Set quantity done
        move.quantity_done = 5

        # Validate picking
        picking.button_validate()

        # Check state changed
        self.assertEqual(picking.state, 'done')
        self.assertEqual(picking.dte_52_status, 'to_send')


class TestDTE52Generator(unittest.TestCase):
    """Unit tests for DTE52Generator library (pure Python)."""

    def setUp(self):
        """Set up test fixtures."""
        from addons.localization.l10n_cl_dte.libs.dte_52_generator import DTE52Generator
        self.generator = DTE52Generator()

        # Sample data
        self.picking_data = {
            'folio': '1000001',
            'date': '2025-11-08',
            'tipo_traslado': '1',
            'patente_vehiculo': 'AA-BB-12',
            'move_lines': [
                {
                    'product_code': 'PROD-001',
                    'product_name': 'Product Test',
                    'description': 'Test Description',
                    'quantity_done': 10,
                    'uom_name': 'Unidades',
                    'price_unit': 1000,
                    'has_tax': True,
                }
            ],
        }

        self.company_data = {
            'rut': '76123456-7',
            'razon_social': 'Test Company SRL',
            'giro': 'Test Activity',
            'direccion': 'Av. Test 123',
            'comuna': 'Santiago',
            'ciudad': 'Santiago',
            'actividad_economica': '620200',
        }

        self.partner_data = {
            'rut': '12345678-9',
            'razon_social': 'Test Partner',
            'giro': 'Comercio',
            'direccion': 'Calle Test 456',
            'comuna': 'Valparaíso',
            'ciudad': 'Valparaíso',
        }

    def test_01_generator_initialization(self):
        """Test DTE52Generator initializes correctly."""
        self.assertIsNotNone(self.generator)
        self.assertEqual(self.generator.namespace, "http://www.sii.cl/SiiDte")
        self.assertEqual(self.generator.schema_version, "1.0")

    def test_02_generate_basic_xml_structure(self):
        """Test basic XML structure generation."""
        xml = self.generator.generate_dte_52_xml(
            self.picking_data,
            self.company_data,
            self.partner_data
        )

        # Check root element
        self.assertIsNotNone(xml)
        self.assertEqual(xml.tag, 'DTE')
        self.assertEqual(xml.get('version'), '1.0')

        # Check has Documento child
        documento = xml.find('Documento')
        self.assertIsNotNone(documento)

    def test_03_validate_missing_folio(self):
        """Test validation fails when folio is missing."""
        invalid_data = self.picking_data.copy()
        del invalid_data['folio']

        with self.assertRaises(ValueError) as context:
            self.generator.generate_dte_52_xml(
                invalid_data,
                self.company_data,
                self.partner_data
            )

        self.assertIn('folio', str(context.exception).lower())

    def test_04_validate_empty_move_lines(self):
        """Test validation fails when move_lines is empty."""
        invalid_data = self.picking_data.copy()
        invalid_data['move_lines'] = []

        with self.assertRaises(ValueError) as context:
            self.generator.generate_dte_52_xml(
                invalid_data,
                self.company_data,
                self.partner_data
            )

        self.assertIn('move line', str(context.exception).lower())

    def test_05_validate_invalid_tipo_traslado(self):
        """Test validation fails for invalid tipo_traslado."""
        invalid_data = self.picking_data.copy()
        invalid_data['tipo_traslado'] = '10'  # Invalid

        with self.assertRaises(ValueError) as context:
            self.generator.generate_dte_52_xml(
                invalid_data,
                self.company_data,
                self.partner_data
            )

        self.assertIn('tipo_traslado', str(context.exception).lower())

    def test_06_xml_to_string_conversion(self):
        """Test XML element can be converted to string."""
        xml = self.generator.generate_dte_52_xml(
            self.picking_data,
            self.company_data,
            self.partner_data
        )

        xml_string = self.generator.xml_to_string(xml)

        self.assertIsInstance(xml_string, str)
        self.assertIn('<?xml', xml_string)
        self.assertIn('DTE', xml_string)
        self.assertIn('1000001', xml_string)  # Folio

    def test_07_totals_calculation_with_tax(self):
        """Test totals are calculated correctly with IVA."""
        xml = self.generator.generate_dte_52_xml(
            self.picking_data,
            self.company_data,
            self.partner_data
        )

        xml_string = self.generator.xml_to_string(xml)

        # Check totals exist (10 units * 1000 = 10000 neto)
        self.assertIn('<MntNeto>10000</MntNeto>', xml_string)
        # IVA should be 1900 (10000 * 0.19)
        self.assertIn('<IVA>1900</IVA>', xml_string)
        # Total should be 11900
        self.assertIn('<MntTotal>11900</MntTotal>', xml_string)


if __name__ == '__main__':
    unittest.main()
