# -*- coding: utf-8 -*-
"""
Unit Tests for DTE Generators (33, 34, 52, 56, 61)
Tests XML generation for all DTE types
"""

import pytest
from datetime import datetime
from lxml import etree


class TestDTEGenerator33:
    """Tests for DTE 33 (Factura Electrónica) generator"""

    def test_generate_basic_invoice(self, sample_invoice_data):
        """Test basic invoice XML generation"""
        from generators.dte_generator_33 import DTEGenerator33

        generator = DTEGenerator33()
        xml = generator.generate(sample_invoice_data['invoice_data'])

        # Verify XML is well-formed
        root = etree.fromstring(xml.encode('ISO-8859-1'))
        assert root is not None

        # Verify DTE type
        tipo_dte = root.find('.//TipoDTE')
        assert tipo_dte is not None
        assert tipo_dte.text == '33'

        # Verify folio
        folio = root.find('.//Folio')
        assert folio is not None
        assert folio.text == '1'

    def test_generate_with_multiple_lines(self, sample_invoice_data):
        """Test invoice with multiple line items"""
        from generators.dte_generator_33 import DTEGenerator33

        # Add multiple lines
        invoice_data = sample_invoice_data['invoice_data'].copy()
        invoice_data['lineas'] = [
            {
                'numero_linea': 1,
                'nombre': 'Item 1',
                'cantidad': 10,
                'precio_unitario': 1000,
                'monto_item': 10000
            },
            {
                'numero_linea': 2,
                'nombre': 'Item 2',
                'cantidad': 5,
                'precio_unitario': 2000,
                'monto_item': 10000
            }
        ]

        generator = DTEGenerator33()
        xml = generator.generate(invoice_data)
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify both lines exist
        detalle_elements = root.findall('.//Detalle')
        assert len(detalle_elements) == 2

    def test_generate_with_discounts(self, sample_invoice_data):
        """Test invoice with discounts"""
        from generators.dte_generator_33 import DTEGenerator33

        invoice_data = sample_invoice_data['invoice_data'].copy()
        invoice_data['lineas'] = [{
            'numero_linea': 1,
            'nombre': 'Item with discount',
            'cantidad': 1,
            'precio_unitario': 10000,
            'descuento_porcentaje': 10,
            'monto_item': 9000
        }]

        generator = DTEGenerator33()
        xml = generator.generate(invoice_data)
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify discount is present
        desc_pct = root.find('.//DescuentoPct')
        assert desc_pct is not None
        assert desc_pct.text == '10'

    def test_missing_required_fields_raises_error(self):
        """Test that missing required fields raises ValidationError"""
        from generators.dte_generator_33 import DTEGenerator33

        generator = DTEGenerator33()

        with pytest.raises(Exception):  # Should raise ValidationError
            generator.generate({})  # Empty data


class TestDTEGenerator61:
    """Tests for DTE 61 (Nota de Crédito) generator"""

    def test_generate_credit_note(self, sample_invoice_data):
        """Test credit note XML generation"""
        from generators.dte_generator_61 import DTEGenerator61

        # Convert to credit note
        invoice_data = sample_invoice_data['invoice_data'].copy()
        invoice_data['documento_referencia'] = {
            'tipo_documento': '33',
            'folio': 100,
            'fecha': '2025-10-20',
            'razon': 'Anulación por error'
        }

        generator = DTEGenerator61()
        xml = generator.generate(invoice_data)
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify DTE type is 61
        tipo_dte = root.find('.//TipoDTE')
        assert tipo_dte is not None
        assert tipo_dte.text == '61'

        # Verify reference exists
        referencia = root.find('.//Referencia')
        assert referencia is not None

        # Verify reference folio
        ref_folio = root.find('.//Referencia/FolioRef')
        assert ref_folio is not None
        assert ref_folio.text == '100'


class TestDTEGenerator56:
    """Tests for DTE 56 (Nota de Débito) generator"""

    def test_generate_debit_note(self, sample_invoice_data):
        """Test debit note XML generation"""
        from generators.dte_generator_56 import DTEGenerator56

        invoice_data = sample_invoice_data['invoice_data'].copy()
        invoice_data['documento_referencia'] = {
            'tipo_documento': '33',
            'folio': 100,
            'fecha': '2025-10-20',
            'razon': 'Intereses por mora'
        }

        generator = DTEGenerator56()
        xml = generator.generate(invoice_data)
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify DTE type is 56
        tipo_dte = root.find('.//TipoDTE')
        assert tipo_dte is not None
        assert tipo_dte.text == '56'


class TestDTEGenerator52:
    """Tests for DTE 52 (Guía de Despacho) generator"""

    def test_generate_shipping_guide(self, sample_invoice_data):
        """Test shipping guide XML generation"""
        from generators.dte_generator_52 import DTEGenerator52

        invoice_data = sample_invoice_data['invoice_data'].copy()
        invoice_data['transporte'] = {
            'tipo_despacho': 1,  # Despacho por cuenta del vendedor
            'direccion_destino': 'Calle Destino 789',
            'comuna_destino': 'Santiago',
            'ciudad_destino': 'Santiago'
        }

        generator = DTEGenerator52()
        xml = generator.generate(invoice_data)
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify DTE type is 52
        tipo_dte = root.find('.//TipoDTE')
        assert tipo_dte is not None
        assert tipo_dte.text == '52'


class TestDTEGenerator34:
    """Tests for DTE 34 (Liquidación Honorarios) generator"""

    def test_generate_fees_settlement(self, sample_invoice_data):
        """Test fees settlement XML generation"""
        from generators.dte_generator_34 import DTEGenerator34

        invoice_data = sample_invoice_data['invoice_data'].copy()
        invoice_data['retencion'] = {
            'tipo_retencion': 1,
            'tasa_retencion': 10,
            'monto_retencion': 10000
        }

        generator = DTEGenerator34()
        xml = generator.generate(invoice_data)
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify DTE type is 34
        tipo_dte = root.find('.//TipoDTE')
        assert tipo_dte is not None
        assert tipo_dte.text == '34'


class TestAllGenerators:
    """Cross-generator tests"""

    @pytest.mark.parametrize('dte_type,generator_class', [
        ('33', 'DTEGenerator33'),
        ('34', 'DTEGenerator34'),
        ('52', 'DTEGenerator52'),
        ('56', 'DTEGenerator56'),
        ('61', 'DTEGenerator61'),
    ])
    def test_all_generators_produce_valid_xml(self, dte_type, generator_class, sample_invoice_data):
        """Test that all generators produce well-formed XML"""
        module = __import__(f'generators.dte_generator_{dte_type}', fromlist=[generator_class])
        generator = getattr(module, generator_class)()

        invoice_data = sample_invoice_data['invoice_data'].copy()

        # Add required fields for specific types
        if dte_type in ['56', '61']:
            invoice_data['documento_referencia'] = {
                'tipo_documento': '33',
                'folio': 100,
                'fecha': '2025-10-20',
                'razon': 'Test'
            }

        xml = generator.generate(invoice_data)

        # Verify XML is well-formed
        root = etree.fromstring(xml.encode('ISO-8859-1'))
        assert root is not None

        # Verify has DTE structure
        assert root.tag == 'DTE' or 'DTE' in root.tag

    def test_generators_handle_special_characters(self, sample_invoice_data):
        """Test that generators properly encode special characters"""
        from generators.dte_generator_33 import DTEGenerator33

        invoice_data = sample_invoice_data['invoice_data'].copy()
        invoice_data['emisor']['razon_social'] = 'Test & Company S.A. <Special>'
        invoice_data['receptor']['razon_social'] = 'Cliente "Especial" Ltda.'

        generator = DTEGenerator33()
        xml = generator.generate(invoice_data)

        # Should not raise XML parsing errors
        root = etree.fromstring(xml.encode('ISO-8859-1'))
        assert root is not None

        # Verify special chars are escaped
        razon_social = root.find('.//Emisor/RznSoc')
        assert '&' not in razon_social.text  # Should be &amp;
        assert '<' not in razon_social.text  # Should be &lt;
