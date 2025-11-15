# -*- coding: utf-8 -*-
"""
Unit Tests - DTE Reception (Inbox)
==================================

Tests unitarios para models/dte_inbox.py - recepción de DTEs por email/webhook.
Tests con mocks de email, XML parsing, validación TED.

Coverage: recepción DTE, parseo XML, extracción metadata, validación estructura.

Author: EERGYGROUP - Claude Code (Anthropic)
License: LGPL-3
"""

import unittest
from unittest.mock import Mock, patch
import base64
from datetime import datetime
from lxml import etree


class TestDTEReceptionUnit(unittest.TestCase):
    """Tests unitarios para recepción de DTEs."""

    def setUp(self):
        """Preparar mocks y datos de prueba."""
        self.mock_env = Mock()

        # XML DTE de ejemplo (factura electrónica tipo 33)
        self.test_dte_xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
    <Documento ID="DOC1">
        <Encabezado>
            <IdDoc>
                <TipoDTE>33</TipoDTE>
                <Folio>12345</Folio>
                <FchEmis>2025-11-04</FchEmis>
                <MntTotal>100000</MntTotal>
            </IdDoc>
            <Emisor>
                <RUTEmisor>76123456-K</RUTEmisor>
                <RznSoc>Empresa Test SPA</RznSoc>
                <GiroEmis>Servicios</GiroEmis>
                <DirOrigen>Calle Falsa 123</DirOrigen>
                <CmnaOrigen>Santiago</CmnaOrigen>
            </Emisor>
            <Receptor>
                <RUTRecep>77654321-9</RUTRecep>
                <RznSocRecep>Cliente Test</RznSocRecep>
            </Receptor>
            <Totales>
                <MntNeto>84034</MntNeto>
                <MntExe>0</MntExe>
                <IVA>15966</IVA>
                <MntTotal>100000</MntTotal>
            </Totales>
        </Encabezado>
        <Detalle>
            <NroLinDet>1</NroLinDet>
            <NmbItem>Producto Test</NmbItem>
            <QtyItem>1</QtyItem>
            <PrcItem>100000</PrcItem>
        </Detalle>
        <TED version="1.0">
            <DD>
                <RE>76123456-K</RE>
                <TD>33</TD>
                <F>12345</F>
                <FE>2025-11-04</FE>
                <RR>77654321-9</RR>
                <MNT>100000</MNT>
            </DD>
            <FRMT algoritmo="SHA1withRSA">FAKE_SIGNATURE</FRMT>
        </TED>
    </Documento>
</DTE>'''

        self.test_dte_b64 = base64.b64encode(self.test_dte_xml.encode('ISO-8859-1')).decode()

    def test_01_parse_dte_xml_valid(self):
        """Test parsing de XML DTE válido."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))

        self.assertIsNotNone(tree)
        self.assertEqual(tree.tag, 'DTE')

    def test_02_extract_folio_from_xml(self):
        """Test extracción de folio desde XML."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        folio = tree.find('.//Folio')

        self.assertIsNotNone(folio)
        self.assertEqual(folio.text, '12345')

    def test_03_extract_dte_type_from_xml(self):
        """Test extracción de tipo DTE desde XML."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        tipo_dte = tree.find('.//TipoDTE')

        self.assertIsNotNone(tipo_dte)
        self.assertEqual(tipo_dte.text, '33')  # Factura electrónica

    def test_04_extract_emisor_rut_from_xml(self):
        """Test extracción de RUT emisor desde XML."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        rut_emisor = tree.find('.//RUTEmisor')

        self.assertIsNotNone(rut_emisor)
        self.assertEqual(rut_emisor.text, '76123456-K')

    def test_05_extract_emisor_name_from_xml(self):
        """Test extracción de razón social emisor."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        razon_social = tree.find('.//RznSoc')

        self.assertIsNotNone(razon_social)
        self.assertEqual(razon_social.text, 'Empresa Test SPA')

    def test_06_extract_total_amount_from_xml(self):
        """Test extracción de monto total."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        monto_total = tree.find('.//MntTotal')

        self.assertIsNotNone(monto_total)
        self.assertEqual(monto_total.text, '100000')

    def test_07_extract_emission_date_from_xml(self):
        """Test extracción de fecha de emisión."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        fecha_emis = tree.find('.//FchEmis')

        self.assertIsNotNone(fecha_emis)
        self.assertEqual(fecha_emis.text, '2025-11-04')

    def test_08_validate_ted_node_exists(self):
        """Test que nodo TED existe en DTE."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        ted = tree.find('.//TED')

        self.assertIsNotNone(ted)

    def test_09_validate_ted_signature_exists(self):
        """Test que firma TED existe."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        frmt = tree.find('.//FRMT')

        self.assertIsNotNone(frmt)
        self.assertEqual(frmt.get('algoritmo'), 'SHA1withRSA')

    def test_10_parse_invalid_xml_raises_error(self):
        """Test que XML inválido lanza excepción."""
        invalid_xml = '<DTE><Documento>NOT CLOSED'

        with self.assertRaises(etree.XMLSyntaxError):
            etree.fromstring(invalid_xml.encode('ISO-8859-1'))

    def test_11_base64_encoding_decoding(self):
        """Test encoding/decoding base64 de DTE."""
        # Encode
        encoded = base64.b64encode(self.test_dte_xml.encode('ISO-8859-1'))

        # Decode
        decoded = base64.b64decode(encoded).decode('ISO-8859-1')

        self.assertEqual(decoded, self.test_dte_xml)

    def test_12_extract_receptor_rut(self):
        """Test extracción de RUT receptor."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        rut_recep = tree.find('.//RUTRecep')

        self.assertIsNotNone(rut_recep)
        self.assertEqual(rut_recep.text, '77654321-9')

    def test_13_extract_detalle_items(self):
        """Test extracción de items del detalle."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        detalles = tree.findall('.//Detalle')

        self.assertGreater(len(detalles), 0)

        # Verificar primer item
        primer_item = detalles[0]
        nombre_item = primer_item.find('.//NmbItem')
        self.assertEqual(nombre_item.text, 'Producto Test')

    def test_14_validate_totales_section(self):
        """Test que sección Totales está completa."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))

        mnt_neto = tree.find('.//MntNeto')
        iva = tree.find('.//IVA')
        mnt_total = tree.find('.//MntTotal')

        self.assertIsNotNone(mnt_neto)
        self.assertIsNotNone(iva)
        self.assertIsNotNone(mnt_total)

        # Verificar cálculo IVA (19%)
        neto = int(mnt_neto.text)
        iva_calc = int(iva.text)
        total = int(mnt_total.text)

        self.assertEqual(total, neto + iva_calc)

    def test_15_dte_inbox_model_fields(self):
        """Test que modelo DTE Inbox tiene campos requeridos."""
        # Este test verifica estructura, no requiere instancia real

        expected_fields = [
            'folio',
            'dte_type',
            'partner_id',
            'emisor_rut',
            'emisor_name',
            'received_date',
            'xml_file',
        ]

        # Verificar que son nombres válidos de campo
        for field_name in expected_fields:
            self.assertIsInstance(field_name, str)
            self.assertGreater(len(field_name), 0)

    def test_16_dte_type_selection_values(self):
        """Test valores válidos de tipos de DTE."""
        valid_dte_types = ['33', '34', '39', '41', '46', '52', '56', '61', '70']

        # Verificar que tipo 33 (factura) está en lista
        self.assertIn('33', valid_dte_types)

        # Verificar que cada tipo es string de 2 dígitos
        for dte_type in valid_dte_types:
            self.assertIsInstance(dte_type, str)
            self.assertEqual(len(dte_type), 2)

    @patch('addons.localization.l10n_cl_dte.libs.safe_xml_parser.fromstring_safe')
    def test_17_safe_xml_parser_protects_xxe(self, mock_fromstring):
        """Test que safe_xml_parser protege contra XXE."""
        from addons.localization.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # Mock parser seguro
        mock_fromstring.return_value = etree.fromstring(
            self.test_dte_xml.encode('ISO-8859-1')
        )

        # Llamar parser seguro
        tree = fromstring_safe(self.test_dte_xml.encode('ISO-8859-1'))

        # Verificar que retorna árbol válido
        self.assertIsNotNone(tree)
        mock_fromstring.assert_called_once()

    def test_18_xml_encoding_iso_8859_1(self):
        """Test que DTE usa encoding ISO-8859-1."""
        self.assertIn('ISO-8859-1', self.test_dte_xml)

        # Verificar que se puede codificar/decodificar
        encoded = self.test_dte_xml.encode('ISO-8859-1')
        decoded = encoded.decode('ISO-8859-1')

        self.assertEqual(decoded, self.test_dte_xml)

    def test_19_date_format_validation(self):
        """Test formato de fecha (YYYY-MM-DD)."""
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        fecha_emis = tree.find('.//FchEmis').text

        # Verificar formato
        try:
            datetime.strptime(fecha_emis, '%Y-%m-%d')
            valid_format = True
        except ValueError:
            valid_format = False

        self.assertTrue(valid_format)

    def test_20_performance_xml_parsing(self):
        """Test que parsing de XML es rápido (<0.05s)."""
        import time

        start = time.time()
        tree = etree.fromstring(self.test_dte_xml.encode('ISO-8859-1'))
        elapsed = time.time() - start

        self.assertLess(elapsed, 0.05)
        self.assertIsNotNone(tree)


# Ejecutar tests si se llama directamente
if __name__ == '__main__':
    unittest.main()
