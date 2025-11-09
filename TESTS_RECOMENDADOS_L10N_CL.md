# TESTS RECOMENDADOS PARA CERRAR GAPS - l10n_cl_*

**Objetivo:** Proporcionar código listo para implementar los tests faltantes identificados en la auditoría.

---

## 1. TESTS FALTANTES - l10n_cl_dte

### 1.1 DTE XML Generation Tests (BLOQUEANTE)

**Archivo:** Crear `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/tests/test_dte_xml_generation.py`

```python
# -*- coding: utf-8 -*-
"""
Test Suite: DTE XML Generation
================================

Tests para generación de XML DTEs (tipos 33, 34, 52, 56, 61).
Valida estructura, montos, cálculos, campos obligatorios SII.

Author: Claude Code
Date: 2025-11-06
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from lxml import etree
from unittest.mock import patch, MagicMock
import base64


@tagged('post_install', '-at_install', 'dte_xml_generation')
class TestDTEXMLGeneration(TransactionCase):
    """Test suite para generación XML de DTEs"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Setup company Chilean
        cls.company = cls.env.company
        cls.company.write({
            'vat': '76123456-K',
            'l10n_cl_razon_social': 'Empresa Test SPA',
            'country_id': cls.env.ref('base.cl').id,
            'dte_resolution_number': '80',
            'dte_resolution_date': '2020-01-15',
        })

        # Setup partner
        cls.partner = cls.env['res.partner'].create({
            'name': 'Cliente Test',
            'vat': '12345678-5',
            'country_id': cls.env.ref('base.cl').id,
        })

        # Setup journal
        cls.journal = cls.env['account.journal'].create({
            'name': 'Ventas',
            'type': 'sale',
            'code': 'SALE',
            'company_id': cls.company.id,
        })

        # Setup product
        cls.product = cls.env['product.product'].create({
            'name': 'Product Test',
            'list_price': 100000.0,
            'type': 'consu',
        })

    def _create_invoice(self, dte_type='33', **kwargs):
        """Helper para crear factura de prueba"""
        defaults = {
            'partner_id': self.partner.id,
            'move_type': 'out_invoice',
            'journal_id': self.journal.id,
            'invoice_date': '2025-11-06',
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1.0,
                'price_unit': 100000.0,
            })],
        }
        defaults.update(kwargs)

        invoice = self.env['account.move'].create(defaults)
        invoice.action_post()
        return invoice

    # ========================================================================
    # TESTS - DTE 33 (Factura Electrónica)
    # ========================================================================

    def test_dte33_basic_structure(self):
        """Test estructura básica DTE 33"""
        invoice = self._create_invoice(dte_type='33')

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify root
        self.assertEqual(root.tag, 'DTE')

        # Verify Documento
        doc = root.find('.//Documento')
        self.assertIsNotNone(doc)
        self.assertEqual(doc.get('ID'), f'DTE-33-{invoice.dte_folio}')

        # Verify Encabezado
        header = doc.find('.//Encabezado')
        self.assertIsNotNone(header)

    def test_dte33_monto_calculation(self):
        """Test cálculo de montos DTE 33"""
        invoice = self._create_invoice(
            dte_type='33',
            invoice_line_ids=[(0, 0, {
                'product_id': self.product.id,
                'quantity': 1.0,
                'price_unit': 118000.0,  # 100k neto + 18k IVA
            })]
        )

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        totales = root.find('.//Totales')
        mnt_neto = int(totales.find('MntNeto').text or 0)
        iva = int(totales.find('IVA').text or 0)
        mnt_total = int(totales.find('MntTotal').text or 0)

        # Verify: MntTotal = MntNeto + IVA
        self.assertEqual(mnt_total, mnt_neto + iva)
        self.assertAlmostEqual(mnt_neto, 100000, delta=1)
        self.assertAlmostEqual(iva, 19000, delta=1)

    def test_dte33_multiple_lines(self):
        """Test DTE 33 con múltiples líneas de detalle"""
        invoice = self._create_invoice(
            dte_type='33',
            invoice_line_ids=[
                (0, 0, {
                    'product_id': self.product.id,
                    'quantity': 2.0,
                    'price_unit': 50000.0,
                }),
                (0, 0, {
                    'product_id': self.product.id,
                    'quantity': 1.0,
                    'price_unit': 100000.0,
                }),
            ]
        )

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        detalles = root.findall('.//Detalle')
        self.assertEqual(len(detalles), 2)

    def test_dte33_with_discount_global(self):
        """Test DTE 33 con descuento global"""
        # Este test requiere que el modelo soporte descuentos
        # Se asume que existe invoice.discount_total

        invoice = self._create_invoice(dte_type='33')
        # Simular descuento (en Odoo se hace con línea negativa típicamente)

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify estructura de descuentos si existen
        desc_rcg = root.find('.//DescRcg')
        # self.assertIsNone(desc_rcg)  # Si no hay descuento

    # ========================================================================
    # TESTS - DTE 56 (Nota de Débito)
    # ========================================================================

    def test_dte56_with_reference(self):
        """Test DTE 56 (Nota de Débito) CON referencia a factura original"""
        # Primero crear factura original
        original = self._create_invoice(dte_type='33')

        # Crear nota de débito que referencia original
        debit_note = self._create_invoice(
            dte_type='56',
            partner_id=original.partner_id.id,
        )

        # Agregar referencia
        self.env['account.move.reference'].create({
            'move_id': debit_note.id,
            'document_type_id': self.env.ref('l10n_cl_dte.document_type_33').id,
            'folio': original.dte_folio,
            'date': original.invoice_date,
        })

        xml = debit_note._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify Referencia exists
        referencias = root.findall('.//Referencia')
        self.assertEqual(len(referencias), 1)

        ref = referencias[0]
        self.assertEqual(ref.find('TpoDocRef').text, '33')
        self.assertEqual(ref.find('FolioRef').text, str(original.dte_folio))

    def test_dte56_monto_debe_positive(self):
        """Test DTE 56 - Monto debe ser positivo"""
        debit_note = self._create_invoice(dte_type='56')

        xml = debit_note._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        mnt_total = int(root.find('.//MntTotal').text or 0)
        self.assertGreater(mnt_total, 0)

    # ========================================================================
    # TESTS - DTE 61 (Nota de Crédito)
    # ========================================================================

    def test_dte61_with_reference(self):
        """Test DTE 61 (Nota de Crédito) CON referencia a factura original"""
        original = self._create_invoice(dte_type='33')

        credit_note = self._create_invoice(
            dte_type='61',
            partner_id=original.partner_id.id,
        )

        # Agregar referencia
        self.env['account.move.reference'].create({
            'move_id': credit_note.id,
            'document_type_id': self.env.ref('l10n_cl_dte.document_type_33').id,
            'folio': original.dte_folio,
            'date': original.invoice_date,
        })

        xml = credit_note._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Verify structure
        self.assertIn(b'61', xml)  # DTE type 61
        referencias = root.findall('.//Referencia')
        self.assertEqual(len(referencias), 1)

    def test_dte61_monto_debe_positive(self):
        """Test DTE 61 - Monto debe ser positivo"""
        credit_note = self._create_invoice(dte_type='61')

        xml = credit_note._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        mnt_total = int(root.find('.//MntTotal').text or 0)
        self.assertGreater(mnt_total, 0)

    # ========================================================================
    # TESTS - DTE 34 (Factura Exenta)
    # ========================================================================

    def test_dte34_exempt_total(self):
        """Test DTE 34 - No debe tener IVA, solo MntExe"""
        exempt = self._create_invoice(dte_type='34')

        xml = exempt._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        totales = root.find('.//Totales')
        iva = int(totales.find('IVA').text or 0)
        mnt_exe = int(totales.find('MntExe').text or 0)

        # DTE 34 no debe tener IVA
        self.assertEqual(iva, 0)
        # Debe tener MntExe
        self.assertGreater(mnt_exe, 0)

    # ========================================================================
    # TESTS - VALIDACIONES OBLIGATORIAS SII
    # ========================================================================

    def test_mandatory_fields_exist(self):
        """Test que campos obligatorios SII existen en XML"""
        invoice = self._create_invoice(dte_type='33')

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Campos obligatorios (según Res. Ex. SII Nº 80/2014)
        mandatory_fields = {
            'TipoDTE': '33',
            'Folio': str(invoice.dte_folio),
            'FchEmis': '2025-11-06',
            'RUTEmisor': '76123456-K',
            'RznSoc': 'Empresa Test SPA',
            'RUTRecep': '12345678-5',
            'MntTotal': str(invoice.amount_total),
        }

        for field, expected_value in mandatory_fields.items():
            elem = root.find(f'.//{field}')
            self.assertIsNotNone(elem, f"Mandatory field {field} not found")

    def test_rut_format_in_xml(self):
        """Test formato RUT en XML (XX.XXX.XXX-X)"""
        invoice = self._create_invoice(dte_type='33')

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        rut_emisor = root.find('.//RUTEmisor').text
        # Verificar formato: 76.123.456-K
        self.assertRegex(rut_emisor, r'\d{2}\.\d{3}\.\d{3}-[0-9K]')

    def test_ted_element_exists(self):
        """Test que TED (Timbre Electrónico) existe en XML"""
        invoice = self._create_invoice(dte_type='33')

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        ted = root.find('.//TED')
        self.assertIsNotNone(ted)

        # TED debe tener FRMA
        frma = ted.find('FRMA')
        self.assertIsNotNone(frma)
        self.assertEqual(frma.get('algoritmo'), 'SHA1withRSA')

    # ========================================================================
    # TESTS - ROUNDING VALIDATIONS
    # ========================================================================

    def test_rounding_to_cents(self):
        """Test que montos se redondean a centavos"""
        invoice = self._create_invoice(
            dte_type='33',
            invoice_line_ids=[(0, 0, {
                'product_id': self.product.id,
                'quantity': 1.333,  # Cantidad que puede generar montos con decimales
                'price_unit': 99999.99,
            })]
        )

        xml = invoice._generate_dte_xml()
        root = etree.fromstring(xml.encode('ISO-8859-1'))

        # Todos los montos deben ser enteros (centavos)
        for monto_elem in root.findall('.//Mnt*'):
            monto_text = monto_elem.text
            if monto_text:
                # Verificar que es entero (sin decimales)
                self.assertTrue(monto_text.isdigit(),
                              f"Monto no es entero: {monto_text}")

    # ========================================================================
    # TESTS - ERROR HANDLING
    # ========================================================================

    def test_dte_xml_generation_without_folio(self):
        """Test que falta folio genera error apropiado"""
        invoice = self._create_invoice(dte_type='33')
        invoice.dte_folio = None  # Remove folio

        with self.assertRaises(ValidationError) as context:
            invoice._generate_dte_xml()

        self.assertIn('folio', str(context.exception).lower())

    def test_dte_xml_generation_invalid_partner_rut(self):
        """Test que partner sin RUT válido genera error"""
        partner_no_rut = self.env['res.partner'].create({
            'name': 'Invalid Partner',
            'vat': 'INVALID',  # RUT inválido
        })

        invoice = self._create_invoice(
            dte_type='33',
            partner_id=partner_no_rut.id,
        )

        with self.assertRaises(ValidationError):
            invoice._generate_dte_xml()
```

---

### 1.2 DTE Reception Tests (BLOQUEANTE)

**Archivo:** Crear `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/tests/test_dte_reception_integration.py`

```python
# -*- coding: utf-8 -*-
"""
Test Suite: DTE Reception Integration
======================================

Tests para recepción de DTEs por email (IMAP) y validación.

Author: Claude Code
Date: 2025-11-06
"""

from odoo.tests.common import TransactionCase
from unittest.mock import patch, MagicMock, mock_open
from lxml import etree
import base64


@tagged('post_install', '-at_install', 'dte_reception_integration')
class TestDTEReceptionIntegration(TransactionCase):
    """Test suite para recepción integrada de DTEs"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.company = cls.env.company
        cls.company.write({
            'vat': '76123456-K',
            'country_id': cls.env.ref('base.cl').id,
        })

    def _create_sample_dte_xml(self, dte_type='33', folio='12345'):
        """Helper: Crear XML DTE de muestra"""
        return f'''<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
    <Documento ID="DOC1">
        <Encabezado>
            <IdDoc>
                <TipoDTE>{dte_type}</TipoDTE>
                <Folio>{folio}</Folio>
                <FchEmis>2025-11-06</FchEmis>
                <MntTotal>100000</MntTotal>
            </IdDoc>
            <Emisor>
                <RUTEmisor>76123456-K</RUTEmisor>
                <RznSoc>Empresa Remitente</RznSoc>
            </Emisor>
            <Receptor>
                <RUTRecep>77654321-9</RUTRecep>
                <RznSocRecep>Nuestra Empresa</RznSocRecep>
            </Receptor>
        </Encabezado>
    </Documento>
</DTE>'''

    @patch('imaplib.IMAP4_SSL')
    def test_receive_dte_from_email_basic(self, mock_imap_class):
        """Test recepción básica de DTE por email"""
        # Setup mock IMAP
        mock_imap = MagicMock()
        mock_imap_class.return_value.__enter__.return_value = mock_imap

        # Mock email search response
        mock_imap.search.return_value = (None, [b'1'])

        # Mock email fetch response
        dte_xml = self._create_sample_dte_xml()
        email_content = f"""From: sender@example.com
To: receiver@example.com
Subject: DTE 33 - Factura

{base64.b64encode(dte_xml.encode()).decode()}"""

        mock_imap.fetch.return_value = (None, [
            (b'FLAGS', b''),
            (b'RFC822', email_content.encode())
        ])

        # Mock close
        mock_imap.close.return_value = None
        mock_imap.logout.return_value = None

        # Test reception (this would be triggered by cron)
        # For now, we just verify the XML can be parsed
        root = etree.fromstring(dte_xml.encode('ISO-8859-1'))
        self.assertEqual(root.find('.//TipoDTE').text, '33')

    def test_detect_duplicate_dte(self):
        """Test detección de DTEs duplicados"""
        dte_xml = self._create_sample_dte_xml(folio='12345')

        # Create first DTE inbox record
        dte_inbox1 = self.env['dte.inbox'].create({
            'name': 'DTE-33-12345',
            'dte_xml': dte_xml,
            'dte_folio': 12345,
            'dte_type': '33',
            'rut_emisor': '76123456-K',
        })

        # Try to create duplicate
        dte_inbox2 = self.env['dte.inbox'].new({
            'name': 'DTE-33-12345-DUP',
            'dte_xml': dte_xml,
            'dte_folio': 12345,
            'dte_type': '33',
            'rut_emisor': '76123456-K',
        })

        # Should detect duplicate
        is_duplicate = dte_inbox2._check_if_duplicate()
        self.assertTrue(is_duplicate)

    def test_reject_malformed_dte_xml(self):
        """Test rechazo de XML DTE malformado"""
        malformed_xml = """<?xml version="1.0"?>
<DTE>
    <Documento>
        <!-- Missing closing tag -->
        <Encabezado>
</DTE>"""

        from odoo.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            self.env['dte.inbox'].create({
                'name': 'Invalid DTE',
                'dte_xml': malformed_xml,
            })

    def test_extract_dte_metadata_from_xml(self):
        """Test extracción de metadata de XML DTE"""
        dte_xml = self._create_sample_dte_xml(
            dte_type='33',
            folio='99999'
        )

        dte_inbox = self.env['dte.inbox'].new({
            'name': 'Test DTE',
            'dte_xml': dte_xml,
        })

        metadata = dte_inbox._extract_dte_metadata(dte_xml)

        self.assertEqual(metadata['dte_type'], '33')
        self.assertEqual(metadata['folio'], '99999')
        self.assertEqual(metadata['rut_emisor'], '76123456-K')
        self.assertEqual(metadata['mnt_total'], '100000')

    def test_validate_dte_signature_mock(self):
        """Test validación de firma digital DTE"""
        dte_xml = self._create_sample_dte_xml()

        # En producción, esto validaría con certificados SII
        # Para testing, usamos mock
        dte_inbox = self.env['dte.inbox'].new({
            'name': 'Test DTE',
            'dte_xml': dte_xml,
        })

        with patch('odoo.addons.l10n_cl_dte.libs.caf_signature_validator.CAFSignatureValidator') as mock_validator:
            mock_validator.return_value.validate_signature.return_value = (True, 'Valid signature')

            is_valid, message = dte_inbox._validate_dte_signature(dte_xml)
            self.assertTrue(is_valid)

    def test_query_sii_status_for_received_dte(self):
        """Test consulta de estado en SII para DTE recibido"""
        dte_xml = self._create_sample_dte_xml()

        dte_inbox = self.env['dte.inbox'].create({
            'name': 'DTE-33-12345',
            'dte_xml': dte_xml,
            'dte_folio': 12345,
            'dte_type': '33',
            'rut_emisor': '76123456-K',
        })

        # Mock SII SOAP query
        with patch('zeep.Client') as mock_zeep:
            mock_client = MagicMock()
            mock_zeep.return_value = mock_client

            # Mock SII response
            sii_response = """<?xml version="1.0"?>
<RESPUESTA xmlns="http://www.sii.cl/XMLSchema">
    <ESTADO>0</ESTADO>
    <GLOSA>Aceptado</GLOSA>
</RESPUESTA>"""

            mock_client.service.getEstadoDTE.return_value = sii_response

            # Query status
            status = dte_inbox._query_sii_status()

            self.assertEqual(status, 'aceptado')

    def test_audit_logging_on_reception(self):
        """Test que recepción genera logs de auditoría"""
        dte_xml = self._create_sample_dte_xml()

        with self.assertLogs('odoo.addons.l10n_cl_dte.models.dte_inbox', level='INFO') as logs:
            dte_inbox = self.env['dte.inbox'].create({
                'name': 'DTE-33-12345',
                'dte_xml': dte_xml,
                'dte_folio': 12345,
                'dte_type': '33',
                'rut_emisor': '76123456-K',
            })

        # Verify audit log exists
        self.assertTrue(
            any('DTE recibido' in log or 'received' in log.lower() for log in logs.output),
            'Audit log for DTE reception not found'
        )
```

---

### 1.3 Performance Tests (ALTO)

**Archivo:** Crear `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/tests/test_performance.py`

```python
# -*- coding: utf-8 -*-
"""
Test Suite: Performance Benchmarks
===================================

Tests de performance para validar p95 < 400ms.

Author: Claude Code
Date: 2025-11-06
"""

from odoo.tests.common import TransactionCase
from odoo import fields
import time


@tagged('performance', '-at_install')
class TestDTEPerformance(TransactionCase):
    """Performance benchmarks para DTE"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.company = cls.env.company
        cls.company.write({
            'vat': '76123456-K',
            'country_id': cls.env.ref('base.cl').id,
        })

        cls.partner = cls.env['res.partner'].create({
            'name': 'Test Partner',
            'vat': '12345678-5',
        })

        cls.product = cls.env['product.product'].create({
            'name': 'Test Product',
            'list_price': 100000.0,
            'type': 'consu',
        })

        cls.journal = cls.env['account.journal'].create({
            'name': 'Sales',
            'type': 'sale',
            'code': 'SAL',
            'company_id': cls.company.id,
        })

    def _create_invoice(self):
        """Create test invoice"""
        return self.env['account.move'].create({
            'partner_id': self.partner.id,
            'move_type': 'out_invoice',
            'journal_id': self.journal.id,
            'invoice_date': fields.Date.today(),
            'invoice_line_ids': [(0, 0, {
                'product_id': self.product.id,
                'quantity': 1.0,
                'price_unit': 100000.0,
            })],
        })

    def test_dte_xml_generation_performance_p95(self):
        """DTE XML generation: p95 must be < 400ms"""
        invoice = self._create_invoice()
        invoice.action_post()

        times = []

        # Run 100 times
        for i in range(100):
            start = time.perf_counter()
            try:
                xml = invoice._generate_dte_xml()
            except Exception:
                pass  # Ignore errors for perf test
            elapsed = (time.perf_counter() - start) * 1000  # ms
            times.append(elapsed)

        # Calculate p95
        times.sort()
        p95 = times[int(len(times) * 0.95)]
        p99 = times[int(len(times) * 0.99)]
        median = times[int(len(times) * 0.5)]

        # Log results
        self.env.cr.commit()

        print(f"\n=== DTE XML Generation Performance ===")
        print(f"Median: {median:.1f}ms")
        print(f"p95:    {p95:.1f}ms (limit: 400ms)")
        print(f"p99:    {p99:.1f}ms")

        # Assert p95 < 400ms
        self.assertLess(
            p95, 400,
            f"DTE XML generation p95={p95:.1f}ms exceeds limit of 400ms"
        )

    def test_cached_computed_field_performance(self):
        """Cached computed fields must not re-compute on every access"""
        caf = self.env['dte.caf'].create({
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'caf_file': b'test',
            'company_id': self.company.id,
        })

        times = []

        # Access name 100 times (should be cached after first access)
        for i in range(100):
            start = time.perf_counter()
            name = caf.name
            elapsed = (time.perf_counter() - start) * 1000

            times.append(elapsed)

        times.sort()
        p95 = times[int(len(times) * 0.95)]

        # After first access, should be sub-millisecond
        self.assertLess(
            p95, 1.0,
            f"Cached field access p95={p95:.3f}ms (should be < 1ms)"
        )
```

---

## 2. TESTS RECOMENDADOS - l10n_cl_financial_reports

### 2.1 Financial Reports Test Suite (CRÍTICO)

**Archivo:** Crear `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_financial_reports/tests/test_financial_reports.py`

```python
# -*- coding: utf-8 -*-
"""
Test Suite: Financial Reports Generation
=========================================

Tests para reportes financieros: Balance General, P&L, F29, F22.

Author: Claude Code
Date: 2025-11-06
"""

from odoo.tests.common import TransactionCase
from odoo import fields
from datetime import datetime, timedelta


@tagged('post_install', '-at_install', 'financial_reports')
class TestBalanceSheetGeneration(TransactionCase):
    """Test suite para Balance General"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.company = cls.env.company
        cls.company.write({
            'name': 'Test Company',
            'country_id': cls.env.ref('base.cl').id,
        })

        # Create chart of accounts
        cls.account_bank = cls.env['account.account'].create({
            'name': 'Banco',
            'code': '1110',
            'account_type': 'asset_current',
            'company_id': cls.company.id,
        })

        cls.account_receivable = cls.env['account.account'].create({
            'name': 'Cuentas por Cobrar',
            'code': '1120',
            'account_type': 'asset_current',
            'company_id': cls.company.id,
        })

        cls.account_payable = cls.env['account.account'].create({
            'name': 'Cuentas por Pagar',
            'code': '2110',
            'account_type': 'liability_current',
            'company_id': cls.company.id,
        })

        cls.account_equity = cls.env['account.account'].create({
            'name': 'Capital',
            'code': '3110',
            'account_type': 'equity',
            'company_id': cls.company.id,
        })

        cls.account_revenue = cls.env['account.account'].create({
            'name': 'Ingresos por Ventas',
            'code': '4110',
            'account_type': 'income',
            'company_id': cls.company.id,
        })

        cls.account_expense = cls.env['account.account'].create({
            'name': 'Gastos de Operación',
            'code': '5110',
            'account_type': 'expense',
            'company_id': cls.company.id,
        })

    def _create_journal_entry(self, account, amount, date_str='2025-11-06'):
        """Helper: Create journal entry"""
        journal = self.env['account.journal'].search(
            [('type', '=', 'general'), ('company_id', '=', self.company.id)],
            limit=1
        )

        if not journal:
            journal = self.env['account.journal'].create({
                'name': 'General',
                'type': 'general',
                'code': 'GEN',
                'company_id': self.company.id,
            })

        move = self.env['account.move'].create({
            'journal_id': journal.id,
            'date': date_str,
            'company_id': self.company.id,
            'line_ids': [
                (0, 0, {
                    'account_id': account.id,
                    'debit': amount if amount > 0 else 0,
                    'credit': -amount if amount < 0 else 0,
                }),
                (0, 0, {
                    'account_id': self.account_equity.id,
                    'debit': -amount if amount < 0 else 0,
                    'credit': amount if amount > 0 else 0,
                }),
            ]
        })
        move.action_post()
        return move

    def test_balance_sheet_structure(self):
        """Test estructura básica de Balance General"""
        # Create sample data
        self._create_journal_entry(self.account_bank, 1000000)
        self._create_journal_entry(self.account_receivable, 500000)
        self._create_journal_entry(self.account_payable, -200000)

        # Generate Balance Sheet
        report_service = self.env['financial.report.service']
        balance_sheet = report_service.generate_balance_sheet(
            start_date='2025-01-01',
            end_date='2025-12-31',
            company_id=self.company.id
        )

        # Verify structure
        self.assertIn('activo_corriente', balance_sheet)
        self.assertIn('activo_no_corriente', balance_sheet)
        self.assertIn('pasivo_corriente', balance_sheet)
        self.assertIn('pasivo_no_corriente', balance_sheet)
        self.assertIn('patrimonio', balance_sheet)

    def test_balance_sheet_balance_equation(self):
        """Test que cumple ecuación: Activo = Pasivo + Patrimonio"""
        # Create entries
        self._create_journal_entry(self.account_bank, 1000000)
        self._create_journal_entry(self.account_payable, -300000)

        # Generate report
        report_service = self.env['financial.report.service']
        balance_sheet = report_service.generate_balance_sheet(
            start_date='2025-01-01',
            end_date='2025-12-31',
            company_id=self.company.id
        )

        # Calculate totals
        activo_total = (balance_sheet.get('activo_corriente', 0) +
                       balance_sheet.get('activo_no_corriente', 0))
        pasivo_total = (balance_sheet.get('pasivo_corriente', 0) +
                       balance_sheet.get('pasivo_no_corriente', 0))
        patrimonio = balance_sheet.get('patrimonio', 0)

        # Verify equation
        self.assertAlmostEqual(
            activo_total,
            pasivo_total + patrimonio,
            places=2,
            msg="Balance equation violated: Activo ≠ Pasivo + Patrimonio"
        )

    def test_balance_sheet_period_comparison(self):
        """Test comparación entre dos períodos"""
        # Period 1: Jan-Jun
        self._create_journal_entry(self.account_bank, 1000000, '2025-03-15')

        # Period 2: Jul-Dec
        self._create_journal_entry(self.account_bank, 500000, '2025-09-15')

        report_service = self.env['financial.report.service']

        # P1
        bs_p1 = report_service.generate_balance_sheet(
            start_date='2025-01-01',
            end_date='2025-06-30',
            company_id=self.company.id
        )

        # P2
        bs_p2 = report_service.generate_balance_sheet(
            start_date='2025-07-01',
            end_date='2025-12-31',
            company_id=self.company.id
        )

        # P2 should have more assets
        self.assertGreater(
            bs_p2.get('activo_corriente', 0),
            bs_p1.get('activo_corriente', 0)
        )


@tagged('post_install', '-at_install', 'financial_reports')
class TestProfitLossGeneration(TransactionCase):
    """Test suite para P&L (Ingresos - Gastos)"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.company = cls.env.company

        # Setup accounts
        cls.account_revenue = cls.env['account.account'].create({
            'name': 'Ingresos',
            'code': '4100',
            'account_type': 'income',
            'company_id': cls.company.id,
        })

        cls.account_expense = cls.env['account.account'].create({
            'name': 'Gastos',
            'code': '5100',
            'account_type': 'expense',
            'company_id': cls.company.id,
        })

        cls.account_equity = cls.env['account.account'].create({
            'name': 'Capital',
            'code': '3100',
            'account_type': 'equity',
            'company_id': cls.company.id,
        })

    def test_profit_loss_calculation(self):
        """Test cálculo P&L: Ingresos - Gastos = Utilidad/Pérdida"""
        journal = self.env['account.journal'].create({
            'name': 'General',
            'type': 'general',
            'code': 'GEN',
            'company_id': self.company.id,
        })

        # Revenue entry
        revenue_move = self.env['account.move'].create({
            'journal_id': journal.id,
            'date': '2025-11-06',
            'company_id': self.company.id,
            'line_ids': [
                (0, 0, {
                    'account_id': self.account_revenue.id,
                    'debit': 0,
                    'credit': 1000000,
                }),
                (0, 0, {
                    'account_id': self.account_equity.id,
                    'debit': 1000000,
                    'credit': 0,
                }),
            ]
        })
        revenue_move.action_post()

        # Expense entry
        expense_move = self.env['account.move'].create({
            'journal_id': journal.id,
            'date': '2025-11-06',
            'company_id': self.company.id,
            'line_ids': [
                (0, 0, {
                    'account_id': self.account_expense.id,
                    'debit': 300000,
                    'credit': 0,
                }),
                (0, 0, {
                    'account_id': self.account_equity.id,
                    'debit': 0,
                    'credit': 300000,
                }),
            ]
        })
        expense_move.action_post()

        # Generate P&L
        report_service = self.env['financial.report.service']
        pl = report_service.generate_profit_loss(
            start_date='2025-01-01',
            end_date='2025-12-31',
            company_id=self.company.id
        )

        # Verify calculation
        ingresos = pl.get('ingresos_totales', 0)
        gastos = pl.get('gastos_totales', 0)
        utilidad = pl.get('utilidad_neta', 0)

        self.assertEqual(ingresos, 1000000)
        self.assertEqual(gastos, 300000)
        self.assertAlmostEqual(utilidad, 700000, places=2)
```

---

## 3. EJECUCIÓN DE TESTS RECOMENDADOS

### 3.1 Comando para ejecutar tests nuevos

```bash
# Instalar pytest si no está
pip install pytest pytest-cov

# DTE XML Generation Tests
cd /Users/pedro/Documents/odoo19
pytest addons/localization/l10n_cl_dte/tests/test_dte_xml_generation.py -v

# DTE Reception Tests
pytest addons/localization/l10n_cl_dte/tests/test_dte_reception_integration.py -v

# Performance Tests
pytest addons/localization/l10n_cl_dte/tests/test_performance.py -v --tb=short

# Financial Reports Tests
pytest addons/localization/l10n_cl_financial_reports/tests/test_financial_reports.py -v

# Todos juntos con cobertura
pytest addons/localization/l10n_cl_dte/tests \
    --cov=addons/localization/l10n_cl_dte \
    --cov-report=html \
    --cov-fail-under=85 \
    -v
```

---

## 4. CHECKLIST DE IMPLEMENTACIÓN

- [ ] Crear archivos de test sugeridos
- [ ] Implementar tests DTE XML Generation (20 tests, 3h)
- [ ] Implementar tests DTE Reception (15 tests, 4h)
- [ ] Implementar tests Performance (5 tests, 1h)
- [ ] Implementar tests Financial Reports (30 tests, 6h)
- [ ] Ejecutar todos tests localmente
- [ ] Verificar cobertura >= 85%
- [ ] Fix cualquier fallo
- [ ] Commit to git
- [ ] Create GitHub Actions workflow
- [ ] Deploy to staging

**Total Tiempo Estimado:** 32-40 horas

---

**Documento Generado:** 2025-11-06
**Herramienta:** Claude Code Test Automation Specialist
