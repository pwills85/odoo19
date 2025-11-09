# Test Strategy - FASE 1: DTE 52 (Guía de Despacho)

**Status:** Enterprise Quality | **Owner:** QA Lead | **Updated:** 2025-11-08

---

## Executive Summary

Test strategy for FASE 1 DTE 52 (Guía de Despacho Electrónica) implementation. This phase covers XML generation, SII submission, and Odoo integration for electronic delivery guides. Supports both new prospective documents and 646 historical pickings.

**Target Coverage:** >90% | **Test Cases:** 30+ | **Execution Time:** <10min | **Success Criteria:** 0 failures + XSD validation

---

## 1. Unit Tests - DTE52 Generator Library

### Test Class: `TestDTE52Generator`

**File:** `addons/localization/l10n_cl_dte/tests/test_dte52_generator_unit.py`

#### Core Generator Tests

| Test Name | Description | Input | Expected | Coverage |
|-----------|-------------|-------|----------|----------|
| `test_generate_xml_estructura_correcta` | XML structure matches SII schema | movimiento object | Valid XML tree | 100% |
| `test_encabezado_fields_presentes` | Header has all required fields | movimiento | All header fields present | 100% |
| `test_detalles_productos_items` | Detail section with products | 5 items | 5 details in XML | 100% |
| `test_traslado_type_venta` | Venta (sale) transport type | tipo_traslado=1 | Code 1 in XML | 100% |
| `test_traslado_type_interno` | Interno (internal) transport type | tipo_traslado=2 | Code 2 in XML | 100% |
| `test_traslado_type_devolucion` | Return transport type | tipo_traslado=3 | Code 3 in XML | 100% |
| `test_all_traslado_types` | All 8 transport types supported | tipos 1-8 | All codes valid | 100% |
| `test_despacho_types_optional` | Despacho type (1-3) optional | despacho=2 | Optional in XML | 100% |
| `test_pdf417_barcode_generated` | PDF417 barcode creation | xml content | Valid barcode | 90% |
| `test_firma_digital_aplicada` | Digital signature applied | signed=True | Signature node present | 90% |

#### Library Integration

**File:** `addons/localization/l10n_cl_dte/libs/dte52_generator.py`

```python
# Core generator function
def generate_dte52_xml(
    encabezado: Dict,
    detalles: List[Dict],
    transporte: Dict,
    firma_digital: str = None
) -> str:
    """
    Generate DTE 52 XML according to SII format v3.3

    Args:
        encabezado: Header with RUT, folio, dates
        detalles: List of product details
        transporte: Transport info (tipo_traslado, etc)
        firma_digital: Optional digital signature

    Returns:
        str: Valid XML string
    """
```

#### Code Pattern

```python
@tagged('unit', 'dte52', 'generator')
class TestDTE52Generator(TransactionCase):

    def setUp(self):
        super().setUp()
        from addons.localization.l10n_cl_dte.libs.dte52_generator import (
            generate_dte52_xml
        )
        self.generate_dte52 = generate_dte52_xml

    def test_generate_xml_estructura_correcta(self):
        """Verify XML structure matches SII spec"""
        encabezado = {
            'RUT_EMISOR': '12345678-9',
            'TIPO_DTE': 52,
            'FOLIO': 1,
            'FECHA_EMISION': '2025-01-15',
            'FECHA_VENCIMIENTO': '2025-02-15',
        }

        detalles = [{
            'NRO_LINEA': 1,
            'CANTIDAD': 10,
            'UNIDAD_MEDIDA': 'unidad',
            'DESCRIPCION': 'Producto Test',
            'PRECIO': 100000,
        }]

        transporte = {
            'TIPO_TRASLADO': '1',
            'RUT_TRANSPORTISTA': '11111111-1',
        }

        xml = self.generate_dte52(encabezado, detalles, transporte)

        # Verify XML structure
        self.assertIn('<?xml', xml)
        self.assertIn('<DTE', xml)
        self.assertIn('<ENCABEZADO', xml)
        self.assertIn('<DETALLES', xml)
        self.assertIn('<TRANSPORTE', xml)

        # Verify it's parseable
        from lxml import etree
        tree = etree.fromstring(xml.encode('utf-8'))
        self.assertIsNotNone(tree)

    def test_traslado_type_venta(self):
        """Verify venta (1) transport type"""
        transporte = {'TIPO_TRASLADO': '1'}
        xml = self.generate_dte52(self.encabezado, self.detalles, transporte)

        self.assertIn('<TIPO_TRASLADO>1</TIPO_TRASLADO>', xml)

    def test_all_traslado_types(self):
        """All 8 transport types must be valid"""
        valid_types = ['1', '2', '3', '4', '5', '6', '7', '8']

        for tipo in valid_types:
            with self.subTest(tipo_traslado=tipo):
                transporte = {'TIPO_TRASLADO': tipo}
                xml = self.generate_dte52(
                    self.encabezado,
                    self.detalles,
                    transporte
                )

                self.assertIn(f'<TIPO_TRASLADO>{tipo}</TIPO_TRASLADO>', xml)

    def test_pdf417_barcode_generated(self):
        """Verify PDF417 barcode generation"""
        xml = self.generate_dte52(
            self.encabezado,
            self.detalles,
            self.transporte,
            include_barcode=True
        )

        # PDF417 barcode embedded
        self.assertIn('<TED_BARCODE', xml)

        # Verify barcode is valid base64
        import base64
        barcode_match = re.search(r'<TED_BARCODE>(.*?)</TED_BARCODE>', xml)
        if barcode_match:
            barcode_data = barcode_match.group(1)
            try:
                base64.b64decode(barcode_data)
            except:
                self.fail("Invalid base64 in barcode")
```

**Coverage Target:** >90%

---

## 2. Unit Tests - Odoo Integration

### Test Class: `TestStockPickingDTE52`

**File:** `addons/localization/l10n_cl_dte/tests/test_stock_picking_dte52.py`

#### Core Integration Tests

| Test Name | Description | Expected Result | Coverage |
|-----------|-------------|------------------|----------|
| `test_generate_dte52_on_validate` | Auto-generate on picking validate | DTE XML created | 100% |
| `test_generate_dte52_delivery` | Sales delivery workflow | Valid DTE 52 | 100% |
| `test_generate_dte52_internal` | Internal transfer workflow | Valid DTE 52 | 100% |
| `test_generate_dte52_return` | Return to vendor workflow | Valid DTE 52 | 100% |
| `test_validation_no_moves` | Block if no delivery moves | ValidationError | 100% |
| `test_validation_partner_no_vat` | Block if partner missing VAT | ValidationError | 100% |
| `test_folio_sequence_no_duplicates` | Folio numbers non-sequential | All unique | 100% |
| `test_folio_auto_increment` | Folio auto-increments | seq+1 | 100% |
| `test_dte52_caf_validation` | CAF certificate required | ValidationError if missing | 100% |
| `test_dte52_signature_applied` | Digital signature applied | Signature block present | 100% |

#### Workflow Tests

**Test 1: Venta Simple**

```
Employee creates sales order:
- Partner: ABC Corp (RUT 76.123.456-7)
- Product: Item qty 10
- Delivery date: 2025-01-15

Flow:
1. Create sales order
2. Confirm sale
3. Create stock picking (auto)
4. Validate picking
5. DTE 52 auto-generated

Verify:
- Picking state = done
- DTE 52 XML created
- tipo_traslado = 1 (venta)
- Folio assigned
- Partner VAT in header
```

**Test 2: Transferencia Interna**

```
Internal warehouse transfer:
- From: Warehouse A
- To: Warehouse B
- Items: 5 units

Verify:
- DTE 52 created
- tipo_traslado = 2 (interno)
- RUT transport = company RUT
```

**Test 3: Devolución**

```
Return from customer:
- Original picking: DTE52-001
- Reason: Damage
- Items: 3 units

Verify:
- DTE 52 created for return
- tipo_traslado = 3 (devolucion)
- Reference to original DTE
```

#### Code Pattern

```python
@tagged('post_install', '-at_install', 'dte52', 'integration')
class TestStockPickingDTE52(TransactionCase):

    def setUp(self):
        super().setUp()
        self.partner = self._create_partner('ABC Corp', vat='76.123.456-7')
        self.product = self._create_product('Test Item')

    def test_generate_dte52_on_validate(self):
        """DTE 52 auto-generates when picking is validated"""
        order = self.env['sale.order'].create({
            'partner_id': self.partner.id,
            'order_line': [(0, 0, {
                'product_id': self.product.id,
                'product_qty': 10,
                'price_unit': 100000,
            })]
        })

        order.action_confirm()

        picking = order.picking_ids[0]
        self.assertEqual(picking.state, 'assigned')

        # Validate picking - should trigger DTE 52 generation
        picking.action_done()

        # Check DTE 52 created
        dte52 = picking.l10n_cl_dte_52_id
        self.assertTrue(dte52, "DTE 52 should be auto-generated")
        self.assertIsNotNone(dte52.xml_content)
        self.assertEqual(dte52.tipo_traslado, '1')  # Venta

    def test_validation_partner_no_vat(self):
        """Picking validation blocked if partner has no VAT"""
        bad_partner = self._create_partner('No VAT Corp', vat=False)

        order = self.env['sale.order'].create({
            'partner_id': bad_partner.id,
            'order_line': [(0, 0, {
                'product_id': self.product.id,
                'product_qty': 5,
            })]
        })

        order.action_confirm()
        picking = order.picking_ids[0]

        with self.assertRaises(ValidationError) as ctx:
            picking.action_done()

        self.assertIn('VAT', str(ctx.exception))

    def test_folio_sequence_no_duplicates(self):
        """Folio numbers never duplicate"""
        order1 = self._create_sale_order(self.partner, self.product, 10)
        order1.action_confirm()
        picking1 = order1.picking_ids[0]
        picking1.action_done()

        folio1 = picking1.l10n_cl_dte_52_id.folio

        order2 = self._create_sale_order(self.partner, self.product, 5)
        order2.action_confirm()
        picking2 = order2.picking_ids[0]
        picking2.action_done()

        folio2 = picking2.l10n_cl_dte_52_id.folio

        self.assertNotEqual(folio1, folio2, "Folios must be unique")
        self.assertEqual(folio2, folio1 + 1, "Folios must be sequential")

    def test_dte52_signature_applied(self):
        """Digital signature applied to DTE 52"""
        order = self._create_sale_order(self.partner, self.product, 10)
        order.action_confirm()
        picking = order.picking_ids[0]
        picking.action_done()

        dte52 = picking.l10n_cl_dte_52_id
        self.assertIn('<FIRMA>', dte52.xml_content)
        self.assertIn('</FIRMA>', dte52.xml_content)
```

**Coverage Target:** >90%

---

## 3. Integration Tests - Complete Workflow

### Test Class: `TestDTE52Workflow`

**File:** `addons/localization/l10n_cl_dte/tests/test_dte52_workflow_integration.py`

#### Scenario 1: End-to-End Venta

**Test Name:** `test_workflow_completo_venta_con_dte52`

```
Timeline:
1. T0: Create sales order (SO-001)
   - 100 items Product A @ $10,000
   - Partner: ABC Corp (RUT 76.123.456-7)

2. T1: Confirm sales order
   - Pick/pack operations created

3. T2: Process picking
   - Update quantities (if needed)

4. T3: Validate picking
   - DTE 52 auto-generated
   - tipo_traslado = 1 (venta)
   - Folio assigned: 1

5. T4: Send to SII (mock)
   - XML signed
   - Submitted to SII
   - Status tracked

Verify:
- Order state: confirmed → shipped
- Picking state: assigned → done
- DTE 52 state: draft → accepted → sent
- XML valid against XSD
- All fields populated correctly
```

**Assertions:**
```python
def test_workflow_completo_venta_con_dte52(self):
    """Complete workflow: SO → Picking → DTE 52 → SII"""

    # 1. Create and confirm
    order = self._create_sale_order(self.partner, self.product, 100)
    order.action_confirm()
    self.assertEqual(order.state, 'sale')

    # 2. Get picking
    picking = order.picking_ids[0]
    self.assertEqual(picking.state, 'assigned')

    # 3. Validate (triggers DTE 52 generation)
    picking.action_done()
    self.assertEqual(picking.state, 'done')

    # 4. Check DTE 52 created
    dte52 = picking.l10n_cl_dte_52_id
    self.assertTrue(dte52)
    self.assertEqual(dte52.state, 'draft')

    # 5. Verify XML valid
    from lxml import etree
    tree = etree.fromstring(dte52.xml_content.encode('utf-8'))
    self.assertIsNotNone(tree)

    # 6. Send to SII (mock)
    with patch('requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '''
            <RecepcionEnvioResponse>
                <RecepcionEnvioResult>
                    <TRACKID>123456789</TRACKID>
                    <STATUS>0</STATUS>
                </RecepcionEnvioResult>
            </RecepcionEnvioResponse>
        '''
        mock_post.return_value = mock_response

        dte52.action_send_to_sii()
        self.assertEqual(dte52.state, 'sent')
        self.assertEqual(dte52.sii_track_id, '123456789')
```

#### Scenario 2: Bulk Processing (646 Pickings)

**Test Name:** `test_646_pickings_retroactive_processing`

```
Scenario: Process 646 historical pickings (pre-DTE52) in batch

Goal: Demonstrate retroactive document generation capability

Process:
1. Load 646 pickings from data fixture
2. Validate each (no VAT errors, proper partner)
3. Auto-generate DTE 52 for each
4. Verify all successful
5. Check folio sequence integrity
6. Performance: <30 seconds for full batch

Verify:
- 646 DTE 52s created
- Folios: 1 to 646 (no gaps)
- All XML valid
- All signed
- No duplicates
- Batch processed in <30s
```

**Code Pattern:**
```python
@tagged('post_install', '-at_install', 'dte52', 'integration', 'smoke')
class TestDTE52Workflow(TransactionCase):

    def test_646_pickings_retroactive_processing(self):
        """Process 646 historical pickings in batch"""
        import time

        # Load test data
        self.env['ir.model.data'].load_data(
            'l10n_cl_dte',
            'tests/fixtures/dte52_646_pickings.xml'
        )

        pickings = self.env['stock.picking'].search([
            ('l10n_cl_dte_52_id', '=', False)
        ], limit=646)

        self.assertEqual(len(pickings), 646)

        # Process in batch
        start = time.time()

        for i, picking in enumerate(pickings):
            picking.action_done()

            if (i + 1) % 100 == 0:
                print(f"Processed {i+1}/646 pickings")

        duration = time.time() - start

        # Verify results
        dte52s = self.env['l10n_cl.dte'].search([
            ('tipo_dte', '=', 52),
        ])

        self.assertEqual(len(dte52s), 646)

        # Check folio integrity
        folios = sorted([d.folio for d in dte52s])
        for i, folio in enumerate(folios):
            self.assertEqual(folio, i + 1, f"Folio gap at position {i}")

        # Performance check
        self.assertLess(duration, 30.0, "Batch must complete in <30 seconds")

        print(f"Processed 646 pickings in {duration:.1f}s ({duration/646*1000:.0f}ms per item)")
```

**Coverage Target:** >90%

---

## 4. XSD Validation Tests

### Test Class: `TestDTE52XSDValidation`

**File:** `addons/localization/l10n_cl_dte/tests/test_dte52_xsd_validation.py`

#### XSD Conformance

**Test Name:** `test_xml_valido_contra_xsd_sii`

```python
@tagged('dte52', 'xsd', 'validation')
class TestDTE52XSDValidation(TransactionCase):

    def setUp(self):
        super().setUp()
        # Load SII XSD for DTE 52
        xsd_path = (
            '/Users/pedro/Documents/odoo19/addons/localization/'
            'l10n_cl_dte/libs/xsd/DTEv33.xsd'
        )
        self.xsd_doc = etree.parse(xsd_path)
        self.xsd_validator = etree.XMLSchema(self.xsd_doc)

    def test_xml_valido_contra_xsd_sii(self):
        """Generated XML validates against SII XSD"""
        picking = self._create_picking_with_dte52()

        dte52 = picking.l10n_cl_dte_52_id
        xml_tree = etree.fromstring(dte52.xml_content.encode('utf-8'))

        # Validate against XSD
        is_valid = self.xsd_validator.validate(xml_tree)

        if not is_valid:
            errors = self.xsd_validator.error_log
            self.fail(f"XML validation failed: {errors}")

        self.assertTrue(is_valid)

    def test_all_required_fields_present(self):
        """Verify all SII-required fields in XML"""
        required_fields = [
            'ENCABEZADO/RUT_EMISOR',
            'ENCABEZADO/TIPO_DTE',
            'ENCABEZADO/FOLIO',
            'ENCABEZADO/FECHA_EMISION',
            'DETALLES/DETALLE/NRO_LINEA',
            'DETALLES/DETALLE/CANTIDAD',
            'TRANSPORTE/TIPO_TRASLADO',
        ]

        dte52 = self._create_dte52_with_full_data()
        xml_tree = etree.fromstring(dte52.xml_content.encode('utf-8'))

        namespaces = {'': 'http://www.sii.cl/SiiDte'}

        for field_path in required_fields:
            element = xml_tree.xpath(f'.//{field_path}', namespaces=namespaces)
            self.assertTrue(element, f"Missing required field: {field_path}")
```

**Coverage Target:** 100%

---

## 5. Performance Tests

### Test Class: `TestDTE52Performance`

**File:** `addons/localization/l10n_cl_dte/tests/test_dte52_performance.py`

#### Performance Benchmarks

| Scenario | Threshold | Metric |
|----------|-----------|--------|
| Single DTE 52 generation | <2 seconds | p95 latency |
| 10 pickings in batch | <5 seconds | Total time |
| 100 pickings in batch | <30 seconds | Total time |
| XML signing | <1 second | Per DTE |
| SII submission (mock) | <5 seconds | Per submission |

**Code Pattern:**

```python
@tagged('performance', 'dte52')
class TestDTE52Performance(TransactionCase):

    def test_generacion_dte52_latency_2_segundos(self):
        """Single DTE 52 generation must be <2 seconds"""
        import time

        order = self._create_sale_order(self.partner, self.product, 100)
        order.action_confirm()
        picking = order.picking_ids[0]

        start = time.time()
        picking.action_done()  # Triggers DTE 52 generation
        duration = time.time() - start

        # Must complete in <2 seconds
        self.assertLess(
            duration, 2.0,
            f"DTE 52 generation took {duration:.2f}s, must be <2s"
        )

    def test_100_pickings_batch_performance(self):
        """Process 100 pickings in <30 seconds"""
        import time

        # Create 100 orders
        orders = [
            self._create_sale_order(self.partner, self.product, 10)
            for _ in range(100)
        ]

        # Confirm all
        for order in orders:
            order.action_confirm()

        pickings = self.env['stock.picking'].search([
            ('id', 'in', [o.picking_ids[0].id for o in orders])
        ])

        start = time.time()

        for picking in pickings:
            picking.action_done()

        duration = time.time() - start

        self.assertLess(
            duration, 30.0,
            f"Batch of 100 took {duration:.1f}s, must be <30s"
        )

        avg_per_item = (duration / 100) * 1000
        print(f"Average: {avg_per_item:.0f}ms per DTE 52")
```

**Coverage Target:** 90%

---

## 6. Test Execution & Coverage

### Running Tests

**All FASE 1 tests:**
```bash
cd /Users/pedro/Documents/odoo19

# Run all DTE 52 tests
pytest addons/localization/l10n_cl_dte/tests/test_dte52*.py \
    -v \
    --cov=addons/localization/l10n_cl_dte \
    --cov-report=html

# Run by category
pytest addons/localization/l10n_cl_dte/tests/test_dte52*.py -m "unit" -v
pytest addons/localization/l10n_cl_dte/tests/test_dte52*.py -m "integration" -v
pytest addons/localization/l10n_cl_dte/tests/test_dte52*.py -m "performance" -v

# Run XSD validation only
pytest addons/localization/l10n_cl_dte/tests/test_dte52_xsd_validation.py -v
```

### Coverage Goals

| Area | Target | Method |
|------|--------|--------|
| Generator library | >90% | Unit tests |
| Odoo integration | >90% | Unit + Integration |
| XML generation | 100% | XSD validation |
| Performance | 100% | Benchmark tests |

---

## 7. Smoke Test Suite

### Critical Path Tests

**Test Name:** `test_smoke_dte52_complete_workflow`

```python
@tagged('smoke', 'critical', 'dte52')
def test_smoke_dte52_complete_workflow(self):
    """Smoke test: DTE 52 complete workflow in 2 minutes"""

    # 1. Login
    self.assertTrue(self.env.user.id > 0)

    # 2. Create sales order
    order = self._create_sale_order(self.partner, self.product, 100)
    self.assertTrue(order.id)

    # 3. Confirm
    order.action_confirm()
    self.assertEqual(order.state, 'sale')

    # 4. Validate picking
    picking = order.picking_ids[0]
    picking.action_done()
    self.assertEqual(picking.state, 'done')

    # 5. Verify DTE 52 created
    dte52 = picking.l10n_cl_dte_52_id
    self.assertTrue(dte52)
    self.assertIsNotNone(dte52.xml_content)

    # 6. Verify XML valid
    from lxml import etree
    tree = etree.fromstring(dte52.xml_content.encode('utf-8'))
    self.assertIsNotNone(tree)

    print("✓ Smoke test PASSED: DTE 52 workflow complete")
```

**Expected Result:** PASS in <120 seconds

---

## 8. Acceptance Criteria

### Phase 1 Sign-Off

- [ ] **Unit Tests:** All 30+ tests PASS
  - Generator: 10/10 tests
  - Odoo integration: 10/10 tests
  - Validations: 5+ tests
  - Performance: 4/4 benchmarks

- [ ] **Integration Tests:** 3+ scenarios PASS
  - Complete venta workflow
  - 646 pickings batch processing
  - Retroactive document generation

- [ ] **XSD Validation:** 100% PASS
  - All generated XML valid against SII XSD
  - All required fields present
  - No schema violations

- [ ] **Performance:** All benchmarks met
  - Single generation: <2 seconds
  - Batch (100): <30 seconds
  - Batch (646): <5 minutes

- [ ] **Coverage:** >90%
  - Generator library: 90%+
  - Odoo integration: 90%+
  - Critical paths: 100%

- [ ] **Smoke Tests:** 100% PASS
  - Critical workflow in <2 minutes
  - All manual steps verify correctly

### Failure Handling

If ANY test fails:
1. Analyze failure cause
2. Fix code or test
3. Re-run full suite
4. Verify regression-free

---

## 9. References & Documentation

### Related Documents

- `docs/testing/TEST_STRATEGY_FASE0_PAYROLL.md` - Prerequisite phase
- `docs/testing/AUTOMATION_ROADMAP.md` - Timeline
- `docs/testing/COVERAGE_REPORT_TEMPLATE.md` - Reporting

### SII DTE 52 Resources

- **SII Manual:** DTEv33 Specification
- **XSD Schema:** `/addons/.../libs/xsd/DTEv33.xsd`
- **Error Codes:** `/addons/.../libs/sii_error_codes.py` (59 codes documented)

---

**Last Updated:** 2025-11-08 | **Phase:** 1 (DTE 52) | **Status:** Ready for Execution
