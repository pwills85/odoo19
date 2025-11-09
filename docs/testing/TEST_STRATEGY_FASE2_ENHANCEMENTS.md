# Test Strategy - FASE 2: Enhancements (BHE + Reports)

**Status:** Enterprise Quality | **Owner:** QA Lead | **Updated:** 2025-11-08

---

## Executive Summary

Test strategy for FASE 2 covering Boletas de Honorarios Electrónicas (BHE) reception and financial reports (Libro Compras, Libro Ventas, F29). These enhancements build on completed FASE 0 (payroll) and FASE 1 (DTE 52) foundations.

**Target Coverage:** >90% | **Test Cases:** 25+ | **Execution Time:** <8min | **Success Criteria:** 0 failures + export validation

---

## 1. Unit Tests - BHE (Boletas de Honorarios Electrónicas)

### Test Class: `TestBHEReception`

**File:** `addons/localization/l10n_cl_dte/tests/test_bhe_reception_unit.py`

#### Core BHE Tests

| Test Name | Description | Input | Expected | Coverage |
|-----------|-------------|-------|----------|----------|
| `test_bhe_reception_create_move` | Receive BHE creates account.move | BHE invoice | Invoice in draft | 100% |
| `test_bhe_validation_folio_duplicate` | Block if BHE folio duplicated | Same folio, same prof | ValidationError | 100% |
| `test_bhe_auto_retention_14_5_percent` | Auto-calculate 14.5% retention | $1M BHE | $145K retention | 100% |
| `test_bhe_retention_tasa_vigente` | Use vigente rate for date | Date 2020-06-15 | 10.75% rate | 100% |
| `test_bhe_wizard_ingreso_manual` | Manual BHE entry via wizard | Wizard form | BHE record created | 100% |
| `test_bhe_validation_profesional_rut` | Validate professional RUT | Invalid RUT | ValidationError | 100% |
| `test_bhe_liquidation_calc` | Verify monto_liquido = bruto - retention | $1M - $145K | $855K | 100% |

#### Historical Retention Rates

**Code Pattern:**

```python
@tagged('post_install', '-at_install', 'bhe', 'unit')
class TestBHEReception(TransactionCase):

    def setUp(self):
        super().setUp()
        self.BHEModel = self.env['l10n_cl.boleta_honorarios']
        self.TasaModel = self.env['l10n_cl.retencion_iue.tasa']
        self.partner = self._create_professional('Dr. Juan López', '12345678-9')

    def test_bhe_auto_retention_14_5_percent(self):
        """BHE 2025: Auto-calculate 14.5% retention"""
        bhe = self.BHEModel.create({
            'numero_boleta': 'BHE-001',
            'fecha_emision': date(2025, 1, 15),
            'profesional_id': self.partner.id,
            'monto_bruto': 1000000,
        })

        # System auto-calculates:
        # - Tasa vigente 2025: 14.5%
        # - Monto retención: 145,000
        # - Monto líquido: 855,000

        self.assertEqual(bhe.tasa_retencion, 14.5)
        self.assertAlmostEqual(bhe.monto_retencion, 145000, delta=1000)
        self.assertAlmostEqual(bhe.monto_liquido, 855000, delta=1000)

    def test_bhe_retention_tasa_vigente(self):
        """Use correct retention rate for date"""
        # Test historical rates
        test_cases = [
            (date(2018, 6, 15), 10.0),      # 2018
            (date(2020, 1, 1), 10.75),      # 2020
            (date(2022, 1, 1), 11.5),       # 2022
            (date(2024, 1, 1), 14.0),       # 2024
            (date(2025, 1, 1), 14.5),       # 2025
        ]

        for fecha, expected_rate in test_cases:
            with self.subTest(fecha=fecha, rate=expected_rate):
                bhe = self.BHEModel.create({
                    'numero_boleta': f'BHE-{fecha.year}',
                    'fecha_emision': fecha,
                    'profesional_id': self.partner.id,
                    'monto_bruto': 1000000,
                })

                self.assertEqual(
                    bhe.tasa_retencion, expected_rate,
                    f"Tasa for {fecha} should be {expected_rate}%"
                )

    def test_bhe_validation_folio_duplicate(self):
        """Block duplicate BHE from same professional"""
        self.BHEModel.create({
            'numero_boleta': 'BHE-001',
            'fecha_emision': date(2025, 1, 15),
            'profesional_id': self.partner.id,
            'monto_bruto': 1000000,
        })

        with self.assertRaises(IntegrityError):
            self.BHEModel.create({
                'numero_boleta': 'BHE-001',  # Duplicate!
                'fecha_emision': date(2025, 1, 20),
                'profesional_id': self.partner.id,
                'monto_bruto': 2000000,
            })

    def test_bhe_wizard_ingreso_manual(self):
        """Manual BHE entry via wizard"""
        wizard = self.env['bhe.wizard.ingreso'].create({
            'numero_boleta': 'BHE-MANUAL-001',
            'fecha_emision': date(2025, 1, 15),
            'profesional_id': self.partner.id,
            'monto_bruto': 1500000,
            'razon_ingreso': 'Honorarios consultoría',
        })

        bhe = wizard.action_create_bhe()

        self.assertTrue(bhe)
        self.assertEqual(bhe.numero_boleta, 'BHE-MANUAL-001')
        self.assertEqual(bhe.monto_bruto, 1500000)
        self.assertAlmostEqual(bhe.monto_retencion, 217500, delta=1000)

    def test_bhe_reception_create_move(self):
        """BHE reception creates account.move"""
        bhe = self.BHEModel.create({
            'numero_boleta': 'BHE-001',
            'fecha_emision': date(2025, 1, 15),
            'profesional_id': self.partner.id,
            'monto_bruto': 1000000,
        })

        bhe.action_validated()

        # Should create supplier invoice
        moves = self.env['account.move'].search([
            ('partner_id', '=', self.partner.id),
            ('move_type', '=', 'in_invoice'),
            ('ref', 'like', 'BHE-001'),
        ])

        self.assertTrue(moves, "BHE should create account.move")
```

**Coverage Target:** 100%

---

## 2. Unit Tests - Retention IUE Rates

### Test Class: `TestRetentionIUERates`

**File:** `addons/localization/l10n_cl_dte/tests/test_retencion_iue_rates.py`

#### Historical Rate Validation

**Test Data:**

```
Year  | Rate  | Effective From | Reference
------|-------|----------------|----------
2018  | 10.0% | 2018-01-01     | Initial
2019  | 10.75%| 2019-01-01     | Increase
2020  | 10.75%| 2020-01-01     | Maintained
2021  | 10.75%| 2021-01-01     | Maintained
2022  | 11.5% | 2022-01-01     | Increase
2023  | 13.5% | 2023-01-01     | Increase
2024  | 14.0% | 2024-01-01     | Increase
2025  | 14.5% | 2025-01-01     | Increase (Reforma)
```

**Code Pattern:**

```python
@tagged('post_install', '-at_install', 'bhe', 'retention')
class TestRetentionIUERates(TransactionCase):

    def setUp(self):
        super().setUp()
        self.TasaModel = self.env['l10n_cl.retencion_iue.tasa']

    def test_retention_rates_data_loaded(self):
        """All historical rates loaded from XML"""
        expected_rates = [
            ('2018-01-01', 10.0),
            ('2019-01-01', 10.75),
            ('2022-01-01', 11.5),
            ('2024-01-01', 14.0),
            ('2025-01-01', 14.5),
        ]

        for fecha_str, expected_rate in expected_rates:
            fecha = date.fromisoformat(fecha_str)

            tasa = self.TasaModel.search([
                ('valid_from', '=', fecha)
            ], limit=1)

            self.assertTrue(
                tasa,
                f"Retention rate for {fecha} not found"
            )
            self.assertEqual(
                tasa.rate, expected_rate,
                f"Rate for {fecha} should be {expected_rate}%"
            )

    def test_get_tasa_vigente_current(self):
        """Get current (2025) retention rate"""
        tasa_actual = self.TasaModel.get_tasa_vigente()

        self.assertEqual(tasa_actual.rate, 14.5)
        self.assertTrue(tasa_actual.valid_from <= date.today())

    def test_get_tasa_vigente_historical(self):
        """Get retention rate for historical date"""
        tasa_2020 = self.TasaModel.get_tasa_vigente(fecha=date(2020, 6, 15))
        self.assertEqual(tasa_2020.rate, 10.75)

        tasa_2022 = self.TasaModel.get_tasa_vigente(fecha=date(2022, 6, 15))
        self.assertEqual(tasa_2022.rate, 11.5)

    def test_no_solapamiento_periodos(self):
        """No overlapping rate periods"""
        tasas = self.TasaModel.search([])

        for i in range(len(tasas) - 1):
            current = tasas[i]
            next_tasa = tasas[i + 1]

            # Current should not have valid_until if next exists
            if next_tasa:
                self.assertFalse(
                    current.valid_until or next_tasa.valid_from <= current.valid_from,
                    "Overlapping rate periods detected"
                )
```

**Coverage Target:** 100%

---

## 3. Unit Tests - Financial Reports (F29, F22)

### Test Class: `TestFinancialReports`

**File:** `addons/localization/l10n_cl_financial_reports/tests/test_reports_unit.py`

#### F29 (RLIQ) Export Tests

| Test Name | Description | Expected | Coverage |
|-----------|-------------|----------|----------|
| `test_libro_compras_csv_formato` | Libro Compras CSV format correct | Valid CSV | 100% |
| `test_libro_ventas_csv_formato` | Libro Ventas CSV format correct | Valid CSV | 100% |
| `test_f29_export_correcto` | F29 export correct structure | Valid F29 | 100% |
| `test_f29_fecha_inicio_vigencia` | F29 period dates correct | From/To correct | 100% |
| `test_f29_consolidacion_dtes` | F29 consolidates DTEs correctly | Sum matches | 100% |
| `test_f29_consolidacion_nomina` | F29 consolidates payroll correctly | Sum matches | 100% |

**Code Pattern:**

```python
@tagged('post_install', '-at_install', 'reports', 'f29')
class TestFinancialReports(TransactionCase):

    def setUp(self):
        super().setUp()
        self.CompanyModel = self.env['res.company']
        self.LibroModel = self.env['account.move.libro']

    def test_libro_compras_csv_formato(self):
        """Libro Compras export in correct CSV format"""
        # Create test invoices
        invoices = self._create_purchase_invoices(5)

        # Generate Libro Compras
        libro = self.env['account.move.libro'].create({
            'name': 'Libro Compras 2025-01',
            'tipo_libro': 'compras',
            'fecha_desde': date(2025, 1, 1),
            'fecha_hasta': date(2025, 1, 31),
        })

        csv_content = libro.export_as_csv()

        # Verify CSV format
        lines = csv_content.strip().split('\n')
        self.assertGreater(len(lines), 1, "CSV should have header + data rows")

        # Verify header
        header = lines[0].split(',')
        expected_headers = [
            'TIPO_DOC', 'FOLIO', 'FECHA', 'RUT_PROVEEDOR',
            'MONTO_NETO', 'IVA', 'MONTO_TOTAL'
        ]
        for exp_header in expected_headers:
            self.assertIn(exp_header, header)

        # Verify data rows match
        self.assertEqual(len(lines) - 1, len(invoices))

    def test_f29_export_correcto(self):
        """F29 export with correct structure"""
        # Create test data
        invoices = self._create_sales_invoices(10)
        payslips = self._create_payslips(5)

        # Create F29
        f29 = self.env['account.move.f29'].create({
            'name': 'F29 2025-01',
            'fecha_desde': date(2025, 1, 1),
            'fecha_hasta': date(2025, 1, 31),
            'company_id': self.env.company.id,
        })

        f29.action_calculate()

        # Export
        export_data = f29.export_for_sii()

        # Verify structure
        self.assertIn('HEADER', export_data)
        self.assertIn('DTES', export_data)
        self.assertIn('RETENCIONES', export_data)
        self.assertIn('FOOTER', export_data)

        # Verify calculations
        self.assertEqual(
            export_data['DTES']['total_neto'],
            sum(inv.amount_untaxed for inv in invoices),
            "F29 DTE neto should match invoice sum"
        )

    def test_f29_consolidacion_dtes(self):
        """F29 consolidates DTEs correctly"""
        # Create 3 sales DTEs
        dte33_1 = self._create_dte(tipo_dte=33, monto=1000000)
        dte33_2 = self._create_dte(tipo_dte=33, monto=2000000)
        dte56 = self._create_dte(tipo_dte=56, monto=-500000)

        f29 = self.env['account.move.f29'].create({
            'fecha_desde': date(2025, 1, 1),
            'fecha_hasta': date(2025, 1, 31),
        })
        f29.action_calculate()

        # Verify consolidation
        dte33_total = f29.dte33_total + f29.dte34_total  # Facturas
        dte56_total = f29.dte56_total  # Notas débito

        self.assertEqual(dte33_total, 3000000)
        self.assertEqual(dte56_total, 500000)
```

**Coverage Target:** >90%

---

## 4. Integration Tests

### Test Class: `TestEnhancementsIntegration`

**File:** `addons/localization/l10n_cl_financial_reports/tests/test_enhancements_integration.py`

#### Scenario 1: BHE → Contabilidad → F29

**Test Name:** `test_bhe_to_f29_integration`

```
Flow:
1. Receive BHE from professional (honorarios)
2. System auto-calculates retention (14.5%)
3. Creates supplier invoice (account.move)
4. F29 consolidates in retenciones section
5. Export shows totals correctly

Verify:
- BHE recorded
- Invoice created with retention
- F29 includes retention amount
- CSV export correct
```

**Code Pattern:**

```python
@tagged('post_install', '-at_install', 'integration', 'bhe_f29')
class TestEnhancementsIntegration(TransactionCase):

    def test_bhe_to_f29_integration(self):
        """BHE reception flows through to F29 consolidation"""
        # 1. Create professional partner
        professional = self._create_professional(
            'Consultora ABC', '12345678-9'
        )

        # 2. Receive BHE
        bhe = self.env['l10n_cl.boleta_honorarios'].create({
            'numero_boleta': 'BHE-001',
            'fecha_emision': date(2025, 1, 15),
            'profesional_id': professional.id,
            'monto_bruto': 1000000,
        })

        # System auto-calculates:
        # - Tasa: 14.5%
        # - Retención: 145,000
        # - Líquido: 855,000

        self.assertEqual(bhe.tasa_retencion, 14.5)
        self.assertAlmostEqual(bhe.monto_retencion, 145000, delta=1000)

        # 3. Validate (creates invoice)
        bhe.action_validated()

        moves = self.env['account.move'].search([
            ('partner_id', '=', professional.id),
            ('move_type', '=', 'in_invoice'),
        ])

        self.assertTrue(moves)
        move = moves[0]

        # Invoice should reflect net amount with retention
        self.assertAlmostEqual(
            move.amount_total, 855000, delta=1000
        )

        # 4. Create F29 including this BHE
        f29 = self.env['account.move.f29'].create({
            'fecha_desde': date(2025, 1, 1),
            'fecha_hasta': date(2025, 1, 31),
        })
        f29.action_calculate()

        # 5. Verify F29 includes retention
        self.assertIn(bhe.id, f29.bhe_ids.ids)
        self.assertAlmostEqual(
            f29.retencion_iue_total, 145000, delta=1000
        )

        # 6. Export and verify
        csv_content = f29.export_as_csv()
        self.assertIn('145000', csv_content)

        print("✓ BHE → F29 integration test PASSED")
```

#### Scenario 2: Complete Monthly Report

**Test Name:** `test_monthly_complete_report_f29_f22`

```
Scenario: Generate complete monthly reports

Data:
- 20 sales invoices (DTEs 33/34)
- 5 debit notes (DTE 56)
- 2 credit notes (DTE 61)
- 10 BHEs received
- 50 payslips processed

Expected:
- Libro Compras: 10 entries
- Libro Ventas: 27 entries
- F29: Complete consolidation
- F22: Manual supplement (if needed)
- No discrepancies
```

**Code Pattern:**

```python
def test_monthly_complete_report_f29_f22(self):
    """Complete monthly report generation"""
    # Setup test data
    self._create_monthly_test_data()

    # Generate all reports for period
    period_start = date(2025, 1, 1)
    period_end = date(2025, 1, 31)

    # 1. Libro Compras
    libro_compras = self.env['account.move.libro'].create({
        'tipo_libro': 'compras',
        'fecha_desde': period_start,
        'fecha_hasta': period_end,
    })
    libro_compras.action_calculate()
    self.assertEqual(libro_compras.move_count, 10)

    # 2. Libro Ventas
    libro_ventas = self.env['account.move.libro'].create({
        'tipo_libro': 'ventas',
        'fecha_desde': period_start,
        'fecha_hasta': period_end,
    })
    libro_ventas.action_calculate()
    self.assertEqual(libro_ventas.move_count, 27)

    # 3. F29
    f29 = self.env['account.move.f29'].create({
        'fecha_desde': period_start,
        'fecha_hasta': period_end,
    })
    f29.action_calculate()

    # Verify consolidation
    total_debit = f29.dte33_total + f29.dte56_total
    total_credit = f29.dte61_total
    net_total = total_debit - total_credit

    self.assertGreater(net_total, 0)

    # 4. Export all
    compras_csv = libro_compras.export_as_csv()
    ventas_csv = libro_ventas.export_as_csv()
    f29_export = f29.export_for_sii()

    self.assertTrue(compras_csv)
    self.assertTrue(ventas_csv)
    self.assertTrue(f29_export)

    print("✓ Monthly complete report test PASSED")
```

**Coverage Target:** >90%

---

## 5. Export Format Validation

### Test Class: `TestExportFormats`

**File:** `addons/localization/l10n_cl_financial_reports/tests/test_export_formats.py`

#### Libro Compras Format

**Test Name:** `test_libro_compras_sii_format`

```python
@tagged('reports', 'export', 'sii')
class TestExportFormats(TransactionCase):

    def test_libro_compras_sii_format(self):
        """Libro Compras export in SII official format"""
        # Create test invoices
        invoices = [
            self._create_purchase_invoice(
                partner_vat='11111111-1',
                amount=1000000,
                invoice_date=date(2025, 1, 5)
            ),
            self._create_purchase_invoice(
                partner_vat='22222222-2',
                amount=2000000,
                invoice_date=date(2025, 1, 15)
            ),
        ]

        libro = self.env['account.move.libro'].create({
            'tipo_libro': 'compras',
            'fecha_desde': date(2025, 1, 1),
            'fecha_hasta': date(2025, 1, 31),
        })
        libro.action_calculate()

        csv = libro.export_as_csv()
        lines = csv.strip().split('\n')

        # Header line
        header = lines[0]
        expected_cols = [
            'TIPO_DOCUMENTO', 'FOLIO', 'FECHA_EMISION',
            'RUT_PROVEEDOR', 'NOMBRE_PROVEEDOR',
            'MONTO_NETO', 'MONTO_IVA', 'MONTO_TOTAL',
            'REFERENCIA_DOCUMENTO', 'REFERENCIA_FOLIO'
        ]

        for col in expected_cols:
            self.assertIn(col, header)

        # Data rows (one per invoice)
        self.assertEqual(len(lines), 3)  # header + 2 invoices

        # Verify row format
        for line in lines[1:]:
            cols = line.split(',')
            self.assertGreaterEqual(len(cols), len(expected_cols))
```

**Coverage Target:** 100%

---

## 6. Test Execution & Coverage

### Running Tests

```bash
cd /Users/pedro/Documents/odoo19

# All FASE 2 tests
pytest addons/localization/l10n_cl_dte/tests/test_bhe*.py \
        addons/localization/l10n_cl_financial_reports/tests/test_*.py \
    -v \
    --cov=addons/localization/l10n_cl_dte \
    --cov=addons/localization/l10n_cl_financial_reports

# BHE only
pytest addons/localization/l10n_cl_dte/tests/test_bhe*.py -v

# Reports only
pytest addons/localization/l10n_cl_financial_reports/tests/test_*.py -v

# Integration only
pytest addons/localization/l10n_cl_financial_reports/tests/test_*integration*.py -v
```

---

## 7. Acceptance Criteria

### Phase 2 Sign-Off

- [ ] **BHE Tests:** 7/7 PASS
  - Reception, retention, validation tests
  - Historical rate validation
  - Wizard integration

- [ ] **Reports Tests:** 8+ PASS
  - Libro Compras/Ventas CSV format
  - F29 consolidation
  - Export formats

- [ ] **Integration:** 3+ scenarios PASS
  - BHE → Invoice → F29
  - Complete monthly reports
  - All exports validate

- [ ] **Coverage:** >90%
  - BHE module: 90%+
  - Financial reports: 90%+
  - Export functions: 100%

- [ ] **Export Validation:** 100% PASS
  - CSV format correct
  - All required columns
  - Data integrity verified

---

## 8. References & Documentation

- `TEST_STRATEGY_FASE0_PAYROLL.md` - Prerequisite
- `TEST_STRATEGY_FASE1_DTE52.md` - Prerequisite

---

**Last Updated:** 2025-11-08 | **Phase:** 2 (Enhancements) | **Status:** Ready for Execution
