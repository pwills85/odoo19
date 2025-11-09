# Test Strategy - FASE 0: Payroll P0

**Status:** Enterprise Quality | **Owner:** QA Lead | **Updated:** 2025-11-08

---

## Executive Summary

Test strategy for FASE 0 payroll critical rules (P0-1, P0-2, P0-3, P0-4). This phase closes fundamental gaps in Chilean payroll compliance 2025. All unit tests must pass before moving to FASE 1.

**Target Coverage:** >95% | **Test Cases:** 25+ | **Execution Time:** <5min | **Success Criteria:** 0 failures

---

## 1. Unit Tests - P0-1: AFP Cap 2025

### Test Class: `TestP0AfpCap2025`

**File:** `addons/localization/l10n_cl_hr_payroll/tests/test_p0_afp_cap_2025.py`

#### Core Tests

| Test Name | Description | Assertion | Coverage |
|-----------|-------------|-----------|----------|
| `test_afp_cap_is_831_uf_2025` | Verify AFP cap loaded correctly as 83.1 UF | cap.amount == 83.1 | 100% |
| `test_afp_cap_not_816_uf` | Ensure old incorrect value (81.6 UF) is removed | no record with 81.6 UF | 100% |
| `test_afp_cap_vigencia` | Verify effective date starts 2025-01-01 | valid_from == 2025-01-01 | 100% |
| `test_afp_cap_no_expiry` | Cap has no end date (valid_until = False) | cap.valid_until == False | 100% |

#### Regulatory References

- **Ley 20.255 Art. 17** - AFP imponible cap (UF-indexed)
- **Superintendencia de Pensiones 2025** - Annual update notification
- **Auditoría 2025-11-07** - Gap P0-1 documentation

#### Code Pattern

```python
@tagged('post_install', '-at_install', 'p0_critical', 'afp_cap')
class TestP0AfpCap2025(TransactionCase):

    def setUp(self):
        super().setUp()
        self.LegalCapsModel = self.env['l10n_cl.legal.caps']

    def test_afp_cap_is_831_uf_2025(self):
        """Verify 83.1 UF cap is loaded for 2025"""
        cap = self.LegalCapsModel.search([
            ('code', '=', 'AFP_IMPONIBLE_CAP'),
            ('valid_from', '=', date(2025, 1, 1))
        ], limit=1)

        self.assertTrue(cap, "AFP cap must exist for 2025")
        self.assertEqual(cap.amount, 83.1)
        self.assertEqual(cap.unit, 'uf')
```

**Coverage Target:** 100%

---

## 2. Unit Tests - P0-2: AFP Calculation Logic

### Test Class: `TestP0AfpCalculation`

**File:** `addons/localization/l10n_cl_hr_payroll/tests/test_p0_afp_calculation.py`

#### Core Tests

| Test Name | Description | Input | Expected | Coverage |
|-----------|-------------|-------|----------|----------|
| `test_afp_no_cap_low_salary` | Salaries < 83.1 UF: 100% of salary | $2,500,000 | 10% × $2,500K | 100% |
| `test_afp_cap_high_salary` | Salaries > 83.1 UF: cap applies | $5,000,000 | 10% × (83.1 UF equivalent) | 100% |
| `test_afp_cap_exact_boundary` | Salary = 83.1 UF: boundary condition | 83.1 UF | 10% × 83.1 UF | 100% |
| `test_afp_cap_multiple_payslips` | Multiple payslips in month | 3 payslips | Each respects cap independently | 100% |
| `test_afp_withholding_amount` | Verify withholding calculated correctly | Base $3M | (83.1 UF × rate) × 10% | 100% |

#### Business Logic

**Ley 20.255 Art. 17** - AFP contribution cap:
```
IF salary <= 83.1 UF THEN
    afp_contribution = salary × 10%
ELSE
    afp_contribution = (83.1 UF) × 10%
END IF
```

**Test Scenario 1: Low Salary**
```
Monthly salary: $2,500,000
- Below 83.1 UF (~$2,890,000 at 2025 rate)
- AFP contribution: $2,500,000 × 10% = $250,000
```

**Test Scenario 2: High Salary**
```
Monthly salary: $5,000,000
- Above 83.1 UF (~$2,890,000)
- AFP contribution: 83.1 UF × rate × 10% = ~$289,000
- Cap prevents contribution of full $500,000
```

#### Code Pattern

```python
@tagged('post_install', '-at_install', 'p0_critical', 'afp_calc')
class TestP0AfpCalculation(TransactionCase):

    def setUp(self):
        super().setUp()
        self.employee = self._create_test_employee()
        self.contract = self._create_test_contract()

    def test_afp_no_cap_low_salary(self):
        """AFP not capped for salaries below 83.1 UF"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            # salary_register = $2,500,000
        })
        payslip.compute_sheet()

        afp_line = payslip.line_ids.filtered(lambda x: x.code == 'AFP')
        self.assertAlmostEqual(afp_line.total, 250000, delta=1000)

    def test_afp_cap_high_salary(self):
        """AFP capped at 83.1 UF for high salaries"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            # salary_register = $5,000,000
        })
        payslip.compute_sheet()

        afp_line = payslip.line_ids.filtered(lambda x: x.code == 'AFP')
        # Should be ~$289,000 not $500,000
        self.assertLess(afp_line.total, 300000)
        self.assertGreater(afp_line.total, 280000)
```

**Coverage Target:** 100%

---

## 3. Unit Tests - P0-3: Reforma 2025 (APV + Cesantía)

### Test Class: `TestP0Reforma2025`

**File:** `addons/localization/l10n_cl_hr_payroll/tests/test_p0_reforma_2025.py`

#### Core Tests

| Test Name | Description | Assertion | Coverage |
|-----------|-------------|-----------|----------|
| `test_reforma_no_aplica_2024` | Contracts before 2025-01-01 excluded | reforma=False | 100% |
| `test_reforma_aplica_2025` | Contracts from 2025-01-01 included | reforma=True | 100% |
| `test_reforma_apv_05_percent` | APV contribution 0.5% | amount = salary × 0.5% | 100% |
| `test_reforma_cesantia_05_percent` | Cesantía reserve 0.5% | amount = salary × 0.5% | 100% |
| `test_reforma_apv_plus_cesantia` | Both APV + Cesantía applied together | total = 1.0% of salary | 100% |
| `test_reforma_error_without_contract` | Missing reforma flag blocks payslip | ValidationError | 100% |

#### Regulatory Context

**Reforma 2025 (Art. 50 CT modificado):**
- APV (Aporte Voluntario Pensión): 0.5% of taxable income
- Cesantía (Fondo Cesantía): 0.5% of taxable income
- Both mandatory from 2025-01-01 forward
- Only applies to NEW contracts or renewed contracts

#### Business Logic

```python
IF contract.start_date >= 2025-01-01 AND contract.type in ['open', 'fixed']:
    apv_contribution = salary × 0.5%
    cesantia_reserve = salary × 0.5%
    total_reforma = apv_contribution + cesantia_reserve
ELSE:
    # Old contracts: no reforma contribution
    apv_contribution = 0
    cesantia_reserve = 0
END IF
```

#### Code Pattern

```python
@tagged('post_install', '-at_install', 'p0_critical', 'reforma_2025')
class TestP0Reforma2025(TransactionCase):

    def test_reforma_aplica_2025(self):
        """Reforma applies to 2025+ contracts"""
        contract = self.env['hr.contract'].create({
            'employee_id': self.employee.id,
            'date_start': date(2025, 1, 15),
            'wage': 3000000,
            'type_id': self.env.ref('hr_contract.contract_type_cdd').id,
        })

        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
        })
        payslip.compute_sheet()

        # Check both APV and Cesantía lines exist
        apv_line = payslip.line_ids.filtered(lambda x: x.code == 'APV')
        cesantia_line = payslip.line_ids.filtered(lambda x: x.code == 'CESANTIA')

        self.assertTrue(apv_line, "APV line must exist for 2025+ contract")
        self.assertAlmostEqual(apv_line.total, 15000, delta=500)  # 3M × 0.5%

        self.assertTrue(cesantia_line, "Cesantía line must exist for 2025+ contract")
        self.assertAlmostEqual(cesantia_line.total, 15000, delta=500)  # 3M × 0.5%

    def test_reforma_no_aplica_2024(self):
        """Reforma does NOT apply to 2024 contracts"""
        contract = self.env['hr.contract'].create({
            'employee_id': self.employee.id,
            'date_start': date(2024, 6, 1),
            'wage': 3000000,
            'type_id': self.env.ref('hr_contract.contract_type_cdd').id,
        })

        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 1, 1),  # Even if payslip in 2025
            'date_to': date(2025, 1, 31),
        })
        payslip.compute_sheet()

        apv_line = payslip.line_ids.filtered(lambda x: x.code == 'APV')
        self.assertFalse(apv_line, "APV should not exist for pre-2025 contract")
```

**Coverage Target:** 100%

---

## 4. Integration Tests

### Test Class: `TestPayrollIntegration`

**File:** `addons/localization/l10n_cl_hr_payroll/tests/test_payroll_integration_fase0.py`

#### Scenario 1: Complete Payslip Workflow

**Test Name:** `test_payslip_completo_p0_todas_reglas`

**Scenario:**
```
Employee: Juan Pérez
Contract: 2025-01-15 (open-ended, wage $3M)
Period: 2025-01-01 to 2025-01-31

Expected Calculations:
- AFP contribution: $3M × 10% capped at 83.1 UF
- APV: $3M × 0.5%
- Cesantía: $3M × 0.5%
- All validations must pass
```

**Assertions:**
- Payslip creates successfully
- All P0 rules applied
- Total deductions = AFP + APV + Cesantía
- No validation errors blocking payslip

#### Scenario 2: Multi-Employee Batch

**Test Name:** `test_payroll_batch_10_employees_p0`

**Scenario:**
```
10 employees with different contract start dates:
- 3 with 2024 contracts (no reforma)
- 7 with 2025 contracts (with reforma)
- Various salaries (below and above AFP cap)

Expected:
- All payslips created without error
- P0 rules applied correctly per contract
- Batch processing completes in <2 seconds
```

#### Scenario 3: Previred Export Integration

**Test Name:** `test_previred_export_con_reform_p0`

**Scenario:**
```
Export 5 payslips to Previred format with P0 rules applied

Expected:
- File generates without error
- All fields correctly populated
- APV/Cesantía fields present in export
- No validation errors
```

#### Code Pattern

```python
@tagged('post_install', '-at_install', 'p0_integration')
class TestPayrollIntegration(TransactionCase):

    def test_payslip_completo_p0_todas_reglas(self):
        """Full payslip workflow with all P0 rules"""
        employee = self._create_employee('Juan Pérez')
        contract = self._create_contract(
            employee_id=employee.id,
            date_start=date(2025, 1, 15),
            wage=3000000
        )

        payslip = self.env['hr.payslip'].create({
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
        })

        # Must not raise ValidationError
        payslip.compute_sheet()
        payslip.action_payslip_done()

        # Verify all P0 rules applied
        lines_by_code = {line.code: line for line in payslip.line_ids}

        self.assertIn('AFP', lines_by_code)
        self.assertIn('APV', lines_by_code)
        self.assertIn('CESANTIA', lines_by_code)

        # Verify amounts
        self.assertAlmostEqual(lines_by_code['APV'].total, 15000, delta=500)
        self.assertAlmostEqual(lines_by_code['CESANTIA'].total, 15000, delta=500)

    def test_payroll_batch_10_employees_p0(self):
        """Test batch payroll with mixed contract dates"""
        import time

        employees = [self._create_employee(f'Emp{i}') for i in range(10)]

        # 3 with 2024 contracts
        for i in range(3):
            self._create_contract(
                employee_id=employees[i].id,
                date_start=date(2024, 6, 1),
                wage=2500000 + (i * 500000)
            )

        # 7 with 2025 contracts
        for i in range(3, 10):
            self._create_contract(
                employee_id=employees[i].id,
                date_start=date(2025, 1, 1),
                wage=2500000 + (i * 500000)
            )

        # Create and compute all payslips
        start_time = time.time()
        payslips = self.env['hr.payslip'].create([
            {
                'employee_id': emp.id,
                'contract_id': emp.contract_ids[0].id,
                'date_from': date(2025, 1, 1),
                'date_to': date(2025, 1, 31),
            }
            for emp in employees
        ])

        for payslip in payslips:
            payslip.compute_sheet()

        duration = time.time() - start_time

        self.assertEqual(len(payslips), 10)
        self.assertLess(duration, 2.0, "Batch processing must complete in <2 seconds")

        # Verify reforma applied correctly
        payslips_2024 = payslips[:3]
        payslips_2025 = payslips[3:]

        for ps in payslips_2024:
            apv = ps.line_ids.filtered(lambda x: x.code == 'APV')
            self.assertFalse(apv, f"Payslip {ps.id} should not have APV")

        for ps in payslips_2025:
            apv = ps.line_ids.filtered(lambda x: x.code == 'APV')
            self.assertTrue(apv, f"Payslip {ps.id} should have APV for 2025 contract")
```

**Coverage Target:** >90%

---

## 5. Validation Tests

### Test Class: `TestPayrollValidations`

**File:** `addons/localization/l10n_cl_hr_payroll/tests/test_payroll_validations_p0.py`

#### Blocking Validations

| Validation | Blocks | Error Message | Test |
|-----------|--------|---------------|------|
| Missing P0-1 (AFP) | payslip_done | "Tope AFP no configurado" | `test_validation_blocks_missing_afp_cap` |
| Missing P0-2 (AFP calc) | compute_sheet | "Fórmula cálculo AFP no definida" | `test_validation_blocks_missing_calc` |
| Missing P0-3 (Reforma) | payslip_done | "Reforma 2025: APV/Cesantía no configurados" | `test_validation_blocks_missing_reforma` |
| Invalid RUT | payslip_done | "RUT empleado inválido" | `test_validation_blocks_invalid_rut` |
| Missing indicators | payslip_done | "Indicadores económicos no actualizados" | `test_validation_blocks_missing_indicators` |

#### Allowing Validations

**Test Name:** `test_validation_allows_valid_payslip`

```python
def test_validation_allows_valid_payslip(self):
    """Valid payslip passes all validations"""
    employee = self._create_employee('Valid Emp', vat='12345678-9')
    contract = self._create_contract(employee.id)

    payslip = self.env['hr.payslip'].create({...})
    payslip.compute_sheet()

    # Should not raise any validation error
    payslip.action_payslip_done()

    self.assertEqual(payslip.state, 'done')
```

**Coverage Target:** 100%

---

## 6. Test Execution & Coverage

### Running Tests

**All FASE 0 tests:**
```bash
cd /Users/pedro/Documents/odoo19

# Run only FASE 0 tests
pytest addons/localization/l10n_cl_hr_payroll/tests \
    -m "p0_critical" \
    -v \
    --cov=addons/localization/l10n_cl_hr_payroll \
    --cov-report=html

# Run with specific tag
pytest addons/localization/l10n_cl_hr_payroll/tests/test_p0_afp_cap_2025.py -v
```

**Using Odoo native runner:**
```bash
docker-compose exec odoo odoo -u l10n_cl_hr_payroll \
    --test-enable \
    --test-tags p0_critical \
    --stop-after-init
```

### Coverage Goals

| Module | Target | Method |
|--------|--------|--------|
| l10n_cl_hr_payroll models | >95% | Unit + Integration |
| Payslip calculation | 100% | Unit tests |
| Validations | 100% | Validation tests |
| Integration flows | >90% | Integration tests |

### Coverage Report

**File:** `docs/testing/COVERAGE_PHASE0.html`

Generated after test run:
```bash
pytest ... --cov-report=html:docs/testing/coverage_phase0
```

---

## 7. Test Data Management

### Fixture Data

**File:** `addons/localization/l10n_cl_hr_payroll/tests/data/test_data_p0.xml`

```xml
<odoo>
    <!-- Legal Caps -->
    <record id="legal_cap_afp_2025" model="l10n_cl.legal.caps">
        <field name="code">AFP_IMPONIBLE_CAP</field>
        <field name="amount">83.1</field>
        <field name="unit">uf</field>
        <field name="valid_from">2025-01-01</field>
        <field name="description">AFP cap 2025 - Ley 20.255 Art. 17</field>
    </record>

    <!-- Test Employee -->
    <record id="employee_p0_test" model="hr.employee">
        <field name="name">Test Employee P0</field>
        <field name="employee_type">employee</field>
        <field name="identification_id">12345678</field>
    </record>

    <!-- Test Contract 2025 -->
    <record id="contract_p0_2025" model="hr.contract">
        <field name="employee_id" ref="employee_p0_test"/>
        <field name="date_start">2025-01-15</field>
        <field name="wage">3000000</field>
        <field name="type_id" ref="hr_contract.contract_type_cdd"/>
    </record>
</odoo>
```

### Data Factory

**File:** `addons/localization/l10n_cl_hr_payroll/tests/factories.py`

```python
class P0PayrollFactory:
    """Factory for creating test payroll objects"""

    @staticmethod
    def create_employee(env, **kwargs):
        defaults = {
            'name': 'Test Employee',
            'employee_type': 'employee',
        }
        defaults.update(kwargs)
        return env['hr.employee'].create(defaults)

    @staticmethod
    def create_contract(env, employee_id, **kwargs):
        defaults = {
            'employee_id': employee_id,
            'date_start': date(2025, 1, 1),
            'wage': 3000000,
            'type_id': env.ref('hr_contract.contract_type_cdd').id,
        }
        defaults.update(kwargs)
        return env['hr.contract'].create(defaults)

    @staticmethod
    def create_payslip(env, employee_id, contract_id, **kwargs):
        defaults = {
            'employee_id': employee_id,
            'contract_id': contract_id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
        }
        defaults.update(kwargs)
        return env['hr.payslip'].create(defaults)
```

---

## 8. Acceptance Criteria

### Phase 0 Sign-Off

- [ ] **Unit Tests:** All 25+ tests PASS
  - P0-1 AFP: 4/4 tests passing
  - P0-2 AFP calc: 5/5 tests passing
  - P0-3 Reforma: 6/6 tests passing
  - P0-4 Validations: 10+ tests passing

- [ ] **Integration Tests:** 3+ scenarios PASS
  - Complete payslip workflow
  - Batch processing (10 employees)
  - Previred export integration

- [ ] **Manual Tests:** 10 real payslips PASS
  - 5 from 2024 contracts (no reforma)
  - 5 from 2025 contracts (with reforma)
  - Various salary levels (below/above AFP cap)
  - Previred export validates successfully

- [ ] **Coverage:** >95%
  - Module coverage: 95%+
  - Critical paths: 100%
  - Validations: 100%

- [ ] **Performance:** <5 minutes
  - Unit tests: <3 min
  - Integration tests: <2 min
  - Total execution: <5 min

- [ ] **Code Quality:** 0 warnings
  - No linting errors
  - All @api.depends properly used
  - No SQL injection risks

### Failure Handling

If ANY test fails:

1. **Root Cause Analysis:** Debug test output
2. **Fix Implementation:** Code change or test correction
3. **Regression Test:** Re-run full test suite
4. **Sign-Off:** Verify all tests passing again

---

## 9. Monitoring & Metrics

### Key Metrics

| Metric | Target | Frequency |
|--------|--------|-----------|
| Test Pass Rate | 100% | Every run |
| Code Coverage | >95% | Every run |
| Execution Time | <5 min | Every run |
| Failure Rate | 0% | Daily |
| Flaky Tests | <1% | Weekly |

### Dashboard

**File:** `docs/testing/COVERAGE_PHASE0_DASHBOARD.md`

Updated after each test run with:
- Test pass/fail counts
- Coverage percentages
- Execution time
- Trend analysis

---

## 10. References & Documentation

### Related Documents

- `AUDITORIA_NOMINA_CHILENA_EXHAUSTIVA_2025-11-07.md` - P0 gap identification
- `RESUMEN_EJECUTIVO_CIERRE_P0_P1_NOMINA.md` - Project plan
- `addons/localization/l10n_cl_hr_payroll/README_P0_P1_GAPS_CLOSED.md` - Implementation details

### Regulatory References

- **Ley 20.255** - SPP contributions and caps
- **Art. 50 CT modificado** - Reforma 2025 requirements
- **DFL 150** - Labor code provisions
- **Ley 19.728** - APV regulations

### Test Standards

- Odoo `TransactionCase` base class
- pytest for coverage reporting
- Mock objects for external dependencies
- TDD approach: tests before implementation

---

**Last Updated:** 2025-11-08 | **Phase:** 0 (Payroll P0) | **Status:** Ready for Execution
