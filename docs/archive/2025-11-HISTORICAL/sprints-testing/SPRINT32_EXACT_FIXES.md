# Sprint 3.2 - Exact Code Fixes

**Quick Reference Guide for Implementation**

---

## Fix 1: Field Name Bug (CRITICAL)

**File:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py`

**Line:** 1136

**Current Code:**
```python
imm = self.indicadores_id.sueldo_minimo
```

**Fixed Code:**
```python
imm = self.indicadores_id.minimum_wage
```

**Impact:** Fixes AttributeError in allowance processing

---

## Fix 2A: Tax Code Test 1

**File:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py`

**Line:** 236

**Current Code:**
```python
tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'TAX')
```

**Fixed Code:**
```python
tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'IMPUESTO_UNICO')
```

---

## Fix 2B: Tax Code Test 2

**File:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py`

**Line:** 256

**Current Code:**
```python
tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'TAX')
```

**Fixed Code:**
```python
tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'IMPUESTO_UNICO')
```

---

## Fix 3: AFC Calculation (INVESTIGATE FIRST)

**Option A - Fix Test Expectation (if current calc is correct):**

**File:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll/tests/test_calculations_sprint32.py`

**Line:** 280

**Current Code:**
```python
expected_afc = 6000
```

**Fixed Code:**
```python
expected_afc = 6125  # Updated to match actual calculation
```

---

**Option B - Fix AFC Calculation (if should use 120.2 UF cap):**

**File:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml`

**Lines:** 180-184

**Current Code:**
```xml
<field name="amount_python_compute">
# AFC Trabajador = 0.6% sobre BASE_TRIBUTABLE
base = categories.BASE_TRIBUTABLE
tasa_afc = 0.006  # 0.6%
result = -(base * tasa_afc)
</field>
```

**Fixed Code:**
```xml
<field name="amount_python_compute">
# AFC Trabajador = 0.6% sobre base con tope 120.2 UF
total_imp = categories.TOTAL_IMPONIBLE

# Obtener tope AFC (120.2 UF)
tope_afc_uf, unit = env['l10n_cl.legal.caps'].get_cap('AFC_CAP', payslip.date_to)
tope_afc_clp = tope_afc_uf * payslip.indicadores_id.uf

# Aplicar tope AFC
base = min(total_imp, tope_afc_clp) if tope_afc_clp > 0 else total_imp
tasa_afc = 0.006  # 0.6%
result = -(base * tasa_afc)
</field>
```

**IMPORTANT:** Choose Option A or B after investigation, NOT both.

---

## Testing Commands

### Test Individual Fixes

**After Fix 1:**
```bash
docker-compose exec odoo odoo --test-enable \
  --test-tags /l10n_cl_hr_payroll:TestPayrollCalculationsSprint32.test_allowance_colacion \
  --stop-after-init
```

**After Fix 2:**
```bash
docker-compose exec odoo odoo --test-enable \
  --test-tags /l10n_cl_hr_payroll:TestPayrollCalculationsSprint32.test_tax_tramo2 \
  --stop-after-init
```

**After Fix 3:**
```bash
docker-compose exec odoo odoo --test-enable \
  --test-tags /l10n_cl_hr_payroll:TestPayrollCalculationsSprint32.test_afc_calculation \
  --stop-after-init
```

### Test All Sprint 3.2

```bash
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --test-enable \
  --test-tags payroll_calc --stop-after-init
```

### Full Regression Test

```bash
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --test-enable \
  --stop-after-init
```

---

## Investigation Command for AFC

Before choosing Fix 3 Option A or B:

```bash
# Add debug logging to AFC rule
docker-compose exec odoo odoo --test-enable \
  --test-tags /l10n_cl_hr_payroll:TestPayrollCalculationsSprint32.test_afc_calculation \
  --log-level=debug --stop-after-init
```

**Look for in output:**
- BASE_TRIBUTABLE actual value
- TOTAL_IMPONIBLE actual value
- AFC line total amount
- Any rounding or intermediate calculations

---

## Implementation Checklist

- [ ] Backup current code
- [ ] Apply Fix 1 (field name)
- [ ] Test Fix 1
- [ ] Apply Fix 2A (tax code test 1)
- [ ] Apply Fix 2B (tax code test 2)
- [ ] Test Fix 2
- [ ] Investigate AFC calculation
- [ ] Apply Fix 3 (Option A or B)
- [ ] Test Fix 3
- [ ] Run full Sprint 3.2 test suite
- [ ] Run regression tests
- [ ] Commit changes

---

## Git Commit Messages

**After Fix 1:**
```
fix(payroll): correct field name in allowance processing

- Fix AttributeError in _process_allowance method
- Change sueldo_minimo to minimum_wage (correct field name)
- Fixes 4 tests: allowance_colacion, allowance_tope_legal, bonus_imponible, full_payslip

Ref: Sprint 3.2 test failures analysis
```

**After Fix 2:**
```
test(payroll): update tax line code in Sprint 3.2 tests

- Change TAX to IMPUESTO_UNICO (actual rule code)
- Fixes test_tax_tramo2 and test_tax_tramo3
- Aligns tests with actual implementation

Ref: Sprint 3.2 test failures analysis
```

**After Fix 3 (Option A):**
```
test(payroll): update AFC expected value in test

- Update expected AFC from 6,000 to 6,125
- Aligns with actual system calculation
- Verified calculation complies with Ley 19.728

Ref: Sprint 3.2 AFC investigation
```

**After Fix 3 (Option B):**
```
fix(payroll): apply AFC-specific cap in calculation

- AFC now uses 120.2 UF cap (AFC_CAP) instead of BASE_TRIBUTABLE
- Complies with Ley 19.728 Art. 7
- Fixes test_afc_calculation

Ref: Sprint 3.2 AFC investigation
```

---

## Quick Copy-Paste Fixes

### Fix 1 Command
```bash
# Edit models/hr_payslip.py line 1136
# Find: imm = self.indicadores_id.sueldo_minimo
# Replace with: imm = self.indicadores_id.minimum_wage
```

### Fix 2 Commands
```bash
# Edit tests/test_calculations_sprint32.py line 236
# Find: tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'TAX')
# Replace with: tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'IMPUESTO_UNICO')

# Edit tests/test_calculations_sprint32.py line 256
# Find: tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'TAX')
# Replace with: tax_line = self.payslip.line_ids.filtered(lambda l: l.code == 'IMPUESTO_UNICO')
```

---

**Total Changes:**
- Files: 2-3 files
- Lines: 3-8 lines
- Time: 15-45 minutes
- Risk: LOW

**Ready for immediate implementation.**
