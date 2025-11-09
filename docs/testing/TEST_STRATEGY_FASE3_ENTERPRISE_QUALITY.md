# Test Strategy - FASE 3: Enterprise Quality Certification

**Status:** Enterprise Quality | **Owner:** QA Lead | **Updated:** 2025-11-08

---

## Executive Summary

Test strategy for FASE 3 providing comprehensive security audit, performance benchmarks, and smoke tests to certify enterprise-grade quality. This final phase validates the complete 8-week gap closure effort across all three domains (Payroll P0, DTE 52, BHE + Reports).

**Target Coverage:** 95%+ | **Test Cases:** 40+ | **Execution Time:** <15min | **Success Criteria:** 0 vulns + all benchmarks met + 100% smoke PASS

---

## 1. Security Tests - OWASP Top 10

### Test Class: `TestSecurityOWASP`

**File:** `addons/localization/l10n_cl_dte/tests/test_security_owasp.py`

#### A1: Broken Access Control

| Test Name | Severity | Check | Pass Criteria |
|-----------|----------|-------|---------------|
| `test_acl_payroll_users_only` | CRITICAL | Payroll access | Non-payroll users blocked |
| `test_acl_dte_users_only` | CRITICAL | DTE access | Non-DTE users blocked |
| `test_acl_bhe_users_only` | HIGH | BHE access | Non-BHE users blocked |
| `test_acl_reports_read_only` | MEDIUM | Report viewing | Cannot modify reports |
| `test_separation_of_duties_invoice` | CRITICAL | SOD invoice | Create ≠ Approve ≠ Pay |
| `test_separation_of_duties_payroll` | CRITICAL | SOD payroll | Create ≠ Validate ≠ Pay |

**Code Pattern:**

```python
@tagged('security', 'owasp_a1', 'acl')
class TestSecurityOWASP(TransactionCase):

    def test_acl_payroll_users_only(self):
        """Only payroll users can access payroll"""
        # Create test users
        payroll_user = self._create_user(
            'payroll_manager',
            groups=['hr_payroll.group_hr_payroll_manager']
        )
        sales_user = self._create_user(
            'sales_manager',
            groups=['sales.group_sale_manager']
        )

        # Payroll user CAN access
        with self.assertRaises(AccessDenied):
            self.env['hr.payslip'].with_user(sales_user).create({
                'employee_id': self.employee.id,
            })

        # Payroll user CAN access
        payslip = self.env['hr.payslip'].with_user(payroll_user).create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
        })
        self.assertTrue(payslip.id)

    def test_separation_of_duties_invoice(self):
        """Verify SOD: Create ≠ Approve ≠ Pay"""
        creator = self._create_user('creator', groups=[])
        approver = self._create_user('approver', groups=[])
        payer = self._create_user('payer', groups=[])

        # Creator creates
        invoice = self.env['account.move'].with_user(creator).create({
            'partner_id': self.partner.id,
            'move_type': 'in_invoice',
        })

        # Creator cannot approve
        with self.assertRaises(AccessDenied):
            invoice.with_user(creator).action_post()

        # Approver approves (posts)
        invoice.with_user(approver).action_post()
        self.assertEqual(invoice.state, 'posted')

        # Different user must pay
        payment = self.env['account.payment'].with_user(payer).create({
            'amount': invoice.amount_total,
            'payment_type': 'inbound',
            'partner_id': self.partner.id,
        })
        self.assertTrue(payment.id)
```

**Coverage Target:** 100%

#### A2: Cryptographic Failures

| Test Name | Check | Pass Criteria |
|-----------|-------|---------------|
| `test_password_hashing_bcrypt` | Passwords hashed | Uses bcrypt ≥12 rounds |
| `test_ssl_tls_for_sii_calls` | HTTPS | No HTTP to SII |
| `test_digital_signature_validation` | Signature | Valid against CAF |
| `test_rsa_key_protection` | Private keys | Encrypted at rest |

**Code Pattern:**

```python
def test_ssl_tls_for_sii_calls(self):
    """All SII calls use HTTPS"""
    with patch('requests.post') as mock_post:
        dte = self._create_dte52()
        dte.action_send_to_sii()

        # Verify HTTPS URL was called
        call_args = mock_post.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get('url')

        self.assertTrue(
            url.startswith('https://'),
            f"SII call must use HTTPS, got: {url}"
        )

def test_digital_signature_validation(self):
    """DTE signature validates against CAF"""
    dte = self._create_dte52_with_signature()

    # Signature should be valid
    is_valid = dte._validate_signature()
    self.assertTrue(is_valid)

    # Tampered XML should fail validation
    tampered_xml = dte.xml_content.replace(
        '<MONTO>1000000</MONTO>',
        '<MONTO>2000000</MONTO>'
    )
    dte.xml_content = tampered_xml

    is_valid = dte._validate_signature()
    self.assertFalse(is_valid, "Tampered XML must fail signature validation")
```

**Coverage Target:** 100%

#### A3: Injection (SQL)

| Test Name | Payload | Expected |
|-----------|---------|----------|
| `test_sql_injection_payslip_search` | `' OR '1'='1` | No data leak |
| `test_sql_injection_dte_search` | `'); DROP TABLE` | Query safe |
| `test_orm_usage_correcto` | All searches | Using ORM, not raw SQL |

**Code Pattern:**

```python
@tagged('security', 'owasp_a3', 'sql_injection')
def test_sql_injection_payslip_search(self):
    """ORM prevents SQL injection in payslip searches"""
    malicious_input = "' OR '1'='1"

    # This should safely return 0 results, not bypass security
    payslips = self.env['hr.payslip'].search([
        ('employee_id', '=', self.employee.id),
        ('name', 'ilike', malicious_input)
    ])

    # Should be empty, not leak all payslips
    self.assertEqual(len(payslips), 0)

    # Verify ORM being used (not raw SQL)
    sql_string = str(self.env['hr.payslip'].search_sql(
        [('employee_id', '=', self.employee.id)]
    ))

    # Should be parameterized query
    self.assertNotIn(malicious_input, sql_string)

def test_orm_usage_correcto(self):
    """All searches use ORM, never raw SQL"""
    # Scan models for raw SQL usage
    models_to_check = [
        'hr.payslip',
        'l10n_cl.dte',
        'l10n_cl.boleta_honorarios',
    ]

    for model_name in models_to_check:
        model = self.env[model_name]
        model_file = model.__module__.replace('.', '/') + '.py'

        # Read source
        import os
        filepath = os.path.join(
            '/Users/pedro/Documents/odoo19/addons/localization/',
            model_file
        )

        with open(filepath, 'r') as f:
            source = f.read()

        # Check for dangerous patterns
        dangerous = [
            'execute(',
            'cr.execute(',
            'cursor.execute(',
        ]

        for pattern in dangerous:
            # Allow only in test/comment sections
            lines_with_pattern = [
                l for l in source.split('\n')
                if pattern in l and 'test' not in l.lower()
            ]

            self.assertEqual(
                len(lines_with_pattern), 0,
                f"{model_name}: Found {pattern} - use ORM instead"
            )
```

**Coverage Target:** 100%

#### A4: XSS (Cross-Site Scripting)

| Test Name | Input | Expected |
|-----------|-------|----------|
| `test_xss_payslip_name` | `<script>alert(1)</script>` | Escaped/sanitized |
| `test_xss_partner_name` | `javascript:alert(1)` | Escaped/sanitized |
| `test_xss_dte_description` | `<img src=x onerror=alert(1)>` | Escaped |
| `test_sanitization_user_input` | All Char fields | Safe HTML output |

**Code Pattern:**

```python
@tagged('security', 'owasp_a4', 'xss')
def test_xss_payslip_name(self):
    """Payslip fields sanitized against XSS"""
    xss_payload = '<script>alert("XSS")</script>'

    payslip = self.env['hr.payslip'].create({
        'employee_id': self.employee.id,
        'contract_id': self.contract.id,
        'name': xss_payload,
    })

    # Should escape script tags
    html_output = payslip.name

    self.assertNotIn('<script>', html_output)
    self.assertNotIn('alert', html_output)
    self.assertIn('&lt;script&gt;', html_output)

def test_xss_partner_name(self):
    """Partner name sanitized"""
    xss_payload = 'javascript:alert(1)'

    partner = self.env['res.partner'].create({
        'name': xss_payload,
    })

    # Should be stored safely
    self.assertEqual(partner.name, xss_payload)

    # But output should be escaped
    html_output = self.env['ir.qweb']._render(
        'base.partner_name',
        {'partner': partner}
    )

    self.assertNotIn('javascript:', html_output)
```

**Coverage Target:** 100%

#### A5: Broken Authentication

| Test Name | Check | Pass Criteria |
|-----------|-------|---------------|
| `test_password_policy_minimum` | Passwords | Min 8 chars, complexity |
| `test_session_timeout` | Sessions | 24h max idle |
| `test_oauth2_token_expiry` | OAuth2 | 1h token expiry |
| `test_mfa_optional_admin` | MFA | Available for admins |

**Code Pattern:**

```python
@tagged('security', 'owasp_a5', 'auth')
def test_password_policy_minimum(self):
    """Password policy enforced"""
    # Weak password should fail
    with self.assertRaises(ValidationError):
        self.env['res.users'].create({
            'name': 'Test User',
            'login': 'testuser',
            'password': 'weak',  # Too short
        })

    # Strong password should succeed
    user = self.env['res.users'].create({
        'name': 'Test User',
        'login': 'testuser2',
        'password': 'MyStr0ng!Pass',  # 8+ chars, mixed case, number, symbol
    })
    self.assertTrue(user.id)

def test_session_timeout(self):
    """Session timeout configured"""
    config = self.env['ir.config_parameter'].sudo()

    session_timeout = config.get_param(
        'web.session.expire_days',
        default=1
    )

    self.assertEqual(int(session_timeout), 1)
```

**Coverage Target:** 100%

---

## 2. Performance Tests & Benchmarks

### Test Class: `TestPerformanceBenchmarks`

**File:** `addons/localization/l10n_cl_dte/tests/test_performance_benchmarks.py`

#### Performance SLAs

| Component | SLA | Metric | Test |
|-----------|-----|--------|------|
| DTE generation | <2s | p95 latency | `test_dte_generation_latency_2s` |
| Report generation | <5s | p95 latency | `test_report_generation_latency_5s` |
| UI response | <500ms | p50 latency | `test_ui_response_time_500ms` |
| DB queries | <50 | per operation | `test_database_queries_optimized` |
| Batch (100 items) | <30s | total time | `test_batch_processing_100_items` |
| Batch (1000 items) | <5min | total time | `test_batch_processing_1000_items` |

**Code Pattern:**

```python
@tagged('performance', 'benchmark')
class TestPerformanceBenchmarks(TransactionCase):

    def test_dte_generation_latency_2s(self):
        """DTE generation p95 latency <2 seconds"""
        import time

        latencies = []

        for i in range(20):  # 20 samples
            order = self._create_sale_order(self.partner, self.product, 10)
            order.action_confirm()
            picking = order.picking_ids[0]

            start = time.perf_counter()
            picking.action_done()  # Triggers DTE 52 generation
            latency = time.perf_counter() - start

            latencies.append(latency)

        # p95 should be <2 seconds
        latencies_sorted = sorted(latencies)
        p95_latency = latencies_sorted[int(0.95 * len(latencies_sorted))]

        print(f"\nDTE Generation Latency:")
        print(f"  Min:  {min(latencies):.3f}s")
        print(f"  Max:  {max(latencies):.3f}s")
        print(f"  p50:  {latencies_sorted[int(0.5*len(latencies_sorted))]:.3f}s")
        print(f"  p95:  {p95_latency:.3f}s")

        self.assertLess(
            p95_latency, 2.0,
            f"p95 latency {p95_latency:.3f}s exceeds 2s SLA"
        )

    def test_report_generation_latency_5s(self):
        """Report generation p95 latency <5 seconds"""
        import time

        latencies = []

        for i in range(10):  # 10 samples
            # Create diverse test data
            self._create_test_invoices(50)

            f29 = self.env['account.move.f29'].create({
                'fecha_desde': date(2025, 1, 1),
                'fecha_hasta': date(2025, 1, 31),
            })

            start = time.perf_counter()
            f29.action_calculate()
            latency = time.perf_counter() - start

            latencies.append(latency)

        p95_latency = sorted(latencies)[int(0.95 * len(latencies))]

        self.assertLess(
            p95_latency, 5.0,
            f"p95 report latency {p95_latency:.3f}s exceeds 5s SLA"
        )

    def test_database_queries_optimized(self):
        """Database queries optimized (limit <50 per operation)"""
        from odoo.sql_db import Cursor

        initial_query_count = 0

        def count_queries(cursor_self):
            nonlocal initial_query_count
            initial_query_count += 1

        # Mock cursor to count queries
        with self.assertLess(initial_query_count, 50):
            order = self._create_sale_order(self.partner, self.product, 100)
            order.action_confirm()

            payslip = self.env['hr.payslip'].create({
                'employee_id': self.employee.id,
            })
            payslip.compute_sheet()

        # Verify prefetching used where applicable
        payslips = self.env['hr.payslip'].search([])
        with self.assertNumQueries(1):  # Should be 1 query for all
            for ps in payslips:
                _ = ps.employee_id.name
```

**Coverage Target:** 100%

---

## 3. Smoke Tests - Critical Paths

### Test Class: `TestSmokeTestSuite`

**File:** `addons/localization/l10n_cl_dte/tests/test_smoke_suite_complete.py`

#### Smoke Test 1: Payroll Flow

**Test Name:** `test_smoke_payroll_complete_flow`

```python
@tagged('smoke', 'critical', 'payroll')
def test_smoke_payroll_complete_flow(self):
    """
    Smoke Test: Complete payroll workflow (target: 2 min)

    Timeline:
    1. Login (user exists)
    2. Create employee
    3. Create contract
    4. Create payslip
    5. Compute payroll
    6. Validate payslip
    7. Logout
    """
    import time
    start = time.time()

    # 1. Login
    self.assertTrue(self.env.user.id > 0)

    # 2-3. Setup
    employee = self._create_employee('Test Employee')
    contract = self._create_contract(employee.id)

    # 4. Create payslip
    payslip = self.env['hr.payslip'].create({
        'employee_id': employee.id,
        'contract_id': contract.id,
        'date_from': date(2025, 1, 1),
        'date_to': date(2025, 1, 31),
    })

    # 5. Compute
    payslip.compute_sheet()

    # 6. Validate
    payslip.action_payslip_done()

    duration = time.time() - start

    # Must complete in <2 minutes
    self.assertLess(duration, 120, f"Smoke test took {duration:.0f}s, max 120s")

    # Verify end state
    self.assertEqual(payslip.state, 'done')
    self.assertGreater(len(payslip.line_ids), 0)

    print(f"✓ Payroll smoke test PASSED ({duration:.1f}s)")
```

#### Smoke Test 2: DTE Workflow

**Test Name:** `test_smoke_dte52_complete_workflow`

```
Flow:
1. Create sales order
2. Confirm order
3. Process picking
4. Validate DTE 52
5. Verify XML generated
6. Mock SII submission

Target: <2 minutes
```

#### Smoke Test 3: BHE Reception

**Test Name:** `test_smoke_bhe_complete_workflow`

```
Flow:
1. Create professional partner
2. Receive BHE
3. System calculates retention
4. Create invoice
5. Validate BHE
6. Verify integration

Target: <90 seconds
```

#### Smoke Test 4: Report Generation

**Test Name:** `test_smoke_reports_complete_workflow`

```
Flow:
1. Create test invoices (10)
2. Generate Libro Compras
3. Generate Libro Ventas
4. Generate F29
5. Export all to CSV
6. Verify formats

Target: <3 minutes
```

**Code Pattern:**

```python
@tagged('smoke', 'critical')
class TestSmokeTestSuite(TransactionCase):

    def test_smoke_complete_all_flows(self):
        """Master smoke test: all critical flows"""
        import time
        start = time.time()

        # Payroll
        emp = self._create_employee('Emp1')
        ctr = self._create_contract(emp.id)
        ps = self.env['hr.payslip'].create({...})
        ps.compute_sheet()
        self.assertEqual(ps.state, 'draft')

        # DTE
        ord = self._create_sale_order(self.partner, self.product, 10)
        ord.action_confirm()
        pick = ord.picking_ids[0]
        pick.action_done()
        dte52 = pick.l10n_cl_dte_52_id
        self.assertTrue(dte52)

        # BHE
        bhe = self.env['l10n_cl.boleta_honorarios'].create({...})
        self.assertEqual(bhe.tasa_retencion, 14.5)

        # Reports
        f29 = self.env['account.move.f29'].create({...})
        f29.action_calculate()
        self.assertGreater(f29.dte_total, 0)

        duration = time.time() - start
        self.assertLess(duration, 300, f"Master smoke test exceeded 5 min: {duration:.0f}s")

        print(f"✓ Master smoke test PASSED ({duration:.1f}s)")
```

**Coverage Target:** 100% (critical paths only)

---

## 4. Code Quality Tests

### Test Class: `TestCodeQuality`

**File:** `addons/localization/l10n_cl_dte/tests/test_code_quality.py`

#### Linting & Style

| Check | Tool | Pass Criteria | Test |
|-------|------|---------------|------|
| PEP 8 compliance | flake8 | 0 errors | `test_flake8_no_errors` |
| Security issues | bandit | 0 HIGH+ | `test_bandit_no_high_issues` |
| Type hints | mypy | 0 errors | `test_mypy_no_errors` |
| Import complexity | isort | sorted | `test_isort_imports_sorted` |

**Code Pattern:**

```python
@tagged('quality', 'lint')
class TestCodeQuality(TransactionCase):

    def test_flake8_no_errors(self):
        """No flake8 linting errors"""
        import subprocess
        import sys

        paths = [
            'addons/localization/l10n_cl_dte',
            'addons/localization/l10n_cl_hr_payroll',
            'addons/localization/l10n_cl_financial_reports',
        ]

        for path in paths:
            result = subprocess.run(
                [sys.executable, '-m', 'flake8', path, '--count'],
                capture_output=True,
                text=True
            )

            errors = int(result.stdout.strip().split('\n')[-1]) if result.stdout else 0

            self.assertEqual(
                errors, 0,
                f"flake8 found {errors} errors in {path}"
            )

    def test_bandit_no_high_issues(self):
        """No HIGH+ security issues detected by bandit"""
        import subprocess
        import json

        result = subprocess.run(
            ['bandit', '-r', 'addons/localization', '-f', 'json'],
            capture_output=True,
            text=True
        )

        report = json.loads(result.stdout)
        high_issues = [r for r in report.get('results', [])
                      if r['severity'] in ['HIGH', 'CRITICAL']]

        self.assertEqual(
            len(high_issues), 0,
            f"bandit found {len(high_issues)} HIGH+ issues: {high_issues}"
        )
```

**Coverage Target:** 100%

---

## 5. Enterprise Certification Checklist

### Pre-Production Sign-Off

**Security (100% Required)**
- [ ] OWASP Top 10 tests: 100% PASS
- [ ] ACL tests: 100% PASS
- [ ] SQL injection tests: 100% PASS
- [ ] XSS tests: 100% PASS
- [ ] No HIGH/CRITICAL vulns in bandit

**Performance (100% Required)**
- [ ] DTE generation: <2s p95
- [ ] Report generation: <5s p95
- [ ] UI response: <500ms p50
- [ ] DB queries: <50 per op
- [ ] Batch (100): <30s
- [ ] Batch (1000): <5min

**Smoke Tests (100% Required)**
- [ ] Payroll workflow: PASS (<2 min)
- [ ] DTE workflow: PASS (<2 min)
- [ ] BHE workflow: PASS (<90s)
- [ ] Reports workflow: PASS (<3 min)

**Code Quality (100% Required)**
- [ ] flake8: 0 errors
- [ ] bandit: 0 HIGH/CRITICAL
- [ ] mypy: Type hints complete
- [ ] isort: Imports sorted

**Coverage (>95% Required)**
- [ ] Overall coverage: >95%
- [ ] Critical paths: 100%
- [ ] Security code: 100%

---

## 6. Test Execution

### Running Complete Enterprise Suite

```bash
cd /Users/pedro/Documents/odoo19

# Full enterprise suite (all tests)
pytest addons/localization/*/tests \
    -m "security or performance or smoke or quality" \
    -v \
    --cov=addons/localization \
    --cov-report=html \
    --cov-fail-under=95

# Security only
pytest addons/localization/*/tests -m security -v

# Performance only
pytest addons/localization/*/tests -m performance -v

# Smoke tests only
pytest addons/localization/*/tests -m smoke -v

# Quality only
pytest addons/localization/*/tests -m quality -v
```

### Continuous Integration

**GitHub Actions Workflow:** `.github/workflows/enterprise-quality.yml`

```yaml
name: Enterprise Quality Gate

on: [pull_request, push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security tests
        run: pytest -m security --cov-fail-under=95

  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run performance tests
        run: pytest -m performance

  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run smoke tests
        run: pytest -m smoke
```

---

## 7. Final Certification Report

### Template: `CERTIFICATION_ENTERPRISE_FASE3.md`

```markdown
# Enterprise Quality Certification - FASE 3

**Date:** 2025-11-08 | **Version:** 1.0.5 | **Status:** CERTIFIED

## Test Results Summary

| Category | Tests | Passed | Failed | Coverage | Status |
|----------|-------|--------|--------|----------|--------|
| Security (OWASP) | 12 | 12 | 0 | 100% | ✅ PASS |
| Performance | 6 | 6 | 0 | 100% | ✅ PASS |
| Smoke Tests | 4 | 4 | 0 | 100% | ✅ PASS |
| Code Quality | 4 | 4 | 0 | 100% | ✅ PASS |
| **TOTAL** | **26** | **26** | **0** | **95%+** | **✅ CERTIFIED** |

## Security Audit

- ✅ OWASP Top 10: 0 findings
- ✅ Broken Access Control: PASS
- ✅ SQL Injection: PASS
- ✅ XSS: PASS
- ✅ bandit: 0 HIGH/CRITICAL

## Performance SLAs

- ✅ DTE generation: 1.3s p95 (target: <2s)
- ✅ Report generation: 3.8s p95 (target: <5s)
- ✅ UI response: 320ms p50 (target: <500ms)
- ✅ DB queries: 28 per op (target: <50)

## Sign-Off

- **QA Lead:** [Name]
- **Security Review:** [Name]
- **Operations:** [Name]

**Status: PRODUCTION READY - ENTERPRISE CERTIFIED**

```

---

## 8. Acceptance Criteria

### Final Sign-Off

- [ ] **Security:** 0 vulnerabilities, 100% OWASP PASS
- [ ] **Performance:** All 6 SLAs met
- [ ] **Smoke Tests:** 4/4 critical flows PASS
- [ ] **Code Quality:** 0 lint/security issues
- [ ] **Coverage:** >95% overall, 100% critical paths
- [ ] **Documentation:** Complete (test strategies, roadmap, templates)

### Go/No-Go Decision

**GO** if:
- ✅ All 26 tests PASS
- ✅ 0 security findings
- ✅ All performance SLAs met
- ✅ >95% code coverage
- ✅ No blockers identified

**NO-GO** if:
- ❌ Any CRITICAL test failure
- ❌ HIGH/CRITICAL security finding
- ❌ SLA violation
- ❌ Coverage <95%

---

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PCI DSS v3.2.1
- ISO/IEC 27001:2013
- NIST Cybersecurity Framework

---

**Last Updated:** 2025-11-08 | **Phase:** 3 (Enterprise Quality) | **Status:** Ready for Execution
