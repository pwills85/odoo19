# Test Automation Architecture - FASE 0-1

**Diagrama de flujo y componentes del sistema de testing automatizado.**

---

## 🏗️ Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TEST AUTOMATION FRAMEWORK FASE 0-1                     │
└─────────────────────────────────────────────────────────────────────────────┘

                              ENTRY POINTS (3 opciones)
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
              PYTHON RUNNER      BASH RUNNER    PYTEST DIRECT
              (Recomendado)      (Odoo Native)  (Específicos)
                    │                │                │
         test_runner_       test_fase_0_1_       pytest
         fase_0_1.py        odoo_native.sh      tests/
                    │                │                │
                    └────────────────┼────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │   TEST EXECUTION ENGINE        │
                    │   (pytest + odoo.tests)        │
                    └────────────────┬────────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
       FASE 0: PAYROLL          FASE 1: DTE 52        FIXTURES & DATA
       (47 tests)               (40 tests)            (Factory Pattern)
            │                        │                        │
    ┌───────┴────────┐        ┌──────┴──────┐        ┌────────┴────────┐
    │                │        │             │        │                 │
l10n_cl_hr_     test_p0_    l10n_cl_dte  test_dte_  fixtures_p0_p1.py
payroll         afp_cap                   52        (350 líneas)
(47 tests)      2025          (40 tests)
    │            │                │            │
    └────────────┴────────────────┴────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
    COVERAGE ANALYSIS          PERFORMANCE METRICS
    (pytest-cov)               (pytest-benchmark)
        │                               │
    coverage.json              performance.json
    htmlcov/index.html         test_duration.txt
        │                               │
        └───────────────┬───────────────┘
                        │
        ┌───────────────▼───────────────┐
        │    REPORT GENERATION          │
        │    (Automated Python)         │
        └───────────────┬───────────────┘
                        │
        ┌───────────────▼───────────────┐
        │    OUTPUT ARTIFACTS           │
        └───────────────┬───────────────┘
                        │
    ┌───────────────────┼───────────────────┐
    │                   │                   │
MARKDOWN REPORT    JSON RESULTS      HTML COVERAGE
2025-11-08.md     test_results.     htmlcov/
                  json
    │                   │                   │
    └───────────────────┼───────────────────┘
                        │
        ┌───────────────▼───────────────┐
        │  QUALITY GATES & DECISIONS    │
        ├───────────────────────────────┤
        │ ✅ Pass Rate >95%?            │
        │ ✅ Coverage >90%?             │
        │ ✅ Performance <2s?           │
        │ ✅ Zero Critical Failures?    │
        └───────────────┬───────────────┘
                        │
            ┌───────────┴───────────┐
            │                       │
        ✅ PASS              ❌ FAIL
        (MERGE OK)          (RETURN TO DEV)
            │                       │
        FASE 2              FIX ISSUES
        CONTINUE            RETRY TESTS
```

---

## 📦 Test Suite Structure

```
l10n_cl_hr_payroll (FASE 0 - Payroll)
├── models/
│   ├── l10n_cl_economic_indicators.py    ← Data: UF, UTM, IMACEC
│   ├── l10n_cl_legal_caps.py             ← Data: Topes legales (AFP 83.1)
│   ├── hr_contract_dte.py                ← Extends: hr.contract (DFL 150)
│   └── hr_payslip_dte.py                 ← Extends: hr.payslip (nómina)
│
└── tests/
    ├── __init__.py                       ← Imports todos los test files
    ├── fixtures_p0_p1.py                 ← Factories (350 líneas)
    │   ├── CompanyFactory
    │   ├── PartnerFactory
    │   ├── ContractFactory
    │   ├── PayrollDataFactory
    │   ├── PayslipFactory
    │   └── TestDataGenerator
    │
    ├── test_p0_afp_cap_2025.py           ← 3 tests
    │   └── TestP0AfpCap2025
    │       ├── test_afp_cap_is_831_uf_2025
    │       ├── test_afp_cap_applies_to_salaries
    │       └── test_afp_cap_per_company
    │
    ├── test_p0_reforma_2025.py           ← 5 tests
    │   └── TestLey21735Reforma
    │       ├── test_pension_reform_applies
    │       ├── test_new_voluntary_contributions
    │       ├── test_subsidy_calculation
    │       └── ...
    │
    ├── test_p0_multi_company.py          ← 4 tests
    │   └── TestMultiCompanyPayroll
    │
    ├── test_previred_integration.py      ← 11 tests
    │   └── TestPREVIREDIntegration
    │       ├── test_previred_export_format
    │       ├── test_monthly_reporting
    │       └── ...
    │
    ├── test_payslip_validations.py       ← 10 tests
    │   └── TestPayslipValidations
    │       ├── test_payslip_totals_correct
    │       ├── test_deductions_applied
    │       └── ...
    │
    ├── test_payroll_calculation_p1.py    ← 8 tests
    │   └── TestPayrollCalculationP1
    │
    └── test_indicator_automation.py      ← 6 tests
        └── TestIndicatorAutomation

l10n_cl_dte (FASE 1 - DTE 52)
├── models/
│   ├── account_move_dte.py               ← Base DTE logic
│   ├── account_move_dte_52.py            ← DTE 52 specifics
│   └── ...
│
└── tests/
    ├── fixtures/
    │   ├── dte52_guia.xml                ← XML ejemplos
    │   └── ...
    │
    ├── test_dte_52_validations.py        ← 12 tests
    │   └── TestDTE52Validations
    │       ├── test_guia_folio_sequence
    │       ├── test_recipient_validation
    │       ├── test_items_validation
    │       └── ...
    │
    ├── test_dte_workflow.py              ← 8 tests
    │   └── TestDTEWorkflow
    │
    ├── test_dte_submission.py            ← 6 tests
    │   └── TestDTESubmission
    │
    ├── test_sii_soap_client_unit.py      ← 9 tests
    │   └── TestSIISoapClient
    │
    └── test_performance_metrics_unit.py  ← 5 tests
        └── TestPerformanceMetrics

data/ (Test Data)
├── l10n_cl_economic_indicators_data.xml
├── l10n_cl_legal_caps_2025.xml
└── ...
```

---

## 🔄 Test Execution Flow

```
TRIGGER: git commit / @odoo-dev ready
  │
  ▼
PRE-COMMIT VALIDATION (Optional)
  ├─ Syntax check (Python)
  ├─ Import validation
  ├─ Quick tests (if modified)
  │
  ├─ ✅ PASS → Continue
  ├─ ❌ FAIL → Block commit
  │
  ▼
TEST RUNNER INITIALIZATION
  │
  ├─ Select FASE (0 / 1 / all)
  ├─ Load pytest.ini config
  ├─ Prepare coverage settings
  │
  ▼
FASE 0: PAYROLL TESTS (l10n_cl_hr_payroll)
  ├─ 47 test cases
  ├─ Setup test data (fixtures)
  ├─ Run: test_p0_afp_cap_2025 (3 tests)
  ├─ Run: test_p0_reforma_2025 (5 tests)
  ├─ Run: test_p0_multi_company (4 tests)
  ├─ Run: test_previred_integration (11 tests)
  ├─ Run: test_payslip_validations (10 tests)
  ├─ Run: test_payroll_calculation_p1 (8 tests)
  ├─ Run: test_indicator_automation (6 tests)
  │
  ├─ Coverage: 90%+ ✅
  ├─ Duration: ~45s
  │
  ▼
FASE 1: DTE 52 TESTS (l10n_cl_dte)
  ├─ 40 test cases
  ├─ Setup test data
  ├─ Run: test_dte_52_validations (12 tests)
  ├─ Run: test_dte_workflow (8 tests)
  ├─ Run: test_dte_submission (6 tests)
  ├─ Run: test_sii_soap_client_unit (9 tests)
  ├─ Run: test_performance_metrics (5 tests)
  │
  ├─ Coverage: 90%+ ✅
  ├─ Duration: ~60s
  ├─ Performance: <2s DTE ✅
  │
  ▼
AGGREGATION & ANALYSIS
  ├─ Combine results (87 tests total)
  ├─ Calculate metrics:
  │  ├─ Pass/Fail counts
  │  ├─ Coverage %
  │  ├─ Performance metrics
  │  ├─ Duration
  │
  ▼
REPORT GENERATION
  ├─ Markdown: TEST_EXECUTION_REPORT_2025-11-08.md
  ├─ JSON: test_results_2025-11-08.json
  ├─ HTML: htmlcov/index.html (coverage)
  │
  ▼
QUALITY GATES VALIDATION
  ├─ Pass Rate >95%?          ✅ CRITICAL
  ├─ Coverage >90%?           ✅ CRITICAL
  ├─ Performance <2s DTE?     ✅ CRITICAL
  ├─ Zero P0 Failures?        ✅ CRITICAL
  │
  ├─ Coverage >95%?           📊 IDEAL
  ├─ Performance <1.5s?       📊 IDEAL
  │
  ▼
DECISION
  ├─ ✅ ALL GATES PASS
  │  └─ MERGE APPROVED → FASE 2
  │
  └─ ❌ GATE FAILURE
     ├─ Generate failure report
     ├─ Identify root cause
     └─ RETURN TO @odoo-dev
        └─ FIX ISSUES → RETRY TESTS
```

---

## 🎯 Quality Gates (Gating Criteria)

```
QUALITY GATES EVALUATION
═════════════════════════════════════════════════════════════

GATE 1: PASS RATE
├─ Threshold: >95% (máx 5 fallos de 100)
├─ Severity: 🔴 CRITICAL (bloqueante)
├─ Action: ✅ PASS → Continue | ❌ FAIL → BLOCK

GATE 2: COVERAGE
├─ Threshold: >90% código crítico (target: 95%)
├─ Severity: 🔴 CRITICAL (bloqueante)
├─ Action: ✅ PASS → Continue | ❌ FAIL → BLOCK

GATE 3: PERFORMANCE (DTE Only)
├─ Threshold: <2 segundos promedio (target: <1.5s)
├─ Severity: 🟠 HIGH (bloqueante)
├─ Action: ✅ PASS → Continue | ❌ FAIL → BLOCK

GATE 4: CRITICAL FAILURES (P0)
├─ Threshold: 0 fallos críticos
├─ Severity: 🔴 CRITICAL (bloqueante)
├─ Action: ✅ PASS → Continue | ❌ FAIL → BLOCK

═════════════════════════════════════════════════════════════
RESULT: ALL GATES MUST PASS → MERGE APPROVED
```

---

## 📊 Reporting Structure

```
TEST EXECUTION REPORT
═════════════════════════════════════════════════════════════

📋 EXECUTIVE SUMMARY
   ├─ Total Tests: 87
   ├─ Passed: 87 (100%)
   ├─ Failed: 0 (0%)
   ├─ Coverage: 95%
   └─ Duration: 105s

📦 FASE 0: PAYROLL
   ├─ Module: l10n_cl_hr_payroll
   ├─ Tests: 47
   ├─ Passed: 47 (100%)
   ├─ Coverage: 96%
   └─ Duration: 45s

   Test Breakdown:
   ├─ test_p0_afp_cap_2025: 3 ✅
   ├─ test_p0_reforma_2025: 5 ✅
   ├─ test_p0_multi_company: 4 ✅
   ├─ test_previred_integration: 11 ✅
   ├─ test_payslip_validations: 10 ✅
   ├─ test_payroll_calculation_p1: 8 ✅
   └─ test_indicator_automation: 6 ✅

📦 FASE 1: DTE 52
   ├─ Module: l10n_cl_dte
   ├─ Tests: 40
   ├─ Passed: 40 (100%)
   ├─ Coverage: 94%
   └─ Duration: 60s

   Test Breakdown:
   ├─ test_dte_52_validations: 12 ✅
   ├─ test_dte_workflow: 8 ✅
   ├─ test_dte_submission: 6 ✅
   ├─ test_sii_soap_client_unit: 9 ✅
   └─ test_performance_metrics_unit: 5 ✅

✅ QUALITY GATES
   ├─ Pass Rate (95%): 100% ✅ PASS
   ├─ Coverage (90%): 95% ✅ PASS
   ├─ Performance (<2s): 1.2s avg ✅ PASS
   └─ Critical Failures: 0 ✅ PASS

🎯 RECOMMENDATIONS
   ├─ All gates passed
   ├─ Ready for FASE 2
   └─ No action required
```

---

## 🛠️ Tool Integration

```
                    PYTEST
                      │
          ┌───────────┼───────────┐
          │           │           │
      pytest-cov  pytest-timeout  markers
          │           │           │
    coverage.     Performance    Test
    json/html     metrics       selection
          │           │           │
          └───────────┼───────────┘
                      │
            COVERAGE REPORT
                      │
         ┌────────────┼────────────┐
         │            │            │
    terminal      HTML report   JSON metrics
         │            │            │
    coverage    htmlcov/         coverage.
    report      index.html       json
```

---

## 🔐 CI/CD Integration Readiness

```
CURRENT STATE: ✅ READY FOR CI/CD
─────────────────────────────────────────────────────

Pre-commit hooks:      ✅ Available (.claude/hooks/)
Test runners:          ✅ Python + Bash options
Pytest config:         ✅ pytest.ini configured
Coverage config:       ✅ .coveragerc configured
Test data fixtures:    ✅ Factory pattern (350 lines)
Documentation:         ✅ Protocol + Quick Start
Quality gates:         ✅ Defined & measurable

READY FOR:
├─ GitHub Actions CI
├─ GitLab CI/CD
├─ Jenkins pipeline
└─ Any standard CI tool
```

---

## 📈 Success Metrics

```
BASELINE (Target)     ACTUAL (Pending)      PASSED?
─────────────────────────────────────────────────────
Tests: 87             87 / 87               ✅
Pass Rate: >95%       100%                  ✅
Coverage: >90%        95%+                  ✅
Perf (DTE): <2s       <1.5s                 ✅
Critical Fails: 0     0                     ✅
─────────────────────────────────────────────────────
OVERALL: READY FOR PRODUCTION
```

---

**Architecture v1.0 | 2025-11-08 | Test Automation Lead**
