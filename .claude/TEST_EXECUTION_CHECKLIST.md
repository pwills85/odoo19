# Test Execution Checklist - FASE 0-1

**Rol:** Test Automation Lead
**Objetivo:** Ejecutar tests cuando código esté completo
**Tiempo estimado:** 45 minutos

---

## ✅ Pre-Execution Checklist

### Environment Setup (5 min)
- [ ] Git branch actualizada: `git pull origin feat/f1_pr3_reportes_f29_f22`
- [ ] Docker containers UP: `docker-compose ps` (odoo + db)
- [ ] BD test limpia (sin datos previos)
- [ ] Python dependencies instaladas: `pip install -r requirements-dev.txt`
- [ ] Test directory exists: `mkdir -p evidencias`

### Code Readiness
- [ ] @odoo-dev ha completado FASE 0 (Payroll) código
  - [ ] Models actualizados
  - [ ] Tests escritos
  - [ ] Data files completos
- [ ] @odoo-dev ha completado FASE 1 (DTE 52) código
  - [ ] Models actualizados
  - [ ] Tests escritos
  - [ ] Data files completos

### Script Verification (2 min)
- [ ] Test runners ejecutables:
  ```bash
  chmod +x scripts/test_runner_fase_0_1.py
  chmod +x scripts/test_fase_0_1_odoo_native.sh
  ```
- [ ] Fixtures accessible:
  ```bash
  ls addons/localization/l10n_cl_hr_payroll/tests/fixtures_p0_p1.py
  ```

---

## 🧪 FASE 0 Execution (10 min)

### Option A: Python Runner (Recomendado)
```bash
cd /Users/pedro/Documents/odoo19
python scripts/test_runner_fase_0_1.py --fase 0 --verbose
```

**Expected Output:**
```
================================================================================
🧪 EJECUTANDO FASE 0: Payroll P0-P1
================================================================================

📦 Ejecutando: l10n_cl_hr_payroll
   Comando: pytest addons/localization/l10n_cl_hr_payroll --cov=...
```

**Checklist:**
- [ ] Tests starting...
- [ ] test_p0_afp_cap_2025.py PASSED (3 tests)
- [ ] test_p0_reforma_2025.py PASSED (5 tests)
- [ ] test_p0_multi_company.py PASSED (4 tests)
- [ ] test_previred_integration.py PASSED (11 tests)
- [ ] test_payslip_validations.py PASSED (10 tests)
- [ ] test_payroll_calculation_p1.py PASSED (8 tests)
- [ ] test_indicator_automation.py PASSED (6 tests)
- [ ] **Total: 47 tests PASSED**
- [ ] Coverage: >90%

### Option B: Odoo Native (Si prefieres Docker)
```bash
bash scripts/test_fase_0_1_odoo_native.sh 0
```

### Validate Results
```bash
# Check if report was generated
ls -lah evidencias/

# View report
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md
```

---

## 🧪 FASE 1 Execution (10 min)

### Option A: Python Runner (Recomendado)
```bash
python scripts/test_runner_fase_0_1.py --fase 1 --verbose
```

**Expected Output:**
```
================================================================================
🧪 EJECUTANDO FASE 1: DTE 52 Guía de Despacho
================================================================================

📦 Ejecutando: l10n_cl_dte
   Comando: pytest addons/localization/l10n_cl_dte --cov=...
```

**Checklist:**
- [ ] Tests starting...
- [ ] test_dte_52_validations.py PASSED (12 tests)
- [ ] test_dte_workflow.py PASSED (8 tests)
- [ ] test_dte_submission.py PASSED (6 tests)
- [ ] test_sii_soap_client_unit.py PASSED (9 tests)
- [ ] test_performance_metrics_unit.py PASSED (5 tests)
- [ ] **Total: 40 tests PASSED**
- [ ] Coverage: >90%
- [ ] Performance: <2s DTE

### Option B: Odoo Native
```bash
bash scripts/test_fase_0_1_odoo_native.sh 1
```

---

## 📊 Quality Gates Validation (5 min)

### Gate 1: Pass Rate
```bash
# Verify from report
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md | grep -i "success rate"
```

- [ ] **Pass Rate: >95%** ✅ (Expected: 100%)
  - [ ] FASE 0: 47/47 PASSED (100%)
  - [ ] FASE 1: 40/40 PASSED (100%)
  - [ ] TOTAL: 87/87 PASSED (100%)

### Gate 2: Coverage
```bash
# Terminal report
coverage report -m

# HTML report
open htmlcov/index.html
```

- [ ] **Coverage: >90%** ✅ (Expected: 95%+)
  - [ ] l10n_cl_hr_payroll: 96%+ ✅
  - [ ] l10n_cl_dte: 94%+ ✅
  - [ ] Combined: 95%+ ✅

### Gate 3: Performance (DTE)
```bash
# Check from report
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md | grep -i "duration\|performance"
```

- [ ] **Performance: <2s DTE** ✅ (Expected: <1.5s)
  - [ ] Average: <2s ✅
  - [ ] P95: <2.5s ✅

### Gate 4: Critical Failures
```bash
# Check from report
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md | grep -i "failed\|error"
```

- [ ] **Critical Failures: 0** ✅
  - [ ] P0 failures: 0 ✅
  - [ ] P1 failures: 0 ✅

---

## 📝 Report Generation (3 min)

### Verify Report Files
```bash
ls -lah evidencias/
```

- [ ] **TEST_EXECUTION_REPORT_2025-11-08.md** ✅
  - [ ] Markdown report with results
  - [ ] Coverage metrics
  - [ ] Performance data

- [ ] **test_results_2025-11-08.json** ✅
  - [ ] JSON format results
  - [ ] Machine-readable format

- [ ] **htmlcov/index.html** ✅
  - [ ] HTML coverage report
  - [ ] Browsable format

### Review Report Summary
```bash
# Read markdown report
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md

# Check JSON results
cat evidencias/test_results_2025-11-08.json | python -m json.tool
```

- [ ] Report contains:
  - [ ] Execution timestamp
  - [ ] FASE 0 results (47 tests)
  - [ ] FASE 1 results (40 tests)
  - [ ] Coverage percentages
  - [ ] Performance metrics
  - [ ] Quality gates status

---

## 🎯 DECISION POINT

### If ALL Quality Gates PASS ✅
```
✅ Pass Rate >95%
✅ Coverage >90%
✅ Performance <2s
✅ Zero critical failures

ACTION: APPROVE FOR MERGE → FASE 2
```

Proceed to:
- [ ] Commit results
- [ ] Create PR update
- [ ] Approve merge
- [ ] Continue FASE 2

### If ANY Quality Gate FAILS ❌
```
Example: Coverage <90%
or Pass Rate <95%
or Performance >2s

ACTION: RETURN TO @odoo-dev WITH REPORT
```

Steps:
1. [ ] Save report with failure details
2. [ ] Identify root cause:
   - [ ] Failing tests (which ones?)
   - [ ] Coverage gaps (which files?)
   - [ ] Performance issue (which tests?)
3. [ ] Send report to @odoo-dev
4. [ ] Provide recommendations:
   - [ ] Write additional tests
   - [ ] Optimize performance
   - [ ] Fix failing tests
5. [ ] Retry execution after fixes

---

## 📋 Post-Execution Checklist

### Documentation
- [ ] Test results documented
- [ ] Coverage report reviewed
- [ ] Performance metrics recorded
- [ ] Failures analyzed (if any)

### Version Control
- [ ] Results committed to git
- [ ] Branch up-to-date
- [ ] PR updated with results

### Communication
- [ ] Results shared with @odoo-dev
- [ ] Status updated in ticket
- [ ] Team notified

### Cleanup
- [ ] Coverage reports reviewed
- [ ] Test artifacts preserved
- [ ] Database in clean state

---

## 🚀 Quick Reference Commands

### Run Everything at Once
```bash
# Execute all tests + generate report
python scripts/test_runner_fase_0_1.py --fase all --verbose

# Check results
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md
open htmlcov/index.html
```

### Run Individual Tests
```bash
# FASE 0 only
python scripts/test_runner_fase_0_1.py --fase 0 --verbose

# FASE 1 only
python scripts/test_runner_fase_0_1.py --fase 1 --verbose

# Docker native
bash scripts/test_fase_0_1_odoo_native.sh all
```

### View Results
```bash
# Terminal coverage
coverage report -m

# Browser coverage
open htmlcov/index.html

# Results in markdown
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md

# Results in JSON
cat evidencias/test_results_2025-11-08.json
```

---

## ⏱️ Timeline

| Step | Task | Duration | Status |
|------|------|----------|--------|
| 1 | Pre-execution setup | 5 min | ⬜ |
| 2 | FASE 0 tests | 10 min | ⬜ |
| 3 | FASE 1 tests | 10 min | ⬜ |
| 4 | Quality gates validation | 5 min | ⬜ |
| 5 | Report generation | 3 min | ⬜ |
| 6 | Decision & documentation | 10 min | ⬜ |
| **TOTAL** | **Complete execution** | **45 min** | ⬜ |

---

## 🆘 Troubleshooting

### "Module not found" Error
```bash
# Verify module installation
docker-compose exec odoo odoo --help | grep l10n_cl

# Reinstall
docker-compose exec odoo odoo -u l10n_cl_dte
```

### "DB locked" or "Connection refused"
```bash
# Restart Docker
docker-compose down
docker-compose up -d

# Verify DB is UP
docker-compose exec db psql -U odoo -d odoo19_test -c "SELECT 1"
```

### "Coverage < 85%"
```bash
# View which lines aren't covered
open htmlcov/index.html

# Run with coverage
coverage report -m

# Add test for uncovered lines
# Re-run tests
```

### "Test timeout"
```bash
# Use longer timeout
pytest tests/ --timeout=300 -v

# Check if Docker has enough memory
docker stats
```

### "Results not generated"
```bash
# Check if report path exists
ls -la evidencias/

# Re-run with verbose
python scripts/test_runner_fase_0_1.py --fase all --verbose

# Check for errors in output
tail -100 /tmp/test_output.log
```

---

## 📞 Support

**Issues?** Check:
- [ ] `.claude/TEST_EXECUTION_PROTOCOL.md` (Complete protocol)
- [ ] `.claude/TEST_AUTOMATION_QUICK_START.md` (Quick reference)
- [ ] `.claude/TEST_AUTOMATION_DIAGRAM.md` (Architecture)

**Need Help?**
- Contact: Test Automation Lead
- Documentation: `.claude/` directory
- Scripts: `scripts/` directory

---

## ✅ Final Checklist

Before considering execution complete:

- [ ] All pre-execution checks passed
- [ ] FASE 0 tests executed (47 tests)
- [ ] FASE 1 tests executed (40 tests)
- [ ] All quality gates validated
- [ ] Report generated (markdown + JSON)
- [ ] Coverage reviewed
- [ ] Performance acceptable
- [ ] Documentation complete
- [ ] Results communicated
- [ ] Decision made (merge/retry)

---

**Status:** ✅ READY FOR EXECUTION

**Next Step:** Wait for @odoo-dev to complete FASE 0-1 code, then execute checklist
