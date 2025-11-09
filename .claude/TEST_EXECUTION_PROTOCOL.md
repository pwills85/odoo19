# Test Execution Protocol - FASE 0-1

**Versión:** 1.0
**Actualizado:** 2025-11-08
**Estado:** Listo para Ejecución

---

## 📋 Protocolo de Ejecución de Tests

### Rol
**Test Automation Lead** - Ejecuta tests cuando código de FASE 0-1 esté completo.

### Activadores

#### FASE 0 - Cuando @odoo-dev complete Ley 21.735 (Reforma Pensiones)
```bash
# Validar cambios en modelo
git diff --stat

# Ejecutar tests FASE 0
python scripts/test_runner_fase_0_1.py --fase 0 --verbose

# ó en Docker nativo
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --test-enable --stop-after-init
```

#### FASE 1 - Cuando @odoo-dev complete DTE 52
```bash
# Validar cambios en modelo
git diff --stat

# Ejecutar tests FASE 1
python scripts/test_runner_fase_0_1.py --fase 1 --verbose

# ó en Docker nativo
docker-compose exec odoo odoo -u l10n_cl_dte --test-enable --stop-after-init
```

---

## 🧪 Suite de Tests

### FASE 0: Payroll P0-P1 (Nómina Chilena)

**Módulo:** `l10n_cl_hr_payroll`
**Objetivo:** Validar cálculos de nómina + compliance legal
**Target Coverage:** >95%

#### Test Files
| Test | Descripción | Tests | Status |
|------|-------------|-------|--------|
| `test_p0_afp_cap_2025.py` | Tope AFP 83.1 UF | 3 | 🔴 Pending |
| `test_p0_reforma_2025.py` | Ley 21.735 Reforma Pensiones | 5 | 🔴 Pending |
| `test_p0_multi_company.py` | Múltiples compañías | 4 | 🔴 Pending |
| `test_previred_integration.py` | Integración PREVIRED | 11 | 🔴 Pending |
| `test_payslip_validations.py` | Validaciones nómina | 10 | 🔴 Pending |
| `test_payroll_calculation_p1.py` | Cálculos P1 | 8 | 🔴 Pending |
| `test_indicator_automation.py` | Indicadores automáticos | 6 | 🔴 Pending |

**Total FASE 0:** 47 tests esperados
**Criterio de Éxito:** Pass >95%, Coverage >95%

### FASE 1: DTE 52 - Guía de Despacho

**Módulo:** `l10n_cl_dte` + `l10n_cl_financial_reports`
**Objetivo:** Validar emisión + recepción + reportes DTE 52
**Target Coverage:** >95%

#### Test Files
| Test | Descripción | Tests | Status |
|------|-------------|-------|--------|
| `test_dte_52_validations.py` | Validaciones DTE 52 | 12 | 🔴 Pending |
| `test_dte_workflow.py` | Workflow completo | 8 | 🔴 Pending |
| `test_dte_submission.py` | Envío a SII | 6 | 🔴 Pending |
| `test_sii_soap_client_unit.py` | Cliente SOAP SII | 9 | 🔴 Pending |
| `test_performance_metrics_unit.py` | Performance benchmarks | 5 | 🔴 Pending |

**Total FASE 1:** 40 tests esperados
**Criterio de Éxito:** Pass >95%, Coverage >95%, Performance <2s DTE

---

## 🛠️ Herramientas

### Test Runner Python
```bash
# FASE 0
python scripts/test_runner_fase_0_1.py --fase 0 --verbose

# FASE 1
python scripts/test_runner_fase_0_1.py --fase 1 --verbose

# AMBAS
python scripts/test_runner_fase_0_1.py --fase all --verbose

# Sin coverage (más rápido)
python scripts/test_runner_fase_0_1.py --fase all --no-cov
```

### Test Runner Docker Nativo
```bash
# FASE 0 (Odoo native tests)
bash scripts/test_fase_0_1_odoo_native.sh 0

# FASE 1 (Odoo native tests)
bash scripts/test_fase_0_1_odoo_native.sh 1

# AMBAS
bash scripts/test_fase_0_1_odoo_native.sh all
```

### Coverage Reports
```bash
# Ver cobertura en terminal
coverage report -m

# Ver cobertura en HTML
open htmlcov/index.html

# JSON para análisis
cat coverage.json
```

---

## 📊 Reporte Consolidado

Cuando completes ejecución, se genera automáticamente:

**Ubicación:** `evidencias/TEST_EXECUTION_REPORT_2025-11-08.md`

**Contenido:**
```markdown
# TEST EXECUTION REPORT - FASE 0-1

**Generado:** 2025-11-08 14:30:00 CLT
**Rama:** feat/f1_pr3_reportes_f29_f22

## Resumen Ejecutivo

| Métrica | FASE 0 | FASE 1 | Total |
|---------|--------|--------|-------|
| Tests Passed | 47 | 40 | 87 |
| Tests Failed | 0 | 0 | 0 |
| Success Rate | 100% | 100% | **100%** |
| Avg Duration | 45s | 60s | 105s |

## Criterios de Éxito
- [x] Tests ejecutados: 100% (87/87)
- [x] Pass rate: >95% (100%)
- [x] Coverage: >95% (FASE 0: 96%, FASE 1: 94%)
- [x] Performance DTE: <2s (avg: 1.2s)
- [x] 0 failures críticos
```

---

## ✅ Checklist de Ejecución

### Pre-Ejecución
- [ ] Código completo (feature completa)
- [ ] Branch actualizado (`git pull`)
- [ ] Docker container activo (`docker-compose up -d`)
- [ ] BD de test limpia
- [ ] Requirements instalados (`pip install -r requirements-dev.txt`)

### Ejecución
- [ ] FASE 0 tests ejecutados
  - [ ] test_p0_afp_cap_2025.py PASSED
  - [ ] test_p0_reforma_2025.py PASSED
  - [ ] test_p0_multi_company.py PASSED
  - [ ] test_previred_integration.py PASSED
  - [ ] test_payslip_validations.py PASSED
  - [ ] test_payroll_calculation_p1.py PASSED
  - [ ] test_indicator_automation.py PASSED
- [ ] FASE 1 tests ejecutados
  - [ ] test_dte_52_validations.py PASSED
  - [ ] test_dte_workflow.py PASSED
  - [ ] test_dte_submission.py PASSED
  - [ ] test_sii_soap_client_unit.py PASSED
  - [ ] test_performance_metrics_unit.py PASSED

### Post-Ejecución
- [ ] Reporte consolidado generado
- [ ] Coverage >95%
- [ ] Performance OK (<2s DTE)
- [ ] 0 failures críticos
- [ ] Commit con resultados
- [ ] PR actualizado con resultados

---

## 🎯 Criterios de Éxito Finales

### DEBE CUMPLIR (BLOQUEANTE)
✅ **Pass Rate:** >95% (máx 5 fallos de 100 tests)
✅ **Coverage:** >90% para lógica crítica
✅ **Performance DTE:** <2 segundos promedio
✅ **Zero Critical Failures:** 0 fallos críticos (P0)

### DEBE DOCUMENTAR
📋 Archivo: `evidencias/TEST_EXECUTION_REPORT_2025-11-08.md`
📊 Métricas: Tests, coverage, performance, recommendations
🔍 Failures: Detalle de fallos (si hay)
⏱️ Duration: Tiempo total de ejecución

### RECOMENDADO (NICE-TO-HAVE)
📈 Coverage >95% para toda lógica (no solo crítica)
🚀 Performance <1.5 segundos (DTE)
📝 Integration tests + UI tests (si tiempo permite)

---

## 🚨 Troubleshooting

### Error: "Module not found"
```bash
# Reinstalar módulos
docker-compose exec odoo odoo -u l10n_cl_hr_payroll,l10n_cl_dte
```

### Error: "DB locked"
```bash
# Recrear BD test
docker-compose down
docker-compose up -d
```

### Error: "Coverage <85%"
```bash
# Agregar test específico
# 1. Identificar líneas no cubiertas (htmlcov/index.html)
# 2. Escribir test que las cubra
# 3. Re-ejecutar
```

### Timeout en tests
```bash
# Aumentar timeout
pytest --timeout=300 tests/

# ó verificar Docker memory
docker stats
```

---

## 📞 Soporte

**Test Automation Lead:** Ejecuta tests según protocol
**Code Owner (@odoo-dev):** Valida que código esté listo
**QA Manager:** Revisa reportes y criterios de éxito

---

**Next Step:** Esperar indicación de @odoo-dev cuando código FASE 0-1 esté completo.
