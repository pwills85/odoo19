# Test Automation Quick Start - FASE 0-1

**Rol:** Test Automation Lead
**Objetivo:** Ejecutar tests automatizados cuando código esté listo
**Tiempo estimado:** 10 minutos de configuración + ejecución

---

## ⚡ Quick Start (5 min)

### 1. Setup (Una sola vez)
```bash
cd /Users/pedro/Documents/odoo19

# Instalar pytest + plugins
pip install -r requirements-dev.txt

# Hacer scripts ejecutables
chmod +x scripts/test_runner_fase_0_1.py
chmod +x scripts/test_fase_0_1_odoo_native.sh
chmod +x .claude/hooks/pre-commit-test-validation.sh

# Crear directorio para reportes
mkdir -p evidencias
```

### 2. Ejecutar Tests

#### Opción A: Python Runner (Recomendado para CI/CD)
```bash
# FASE 0 - Nómina
python scripts/test_runner_fase_0_1.py --fase 0

# FASE 1 - DTE 52
python scripts/test_runner_fase_0_1.py --fase 1

# AMBAS
python scripts/test_runner_fase_0_1.py --fase all

# Con verbose + coverage
python scripts/test_runner_fase_0_1.py --fase all --verbose
```

#### Opción B: Odoo Native Tests (Recomendado para desarrollo)
```bash
# FASE 0
bash scripts/test_fase_0_1_odoo_native.sh 0

# FASE 1
bash scripts/test_fase_0_1_odoo_native.sh 1

# AMBAS
bash scripts/test_fase_0_1_odoo_native.sh all
```

#### Opción C: pytest directamente (Para tests específicos)
```bash
# FASE 0 con coverage
cd addons/localization/l10n_cl_hr_payroll
pytest tests/test_p0_afp_cap_2025.py -v --cov=..

# FASE 1 con coverage
cd ../../l10n_cl_dte
pytest tests/test_dte_52_validations.py -v --cov=..

# Todos tests
pytest tests/ --cov=addons/localization/l10n_cl_dte,addons/localization/l10n_cl_hr_payroll
```

### 3. Ver Resultados
```bash
# Reporte markdown
cat evidencias/TEST_EXECUTION_REPORT_2025-11-08.md

# Cobertura en terminal
coverage report

# Cobertura en browser
open htmlcov/index.html

# JSON con resultados
cat evidencias/test_results_2025-11-08.json
```

---

## 📦 Estructura de Tests

### FASE 0: Nómina (l10n_cl_hr_payroll)
```
addons/localization/l10n_cl_hr_payroll/
├── tests/
│   ├── __init__.py
│   ├── fixtures_p0_p1.py          ← Factories para test data
│   ├── test_p0_afp_cap_2025.py    ← AFP tope 83.1 UF
│   ├── test_p0_reforma_2025.py    ← Ley 21.735
│   ├── test_p0_multi_company.py   ← Multi-company
│   ├── test_previred_integration.py
│   ├── test_payslip_validations.py
│   ├── test_payroll_calculation_p1.py
│   └── test_indicator_automation.py
├── models/
│   ├── l10n_cl_economic_indicators.py
│   ├── l10n_cl_legal_caps.py
│   ├── hr_payslip_dte.py
│   └── ...
└── data/
    ├── l10n_cl_economic_indicators_data.xml
    ├── l10n_cl_legal_caps_2025.xml
    └── ...
```

### FASE 1: DTE 52 (l10n_cl_dte)
```
addons/localization/l10n_cl_dte/
├── tests/
│   ├── __init__.py
│   ├── fixtures/
│   │   ├── dte52_guia.xml
│   │   └── ...
│   ├── smoke/
│   │   └── smoke_xsd_dte52.py
│   ├── test_dte_52_validations.py
│   ├── test_dte_workflow.py
│   ├── test_dte_submission.py
│   ├── test_sii_soap_client_unit.py
│   └── test_performance_metrics_unit.py
├── models/
│   ├── account_move_dte.py
│   ├── account_move_dte_52.py
│   └── ...
└── libs/
    ├── dte_generator.py
    ├── xml_signer.py
    └── sii_soap_client.py
```

---

## 🧪 Criterios de Éxito

### FASE 0
- [x] Archivos de test creados
- [ ] Tests ejecutados: 47 tests
- [ ] Pass rate: >95%
- [ ] Coverage: >90% crítica, >95% ideal
- [ ] Reporte generado

### FASE 1
- [x] Archivos de test creados
- [ ] Tests ejecutados: 40 tests
- [ ] Pass rate: >95%
- [ ] Coverage: >90% crítica, >95% ideal
- [ ] Performance <2s DTE
- [ ] Reporte generado

---

## 📊 Ejemplo de Reporte

```markdown
# TEST EXECUTION REPORT - FASE 0-1

## Resumen Ejecutivo

| Métrica | FASE 0 | FASE 1 | Total |
|---------|--------|--------|-------|
| Tests Ejecutados | 47 | 40 | 87 |
| Tests Pasados | 47 | 40 | 87 |
| Tests Fallidos | 0 | 0 | 0 |
| Pass Rate | 100% | 100% | **100%** |
| Coverage | 96% | 94% | **95%** |
| Duration | 45s | 60s | 105s |

## Resultados por Módulo

| Módulo | Passed | Failed | Coverage |
|--------|--------|--------|----------|
| l10n_cl_hr_payroll | 47 | 0 | 96% ✅ |
| l10n_cl_dte | 30 | 0 | 93% ✅ |
| l10n_cl_financial_reports | 10 | 0 | 95% ✅ |

## Criterios de Éxito
- [x] Tests ejecutados: 100%
- [x] Pass rate: >95%
- [x] Coverage: >90% crítica
- [x] Performance: <2s
- [x] Zero critical failures
```

---

## 🔧 Troubleshooting

### "Module not found"
```bash
# Verificar modulo está instalado
docker-compose exec odoo odoo --help | grep l10n_cl

# Instalar si falta
docker-compose exec odoo odoo -u l10n_cl_dte
```

### "DB locked / Connection refused"
```bash
# Restart Docker
docker-compose down
docker-compose up -d

# Verificar BD está UP
docker-compose exec db psql -U odoo -d odoo19_test -c "SELECT 1"
```

### "Coverage < 85%"
```bash
# Ver qué líneas no están cubiertas
open htmlcov/index.html

# Identificar gaps
grep -r "pragma: no cover" addons/localization/l10n_cl_dte/

# Escribir test para esa línea
# Re-ejecutar pytest
```

### "Test timeout"
```bash
# Usar timeout mayor
pytest tests/ --timeout=300

# ó en runner
python scripts/test_runner_fase_0_1.py --fase all --verbose
```

---

## 🚀 Flujo Completo

```
1. @odoo-dev completa código FASE 0-1
   ↓
2. Test Lead ejecuta: python scripts/test_runner_fase_0_1.py --fase all
   ↓
3. Resultado:
   - Si PASS: ✅ Continuar con FASE 2
   - Si FAIL: 🔴 Retornar a @odoo-dev con reporte
   ↓
4. Generar reporte: evidencias/TEST_EXECUTION_REPORT_2025-11-08.md
   ↓
5. Commit + Push + PR update
```

---

## 📝 Checklist Pre-Ejecución

- [ ] `git pull` (última versión)
- [ ] `docker-compose up -d` (contenedores UP)
- [ ] `pip install -r requirements-dev.txt` (dependencias OK)
- [ ] `mkdir -p evidencias` (directorio reportes)
- [ ] BD test limpia (sin datos previos)

---

## 📞 Contacto

**Test Automation Lead:** Pedro (@test-lead)
**Documentación:** `.claude/TEST_EXECUTION_PROTOCOL.md`
**Fixtures:** `tests/fixtures_p0_p1.py`

---

**¡Listo para ejecutar tests cuando código esté completo!**
