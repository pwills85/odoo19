# BASELINE FASE 0 - Métricas Iniciales
## Fecha: 2025-11-07

**Objetivo:** Establecer métricas de rendimiento, cobertura y calidad antes de los PRs de Fase 0 para medir mejoras y detectar regresiones.

---

## 📊 Métricas de Rendimiento (Estimadas)

### DTE - Dashboard y Operaciones

| Operación | Tiempo Estimado | Consultas SQL | Estado |
|-----------|----------------|---------------|--------|
| **Dashboard DTE carga inicial** | ~3-5s | 100-150 (no medido) | ⚠️ SIN BASELINE |
| **Envío DTE al SII** | 500ms-60s+ | 20-30 | 🔴 **SIN TIMEOUT** |
| **Generación XML DTE** | 50-100ms | 10-15 | ✅ Aceptable |
| **Firma XML** | 30-50ms | 5 | ✅ Aceptable |

**Issues Detectados:**
- 🔴 **CRÍTICO:** SII SOAP client SIN timeout configurado → workers pueden colgar indefinidamente
- ⚠️ Dashboard sin mediciones p50/p95 formales

### Nómina - Cálculo de Liquidación

| Operación | Tiempo Estimado | Consultas SQL | Estado |
|-----------|----------------|---------------|--------|
| **Cálculo payslip individual** | 200-500ms | 30-50 | ⚠️ No medido |
| **Generación LRE (10 empleados)** | 2-5s | 50-100 | ⚠️ No medido |
| **Regla TOPE_IMPONIBLE_UF** | - | 2-3 | 🔴 **BLOQUEANTE** |

**Issues Detectados:**
- 🔴 **CRÍTICO:** Regla TOPE_IMPONIBLE_UF busca campo inexistente → NO FUNCIONA
- ⚠️ Fallback hardcoded 81.6 UF * 38000

### Reportes Financieros

| Operación | Tiempo Estimado | Consultas SQL | Estado |
|-----------|----------------|---------------|--------|
| **Balance Sheet (100 cuentas)** | <2s | 30-40 | ✅ Cumple objetivo |
| **Income Statement** | <2s | 30-40 | ✅ Cumple objetivo |
| **F29 cálculo** | - | - | 🔴 **NO FUNCIONAL** |
| **F22 cálculo** | - | - | 🔴 **NO FUNCIONAL** |

**Issues Detectados:**
- 🔴 F29 y F22 no operativos (ver PR-3)

---

## 🧪 Cobertura de Tests (Estimada)

### Global

| Módulo | Tests Ejecutables | Cobertura Estimada | Estado |
|--------|-------------------|-------------------|--------|
| **l10n_cl_dte** | ~15 smoke tests | ~60-70% | ⚠️ Sin suite unificada |
| **l10n_cl_hr_payroll** | 14 tests (P1) | ~92% (declarado) | ✅ Buena cobertura |
| **l10n_cl_financial_reports** | 26 tests (Sprint 1) | ~90% (estimado) | ✅ Buena cobertura |
| **GLOBAL** | ~55 tests | **~70%** | 🟡 Debajo objetivo 85% |

**Issues Detectados:**
- Sin suite pytest unificada
- Sin medición de cobertura global ejecutable
- Sin QueryCounter en tests críticos

### Tests Faltantes Críticos

- ❌ DTE: SOAP timeout/retry (PR-1 lo agregará)
- ❌ Nómina: Tope AFP dinámico con vigencias (PR-2 lo agregará)
- ❌ Reportes: F29 cálculo básico (PR-3 lo agregará)
- ❌ Finiquito: No existe (PR-4 lo agregará)
- ❌ Previred: No existe (PR-5 lo agregará)

---

## 🔒 Seguridad y Compliance

### ACLs

| Categoría | Estado | Issues |
|-----------|--------|--------|
| **DTE Models** | 🟡 Parcial | 16 modelos sin ACLs |
| **Nómina Models** | ✅ Completo | ACLs correctos (incluye LRE post quick-win) |
| **Reportes Models** | ⚠️ Incompleto | Falta validación multi-company |

### Validaciones

| Categoría | Estado | Issues |
|-----------|--------|--------|
| **Hardcoding valores legales** | 🔴 Presente | Fallback 81.6 UF, tabla impuesto hardcoded |
| **Multi-compañía** | 🟡 Parcial | DTE y Nómina OK; Reportes sin validar |
| **i18n** | 🟡 Parcial | DTE parcial, Nómina faltante, Reportes OK |

---

## 📈 Métricas de Código

### Complejidad (Estimada)

| Módulo | LOC Python | LOC Tests | Ratio | Complejidad |
|--------|-----------|-----------|-------|-------------|
| **l10n_cl_dte** | ~16,000 | ~2,000 | 8:1 | Alta |
| **l10n_cl_hr_payroll** | ~8,000 | ~1,200 | 6.7:1 | Media |
| **l10n_cl_financial_reports** | ~6,000 | ~1,500 | 4:1 | Baja-Media |

### Lint y Calidad

| Herramienta | Estado | Issues Estimados |
|-------------|--------|------------------|
| **flake8/ruff** | ⚠️ No ejecutado global | ~50-100 warnings menores |
| **pylint** | ⚠️ No ejecutado global | ~20-30 conventions |
| **mypy** | ❌ No configurado | N/A |

---

## 🎯 Objetivos Fase 0 (Post PR-1 y PR-2)

### Rendimiento Target

| Métrica | Baseline | Target Post-PR1/PR2 | Mejora Esperada |
|---------|----------|---------------------|-----------------|
| **SOAP SII timeout config** | ❌ No | ✅ Sí (10s/30s) | Elimina workers colgados |
| **SOAP SII retry** | ❌ No | ✅ Sí (3x backoff) | +Robustez ante fallos SII |
| **Tope AFP dinámico** | ❌ Roto | ✅ Funcional con vigencias | Desbloquea P2 Nómina |
| **Tests SOAP client** | 0 | ≥3 (timeout, retry, happy) | +Confianza |
| **Tests tope AFP** | 0 específicos | ≥2 (feliz, negativo) | +Confianza |

### Cobertura Target

| Módulo Tocado | Baseline | Target | Ganancia |
|---------------|----------|--------|----------|
| **sii_soap_client.py** | ~0% tests | ≥90% | +90% |
| **hr_salary_rules_p1.xml** | ~95% (reglas) | ≥95% | Mantiene |
| **GLOBAL** | ~70% | ~72% | +2% (pequeño incremento) |

### Issues Cerrados Target

- ✅ DTE-C002: SOAP timeout (CRÍTICO)
- ✅ NOM-C001: Tope AFP (CRÍTICO)
- **Total Fase 0 primera ola:** 2/10 críticos cerrados (20%)

---

## 📋 Baseline de Herramientas QA

### Ejecutables Actuales

```bash
# Lint (si existe configuración)
ruff check addons/localization/
flake8 addons/localization/

# Tests Odoo
odoo-bin -d test_db --test-enable --stop-after-init -u l10n_cl_dte

# Tests pytest (no configurado global)
pytest addons/localization/l10n_cl_hr_payroll/tests/

# Coverage (no configurado global)
pytest --cov=addons/localization --cov-report=html
```

### Faltantes Pre-Fase0

- ❌ pytest.ini global
- ❌ .coveragerc global
- ❌ compliance_check.py automatizado
- ❌ CI pipeline GitHub Actions
- ❌ Pre-commit hooks

---

## 🔬 Metodología de Medición

### Rendimiento

**No medido actualmente.** Post-Fase0 se implementará:

```python
# Usar en tests críticos
from time import time
from odoo.tests.common import TransactionCase

class TestPerformance(TransactionCase):
    def test_soap_send_performance(self):
        start = time()
        # Acción
        duration = time() - start
        self.assertLess(duration, 2.0, "SOAP send debe < 2s")
```

### QueryCounter

**No implementado actualmente.** Post-Fase0 se implementará:

```python
# Usar en tests críticos
from odoo.tests.common import BaseCase

class TestQueries(BaseCase):
    def test_payslip_calculate_queries(self):
        with self.assertQueryCount(max_count=50):
            payslip.compute_sheet()
```

---

## 📊 Resumen Ejecutivo

### Estado Pre-Fase0

| Categoría | Score | Comentario |
|-----------|-------|------------|
| **Rendimiento** | 🟡 60/100 | Sin timeouts SOAP; sin métricas formales |
| **Tests** | 🟡 70/100 | Cobertura ~70%; sin suite unificada |
| **Seguridad** | 🟡 65/100 | ACLs parciales; hardcoding presente |
| **i18n** | 🟡 60/100 | Parcial en DTE/Nómina; OK en Reportes |
| **Documentación** | 🟢 80/100 | Buena en general; falta compliance docs |

**Score Global:** **67/100** (ACEPTABLE con mejoras necesarias)

### Impacto Esperado Post-PR1/PR2

| Categoría | Pre | Post | Delta |
|-----------|-----|------|-------|
| **Rendimiento** | 60 | 70 | +10 (timeouts + robustez) |
| **Tests** | 70 | 73 | +3 (nuevos tests SOAP + AFP) |
| **Seguridad** | 65 | 66 | +1 (elimina hardcode AFP) |
| **Issues Críticos** | 10 | 8 | -2 (20% reducción) |

**Score Global Proyectado:** **69/100** (+2 puntos)

---

## 🚀 Próximos Pasos

1. **Ejecutar PR-1:** DTE-SOAP-TIMEOUT
2. **Ejecutar PR-2:** NOMINA-TOPE-AFP
3. **Crear compliance_check.py**
4. **Actualizar este baseline** con métricas reales post-implementación
5. **Comparar:** Baseline vs Post-PRs en sección "Resultados"

---

**Documento Vivo:** Este baseline se actualizará con mediciones reales una vez implementados los PRs y ejecutados los tests.

**Fecha Creación:** 2025-11-07
**Responsable:** Claude Code - Agente QA
**Versión:** 1.0

---

## 🧩 Integración con script de compliance (automático)

Para estandarizar la captura y comparación de métricas, se incorpora el script `scripts/compliance_check.py` con los siguientes modos:

- `--baseline`: genera un archivo JSON con métricas crudas (lint, cobertura pytest, i18n, escaneo básico de seguridad). No requiere Odoo corriendo.
- `--report`: imprime un resumen comparativo contra objetivos por defecto (configurables) y puede fallar el proceso si hay regresiones u objetivos incumplidos.

Ejemplos (opcional):

```bash
# Generar baseline cruda (JSON) en .compliance/
python3 scripts/compliance_check.py --baseline -o .compliance/baseline_2025-11-07.json

# Generar reporte comparando contra la baseline previa y fallar si empeora
python3 scripts/compliance_check.py --report --compare .compliance/baseline_2025-11-07.json --fail-on-regression
```

Métricas que captura automáticamente hoy:

- Lint count (ruff/flake8 si están instalados).
- Cobertura global (pytest + coverage si están instalados).
- Cobertura i18n aproximada para `es_CL` y `en_US` (conteo de msgstr no vacíos vs total en archivos .po).
- Escaneo básico de patrones de riesgo en código Python (`eval`, `exec`, `os.system`, `subprocess` con `shell=True`).

Limitaciones actuales:

- No mide aún tiempos de operaciones (SOAP, dashboards) ni consultas SQL; esas métricas se integrarán vía tests en Fase 1 con QueryCounter y cronometraje.

## 🗂️ Historial

| Fecha       | Cambio                                      | Autor        | Hash |
|-------------|---------------------------------------------|--------------|------|
| 2025-11-07  | Creación inicial del baseline                | Claude Code  | TBD  |
| 2025-11-07  | Se documenta integración con compliance     | Copilot      | TBD  |
