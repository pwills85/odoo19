# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS SPRINT 2 (V5.13)
## Fase 1: Análisis Root Cause con Normativa Validada | Implementación Precisa

**Versión:** 5.13 (Fase 1: Root Cause Analysis + Implementación con Normativa Validada)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (Fase 0 completada ✅, Fase 1 iniciando)  
**Base:** PROMPT V5.12 + Log Agente Líneas 892-1029 + Hallazgos Regulatorios Validados  
**Progreso Actual:** 7 horas invertidas (Fase 0: 1.5h completada ✅)  
**Estado Real Validado:** 19 tests fallando (28 → 19 = -32% progreso acumulado ✅)

---

## ✅ RECONOCIMIENTO: FASE 0 COMPLETADA EXITOSAMENTE

### Evaluación del Trabajo Realizado (Calificación: 10/10)

**Fase 0: Investigación Regulatoria:** ✅ COMPLETADA CON EXCELENCIA

**Fortalezas Identificadas:**
- ✅ **Investigación Completa:** 4/4 problemas investigados con validación regulatoria completa
- ✅ **Hallazgos Críticos Identificados:** Detectó que el fix anterior estaba INCORRECTO
- ✅ **Fuentes Oficiales Consultadas:** DT, SP, SII, Previred con citas específicas
- ✅ **Documentación Completa:** 5 archivos de evidencia generados con referencias normativas
- ✅ **Root Cause Real Identificado:** Problema #1 no es gratificación imponible, sino otro issue

**Hallazgos Críticos Validados:**

1. **🔴 CRÍTICO #1: Fix Anterior INCORRECTO**
   - ❌ Fix anterior: `GRAT_SOPA.imponible=False` → INCORRECTO
   - ✅ Normativa validada: Gratificación SÍ es imponible (DT, SP, D.L. 3.501 Art. 28)
   - ✅ Root Cause Real: Investigar por qué `total_imponible` es ~15M vs ~7.9M esperado

2. **🔴 CRÍTICO #2: Tope AFC Desactualizado**
   - ❌ Código actual: 120.2 UF (desactualizado - circa 2021)
   - ✅ Valor correcto 2025: 131.9 UF
   - ✅ Impacto: Sub-pago de AFC para sueldos altos, tests fallando

3. **✅ CORRECTO: Cálculo Base Tributable**
   - ✅ Gratificación SÍ afecta base tributable (confirmado por SII, DL 824)
   - ✅ Sistema ya tiene implementación correcta
   - ✅ Solo validar que `GRAT_SOPA.tributable=True`

4. **🟡 MENOR: Código Incorrecto en Tests**
   - ❌ Tests buscan código 'HEALTH' (inglés)
   - ✅ Código real es 'SALUD' (español)
   - ✅ Solución: Actualizar tests

**Calificación Detallada:**

| Aspecto | Calificación | Comentario |
|---------|--------------|------------|
| **Investigación Regulatoria** | 10/10 | Investigación completa con fuentes oficiales |
| **Hallazgos Críticos** | 10/10 | Detectó que fix anterior estaba incorrecto |
| **Documentación** | 10/10 | 5 archivos de evidencia con referencias normativas |
| **Root Cause Analysis** | 10/10 | Identificó root cause real del problema #1 |
| **Protocolo Seguido** | 10/10 | Siguió protocolo V5.12 perfectamente |

**Conclusión:** Trabajo excepcional. El agente completó Fase 0 con excelencia y detectó que el fix anterior estaba incorrecto. Proceder con Fase 1: Root Cause Analysis con normativa validada.

---

## 🎯 FASE 1: ANÁLISIS ROOT CAUSE CON NORMATIVA VALIDADA (1h)

### ⚠️ PROTOCOLO OBLIGATORIO - SIN EXCEPCIONES

**El agente DEBE seguir este protocolo paso a paso, usando los hallazgos regulatorios validados.**

---

## 📋 PROBLEMA #1: total_imponible Mal Calculado (~15M vs ~7.9M Esperado)

### ⚠️ CRÍTICO: Fix Anterior Estaba INCORRECTO

**Hallazgo Regulatorio Validado:**
- ✅ Gratificación legal SÍ es imponible según normativa chilena (DT, SP, D.L. 3.501 Art. 28)
- ❌ Fix anterior (`GRAT_SOPA.imponible=False`) estaba INCORRECTO
- ✅ Root Cause Real: Investigar por qué `total_imponible` incluye ~15M cuando debería ser ~7.9M

**Pregunta Crítica:** ¿Por qué `total_imponible` es ~15M cuando debería ser ~7.9M?

**Hipótesis a Investigar:**
1. ¿Doble conteo de gratificación?
2. ¿Otras líneas incorrectamente marcadas como `imponible=True`?
3. ¿Bug en lógica de campo computado `_compute_totals()`?
4. ¿Gratificación se está calculando incorrectamente (monto muy alto)?

### Paso 1.1: Investigar Cálculo de total_imponible (20min)

**Tareas Obligatorias:**

1. **Analizar Código de `_compute_totals()`:**
   ```bash
   # Leer método completo
   grep -A 50 "_compute_totals\|total_imponible.*=" addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
   ```

2. **Verificar Qué Líneas Tienen `imponible=True`:**
   ```bash
   # Buscar todas las categorías con imponible=True
   grep -r "imponible.*True\|imponible=True" addons/localization/l10n_cl_hr_payroll/data/
   
   # Verificar categoría GRAT_SOPA
   grep -A 10 "GRAT_SOPA" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rule_category_sopa.xml
   ```

3. **Crear Script de Depuración:**
   ```python
   # Ejecutar en shell de Odoo para un payslip específico
   payslip = env['hr.payslip'].browse([ID_PAYSLIP])
   payslip.action_compute_sheet()
   
   # Ver todas las líneas con imponible=True
   imponible_lines = payslip.line_ids.filtered(
       lambda l: l.category_id and l.category_id.imponible == True
   )
   
   for line in imponible_lines:
       print(f"Code: {line.code}, Category: {line.category_id.code}, Total: {line.total}")
   
   print(f"Total Imponible Calculado: {payslip.total_imponible}")
   print(f"Suma Manual: {sum(imponible_lines.mapped('total'))}")
   ```

4. **Verificar Cálculo de Gratificación:**
   ```bash
   # Buscar cómo se calcula gratificación
   grep -r "_compute_gratification\|gratification.*amount\|GRAT" addons/localization/l10n_cl_hr_payroll/models/ --include="*.py"
   ```

**Entregable Parcial:**
- Lista de todas las líneas con `imponible=True` y sus montos
- Verificación de si gratificación se está duplicando
- Identificación de otras líneas que pueden estar causando el problema

### Paso 1.2: Identificar Root Cause Real (15min)

**Tareas Obligatorias:**

1. **Comparar Valores Esperados vs Obtenidos:**
   - Test espera: ~7.9M (sueldo base + bono)
   - Sistema obtiene: ~15M
   - Diferencia: ~7M adicionales

2. **Analizar Posibles Causas:**
   - ¿Gratificación se está calculando con monto incorrecto?
   - ¿Gratificación se está sumando dos veces?
   - ¿Otras líneas incorrectamente marcadas como imponibles?
   - ¿Bug en lógica de `_compute_totals()`?

3. **Validar con Test Específico:**
   ```bash
   # Ejecutar test específico con log detallado
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32.test_bonus_imponible \
       --log-level=test
   ```

**Entregable Parcial:**
- Root cause identificado con evidencia
- Explicación de por qué `total_imponible` es ~15M
- Solución propuesta basada en root cause real

### Paso 1.3: Documentar Root Cause (5min)

**Entregable Final Problema #1:**
- Archivo: `evidencias/fase1_root_cause_total_imponible.md`
- Contenido:
  - Root cause identificado
  - Evidencia del root cause
  - Solución propuesta
  - Referencias a normativa validada

---

## 📋 PROBLEMA #2: AFC Sin Tope Aplicado (Tope Desactualizado)

### ⚠️ CRÍTICO: Tope AFC Desactualizado

**Hallazgo Regulatorio Validado:**
- ❌ Código actual: 120.2 UF (desactualizado - circa 2021)
- ✅ Valor correcto 2025: 131.9 UF
- ✅ Impacto: Sub-pago de AFC para sueldos altos, tests fallando

**Solución:** Actualizar tope AFC de 120.2 UF a 131.9 UF en 4 archivos

### Paso 2.1: Identificar Archivos a Actualizar (5min)

**Archivos Identificados por Agente:**
1. `data/l10n_cl_legal_caps_2025.xml` - Cambiar `cap_amount`
2. `models/hr_payslip.py:1640` - Valor fallback
3. `tests/test_calculations_sprint32.py:300` - Valor en test
4. Comentarios en código

**Tareas Obligatorias:**

1. **Verificar Archivos:**
   ```bash
   # Buscar todas las referencias a 120.2
   grep -r "120\.2\|120,2" addons/localization/l10n_cl_hr_payroll/
   
   # Verificar archivo de legal caps
   grep -A 5 "AFC_CAP" addons/localization/l10n_cl_hr_payroll/data/l10n_cl_legal_caps_2025.xml
   ```

2. **Documentar Cambios Necesarios:**
   - Lista de archivos a actualizar
   - Líneas específicas a cambiar
   - Valores antiguos vs nuevos

**Entregable Parcial:**
- Lista completa de archivos a actualizar
- Líneas específicas con valores antiguos y nuevos

### Paso 2.2: Implementar Cambios (10min)

**Tareas Obligatorias:**

1. **Actualizar `data/l10n_cl_legal_caps_2025.xml`:**
   ```xml
   <!-- Cambiar de: -->
   <field name="amount">120.2</field>
   
   <!-- A: -->
   <field name="amount">131.9</field>
   ```

2. **Actualizar `models/hr_payslip.py`:**
   ```python
   # Cambiar fallback de:
   tope_afc = self.indicadores_id.uf * 120.2
   
   # A:
   tope_afc = self.indicadores_id.uf * 131.9  # Tope AFC 2025 según SP
   ```

3. **Actualizar `tests/test_calculations_sprint32.py`:**
   ```python
   # Cambiar de:
   tope_clp = self.indicators.uf * 120.2
   
   # A:
   tope_clp = self.indicators.uf * 131.9  # Tope AFC 2025 según SP
   ```

4. **Actualizar Comentarios:**
   - Actualizar todos los comentarios que mencionen 120.2 UF
   - Agregar referencia a normativa: "Tope AFC 2025 según SP: 131.9 UF"

**Entregable Parcial:**
- Cambios implementados en los 4 archivos
- Comentarios actualizados con referencias normativas

### Paso 2.3: Validar Cambios (5min)

**Tareas Obligatorias:**

1. **Verificar que Cambios se Aplicaron:**
   ```bash
   # Verificar que no quedan referencias a 120.2
   grep -r "120\.2" addons/localization/l10n_cl_hr_payroll/ | grep -v ".pyc"
   
   # Verificar que se actualizó a 131.9
   grep -r "131\.9" addons/localization/l10n_cl_hr_payroll/
   ```

2. **Ejecutar Test Específico:**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32.test_afc_tope \
       --log-level=error
   ```

**Entregable Parcial:**
- Verificación de que cambios se aplicaron correctamente
- Resultado del test específico

---

## 📋 PROBLEMA #3: Impuesto Único Mal Calculado

### ✅ CORRECTO: Implementación Ya Es Correcta

**Hallazgo Regulatorio Validado:**
- ✅ Gratificación SÍ afecta base tributable (confirmado por SII, DL 824)
- ✅ Sistema ya tiene implementación correcta con `hr.tax.bracket` model
- ✅ Solo validar que `GRAT_SOPA.tributable=True`

**Solución:** Validar que `GRAT_SOPA.tributable=True` y que cálculo funciona correctamente

### Paso 3.1: Validar Configuración (5min)

**Tareas Obligatorias:**

1. **Verificar Categoría GRAT_SOPA:**
   ```bash
   # Verificar que GRAT_SOPA tiene tributable=True
   grep -A 10 "GRAT_SOPA" addons/localization/l10n_cl_hr_payroll/data/hr_salary_rule_category_sopa.xml
   ```

2. **Verificar Cálculo de Base Tributable:**
   ```bash
   # Verificar cómo se calcula base_tributable
   grep -A 20 "base_tributable\|total_tributable\|_calculate_progressive_tax" addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
   ```

**Entregable Parcial:**
- Confirmación de que `GRAT_SOPA.tributable=True`
- Verificación de que cálculo funciona correctamente

### Paso 3.2: Investigar Por Qué Test Falla (10min)

**Tareas Obligatorias:**

1. **Ejecutar Test Específico con Log Detallado:**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32.test_tax_tramo3 \
       --log-level=test
   ```

2. **Analizar Valores Esperados vs Obtenidos:**
   - Test espera: 32,575
   - Sistema obtiene: 19,698
   - Diferencia: -12,877

3. **Verificar Cálculo de Base Tributable:**
   - ¿Base tributable se calcula correctamente?
   - ¿Se están restando descuentos previsionales correctamente?
   - ¿Gratificación se incluye en base tributable?

**Entregable Parcial:**
- Root cause identificado
- Explicación de por qué test falla
- Solución propuesta

---

## 📋 PROBLEMA #4: Línea HEALTH No Existe

### 🟡 MENOR: Código Incorrecto en Tests

**Hallazgo Regulatorio Validado:**
- ❌ Tests buscan código 'HEALTH' (inglés)
- ✅ Código real es 'SALUD' (español)
- ✅ Solución: Actualizar tests para usar 'SALUD'

**Solución:** Reemplazar 'HEALTH' → 'SALUD' en tests

### Paso 4.1: Identificar Tests a Actualizar (5min)

**Tareas Obligatorias:**

1. **Buscar Todas las Referencias a 'HEALTH':**
   ```bash
   # Buscar referencias a HEALTH en tests
   grep -r "HEALTH\|'HEALTH'\|\"HEALTH\"" addons/localization/l10n_cl_hr_payroll/tests/
   ```

2. **Verificar Código Real de Salud:**
   ```bash
   # Buscar código real de salud en reglas salariales
   grep -r "code.*SALUD\|code.*salud" addons/localization/l10n_cl_hr_payroll/data/
   ```

**Entregable Parcial:**
- Lista de archivos de tests a actualizar
- Líneas específicas a cambiar

### Paso 4.2: Actualizar Tests (5min)

**Tareas Obligatorias:**

1. **Reemplazar 'HEALTH' → 'SALUD' en Tests:**
   ```bash
   # Reemplazar en todos los archivos de tests
   find addons/localization/l10n_cl_hr_payroll/tests/ -name "*.py" -exec sed -i "s/'HEALTH'/'SALUD'/g" {} \;
   find addons/localization/l10n_cl_hr_payroll/tests/ -name "*.py" -exec sed -i "s/\"HEALTH\"/\"SALUD\"/g" {} \;
   ```

2. **Verificar Cambios:**
   ```bash
   # Verificar que no quedan referencias a HEALTH
   grep -r "HEALTH" addons/localization/l10n_cl_hr_payroll/tests/
   
   # Verificar que se actualizó a SALUD
   grep -r "SALUD" addons/localization/l10n_cl_hr_payroll/tests/
   ```

**Entregable Parcial:**
- Cambios implementados
- Verificación de que cambios se aplicaron correctamente

---

## 🎯 FASE 2: IMPLEMENTACIÓN CON NORMATIVA VALIDADA (1-1.5h)

### ⚠️ PROTOCOLO OBLIGATORIO - SOLO DESPUÉS DE FASE 1

**El agente DEBE completar Fase 1 antes de iniciar Fase 2.**

### Paso 2.1: Implementar Fixes con Referencias Normativas (45min-1h)

**Para cada problema resuelto en Fase 1:**

1. **Implementar Solución:**
   - Código debe incluir comentarios con referencias normativas
   - Ejemplo:
     ```python
     # Tope AFC 2025 según Superintendencia de Pensiones: 131.9 UF
     # Referencia: SP - Límite máximo mensual AFC (Enero 2025)
     tope_afc = self.indicadores_id.uf * 131.9
     ```

2. **Validar Cumplimiento Normativo:**
   - ¿La solución cumple con normativa validada?
   - ¿Hay otras consideraciones normativas?
   - ¿La solución es completa según normativa?

3. **Documentar Decisiones Normativas:**
   - Por qué se implementó de esta manera
   - Qué normativa lo respalda
   - Referencias específicas

### Paso 2.2: Validar Implementación (15min)

**Tareas Obligatorias:**

1. **Ejecutar Tests Específicos:**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32 \
       --log-level=error
   ```

2. **Validar que Cálculos Coinciden con Normativa:**
   - ¿Los cálculos coinciden con normativa validada?
   - ¿Los valores esperados son correctos según normativa?

---

## 🎯 FASE 3: VALIDACIÓN INCREMENTAL (15min)

### Paso 3.1: Checkpoint DESPUÉS (10min)

**Tareas Obligatorias:**

1. **Ejecutar Suite Completa de Tests:**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32 \
       --log-level=error \
       2>&1 | tee evidencias/task_2.1_after_$(date +%Y%m%d_%H%M%S).log
   ```

2. **Validar Mejora:**
   - Tests pasando: X/6
   - Comparar: ANTES vs DESPUÉS
   - Validar: Score mejoró

### Paso 3.2: Commit Estructurado con Referencias Normativas (5min)

**Formato de Commit:**

```
fix(tests): resolve test_calculations_sprint32 with regulatory validation

Root Cause Analysis (Phase 1):
- Problema #1: [Root cause identificado con evidencia]
- Problema #2: AFC tope desactualizado (120.2 → 131.9 UF)
- Problema #3: [Root cause identificado]
- Problema #4: Tests usaban código incorrecto ('HEALTH' → 'SALUD')

Regulatory Validation (Phase 0):
- Gratificación SÍ es imponible según DT, SP, D.L. 3.501 Art. 28
- Tope AFC 2025: 131.9 UF según Superintendencia de Pensiones
- Base tributable correcta según SII, DL 824
- Código salud: 'SALUD' según especificación Previred

Fixes Implementados:
- [Descripción técnica de cada fix]
- Referencias normativas incluidas en código
- Comentarios con citas específicas de normativa

Regulatory References:
- DT: [URL específica]
- SP: [URL específica]
- SII: [URL específica]
- Previred: [URL específica]
- D.L. 3.501 Art. 28
- DL 824

Tests Resolved: 0/6 → 6/6 (100%)
Coverage: 82% → 88% (estimado)
Time: X minutes

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_13.md TASK 2.1
```

---

## 📊 PROYECCIÓN ACTUALIZADA

### Tiempo Estimado

| Fase | Tiempo | Estado |
|------|--------|--------|
| **Fase 0** | 1.5h | ✅ COMPLETADA |
| **Fase 1** | 1h | ⏳ INICIANDO |
| **Fase 2** | 1-1.5h | ⏳ PENDIENTE |
| **Fase 3** | 15min | ⏳ PENDIENTE |
| **Total** | **3.75-4.25h** | **En progreso** |

---

## ✅ CONCLUSIÓN Y RECOMENDACIÓN

### Estado Actual

**Fase 0 Completada:** ✅ EXCELENTE
- Investigación regulatoria completa con fuentes oficiales
- Hallazgos críticos identificados (fix anterior incorrecto)
- Documentación completa con referencias normativas
- Root cause real identificado para problema #1

**Próximos Pasos:**

1. **Fase 1: Root Cause Analysis (1h)**
   - Investigar root cause real del problema #1
   - Validar configuración de problema #3
   - Documentar root causes con evidencia

2. **Fase 2: Implementación (1-1.5h)**
   - Implementar fixes con referencias normativas
   - Validar cumplimiento normativo
   - Documentar decisiones normativas

3. **Fase 3: Validación (15min)**
   - Checkpoint DESPUÉS
   - Commit estructurado con referencias normativas

**Recomendación:**

**El agente DEBE:**

1. **INICIAR Fase 1: Root Cause Analysis AHORA**
2. **Seguir protocolo paso a paso sin saltar ningún paso**
3. **Usar hallazgos regulatorios validados de Fase 0**
4. **NO revertir fix anterior sin investigar root cause real primero**
5. **Implementar fixes con referencias normativas en código**

**Objetivo:** Resolver los 6 tests fallando con soluciones validadas por normativa chilena.

---

**FIN DEL PROMPT MASTER V5.13**

