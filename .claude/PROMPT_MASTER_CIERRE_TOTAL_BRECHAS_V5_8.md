# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS SPRINT 2 (V5.8)
## Progreso Validado | Continuación Fase 1 | Máxima Precisión

**Versión:** 5.8 (Progreso Validado - Continuación Fase 1)  
**Fecha:** 2025-11-09  
**Estado:** EN PROGRESO (Fase 1 parcialmente completada)  
**Base:** PROMPT V5.7 + Log Agente Líneas 915-1033  
**Progreso Actual:** 2.5 horas invertidas (Fase 1)  
**Estado Real Validado:** 21 tests fallando (28 → 21 = -25% progreso ✅)

---

## ✅ RECONOCIMIENTO DE PROGRESO REAL

### Trabajo Completado Correctamente

**TASK 1.1: test_apv_calculation** ✅ COMPLETADO AL 100%
- Tests resueltos: 2/2 (100%)
- Commit generado: Estructurado y documentado
- Evidencia: `evidencias/task_1.1_after.log`
- **Calificación:** 10/10 - Trabajo profesional, validación incremental correcta

**TASK 1.2: test_ley21735_reforma_pensiones** ⚠️ PARCIALMENTE COMPLETADO (67%)
- Tests resueltos: 4/6 (67%)
- Progreso: 6 errores → 2 errores (67% reducción)
- Commit generado: Estructurado con estado parcial documentado
- **Calificación:** 9/10 - Excelente trabajo, documentación honesta del estado parcial

**TASK 1.3: CHECKPOINT FASE 1** ✅ COMPLETADO CORRECTAMENTE
- Suite completa ejecutada
- Métricas exactas documentadas
- Progreso real validado: 28 → 21 tests fallando (-25%)
- **Calificación:** 10/10 - Protocolo seguido correctamente

### Métricas de Progreso Real

| Métrica | Inicial | Fase 1 | Progreso |
|---------|---------|--------|----------|
| **Total Fallando** | 28 | 21 | **-25% ✅** |
| **FAIL** | 10 | 8 | -20% |
| **ERROR** | 18 | 13 | -28% |
| **Tiempo Invertido** | 0h | 2.5h | En línea con estimación |

**Conclusión:** El agente está siguiendo el PROMPT V5.7 correctamente y haciendo progreso real.

---

## ⚠️ PRINCIPIOS FUNDAMENTALES (MANTENER ESTRICTOS)

### 🚫 REGLA #1: SIN IMPROVISACIÓN
- ✅ **MANTENER:** Solo ejecutar tareas explícitamente definidas
- ✅ **MANTENER:** Validar estado real ANTES de reportar progreso
- ✅ **MANTENER:** Ejecutar tests DESPUÉS de cada fix

### 🚫 REGLA #2: SIN PARCHES
- ✅ **MANTENER:** Soluciones arquitectónicamente correctas
- ✅ **MANTENER:** Entender causa raíz antes de implementar
- ✅ **MANTENER:** NO crear workarounds temporales

### 🎯 REGLA #3: MÁXIMA PRECISIÓN
- ✅ **MANTENER:** Reportar métricas exactas (no estimadas)
- ✅ **MANTENER:** Documentar evidencia de cada cambio
- ✅ **MANTENER:** Checkpoint después de cada fix

### 💼 REGLA #4: TRABAJO PROFESIONAL
- ✅ **MANTENER:** Commits estructurados y descriptivos
- ✅ **MANTENER:** Documentación completa de decisiones
- ✅ **MANTENER:** Honestidad en reporte de estado parcial

---

## 📋 TAREAS PENDIENTES (CONTINUACIÓN FASE 1)

### TASK 1.2 COMPLETAR: Resolver 2 Tests Pendientes (30-45min) ⚠️ PRIORIDAD ALTA

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 30-45min  
**Estado:** 4/6 tests resueltos (67%), 2 tests pendientes

**Tests Pendientes Identificados:**

1. **test_06: validation_blocks_missing_aporte** (FAIL)
   - Problema: Validación no se dispara como esperado
   - Ubicación: `test_ley21735_reforma_pensiones.py:test_06`
   - Validación esperada: `@api.constrains` en `hr.payslip` línea 614

2. **test_09: wage_cero_no_genera_aporte** (ERROR)
   - Problema: Modelo rechaza wage=0 (validación `_check_wage_positive`)
   - Ubicación: `test_ley21735_reforma_pensiones.py:test_09`
   - Validación encontrada: `hr_contract_stub_ce.py:206`

**PROTOCOLO OBLIGATORIO:**

#### 1. Análisis Root Cause (15min)

**Para test_06:**

**Análisis del Test:**
- El test crea una nómina y la calcula (línea 326)
- Fuerza `aplica_ley21735=True` pero `employer_total_ley21735=0` (líneas 329-332)
- Intenta confirmar con `payslip.action_done()` (línea 336)
- Espera que se lance `ValidationError` con mensaje que contenga 'Ley 21.735' y 'aporte empleador'

**Análisis de la Validación:**
- La validación existe en `hr_payslip.py:614-634`
- Usa `@api.constrains('state', 'aplica_ley21735', 'employer_total_ley21735')`
- Se ejecuta cuando `state == 'done'` y `aplica_ley21735=True` y `employer_total_ley21735 <= 0`

**Problema Identificado:**
- La validación se ejecuta cuando `state` cambia a `'done'`
- `action_done()` probablemente hace `write({'state': 'done'})`
- El `@api.constrains` debería ejecutarse automáticamente cuando `state` cambia
- **Posible causa:** La validación se ejecuta pero el mensaje de error no coincide con lo esperado por el test

**Solución Arquitectónica:**

**Opción A: Validación Existe Pero Mensaje No Coincide**
- Verificar que el mensaje de error contiene 'Ley 21.735' y 'aporte empleador'
- El mensaje actual (línea 628-633) parece correcto
- **Verificar:** ¿Se está ejecutando la validación pero el test no la captura?

**Opción B: Validación No Se Ejecuta Por Timing**
- `action_done()` podría cambiar `state` antes de que se ejecute la validación
- **Solución:** Asegurar que la validación se ejecute en el momento correcto
```python
def action_done(self):
    """
    Marcar como pagado
    
    Técnica Odoo 19 CE:
    - Validaciones se ejecutan automáticamente con @api.constrains
    - No necesitamos llamar validación manualmente
    """
    # Las validaciones @api.constrains se ejecutan automáticamente
    # cuando hacemos write({'state': 'done'})
    self.write({'state': 'done'})
    return True
```

**Opción C: Validación Necesita Ajuste en Condición**
- Verificar que la condición del `@api.constrains` captura el cambio correctamente
- **Solución:** Asegurar que todos los campos están en la lista de constraints
```python
@api.constrains('state', 'aplica_ley21735', 'employer_total_ley21735')
def _validate_ley21735_before_confirm(self):
    """
    Validación Ley 21.735 antes de confirmar nómina
    
    Técnica Odoo 19 CE:
    - @api.constrains se ejecuta cuando cualquiera de los campos cambia
    - Validar solo cuando state cambia a 'done'
    """
    for payslip in self:
        # Validar solo cuando se confirma (state='done')
        if payslip.state == 'done' and payslip.aplica_ley21735:
            if not payslip.employer_total_ley21735 or payslip.employer_total_ley21735 <= 0:
                raise ValidationError(
                    f"Error Ley 21.735 - Nómina {payslip.name}\n\n"
                    f"Esta nómina está afecta a Ley 21.735 (período desde 01-08-2025) "
                    f"pero no tiene aporte empleador calculado.\n\n"
                    f"Período: {payslip.date_from} - {payslip.date_to}\n"
                    f"Aporte calculado: ${payslip.employer_total_ley21735:,.0f}\n\n"
                    f"Verifique que el contrato tenga remuneración imponible válida."
                )
```

**Recomendación:** Verificar primero si la validación se está ejecutando pero el mensaje no coincide. Si no se ejecuta, usar **Opción B** o **Opción C** según corresponda.

**Para test_09:**

1. **Leer Validación `_check_wage_positive`:**
   ```bash
   grep -A 15 "_check_wage_positive" addons/localization/l10n_cl_hr_payroll/models/hr_contract_stub_ce.py
   ```

2. **Analizar Test:**
   ```bash
   grep -A 30 "def test_09" addons/localization/l10n_cl_hr_payroll/tests/test_ley21735_reforma_pensiones.py
   ```

3. **Decisión Arquitectónica:**
   - ¿El test es incorrecto? (wage=0 no debería ser válido)
   - ¿La validación es demasiado estricta? (wage=0 debería permitirse en casos especiales)
   - **NO crear parche**, decidir arquitectónicamente qué es correcto

#### 2. Implementación (15-20min)

**Para test_06:**

**Opción A: Validación No Existe**
```python
# En hr_payslip.py, agregar validación arquitectónicamente correcta
@api.constrains('state', 'aplica_ley21735', 'employer_total_ley21735')
def _check_ley21735_aporte(self):
    """
    Validar que contratos desde 2025-01-01 tienen aporte Ley 21.735 calculado
    
    Técnica Odoo 19 CE:
    - Validación antes de confirmar nómina
    - Mensaje claro de error
    """
    for record in self:
        if record.state == 'done':
            # Validar solo si aplica Ley 21.735
            if record.aplica_ley21735 and not record.employer_total_ley21735:
                raise ValidationError(_(
                    'Contratos desde 2025-01-01 deben tener aporte Ley 21.735 calculado. '
                    'Recalcule la nómina antes de confirmar.'
                ))
```

**Opción B: Validación Existe Pero No Se Dispara**
- Analizar condición de `@api.constrains`
- Verificar que campos están correctamente configurados
- Ajustar condición si es necesario

**Para test_09:**

**Análisis del Test:**
- El test intenta crear un contrato con `wage=0` (línea 446)
- El test espera que NO se genere aporte si `wage=0`
- La validación `_check_wage_positive` (línea 206) rechaza `wage <= 0`

**Problema Identificado:**
- El test intenta crear contrato con `wage=0` pero la validación lo rechaza
- El test no puede ejecutarse porque falla en la creación del contrato

**Decisión Arquitectónica Requerida:**

**Opción A: Test Incorrecto (wage=0 no debería ser válido según normativa chilena)**
- Según normativa chilena, un contrato debe tener sueldo base > 0
- La validación `_check_wage_positive` es correcta
- **Solución:** Modificar test para usar wage mínimo válido en lugar de 0
```python
# Modificar test para usar wage mínimo válido
def test_09_wage_cero_no_genera_aporte(self):
    """Test que wage mínimo no genera aporte (no wage=0)"""
    # Usar wage mínimo válido pero muy bajo (ej: 1000 CLP)
    # O usar wage que genere aporte = 0 por redondeo
    contract = self.env['hr.contract'].create({
        'name': 'Contrato Sin Sueldo',
        'employee_id': self.employee.id,
        'wage': 1000,  # Muy bajo, pero válido
        'date_start': date(2025, 8, 1),
        'state': 'open',
        'afp_id': self.afp.id
    })
    # Verificar que aporte = 0 por redondeo o por ser muy bajo
```

**Opción B: Validación Demasiado Estricta (wage=0 debería permitirse en casos especiales)**
- Si hay casos especiales donde wage=0 es válido (contratos suspendidos, etc.)
- **Solución:** Modificar validación para permitir wage=0 en casos específicos
```python
# Modificar validación para permitir wage=0 en casos especiales
@api.constrains('wage')
def _check_wage_positive(self):
    """
    Validar wage positivo, excepto casos especiales
    
    Técnica Odoo 19 CE:
    - Permitir wage=0 solo en casos específicos documentados
    - Por defecto, wage debe ser > 0
    """
    for record in self:
        # Permitir wage=0 solo si está suspendido o en casos especiales
        if record.wage == 0 and record.state not in ('suspended', 'special_case'):
            raise ValidationError(_('El sueldo base debe ser mayor a cero.'))
```

**Recomendación:** Seguir **Opción A** (test incorrecto) porque según normativa chilena, un contrato debe tener sueldo base > 0. La validación es correcta.

#### 3. Checkpoint DESPUÉS (5min)

```bash
docker-compose run --rm odoo odoo -d odoo19 \
    --test-enable --stop-after-init \
    --test-tags=/l10n_cl_hr_payroll:TestLey21735ReformaPensiones \
    --log-level=error \
    2>&1 | tee evidencias/task_1.2_complete_after.log
```

**Validaciones:**
- ✅ Tests pasando: 6/6 (100%)
- ✅ Sin errores en log
- ✅ Comparar: ANTES (4/6) vs DESPUÉS (6/6)

#### 4. Commit Estructurado (5min)

```
fix(tests): complete test_ley21735_reforma_pensiones (6/6 tests)

- Fix test_06_validation_blocks_missing_aporte
  - [Descripción técnica del fix]
- Fix test_09_wage_cero_no_genera_aporte
  - [Descripción técnica del fix]
  
Tests Resolved: 4/6 → 6/6 (100%)
Coverage: 76% → 82% (estimado)
Time: X minutes

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_8.md TASK 1.2 COMPLETAR
```

**DoD TASK 1.2 COMPLETAR:**
- ✅ Tests pasando: 6/6 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada (logs antes/después)
- ✅ Decisión arquitectónica documentada

---

### TASK 2.1: CORREGIR test_calculations_sprint32 (1.5-2h) ⚠️ SIGUIENTE PRIORIDAD

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 1.5-2h  
**Complejidad:** MEDIA

**Estado Actual:**
- 6 tests fallando (todos FAIL, no ERROR):
  - `test_afc_tope`: FAIL
  - `test_allowance_colacion`: FAIL
  - `test_bonus_imponible`: FAIL
  - `test_full_payslip_with_inputs`: FAIL
  - `test_tax_tramo1_exento`: FAIL
  - `test_tax_tramo3`: FAIL

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 1.1 pero con más tiempo)

1. **Checkpoint ANTES (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32 \
       --log-level=error \
       2>&1 | tee evidencias/task_2.1_before.log
   ```
   - Documentar: Tests pasando ANTES: X/6
   - Documentar: Errores específicos encontrados

2. **Análisis Root Cause (30min):**
   - Leer código de cada test fallando
   - Identificar qué esperan vs qué reciben
   - Analizar código de cálculo relacionado
   - **NO IMPLEMENTAR** hasta entender completamente

3. **Implementación (45min-1h):**
   - Implementar solución arquitectónicamente correcta
   - Seguir estándares Odoo 19 CE
   - **NO crear parches o workarounds**
   - Documentar decisiones técnicas en código

4. **Checkpoint DESPUÉS (5min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll:TestPayrollCalculationsSprint32 \
       --log-level=error \
       2>&1 | tee evidencias/task_2.1_after.log
   ```
   - Documentar: Tests pasando DESPUÉS: X/6
   - Comparar: ANTES vs DESPUÉS
   - Validar: Score mejoró

5. **Commit Estructurado (5min):**
   ```
   fix(tests): resolve test_calculations_sprint32 failures (6/6 tests)

   - Fix test_afc_tope
   - Fix test_allowance_colacion
   - Fix test_bonus_imponible
   - Fix test_full_payslip_with_inputs
   - Fix test_tax_tramo1_exento
   - Fix test_tax_tramo3
   - [Descripción técnica de fixes]
   
   Tests Resolved: 0/6 → 6/6 (100%)
   Coverage: 82% → 88% (estimado)
   Time: X minutes
   
   Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5_8.md TASK 2.1
   ```

**DoD TASK 2.1:**
- ✅ Tests pasando: 6/6 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada (logs antes/después)

---

### TASK 2.2: CORREGIR test_payslip_totals (15-30min) ⚠️ QUICK WIN

**Agente Responsable:** `@test-automation`  
**Agente Soporte:** `@odoo-dev`  
**Prioridad:** P1 - ALTA  
**Estimación:** 15-30min  
**Complejidad:** BAJA

**Estado Actual:**
- 1 test fallando: FAIL (no ERROR, más fácil de resolver)

**PROTOCOLO OBLIGATORIO:** (Igual que TASK 1.1 pero más rápido)

1. Checkpoint ANTES
2. Análisis Root Cause (5min)
3. Implementación (10-15min)
4. Checkpoint DESPUÉS
5. Commit Estructurado

**DoD TASK 2.2:**
- ✅ Tests pasando: 1/1 (100%)
- ✅ Sin errores en log
- ✅ Commit estructurado generado
- ✅ Evidencia documentada

---

### TASK 2.3: CHECKPOINT FASE 2 (15min) ⚠️ OBLIGATORIO

**Agente Responsable:** `@odoo-dev`  
**Agente Soporte:** `@test-automation`  
**Prioridad:** P0 - CRÍTICA  
**Estimación:** 15min

**PROTOCOLO OBLIGATORIO:**

1. **Ejecutar Suite Completa (10min):**
   ```bash
   docker-compose run --rm odoo odoo -d odoo19 \
       --test-enable --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll \
       --log-level=error \
       2>&1 | tee evidencias/checkpoint_fase2_$(date +%Y%m%d_%H%M%S).log
   ```

2. **Analizar Resultados (5min):**
   - Documentar: Tests pasando: X/17
   - Documentar: Cobertura: X%
   - Documentar: Errores restantes: N
   - Comparar: Estado inicial vs Estado actual

3. **Decisión:**
   - ✅ Si score mejoró: Continuar con Fase 3
   - ⚠️ Si score no mejoró: Analizar root cause antes de continuar
   - ❌ Si score empeoró: Detener y re-evaluar estrategia

**DoD TASK 2.3:**
- ✅ Suite completa ejecutada
- ✅ Métricas exactas documentadas
- ✅ Decisión tomada con evidencia
- ✅ Reporte generado

---

## 📊 PROYECCIÓN ACTUALIZADA

### Cobertura Esperada

| Fase | Tests | Cobertura | Tiempo |
|------|-------|-----------|--------|
| **Actual** | 12/17 | 76% | 2.5h |
| **Tras TASK 1.2 Completar** | 14/17 | 82% | +30-45min |
| **Tras TASK 2.1** | 20/17* | 100%* | +1.5-2h |
| **Tras TASK 2.2** | 21/17* | 100%* | +15-30min |
| **Tras TASK 2.3 (Checkpoint)** | Validación | Validación | +15min |
| **Tras Fase 3 (Alta Complejidad)** | 17/17 | 100% | +2-3h |
| **Final (DoD)** | 17/17 | 100% | +30min |

*Nota: Algunos tests pueden ser subtests, por eso puede haber más de 17 tests individuales

**Total Estimado Restante:** 4.5-6 horas adicionales (7-8.5 horas totales)

---

## 🎯 ORDEN DE EJECUCIÓN OBLIGATORIO

### FASE 1 COMPLETAR (30-45min)

1. ✅ **TASK 1.2 COMPLETAR:** Resolver 2 tests pendientes (30-45min)
   - test_06: validation_blocks_missing_aporte
   - test_09: wage_cero_no_genera_aporte

### FASE 2 CONTINUAR (2-2.5 horas)

2. ✅ **TASK 2.1:** Corregir test_calculations_sprint32 (1.5-2h)
3. ✅ **TASK 2.2:** Corregir test_payslip_totals (15-30min)
4. ✅ **TASK 2.3:** CHECKPOINT FASE 2 (15min) - OBLIGATORIO

### FASE 3 (2-3 horas)

5. ⏳ **TASK 3.1:** Corregir test_lre_generation (2-3h)
6. ⏳ **TASK 3.2:** Corregir test_p0_multi_company (2-3h)
7. ⏳ **TASK 3.3:** Validación Final y DoD (30min)

---

## ✅ CONCLUSIÓN Y RECOMENDACIÓN

### Estado Actual

**Progreso Real Validado:**
- ✅ 28 → 21 tests fallando (-25% progreso)
- ✅ TASK 1.1 completado al 100%
- ✅ TASK 1.2 completado al 67% (parcial)
- ✅ Protocolo de validación incremental seguido correctamente
- ✅ Commits estructurados y documentados

**Próximos Pasos:**
1. Completar TASK 1.2 (2 tests pendientes)
2. Continuar con Fase 2 (TASK 2.1 y 2.2)
3. Ejecutar CHECKPOINT FASE 2
4. Continuar con Fase 3 si score mejoró

### Recomendación

**Continuar con el protocolo establecido:**
- ✅ Mantener principios estrictos (SIN IMPROVISACIÓN, SIN PARCHES)
- ✅ Validación incremental obligatoria después de cada fix
- ✅ Documentar decisiones arquitectónicas
- ✅ Reportar métricas exactas (no estimadas)

**Objetivo:** 100% cobertura (17/17 tests) con trabajo profesional, robusto y de máxima precisión.

---

**FIN DEL PROMPT MASTER V5.8**

