# 🎯 INSTRUCCIÓN PARA @odoo-dev - EJECUCIÓN SPRINT 1
## Completar 2% Restante | Máxima Precisión | Zero Errors

**Fecha:** 2025-11-09  
**Agente:** `@odoo-dev`  
**Coordinador:** Senior Engineer  
**Sprint:** SPRINT 1 - Completar 2% Restante  
**Prioridad:** 🔴 CRÍTICA  
**Timeline:** 2 horas estimadas

---

## ✅ CONFIRMACIÓN DE ESTADO ACTUAL

**Estado Verificado:**
- ✅ Branch: `feat/cierre_total_brechas_profesional` activo
- ✅ SPRINT 0: 100% completado
- ✅ SPRINT 1: 98% completado
- ✅ Módulo `l10n_cl_hr_payroll`: `state=installed`, versión `19.0.1.0.0`
- ✅ Tests Core: 178/237 pasando (75%)
- ✅ Fixes P0: Todos completados

**Issues Restantes (2%):**
- ⚠️ Vista search hr.payslip comentada (P1 - Quick Win)
- ⚠️ 59 tests fallando (P1 - Requiere análisis sistemático)
- ⚠️ Warnings no bloqueantes (P2 - Deferido a SPRINT 2)

---

## 🎯 INSTRUCCIÓN: EJECUTAR SPRINT 1 (Completar 2% Restante)

**ACCIÓN CONFIRMADA:** Ejecutar **SPRINT 1** para completar el 2% restante antes de proceder con SPRINT 2.

**Seguir estrictamente:** `.claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V3.md` - Sección SPRINT 1

---

## 📋 TAREAS A EJECUTAR

### TASK 1.1: Corregir Vista Search hr.payslip (30min)

**Archivo:** `addons/localization/l10n_cl_hr_payroll/views/hr_payslip_views.xml`

**Problema:** Vista search comentada temporalmente (líneas 162-180)

**Acciones Requeridas:**

1. **Descomentar vista search:**
   - Remover comentarios `<!--` y `-->` de las líneas 161-180
   - Verificar que el campo `name` existe (debe estar en línea 164)
   - Validar sintaxis XML con `xmllint`

2. **Descomentar referencia en action:**
   - Remover comentarios de la línea 190
   - Verificar que la referencia `ref="view_hr_payslip_search"` es correcta

3. **Validar instalación:**
   ```bash
   docker exec odoo19_app odoo \
       -c /etc/odoo/odoo.conf \
       -d odoo19 \
       -i l10n_cl_hr_payroll \
       --stop-after-init \
       --log-level=error
   ```

4. **Validar funcionalidad:**
   - Verificar que la búsqueda funciona en UI
   - Probar filtros y agrupaciones

**DoD TASK 1.1:**
- ✅ Vista search descomentada y funcionando
- ✅ Instalación exitosa validada (`state=installed`)
- ✅ Búsqueda funcional en UI verificada
- ✅ Sin errores en log de instalación

**Evidencia Requerida:**
- Captura de pantalla de búsqueda funcionando
- Log de instalación sin errores
- Commit con mensaje estructurado

---

### TASK 1.2: Análisis Sistemático de Tests Fallando (1h)

**Objetivo:** Categorizar y priorizar los 59 tests fallando

**Proceso Detallado:**

1. **Ejecutar tests con log detallado:**
   ```bash
   docker exec odoo19_app odoo \
       -c /etc/odoo/odoo.conf \
       -d odoo19 \
       --test-enable \
       --stop-after-init \
       --test-tags=/l10n_cl_hr_payroll \
       --log-level=test \
       2>&1 | tee evidencias/sprint1_tests_analysis.log
   ```

2. **Categorizar fallos sistemáticamente:**
   
   **Categoría A: Previred Integration**
   - Identificar tests relacionados con Previred
   - Causas posibles: Configuración, dependencias externas, formato archivo
   - Prioridad: P1 (no bloqueante para core)
   
   **Categoría B: Multi-Company**
   - Identificar tests relacionados con multi-compañía
   - Causas posibles: Configuración compañías, ir.rules, ACL
   - Prioridad: P1 (no bloqueante para core)
   
   **Categoría C: Validation Rules**
   - Identificar tests relacionados con reglas de validación
   - Causas posibles: Constraints, validaciones de negocio
   - Prioridad: P1 (no bloqueante para core)
   
   **Categoría D: Core Functionality**
   - Identificar tests relacionados con funcionalidad core
   - Causas posibles: Campos faltantes, lógica incorrecta
   - Prioridad: P0 (bloqueante si afecta core)
   
   **Categoría E: Otros**
   - Tests que no encajan en categorías anteriores
   - Analizar caso por caso

3. **Identificar causas raíz:**
   - Para cada categoría, identificar la causa raíz más probable
   - Documentar con evidencia (`file:line`)

4. **Priorizar correcciones:**
   - P0: Core Functionality (corregir inmediatamente)
   - P1: Previred, Multi-Company, Validation Rules (SPRINT 2)
   - P2: Otros (SPRINT 2 o posteriores)

**DoD TASK 1.2:**
- ✅ Análisis completo de fallos documentado en `evidencias/sprint1_tests_analysis.md`
- ✅ Categorización realizada (tabla con categorías y conteos)
- ✅ Causas raíz identificadas (con evidencia)
- ✅ Plan de corrección definido (priorizado P0 → P1 → P2)
- ✅ Tests core identificados y priorizados

**Formato del Reporte de Análisis:**

```markdown
# Análisis Sistemático de Tests Fallando - SPRINT 1

**Fecha:** 2025-11-09
**Total Tests:** 237
**Tests Pasando:** 178 (75%)
**Tests Fallando:** 59 (25%)

## Categorización de Fallos

| Categoría | Cantidad | Prioridad | Causa Raíz Probable | Plan Corrección |
|-----------|----------|-----------|---------------------|-----------------|
| Previred Integration | X | P1 | ... | SPRINT 2 |
| Multi-Company | X | P1 | ... | SPRINT 2 |
| Validation Rules | X | P1 | ... | SPRINT 2 |
| Core Functionality | X | P0 | ... | SPRINT 1 (si crítico) |
| Otros | X | P2 | ... | SPRINT 2+ |

## Detalle por Categoría

### Categoría A: Previred Integration
- Test: `test_previred_integration.py::TestPreviredIntegration::test_export_105_campos`
- Error: ...
- Causa Raíz: ...
- Evidencia: `file:line`

[... más detalles ...]

## Plan de Corrección Priorizado

### P0 - Inmediato (SPRINT 1)
- [ ] Test X (Core Functionality)

### P1 - SPRINT 2
- [ ] Tests Previred Integration (X tests)
- [ ] Tests Multi-Company (X tests)
- [ ] Tests Validation Rules (X tests)

### P2 - SPRINT 2+
- [ ] Tests Otros (X tests)
```

**Evidencia Requerida:**
- Log completo de tests (`evidencias/sprint1_tests_analysis.log`)
- Reporte estructurado (`evidencias/sprint1_tests_analysis.md`)
- Tabla de categorización
- Plan de corrección priorizado

---

### TASK 1.3: Commit Final SPRINT 1 (30min)

**Objetivo:** Commit estructurado con toda la evidencia del SPRINT 1

**Contenido del Commit:**

1. **Cambios de código:**
   - Vista search hr.payslip descomentada
   - Cualquier otro cambio realizado

2. **Evidencias:**
   - `evidencias/sprint1_tests_analysis.log`
   - `evidencias/sprint1_tests_analysis.md`
   - Capturas de pantalla (si aplica)

3. **Documentación:**
   - Actualizar README si aplica
   - Actualizar CHANGELOG.md

**Mensaje de Commit Estructurado:**

```
feat(l10n_cl_hr_payroll): complete SPRINT 1 - 100% (vista search + análisis tests)

SPRINT 1 - Resolver Hallazgos P0 Bloqueantes (100% COMPLETADO)

Completa el 2% restante del SPRINT 1:
- Vista search hr.payslip descomentada y funcionando
- Análisis sistemático de 59 tests fallando
- Categorización y priorización de correcciones

Changes:
- views/hr_payslip_views.xml: Descomentar vista search (líneas 162-180)
  * Vista search funcionando correctamente
  * Referencia en action descomentada
- evidencias/sprint1_tests_analysis.log: Log completo de tests
- evidencias/sprint1_tests_analysis.md: Análisis sistemático de fallos
  * 59 tests categorizados (Previred, Multi-Company, Validation Rules, Core, Otros)
  * Causas raíz identificadas
  * Plan de corrección priorizado (P0 → P1 → P2)

Tests: 178/237 pasando (75%)
Module: INSTALLED (state=installed verified)
Vista Search: FUNCIONANDO ✅
Análisis Tests: COMPLETO ✅

Next Steps:
- SPRINT 2: Corregir tests P1 (Previred, Multi-Company, Validation Rules)
- SPRINT 2: P1 Quick Wins (Dashboard, DTE scope, warnings)

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V3.md SPRINT 1
```

**DoD TASK 1.3:**
- ✅ Commit estructurado realizado
- ✅ Mensaje de commit completo y profesional
- ✅ Todas las evidencias incluidas
- ✅ Documentación actualizada
- ✅ Branch listo para merge (si aplica)

---

## 📊 DEFINITION OF DONE (DoD) SPRINT 1

### Criterios Obligatorios

| Criterio | Descripción | Validación |
|----------|-------------|------------|
| **1. Vista Search Funcionando** | Vista search descomentada y operativa | Búsqueda funciona en UI |
| **2. Análisis Tests Completo** | 59 tests categorizados y priorizados | Reporte estructurado generado |
| **3. Módulo Instalado** | Módulo sigue instalado sin errores | `state=installed` verificado |
| **4. Evidencias Documentadas** | Todas las evidencias guardadas | Carpeta `evidencias/` completa |
| **5. Commit Realizado** | Commit estructurado con evidencia | Git commit realizado |

**DoD SPRINT 1:** 5/5 criterios deben cumplirse

---

## 🚨 PROTOCOLO DE EJECUCIÓN

### Paso a Paso

1. **Crear TODO List:**
   ```bash
   # Usar todo_write para trackear progreso
   ```

2. **Ejecutar TASK 1.1:**
   - Descomentar vista search
   - Validar instalación
   - Verificar funcionalidad
   - Marcar TODO como completado

3. **Ejecutar TASK 1.2:**
   - Ejecutar tests con log detallado
   - Categorizar fallos
   - Generar reporte estructurado
   - Marcar TODO como completado

4. **Ejecutar TASK 1.3:**
   - Preparar commit
   - Incluir evidencias
   - Realizar commit estructurado
   - Marcar TODO como completado

5. **Validar DoD:**
   - Verificar los 5 criterios cumplidos
   - Reportar al coordinador

6. **Reportar al Coordinador:**
   - Resumen ejecutivo del SPRINT 1
   - Evidencias generadas
   - Próximos pasos (SPRINT 2)

---

## 📋 KNOWLEDGE BASE OBLIGATORIA

**ANTES de ejecutar, consultar:**

1. `.claude/agents/knowledge/odoo19_patterns.md`
   - Sintaxis Odoo 19 para vistas search
   - Patrones de validación

2. `.codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md`
   - Contexto de hallazgos originales
   - Soluciones propuestas

3. `.claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V3.md`
   - Estructura completa del SPRINT 1
   - DoD y criterios de validación

---

## 🎯 SOPORTE DISPONIBLE

**Agentes de Soporte:**
- `@test-automation`: Disponible para ejecutar tests y análisis si necesario
- Coordinador: Disponible para consultas y validaciones

**Reportar al Coordinador:**
- Al completar cada TASK
- Si encuentras errores críticos
- Al completar SPRINT 1 completo

---

## ✅ CONFIRMACIÓN FINAL

**Instrucción Confirmada:**
- ✅ Ejecutar SPRINT 1 (completar 2% restante)
- ✅ Seguir PROMPT V3 estrictamente
- ✅ Cumplir DoD completo (5/5 criterios)
- ✅ Generar evidencias estructuradas
- ✅ Reportar al coordinador al completar

**Proceder con ejecución inmediata.**

---

**FIN DE LA INSTRUCCIÓN**

