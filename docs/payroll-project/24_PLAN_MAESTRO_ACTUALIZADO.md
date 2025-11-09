# 📋 PLAN MAESTRO ACTUALIZADO - Sistema Nóminas Chile

**Fecha Actualización:** 2025-10-22  
**Estado:** Incorpora hallazgos SOPA 2025  
**Objetivo:** 60/100 → 95/100 (Excelencia Mundial)

---

## 🎯 CAMBIOS PRINCIPALES

### **ANTES (Plan Original)**
- Sprint 3.1: Testing (16h)
- Sprint 3.2: Cálculos (8h)
- Sprint 3.3: Performance (6h)
- Sprint 3.4: Previred (8h)
- **Total:** 38 horas

### **AHORA (Plan Actualizado)**
- **Sprint 3.0: MIGRAR SOPA 2025 (8h)** 🔴 NUEVO
- Sprint 3.1: Testing (16h)
- Sprint 3.2: Cálculos Completos (8h)
- Sprint 3.3: Performance (6h)
- Sprint 3.4: Previred (8h)
- **Total:** 46 horas

---

## 🔴 FASE 1: CRÍTICO (46 horas - 6 días)

### **SPRINT 3.0: MIGRAR SOPA 2025** (8h - 1 día) 🆕

**Objetivo:** Traer estructura probada de Odoo 11

**Justificación:**
- ✅ Sistema probado 2+ años en producción
- ✅ Compatible 100% con Odoo 19 CE
- ✅ Solo cambios sintácticos (decoradores)
- ✅ Ahorra 2-3 semanas de diseño
- ✅ Riesgo BAJO

**Sub-tareas:**
1. **Fase 0: Preparación** (30min)
   - Backup módulo actual
   - Crear branch Git
   - Identificar archivos

2. **Fase 1: Estructura** (3h)
   - Extender modelo `hr_salary_rule_category`
   - Crear 13 categorías base
   - Crear 9 categorías SOPA

3. **Fase 2: Totalizadores** (2h)
   - Agregar computed fields en `hr_payslip`
   - `total_imponible`, `total_tributable`, etc.

4. **Fase 3: Cálculos** (2h)
   - Refactorizar `_calculate_afp()`
   - Refactorizar `_calculate_tax()`
   - Usar totalizadores

5. **Fase 4: Testing** (30min)
   - Tests unitarios
   - Validación jerarquía

**Entregables:**
- ✅ 22 categorías configuradas
- ✅ Jerarquía parent/child funcionando
- ✅ Flags: imponible, tributable, afecta_gratificacion
- ✅ 4 totalizadores computed
- ✅ Cálculos usando bases correctas

**Documentos:**
- `21_MIGRACION_SOPA_2025_ODOO11_A_ODOO19.md`
- `22_COMPATIBILIDAD_SOPA_2025_ODOO19.md`
- `23_PLAN_IMPLEMENTACION_SOPA_2025.md`

---

### **SPRINT 3.1: TESTING** (16h - 2 días)

**Sin cambios** - Mantiene plan original

**Entregables:**
- 153 tests (80% coverage)
- Tests unitarios Odoo (45)
- Tests AI-Service (20)
- Tests integración (32)
- Tests E2E (8)

---

### **SPRINT 3.2: CÁLCULOS COMPLETOS** (8h - 1 día)

**Actualizado:** Ahora usa estructura SOPA

**Cambios:**
- ✅ Usa `total_imponible` (no sueldo directo)
- ✅ Usa `total_tributable` (no cálculo manual)
- ✅ Usa `total_gratificacion_base`

**Entregables:**
- Impuesto único 7 tramos ✅
- Gratificación legal ✅
- Asignaciones familiares ✅
- Colación y movilización ✅

---

### **SPRINT 3.3: PERFORMANCE** (6h - 1 día)

**Sin cambios** - Mantiene plan original

**Entregables:**
- Índices DB
- Cache Redis
- Performance <100ms p95

---

### **SPRINT 3.4: PREVIRED** (8h - 1 día)

**Sin cambios** - Mantiene plan original

**Entregables:**
- Generator 105 campos
- Wizard export
- Validación formato

---

## 🟡 FASE 2: IMPORTANTE (21 horas - 3 días)

**Sin cambios** - Mantiene plan original

### **SPRINT 4.1: FINIQUITO** (6h)
### **SPRINT 4.2: MONITORING** (4h)
### **SPRINT 4.3: CI/CD** (4h)
### **SPRINT 4.4: DOCS** (4h)
### **SPRINT 4.5: SECURITY + UX** (3h)

---

## 📊 COMPARATIVA PLANES

| Aspecto | Plan Original | Plan Actualizado | Diferencia |
|---------|---------------|------------------|------------|
| **Duración Fase 1** | 38h (5d) | 46h (6d) | +8h (+1d) |
| **Duración Fase 2** | 21h (3d) | 21h (3d) | Sin cambio |
| **Total** | 59h (7.5d) | 67h (8.5d) | +8h (+1d) |
| **Scoring Final** | 95/100 | 95/100 | Sin cambio |
| **Riesgo** | Medio | Bajo | ✅ Mejora |

---

## ✅ VENTAJAS DEL PLAN ACTUALIZADO

### **1. Menor Riesgo**
- Sistema probado vs diseño nuevo
- 2+ años en producción
- Sin reclamos legales

### **2. Mejor Arquitectura**
- 22 categorías vs 4
- Jerarquía clara
- Flags explícitos

### **3. Compliance 100%**
- Estructura validada por DT
- Cálculos correctos garantizados
- Previred compatible

### **4. Ahorro Neto**
- +8h migración SOPA
- -24h diseño nuevo
- **Ahorro: 16 horas**

---

## 📋 ORDEN DE EJECUCIÓN

### **Secuencia Crítica:**

```
1. Sprint 3.0: MIGRAR SOPA 2025 (8h)
   ↓ BLOQUEANTE
2. Sprint 3.1: Testing (16h)
   ↓
3. Sprint 3.2: Cálculos (8h)
   ↓
4. Sprint 3.3: Performance (6h)
   ↓
5. Sprint 3.4: Previred (8h)
   ↓
6. Fase 2: Importante (21h)
```

**CRÍTICO:** Sprint 3.0 debe ejecutarse PRIMERO.  
Sin estructura SOPA, los cálculos serán incorrectos.

---

## 🎯 HITOS

| Hito | Sprint | Scoring | Estado |
|------|--------|---------|--------|
| **Estructura Legal** | 3.0 | 60→70 | Pendiente |
| **Testing Base** | 3.1 | 70→80 | Pendiente |
| **Cálculos Completos** | 3.2 | 80→85 | Pendiente |
| **Performance** | 3.3 | 85→88 | Pendiente |
| **Previred** | 3.4 | 88→90 | Pendiente |
| **Finiquito** | 4.1 | 90→92 | Pendiente |
| **Monitoring** | 4.2 | 92→93 | Pendiente |
| **CI/CD** | 4.3 | 93→94 | Pendiente |
| **Docs + Security** | 4.4-4.5 | 94→95 | Pendiente |

---

## 📊 MÉTRICAS DE ÉXITO

| Métrica | Actual | Objetivo | Gap |
|---------|--------|----------|-----|
| **Scoring** | 60/100 | 95/100 | -35 |
| **Tests** | 0/153 | 153 | -153 |
| **Categorías** | 4 | 22 | -18 |
| **Totalizadores** | 1 | 4 | -3 |
| **Performance** | ~500ms | <100ms | -400ms |
| **Compliance** | 50% | 100% | -50% |

---

## ✅ RECOMENDACIÓN

**APROBAR PLAN ACTUALIZADO**

**Razones:**
1. ✅ Incorpora sistema probado (SOPA 2025)
2. ✅ Reduce riesgo legal
3. ✅ Mejor arquitectura
4. ✅ Solo +1 día adicional
5. ✅ Ahorro neto de 16 horas

**Próximo paso:** Ejecutar Sprint 3.0

---

## 📚 DOCUMENTOS DEL PROYECTO

### **Análisis y Planificación**
1. `00_MASTER_PLAN.md` - Plan original
2. `18_GAPS_ANALYSIS_EXCELENCIA.md` - Análisis gaps
3. `19_PLAN_CIERRE_BRECHAS.md` - Plan original cierre
4. `24_PLAN_MAESTRO_ACTUALIZADO.md` - **Este documento**

### **Análisis SOPA 2025**
5. `20_ESTRUCTURA_SALARIAL_CHILE.md` - Problema identificado
6. `21_MIGRACION_SOPA_2025_ODOO11_A_ODOO19.md` - Análisis migración
7. `22_COMPATIBILIDAD_SOPA_2025_ODOO19.md` - Compatibilidad técnica
8. `23_PLAN_IMPLEMENTACION_SOPA_2025.md` - Plan ejecutable

### **Implementación**
9. `03_IMPLEMENTATION_PHASES.md` - Fases detalladas
10. `06_TESTING_STRATEGY.md` - Estrategia testing

---

**Documento generado:** 2025-10-22  
**Versión:** 2.0  
**Estado:** ✅ PLAN ACTUALIZADO - LISTO PARA EJECUCIÓN
