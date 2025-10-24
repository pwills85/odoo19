# 🚀 FASES DE IMPLEMENTACIÓN (Detalle por Sprint)

**Proyecto:** l10n_cl_hr_payroll  
**Duración:** 10 semanas | 10 sprints  
**Equipo:** 2 devs

---

## FASE 1: CORE (4 semanas)

### **SPRINT 1 (Semana 1): Fundamentos**

**Objetivo:** Estructura base del proyecto

| Día | Tarea | Responsable | Entregable |
|-----|-------|-------------|------------|
| 1-2 | Setup proyecto (Docker, CI/CD) | DevOps | Infraestructura |
| 3-4 | Modelos base Odoo | Dev Odoo | 5 modelos |
| 5 | Migraciones SQL | Dev Python | Scripts SQL |

**Entregables:**
- ✅ Docker Compose funcionando
- ✅ 5 modelos creados
- ✅ 20 tests unitarios
- ✅ CI/CD configurado

---

### **SPRINT 2 (Semana 2): Calculadoras**

**Objetivo:** Payroll-Service con 3 calculadoras

| Día | Tarea | Responsable | Entregable |
|-----|-------|-------------|------------|
| 1-2 | AFPCalculator | Dev Python | Endpoint + 10 tests |
| 3-4 | HealthCalculator | Dev Python | Endpoint + 8 tests |
| 5 | TaxCalculator | Dev Python | Endpoint + 15 tests |

**Entregables:**
- ✅ 3 calculadoras funcionando
- ✅ 33 tests pasando
- ✅ API REST documentada (OpenAPI)
- ✅ Performance <100ms p95

---

### **SPRINT 3 (Semana 3): Integración**

**Objetivo:** Odoo ↔ Payroll-Service

| Día | Tarea | Responsable | Entregable |
|-----|-------|-------------|------------|
| 1-2 | API Client (retry, circuit breaker) | Dev Odoo | Cliente robusto |
| 3-4 | compute_sheet() | Dev Odoo | Liquidación básica |
| 5 | Views básicas | Dev Odoo | UI operativa |

**Entregables:**
- ✅ Integración completa
- ✅ Liquidación básica funcional
- ✅ 15 tests integración

---

### **SPRINT 4 (Semana 4): Gratificación + Reforma**

**Objetivo:** Features avanzadas

| Día | Tarea | Responsable | Entregable |
|-----|-------|-------------|------------|
| 1-2 | GratificationCalculator | Dev Python | Endpoint + 8 tests |
| 3-4 | Reforma 2025 (aporte empleador) | Dev Python | Endpoint + 6 tests |
| 5 | Testing E2E | Ambos | Bug fixing |

**Entregables:**
- ✅ Gratificación legal
- ✅ Reforma 2025
- ✅ Sistema core completo
- ✅ 68 tests totales

---

## FASE 2: COMPLIANCE (3 semanas)

### **SPRINT 5 (Semana 5): Previred**

| Día | Tarea | Entregable |
|-----|-------|------------|
| 1-2 | PreviredGenerator (105 campos) | Endpoint + 12 tests |
| 3-4 | Wizard Previred | UI funcional |
| 5 | Certificado F30-1 | Reporte PDF |

**Entregables:**
- ✅ Archivo Previred válido
- ✅ Wizard operativo
- ✅ 16 tests

---

### **SPRINT 6 (Semana 6): Finiquito**

| Día | Tarea | Entregable |
|-----|-------|------------|
| 1-2 | SettlementCalculator | Endpoint + 10 tests |
| 3-4 | Modelo + Wizard | UI completa |
| 5 | Reporte finiquito | PDF legal |

**Entregables:**
- ✅ Finiquito completo
- ✅ 18 tests

---

### **SPRINT 7 (Semana 7): Audit Trail**

| Día | Tarea | Entregable |
|-----|-------|------------|
| 1-2 | Modelo audit | hr_payroll_audit.py |
| 3-4 | Integración hooks | Tracking automático |
| 5 | Reportes audit | Vista + exportación |

**Entregables:**
- ✅ Audit trail completo
- ✅ Compliance Art. 54 CT
- ✅ 6 tests

---

## FASE 3: IA (3 semanas)

### **SPRINT 8 (Semana 8): Validación IA**

| Día | Tarea | Entregable |
|-----|-------|------------|
| 1-2 | Validación contratos (Claude) | Endpoint + 8 tests |
| 3-4 | Detección anomalías | Endpoint + 10 tests |
| 5 | Integración Odoo | UI warnings |

**Entregables:**
- ✅ Validación IA
- ✅ 23 tests

---

### **SPRINT 9 (Semana 9): Optimización**

| Día | Tarea | Entregable |
|-----|-------|------------|
| 1-2 | Optimizador tributario | Endpoint + 8 tests |
| 3-4 | Chat laboral | Endpoint + 6 tests |
| 5 | UI Chat | Widget Odoo |

**Entregables:**
- ✅ Optimizador funcionando
- ✅ Chat operativo
- ✅ 18 tests

---

### **SPRINT 10 (Semana 10): Finalización**

| Día | Tarea | Entregable |
|-----|-------|------------|
| 1-2 | Dashboards + Analytics | Chart.js |
| 3 | Documentación completa | README + API docs |
| 4 | Performance tuning | Optimización |
| 5 | Release | Deploy staging |

**Entregables:**
- ✅ Sistema completo
- ✅ Documentación
- ✅ 153 tests totales
- ✅ Scoring 95/100

---

## 📊 RESUMEN POR FASE

| Fase | Tests | LOC | Features |
|------|-------|-----|----------|
| FASE 1 | 68 | 3,000 | Liquidaciones básicas |
| FASE 2 | 40 | 1,500 | Previred + Finiquito |
| FASE 3 | 45 | 1,000 | IA + Analytics |
| **TOTAL** | **153** | **5,500** | **Sistema completo** |

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0
