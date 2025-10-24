# 📐 PLAN MAESTRO: Sistema Nóminas Chile (Ingeniería de Detalles)

**Proyecto:** l10n_cl_hr_payroll  
**Fecha:** 2025-10-22  
**Tipo:** Ingeniería de Detalles  
**Ingeniero:** Senior System Architect

---

## 🎯 EXECUTIVE SUMMARY

### Objetivo
Sistema enterprise-grade de nóminas para Chile en Odoo 19 CE, arquitectura microservicios + IA, cumplimiento 100% normativa 2025.

### Alcance
- Módulo Odoo (l10n_cl_hr_payroll)
- Microservicio Payroll-Service (FastAPI)
- Extensión AI-Service (Claude)
- Migración datos Odoo 11 → 19
- Testing 80% coverage

### Restricciones
- **Presupuesto:** $24,000 USD
- **Tiempo:** 10 semanas
- **Equipo:** 2 devs (1 Odoo + 1 Python)
- **Stack:** Odoo 19 CE + Python 3.11+ + PostgreSQL 15+

### Entregables
- Sistema funcional 100%
- Scoring 95/100 (World-Class)
- Documentación técnica completa
- Tests automatizados (153 casos)
- Plan de migración ejecutado

---

## 📊 DIMENSIONES DEL PROYECTO

### 1. Módulo Odoo (l10n_cl_hr_payroll)
- Modelos: hr_contract_cl, hr_payslip, hr_settlement, hr_economic_indicators
- Vistas: Formularios, listas, wizards
- Reportes: QWeb (liquidación, finiquito)
- Seguridad: Grupos, permisos
- Integración: EERGY AI Microservice

### 2. EERGY AI Microservice (Reutilizar existente) 
- **Extracción Indicadores**: Previred (60 campos) + SII (32 campos)
- **Portal Empleados**: SQL Direct, autenticación JWT
- **Validación IA**: Claude API para contratos y liquidaciones
- **Chat Laboral**: Consultas con Claude
- **Audit Trail**: Blockchain (Art. 54 CT)
- **Enterprise**: Logging, métricas, alertas (15.5/16)

**NOTA:** Microservicio ya existe en Odoo 11. Solo requiere:
- Actualizar conexión DB (Odoo 11 → Odoo 19)
- Agregar métodos integración en modelos Odoo
- Tiempo adaptación: 1 día

### 2. ARQUITECTURA TÉCNICA
Ver: `02_ARCHITECTURE.md`

**4 Capas:**
- Presentación (Odoo UI)
- Lógica Negocio (Odoo Models)
- Servicios (Microservicios)
- Persistencia (PostgreSQL)

### 3. FASES DE IMPLEMENTACIÓN
Ver: `03_IMPLEMENTATION_PHASES.md`

**FASE 1: Core (4 semanas)**
- Sprint 1-4: Fundamentos + Calculadoras + Integración

**FASE 2: Compliance (3 semanas)**
- Sprint 5-7: Previred + Finiquito + Audit Trail

**FASE 3: IA (3 semanas)**
- Sprint 8-10: Validación IA + Optimización + Analytics

### 4. MODELO DE DATOS
Ver: `04_DATA_MODEL.md`

**Entidades principales:**
- hr_afp, hr_isapre (maestros)
- hr_contract (300 registros)
- hr_payslip (50,000 registros)
- hr_payslip_line (500,000 registros)
- hr_settlement (finiquitos)
- hr_payroll_audit (50,000 registros)

### 5. API CONTRACTS
Ver: `05_API_CONTRACTS.md`

**Payroll-Service:**
- POST /api/payroll/calculate
- POST /api/previred/generate
- POST /api/settlement/calculate

**AI-Service:**
- POST /api/payroll/validate
- POST /api/contract/analyze
- POST /api/payroll/optimize

### 6. TESTING STRATEGY
Ver: `06_TESTING_STRATEGY.md`

**Pirámide:**
- E2E: 8 tests (5%)
- Integración: 32 tests (20%)
- Unitarios: 113 tests (75%)
- **Total: 153 tests (80% coverage)**

---

## 📅 ROADMAP EJECUTIVO

| Fase | Duración | Sprints | Entregables Clave |
|------|----------|---------|-------------------|
| **FASE 1: Core** | 4 sem | 1-4 | Liquidaciones básicas funcionando |
| **FASE 2: Compliance** | 3 sem | 5-7 | Previred + Finiquito + Audit |
| **FASE 3: IA** | 3 sem | 8-10 | Validación IA + Optimización |
| **TOTAL** | **10 sem** | **10** | **Sistema completo** |

---

## 📊 MÉTRICAS DE ÉXITO

| Métrica | Objetivo | Medición |
|---------|----------|----------|
| **Scoring Total** | 95/100 | Auditoría final |
| **Testing Coverage** | 80% | pytest-cov |
| **Performance** | <2s p95 | Locust |
| **Uptime** | 99.5% | Prometheus |
| **Compliance Legal** | 100% | Checklist SII |

---

## 🎯 CRITERIOS DE ACEPTACIÓN GLOBAL

### Funcionales
- [ ] Liquidación básica genera correctamente
- [ ] Previred 105 campos válido
- [ ] Finiquito con todos componentes
- [ ] Reforma 2025 implementada
- [ ] Audit trail 7 años

### Técnicos
- [ ] Tests: 153 casos pasando
- [ ] Performance: <2s p95
- [ ] Uptime: 99.5%
- [ ] Documentación completa
- [ ] Sin errores críticos

### Negocio
- [ ] Scoring: 95/100
- [ ] ROI: 5 meses
- [ ] Migración exitosa
- [ ] Usuarios capacitados

---

## 📋 DOCUMENTOS DE REFERENCIA

1. **00_MASTER_PLAN.md** (este documento)
2. **01_BUSINESS_DOMAIN.md** - Análisis de dominio
3. **02_ARCHITECTURE.md** - Diseño arquitectónico
4. **03_IMPLEMENTATION_PHASES.md** - Fases detalladas
5. **04_DATA_MODEL.md** - Modelo de datos
6. **05_API_CONTRACTS.md** - Especificaciones API
7. **06_TESTING_STRATEGY.md** - Estrategia de testing

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ APROBADO PARA IMPLEMENTACIÓN
