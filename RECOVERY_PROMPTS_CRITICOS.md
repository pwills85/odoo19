# 🆘 RECOVERY: PROMPTs Críticos para Cierre de Brechas

**Fecha de Recovery:** 2025-11-09  
**Situación:** Pérdida de comunicación con agentes  
**Objetivo:** Recuperar contexto completo de PROMPTs generados  

---

## 📋 ÍNDICE DE PROMPTs CRÍTICOS

### 🔴 PROMPTs AI SERVICE (Microservicio IA)

1. **PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md** ⭐ **PRINCIPAL**
   - **Ubicación:** `/Users/pedro/Documents/odoo19/PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md`
   - **Tamaño:** 1,119 líneas (32KB)
   - **Fecha:** 2025-11-09 03:10
   - **Estado:** ✅ Pusheado a GitHub (commit a4a975fa)
   - **Alcance:** Cierre 10 brechas AI Service
   - **Score:** 82/100 → 100/100
   - **Duración:** 17 días (8 sprints)

2. **AI_SERVICE_GAP_ANALYSIS_2025-11-09.md** 📊 **ANÁLISIS BASE**
   - **Ubicación:** `/Users/pedro/Documents/odoo19/docs/gap-closure/AI_SERVICE_GAP_ANALYSIS_2025-11-09.md`
   - **Tamaño:** 1,089 líneas (30KB)
   - **Fecha:** 2025-11-09
   - **Estado:** ✅ Integrado desde rama remota (commit e055bf4e)
   - **Contenido:** Análisis exhaustivo validación PHASE 1
   - **Brechas:** 10 total (5 P1 + 3 P2 + 2 P3)

---

### 🔴 PROMPTs FACTURACIÓN ELECTRÓNICA (DTE)

3. **PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md** ⭐ **PRINCIPAL DTE**
   - **Ubicación:** `/Users/pedro/Documents/odoo19/.claude/PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md`
   - **Tamaño:** 1,399 líneas (40KB)
   - **Fecha:** 2025-11-09 01:56
   - **Estado:** ✅ Pusheado a GitHub (commit a73fe265)
   - **Alcance:** Cierre brechas críticas l10n_cl_dte
   - **Score:** 64/100 → 98/100
   - **Hallazgos:** 9 brechas (1 H1 XXE P0 + 8 otros)
   - **Duración:** 54-83h (6 sprints)

4. **PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5.md** 📋 **VERSIÓN MASTER**
   - **Ubicación:** `/Users/pedro/Documents/odoo19/.claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS_V5.md`
   - **Tamaño:** 44KB
   - **Fecha:** 2025-11-09 03:04
   - **Alcance:** Cierre total brechas DTE + Nómina
   - **Módulos:** l10n_cl_dte, l10n_cl_hr_payroll

---

## 🎯 RESUMEN EJECUTIVO

### AI Service - 10 Brechas Identificadas

| ID | Brecha | Prioridad | Ubicación | Esfuerzo |
|----|--------|-----------|-----------|----------|
| **P1-1** | Test Coverage No Medida | 🔴 P1 | tests/, clients/, chat/ | 10 días |
| **P1-2** | TODOs Críticos (3) | 🔴 P1 | 3 archivos | 10h |
| **P1-3** | Redis SPOF | 🔴 P1 | docker-compose.yml | 3 días |
| **P1-4** | Config Testing Faltante | 🔴 P1 | pyproject.toml | 1h |
| **P1-5** | Tests PHASE 1 Faltantes | 🔴 P1 | tests/integration/ | 3 días |
| **P2-1** | Knowledge Base In-Memory | 🟡 P2 | knowledge_base.py | 4h |
| **P2-2** | Health Check Incompleto | 🟡 P2 | main.py:231-268 | 4h |
| **P2-3** | Prometheus Alerting | 🟡 P2 | monitoring/ | 1 día |
| **P3-1** | Hardcoded API Keys | 🟢 P3 | config.py:25 | 5min |
| **P3-2** | Rate Limiting IP-based | 🟢 P3 | main.py:67 | 2h |

**Total AI Service:** 17 días (3-4 semanas)

---

### Facturación Electrónica - 9 Brechas Críticas

| ID | Brecha | Prioridad | Archivos Afectados | Esfuerzo |
|----|--------|-----------|-------------------|----------|
| **H1** | XXE Vulnerability | 🔴 P0 | 16 archivos | 2-4h |
| **H2** | Odoo Imports en libs/ | 🔴 P1 | 2 archivos | 3-5h |
| **H9** | Cumplimiento Normativo | 🔴 P0 | 3 reportes SII | 40-60h |
| **H10** | Certificado SII Testing | 🟡 P2 | dte_caf.py | 2-3h |
| **H11** | Monolito dte_inbox | 🟡 P2 | 1,236 líneas | 6-10h |
| **H4** | Rate Limiting | 🟢 P3 | middleware | 1-2h |
| **H6** | Circuit Breaker | 🟢 P3 | sii_authenticator | 2-3h |
| **H7** | Retry Strategy | 🟢 P3 | HTTP clients | 1-2h |
| **H8** | Async Bottlenecks | 🟢 P3 | xml_signer | 2-3h |

**Total DTE:** 54-83h (2-3 semanas)

---

## 📅 PLAN DE SPRINTS

### AI Service - 8 Sprints

```
SPRINT 0:  Backup + baseline            (30 min)  → Score: 82/100
SPRINT 1:  P1-1 Testing foundation      (5 días)  → Score: 89/100 (+7)
SPRINT 2:  P1-5 Integration tests       (2 días)  → Score: 92/100 (+3)
SPRINT 3:  P1-2 TODOs críticos          (3 días)  → Score: 95/100 (+3)
SPRINT 4:  P2-2 Enhanced health checks  (1 día)   → Score: 96/100 (+1)
SPRINT 5:  P1-3 Redis HA                (3 días)  → Score: 98/100 (+2)
SPRINT 6:  P2-3 Prometheus alerting     (1 día)   → Score: 99/100 (+1)
SPRINT 7:  P3 Nice-to-have              (1 día)   → Score: 100/100 (+1)
SPRINT 8:  Validación final             (1 día)   → Score: 100/100 ✅
──────────────────────────────────────────────────────────────────────
TOTAL:     17 días (3-4 semanas)        Score final: 100/100
```

### Facturación Electrónica - 6 Sprints

```
SPRINT 0:  Backup + tests baseline      (30 min)  → Score: 64/100
SPRINT 1:  H1 XXE Fix (16 archivos)     (2-4h)    → Score: 89/100 (+25)
SPRINT 2:  H10 Certificado SII          (2-3h)    → Score: 92/100 (+3)
SPRINT 3:  H2 Pure Python (2 archivos)  (3-5h)    → Score: 95/100 (+3)
SPRINT 4:  H11 dte_inbox refactor       (6-10h)   → Score: 97/100 (+2)
SPRINT 5:  H9 Compliance (3 reportes)   (40-60h)  → Score: 100/100 (+3)
SPRINT 6:  Validación SII + tests       (2-3h)    → Score: 100/100 ✅
──────────────────────────────────────────────────────────────────────
TOTAL:     54-83h (2-3 semanas)         Score final: 100/100
```

---

## 👥 SUB-AGENTES ASIGNADOS

### Para AI Service

1. **Test Automation Specialist** (`.claude/agents/test-automation.md`)
   - Responsable: P1-1, P1-4, P1-5
   - Tests: anthropic_client.py, chat/engine.py, integration
   - Duración: 10 días

2. **AI & FastAPI Developer** (`.claude/agents/ai-fastapi-dev.md`)
   - Responsable: P1-2, P2-1, P2-2
   - Features: TODOs críticos, knowledge base, health checks
   - Duración: 5 días

3. **Docker & DevOps Expert** (`.claude/agents/docker-devops.md`)
   - Responsable: P1-3, P2-3
   - Infraestructura: Redis HA, Prometheus alerting
   - Duración: 4 días

4. **DTE Compliance Expert** (`.claude/agents/dte-compliance.md`)
   - Responsable: Validación final
   - Scope: Read-only, compliance verification
   - Duración: 1 día

### Para Facturación Electrónica

1. **Odoo Developer** (`.claude/agents/odoo-dev.md`)
   - Responsable: H1, H2, H9, H11
   - Scope: Core DTE functionality
   - Duración: 50-70h

2. **Test Automation Specialist** (`.claude/agents/test-automation.md`)
   - Responsable: Tests XXE, tests compliance
   - Scope: Security + regulatory tests
   - Duración: 10-15h

3. **Docker & DevOps Expert** (`.claude/agents/docker-devops.md`)
   - Responsable: H10 (certificado SII)
   - Scope: Deployment configurations
   - Duración: 2-3h

4. **DTE Compliance Expert** (`.claude/agents/dte-compliance.md`)
   - Responsable: H9 validation
   - Scope: SII compliance verification
   - Duración: Durante todo Sprint 5

---

## 🚀 COMANDOS DE INICIO RÁPIDO

### Ejecutar AI Service Gap Closure

```bash
# 1. Crear branch de trabajo
git checkout -b feat/ai_service_gap_closure

# 2. Backup (SPRINT 0)
codex-docker-devops "Ejecuta SPRINT 0 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"

# 3. Ejecutar sprints secuencialmente
codex-test-automation "Ejecuta SPRINT 1 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-test-automation "Ejecuta SPRINT 2 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-ai-fastapi-dev "Ejecuta SPRINT 3 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-ai-fastapi-dev "Ejecuta SPRINT 4 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-docker-devops "Ejecuta SPRINT 5 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-docker-devops "Ejecuta SPRINT 6 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-ai-fastapi-dev "Ejecuta SPRINT 7 - P3-2 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-docker-devops "Ejecuta SPRINT 7 - P3-1 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
codex-dte-compliance "VALIDACIÓN READ-ONLY - SPRINT 8 de PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md"
```

### Ejecutar DTE Gap Closure

```bash
# 1. Crear branch de trabajo
git checkout -b feat/dte_gap_closure_professional

# 2. Backup (SPRINT 0)
codex-docker-devops "Ejecuta SPRINT 0 de PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md"

# 3. XXE Fix (SPRINT 1) - CRÍTICO P0
codex-odoo-dev "Ejecuta SPRINT 1 (H1 XXE) de PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md"

# Validación XXE
codex-dte-compliance "VALIDACIÓN READ-ONLY - SPRINT 1 XXE Fix"

# 4. Sprints posteriores
codex-odoo-dev "Ejecuta SPRINT 2 (H10 Certificado) de PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md"
codex-odoo-dev "Ejecuta SPRINT 3 (H2 Pure Python) de PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md"
codex-odoo-dev "Ejecuta SPRINT 4 (H11 Refactor) de PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md"
codex-odoo-dev "Ejecuta SPRINT 5 (H9 Compliance) de PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md"
codex-dte-compliance "VALIDACIÓN FINAL - SPRINT 6"
```

---

## 📊 ESTADO ACTUAL DEL REPOSITORIO

### Branch Actual
```
Branch: feat/cierre_total_brechas_profesional
Status: ✅ Up to date with origin
Último commit: a4a975fa (PROMPT AI Service orquestado)
```

### Commits Críticos Recientes
```
a4a975fa - docs(prompts): PROMPT AI Service orquestado (2025-11-09 03:10)
948e6002 - security(l10n_cl_dte): XXE fixes (3 blockers)
a4c6375c - test(l10n_cl_dte): XXE security tests (23 tests)
a73fe265 - docs(prompts): PROMPT DTE V4 INTEGRADO
```

### Archivos Pendientes de Commit

**Modified (6):**
- `.claude/settings.local.json`
- `ai-service/chat/engine.py`
- `ai-service/chat/knowledge_base.py`
- `ai-service/main.py`
- `ai-service/utils/redis_helper.py`
- `docker-compose.yml`

**Untracked (14):**
- Progress reports Sprint 1-3
- Test scripts (XXE, Redis failover)
- Documentation (REDIS_HA_SETUP.md, etc.)

---

## ✅ CHECKLIST DE VALIDACIÓN

### AI Service - Pre-ejecución

- [ ] Leer `PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md` completo
- [ ] Leer `AI_SERVICE_GAP_ANALYSIS_2025-11-09.md` (análisis base)
- [ ] Verificar sub-agentes disponibles en `.claude/agents/`
- [ ] Crear branch `feat/ai_service_gap_closure`
- [ ] Ejecutar SPRINT 0 (backup)

### Facturación Electrónica - Pre-ejecución

- [ ] Leer `PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md` completo
- [ ] Verificar `libs/safe_xml_parser.py` existe (XXE fix)
- [ ] Verificar sub-agentes disponibles
- [ ] Crear branch `feat/dte_gap_closure_professional`
- [ ] Ejecutar SPRINT 0 (backup)

---

## 🔴 PRIORIDADES CRÍTICAS

### AI Service

1. **P1-1: Test Coverage** (10 días)
   - Sin tests para anthropic_client.py (483 LOC)
   - Sin tests para chat/engine.py (658 LOC)
   - Coverage desconocido (estimado 60-70%)

2. **P1-3: Redis SPOF** (3 días)
   - Sin replication, sin sentinel
   - Pérdida total si Redis cae

3. **P1-2: TODOs Críticos** (10h)
   - confidence=95.0 hardcoded
   - Métricas SII Monitor dummy
   - Knowledge base vacío

### Facturación Electrónica

1. **H1: XXE Vulnerability** (2-4h) 🔴 **BLOCKER**
   - 16 archivos críticos sin protección
   - OWASP A4:2017 HIGH severity
   - Solución disponible: `libs/safe_xml_parser.py`

2. **H9: Cumplimiento Normativo** (40-60h) 🔴 **BLOCKER**
   - Consumo de Folios (placeholder)
   - Libro de Compras (placeholder)
   - Libro de Ventas (placeholder)
   - Multas SII si no implementado

3. **H2: Odoo Imports en libs/** (3-5h) 🔴 **P1**
   - 2 archivos rompen patrón pure Python
   - Dificulta testing y reusabilidad

---

## 📎 REFERENCIAS

### Documentos AI Service
- **PROMPT Principal:** `PROMPT_EJECUCION_OPCION_A_ORQUESTADO.md` (1,119 líneas)
- **Análisis:** `docs/gap-closure/AI_SERVICE_GAP_ANALYSIS_2025-11-09.md` (1,089 líneas)
- **Sub-agentes:** `.claude/agents/` (test-automation, ai-fastapi-dev, docker-devops, dte-compliance)

### Documentos Facturación Electrónica
- **PROMPT Principal:** `.claude/PROMPT_CIERRE_BRECHAS_PROFESIONAL_V4_INTEGRADO.md` (1,399 líneas)
- **Auditoría Remota:** `.claude/AUDITORIA_L10N_CL_DTE_REPORTE_FINAL.md` (946 líneas)
- **Sub-agentes:** `.claude/agents/` (odoo-dev, test-automation, docker-devops, dte-compliance)

### Knowledge Base
- **Patrones Odoo 19:** `.claude/agents/knowledge/odoo19_patterns.md`
- **SII Regulatory:** `.claude/agents/knowledge/sii_regulatory_context.md`
- **Arquitectura:** `.claude/agents/knowledge/project_architecture.md`

---

## 🎯 OBJETIVO FINAL

### AI Service
- **Score Actual:** 82/100
- **Score Target:** 100/100
- **Gap:** 18 puntos
- **Duración:** 17 días (3-4 semanas)
- **Resultado:** Production-ready con calidad enterprise-grade

### Facturación Electrónica
- **Score Actual:** 64/100
- **Score Target:** 100/100
- **Gap:** 36 puntos
- **Duración:** 54-83h (2-3 semanas)
- **Resultado:** SII compliant, production-ready

---

**Última Actualización:** 2025-11-09  
**Documento de Recovery:** RECOVERY_PROMPTS_CRITICOS.md  
**Estado:** ✅ LISTO PARA RE-INICIAR EJECUCIÓN

---

## 📞 PRÓXIMOS PASOS INMEDIATOS

1. **Revisar este documento completo** (5 min)
2. **Elegir qué cierre ejecutar primero:**
   - **Opción A:** AI Service (menos crítico, 17 días)
   - **Opción B:** Facturación Electrónica (más crítico, XXE P0 blocker)
   - **Opción C:** Paralelo (ambos simultáneamente con sub-agentes)

3. **Ejecutar SPRINT 0** del elegido (backup + baseline)
4. **Comenzar SPRINT 1** con validación continua

**Recomendación:** Ejecutar **Opción B** (DTE) primero por tener XXE P0 blocker que impide producción.
