# 🎯 Guía de Selección de Templates P4

**Versión:** 1.0.0  
**Fecha:** 2025-11-12  
**Objetivo:** Elegir template P4 óptimo según contexto de desarrollo/auditoría

---

## 📊 Resumen Ejecutivo: ¿Cuál Template Usar?

### Decision Tree Rápido

```
¿Qué necesitas?
│
├─ ❓ Validar lógica negocio (algoritmos, integraciones)
│  └─ ✅ P4-Deep (5-10 min)
│
├─ ❓ Preparar producción (ACLs, manifest, views)
│  └─ ✅ P4-Infrastructure (3-5 min)
│
├─ ❓ Auditoría completa 360° (certificación, due diligence)
│  └─ ✅ P4-Deep Extended (12-15 min)
│
└─ ❓ Investigar/desarrollar con Docker + Odoo
   └─ ✅ Docker/Odoo Development (referencia comandos)
```

---

## 🔍 Tabla Comparativa Completa

| Criterio | P4-Deep | P4-Infrastructure | P4-Deep Extended | Docker/Odoo Dev |
|----------|---------|-------------------|------------------|-----------------|
| **Objetivo** | Lógica negocio + integraciones | Infraestructura Odoo | Auditoría 360° completa | Desarrollo práctico |
| **Dimensiones** | A-J (10) | K-O (5) | A-O (15) | N/A (comandos) |
| **Palabras** | 1,200-1,500 | 400-600 | 1,500-1,800 | 600-900 (referencia) |
| **Tiempo** | 5-10 min | 3-5 min | 12-15 min | N/A (consulta) |
| **Referencias** | ≥30 | ≥8 | ≥40 | N/A |
| **Verificaciones** | ≥6 (1 P0, 2 P1, 3 P2) | ≥3 (1 P0, 1 P1, 1 P2) | ≥9 (2 P0, 3 P1, 4 P2) | N/A |
| **Enfoque** | Profundo selectivo | Amplio técnico | Profundo exhaustivo | Práctico operacional |

---

## 📋 Detalles por Template

### 1️⃣ P4-Deep (Auditoría Lógica Negocio)

**Archivo:** `docs/prompts_desarrollo/templates/prompt_p4_deep_template.md`

#### ✅ Usar cuando:

- **Sprint desarrollo activo** (3-5 días)
- **Validación integraciones** HTTP/SOAP/APIs externas
- **Compliance crítico:** Firma digital DTE, CAF, tope imponible payroll
- **Refactoring lógica:** Algoritmos validación, cálculos financieros
- **Code review profundo:** Patrones diseño, performance N+1
- **Pre-merge auditoría:** Feature lista para PR

#### ❌ NO usar cuando:

- Necesitas validar ACLs (usa P4-Infrastructure)
- Necesitas verificar `__manifest__.py` (usa P4-Infrastructure)
- Necesitas auditar views XML (usa P4-Infrastructure o Extended)
- Necesitas compliance SII 100% (TED barcode - usa Extended)

#### 📊 Output Esperado:

```markdown
# Auditoría Arquitectónica Profunda: l10n_cl_dte

## Dimensiones Analizadas (A-J)

### A) Arquitectura y Modularidad
- Separación responsabilidades ✅
- Patrones herencia Odoo ✅
- Monolitos identificados: account_move.py (1,200 LOC) ⚠️

### B) Patrones de Diseño
- @api.depends correctos ✅
- Computed fields con store justificado ✅
- Trade-off evaluado: store=True vs on-the-fly

### C) Integraciones Externas
- SII SOAP: Timeout configurado ✅
- Circuit breaker: 5 failure threshold ✅
- Retry con exponential backoff ⚠️ FALTA

[... dimensiones D-J ...]

## Hallazgos Críticos

### P0-01: Validación Firma Digital Incompleta
**Archivo:** models/account_move_dte.py:245
**Impacto:** Compliance SII bloqueado
**Esfuerzo:** 6-8 horas

[... 4 P0 más + 15 P1 ...]

## Recomendaciones Priorizadas

### R1: Implementar Validación CRL Certificados (P0)
[Snippet ANTES/DESPUÉS]
[Impacto cuantificado]
[Comando validación]

[Total: 1,420 palabras, 47 referencias, 8 verificaciones]
```

#### 🎯 Fortalezas Validadas:

- ✅ Detecta **lógica negocio crítica** (firma digital, CAF, tope imponible)
- ✅ **Compliance profundo** (SII, Previred, Código del Trabajo)
- ✅ **Performance análisis** (N+1 queries, prefetch, caching)
- ✅ **Arquitectura profunda** (patrones diseño, trade-offs)
- ✅ **Testing gaps** (coverage, edge cases, mocks)

---

### 2️⃣ P4-Infrastructure (Auditoría Infraestructura Odoo)

**Archivo:** `docs/prompts_desarrollo/templates/prompt_p4_infrastructure_template.md`

#### ✅ Usar cuando:

- **Pre-producción** (deployment checklist)
- **Post-migración** (Odoo 11→19 compliance)
- **Compliance SII 100%** (TED barcode, dashboards, wizards)
- **Auditoría rápida técnica** (ACLs, manifest, views)
- **Gap analysis infraestructura** (después de P4-Deep)
- **Certificación ISO 27001** (security files)

#### ❌ NO usar cuando:

- Necesitas analizar lógica negocio (usa P4-Deep)
- Necesitas auditar integraciones HTTP (usa P4-Deep)
- Necesitas análisis performance queries (usa P4-Deep)
- Necesitas auditar testing (usa P4-Deep)

#### 📊 Output Esperado:

```markdown
# Auditoría Infraestructura: l10n_cl_dte

## Dimensiones Analizadas (K-O)

### K) Security Files - ACLs
- Modelos detectados: 40
- ACLs existentes: 24
- **GAP CRÍTICO:** 16 modelos sin ACLs ❌

**Modelos sin ACLs:**
- ai.agent.selector
- ai.chat.integration
- dte.commercial.response.wizard
[... 13 más]

### L) Manifest Integrity
- Archivos comentados: 7 detectados
- **CRÍTICO:** Dashboards (740 líneas) COMENTADO
- **ALTO:** 4 wizards COMENTADOS

### M) Views XML - Odoo 19 Compatibility
- Dashboards tipo="dashboard" detectados: 2 ❌
- **FIX REQUERIDO:** Convertir a tipo="kanban"

[... dimensiones N-O ...]

## Hallazgos Priorizados

### P0-01: 16 ACLs Faltantes
**Esfuerzo:** 30 minutos
**Fix:** [Comando copy-paste ready]

### P1-01: Dashboards Desactivados
**Esfuerzo:** 10-12 horas
**Fix:** [Código ANTES/DESPUÉS]

[Total: 520 palabras, 9 referencias, 3 verificaciones]
```

#### 🎯 Fortalezas Validadas:

- ✅ Detecta **ACLs faltantes** (AccessError producción)
- ✅ Detecta **archivos comentados** (funcionalidad oculta)
- ✅ Detecta **dashboards deprecados** (Odoo 19 breaking changes)
- ✅ Detecta **TED barcode ausente** (compliance SII)
- ✅ **Rápido** (3-5 min vs 5-10 P4-Deep)

---

### 3️⃣ P4-Deep Extended (Auditoría 360° Completa)

**Archivo:** `docs/prompts_desarrollo/templates/prompt_p4_deep_extended_template.md`

#### ✅ Usar cuando:

- **Certificación ISO 27001 / SOC 2** (auditoría exhaustiva)
- **Due diligence técnico** (M&A, inversión)
- **Release major** (v2.0, producción inicial)
- **Auditoría anual completa** (Q4 review)
- **Post-incidente crítico** (root cause analysis profundo)
- **Pre-certificación SII** (compliance 100% garantizado)

#### ❌ NO usar cuando:

- Sprint rápido (usa P4-Deep o P4-Infrastructure)
- Validación específica de feature (usa P4-Deep)
- Pre-producción rutinaria (usa P4-Infrastructure)
- Tiempo limitado (<15 min) (usa P4-Deep)

#### 📊 Output Esperado:

```markdown
# Auditoría 360° Completa: l10n_cl_dte

## Dimensiones Analizadas (A-O)

### BLOQUE 1: LÓGICA NEGOCIO (A-J)

[Análisis profundo igual que P4-Deep]

### BLOQUE 2: INFRAESTRUCTURA (K-O)

[Análisis profundo igual que P4-Infrastructure]

## Hallazgos Consolidados

### P0 - CRÍTICOS (7 totales)
- P0-01: Firma digital (P4-Deep)
- P0-02: CAF cifrado (P4-Deep)
- P0-03: Tope imponible (P4-Deep)
- P0-04: API keys (P4-Deep)
- P0-05: SSL/TLS (P4-Deep)
- P0-06: 16 ACLs (P4-Infrastructure) 🆕
- P0-07: Dashboards (P4-Infrastructure) 🆕

### P1 - ALTOS (19 totales)
[15 de P4-Deep + 4 de P4-Infrastructure]

## Recomendaciones Priorizadas

[Roadmap completo: P0→P1→P2 con dependencias]

[Total: 1,750 palabras, 52 referencias, 11 verificaciones]
```

#### 🎯 Fortalezas Validadas:

- ✅ **Cobertura 100%** (lógica + infraestructura)
- ✅ **Hallazgos consolidados** (no duplicados)
- ✅ **Roadmap completo** (P0→P1→P2 con dependencias)
- ✅ **Due diligence ready** (certificación, M&A)
- ✅ **Compliance total** (SII 100%, ISO 27001, SOC 2)

---

### 4️⃣ Docker/Odoo Development (Referencia Comandos)

**Archivo:** `docs/prompts_desarrollo/templates/prompt_docker_odoo_development.md`

#### ✅ Usar cuando:

- **Investigación** (shell Odoo, queries DB)
- **Desarrollo** (instalar/actualizar módulos)
- **Testing** (pytest, Odoo test framework)
- **Debugging** (logs, shell debug mode)
- **Mantenimiento** (backup/restore, vacuum)
- **Troubleshooting** (módulos no instalan, tests fallan)

#### ❌ NO usar cuando:

- Necesitas auditoría (usa P4-Deep/Infrastructure/Extended)
- Necesitas análisis arquitectónico (usa P4-Deep)
- Necesitas recomendaciones priorizadas (usa P4-Deep/Infrastructure)

#### 📊 Contenido:

```markdown
# Comandos Docker + Odoo CLI Profesionales

## 1. Gestión Módulos
[Comandos instalar, actualizar, verificar]

## 2. Testing
[pytest, Odoo test framework, coverage]

## 3. Shell y Debugging
[Shell interactivo, debug mode, investigación]

## 4. Base de Datos
[Backup, restore, queries SQL]

## 5. Operaciones Servidor
[Configuración, startup, health checks]

## 6. Desarrollo
[Scaffolding, dependencias]

## 7. Traducciones
[i18n export/import]

## 8. Monitoreo
[Logs, métricas, health checks]

## 9. Mantenimiento
[Cache, reindex, vacuum]

## 10. Troubleshooting
[Guías resolución problemas comunes]

[Total: 650 palabras, comandos copy-paste ready]
```

---

## 🎯 Escenarios Prácticos: ¿Cuál Template?

### Escenario 1: Sprint Desarrollo Feature DTE

**Contexto:**
- Sprint 2 semanas
- Implementar validación firma digital mejorada
- Code review antes de merge

**Template recomendado:** ✅ **P4-Deep**

**Razón:**
- Enfoque en lógica negocio (firma digital, certificados)
- Valida integraciones SII SOAP
- Identifica performance issues (N+1 queries)
- Rápido (5-10 min)

**Comando:**
```bash
copilot -p "$(cat docs/prompts_desarrollo/templates/prompt_p4_deep_template.md)" \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_dte_p4deep_$(date +%Y%m%d).md
```

---

### Escenario 2: Pre-Producción Deployment

**Contexto:**
- Deployment a producción en 3 días
- Validar checklist técnico
- Asegurar compliance SII 100%

**Template recomendado:** ✅ **P4-Infrastructure**

**Razón:**
- Verifica ACLs completas (evita AccessError producción)
- Detecta archivos comentados (funcionalidad oculta)
- Valida TED barcode (compliance SII)
- Rápido (3-5 min)

**Comando:**
```bash
copilot -p "$(cat docs/prompts_desarrollo/templates/prompt_p4_infrastructure_template.md)" \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_dte_p4infra_$(date +%Y%m%d).md
```

---

### Escenario 3: Certificación ISO 27001

**Contexto:**
- Auditoría ISO 27001 en 1 mes
- Due diligence técnico exhaustivo
- Documentación compliance completa

**Template recomendado:** ✅ **P4-Deep Extended**

**Razón:**
- Cobertura 360° (lógica + infraestructura)
- Hallazgos consolidados (no duplicados)
- Roadmap completo (P0→P1→P2)
- Due diligence ready

**Comando:**
```bash
copilot -p "$(cat docs/prompts_desarrollo/templates/prompt_p4_deep_extended_template.md)" \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_dte_p4extended_$(date +%Y%m%d).md
```

---

### Escenario 4: Debugging Issue Producción

**Contexto:**
- Error en producción: Facturas DTE no generan XML
- Necesito investigar root cause
- Acceso a logs + DB

**Template recomendado:** ✅ **Docker/Odoo Development**

**Razón:**
- Comandos shell Odoo (investigación)
- Queries DB directas (análisis datos)
- Logs debugging (trace error)
- Troubleshooting guiado

**Uso:**
```bash
# 1. Ver logs error
docker compose logs odoo | grep ERROR | grep "dte"

# 2. Shell Odoo investigación
docker compose exec odoo odoo-bin shell -d odoo19_db

# 3. Query directa DB
docker compose exec db psql -U odoo -h db odoo19_db -c "
SELECT id, name, l10n_cl_dte_status, l10n_cl_dte_xml
FROM account_move
WHERE move_type = 'out_invoice' AND l10n_cl_dte_xml IS NULL
ORDER BY id DESC LIMIT 5;
"

# 4. Referencia: docs/prompts_desarrollo/templates/prompt_docker_odoo_development.md
```

---

## 📊 Matriz de Selección Rápida

| Necesidad | Tiempo | Template | Comando |
|-----------|--------|----------|---------|
| **Validar lógica negocio** | 5-10 min | P4-Deep | `copilot -p "$(cat prompt_p4_deep_template.md)"` |
| **Pre-producción checklist** | 3-5 min | P4-Infrastructure | `copilot -p "$(cat prompt_p4_infrastructure_template.md)"` |
| **Auditoría completa 360°** | 12-15 min | P4-Deep Extended | `copilot -p "$(cat prompt_p4_deep_extended_template.md)"` |
| **Investigar/desarrollar** | N/A | Docker/Odoo Dev | Referencia comandos |
| **Code review PR** | 5-10 min | P4-Deep | - |
| **Post-migración Odoo** | 3-5 min | P4-Infrastructure | - |
| **Certificación ISO** | 12-15 min | P4-Deep Extended | - |
| **Debugging producción** | N/A | Docker/Odoo Dev | - |

---

## 🎓 Recomendaciones por Rol

### Desarrollador (Feature Development)

**Workflow típico:**
1. **Durante desarrollo:** Docker/Odoo Dev (comandos)
2. **Pre-PR:** P4-Deep (validar lógica)
3. **Post-merge:** P4-Infrastructure (verificar no rompió infraestructura)

---

### Tech Lead (Code Review)

**Workflow típico:**
1. **Review PR:** P4-Deep (análisis profundo lógica)
2. **Merge decision:** P4-Infrastructure (checklist técnico)
3. **Post-deployment:** Logs + Docker/Odoo Dev (validación producción)

---

### DevOps / SRE (Deployment)

**Workflow típico:**
1. **Pre-deployment:** P4-Infrastructure (checklist compliance)
2. **Post-deployment:** Docker/Odoo Dev (health checks, logs)
3. **Incident response:** Docker/Odoo Dev (debugging, rollback)

---

### Auditor / QA (Compliance)

**Workflow típico:**
1. **Sprint auditoría:** P4-Deep + P4-Infrastructure (ambos)
2. **Certificación:** P4-Deep Extended (exhaustivo)
3. **Validación fixes:** P4-Infrastructure (re-auditoría rápida)

---

## ✅ Conclusión: Estrategia Híbrida Óptima

### Combinación Recomendada por Fase

**Fase 1: Desarrollo (Sprint 1-2 semanas)**
- ✅ P4-Deep (validación lógica negocio)
- ✅ Docker/Odoo Dev (investigación, testing)

**Fase 2: Pre-Producción (3-5 días)**
- ✅ P4-Infrastructure (checklist técnico)
- ✅ Docker/Odoo Dev (smoke tests)

**Fase 3: Producción (deployment)**
- ✅ Docker/Odoo Dev (health checks, monitoring)

**Fase 4: Post-Producción (mensual)**
- ✅ P4-Deep Extended (auditoría 360° completa)

---

## 📖 Referencias

- **P4-Deep Template:** `docs/prompts_desarrollo/templates/prompt_p4_deep_template.md`
- **P4-Infrastructure Template:** `docs/prompts_desarrollo/templates/prompt_p4_infrastructure_template.md`
- **P4-Deep Extended Template:** `docs/prompts_desarrollo/templates/prompt_p4_deep_extended_template.md`
- **Docker/Odoo Development:** `docs/prompts_desarrollo/templates/prompt_docker_odoo_development.md`
- **Estrategia Prompting:** `docs/prompts_desarrollo/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`

---

**Versión:** 1.0.0  
**Última actualización:** 2025-11-12  
**Mantenedor:** Pedro Troncoso (@pwills85)
