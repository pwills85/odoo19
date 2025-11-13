# 📚 KNOWLEDGE BASE - Índice Central Documentación Técnica

**Versión:** 1.0.0
**Fecha:** 2025-11-12
**Propósito:** Repositorio central de documentación técnica del proyecto Odoo 19 CE EERGYGROUP

---

## 🎯 Sobre Esta Carpeta

La **Knowledge Base** contiene toda la documentación técnica fundamental necesaria para trabajar en el proyecto. Esta carpeta es **autosostenida** - contiene TODO lo necesario sin dependencias externas.

**Principio de Autosostenibilidad:**
> Un agente/desarrollador con acceso SOLO a `docs/prompts/` puede ser 100% productivo usando únicamente esta documentación.

---

## 📁 ARCHIVOS DISPONIBLES (10 documentos)

### 1. Stack & Deployment

#### deployment_environment.md
**Propósito:** Arquitectura completa del stack Docker Compose

**Contiene:**
- Diagrama arquitectura (Odoo + PostgreSQL + Redis HA + AI Service)
- Configuración servicios (docker-compose.yml explicado)
- Networking y volumes
- Resource limits y tuning
- Deployment modes (desarrollo vs producción)
- Monitoring y troubleshooting

**Cuándo usar:**
- Entender infraestructura del proyecto
- Configurar entorno local
- Troubleshooting problemas deployment
- Optimizar recursos

**Relacionado:** `docker_odoo_command_reference.md`

---

#### docker_odoo_command_reference.md
**Propósito:** Referencia completa comandos Docker + Odoo CLI

**Contiene:**
- Gestión módulos (install, update, uninstall)
- Testing (pytest + Odoo framework)
- Shell y debugging (ORM access, pdb)
- Base de datos (backup, restore, SQL)
- Logs y monitoring
- Troubleshooting paso a paso

**Cuándo usar:**
- Desarrollo día a día
- Ejecutar tests
- Debugging código
- Gestión base de datos
- Resolver problemas técnicos

**Relacionado:** `deployment_environment.md`, `odoo19_patterns.md`

---

### 2. Odoo 19 CE Compliance

#### odoo19_deprecations_reference.md
**Propósito:** Referencia rápida deprecaciones Odoo 19 CE

**Contiene:**
- Lista resumida 8 patrones deprecación (P0/P1/P2)
- Ejemplos antes/después
- Deadlines críticos
- Comandos validación rápida

**Cuándo usar:**
- Consulta rápida durante desarrollo
- Validar si código usa técnicas obsoletas
- Referencia en code reviews

**Relacionado:** `compliance_status.md`, `02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`

---

#### compliance_status.md
**Propósito:** Estado actual compliance Odoo 19 CE del proyecto

**Contiene:**
- Resumen ejecutivo (61 deprecaciones totales)
- Progreso por patrón (P0/P1/P2)
- Progreso por módulo (DTE, Payroll, Financial)
- Plan acción priorizado (4 sprints)
- Riesgos identificados
- Métricas objetivo

**Cuándo usar:**
- Planning sprints cierre brechas
- Reportes a stakeholders
- Priorizar trabajo compliance
- Tracking progreso

**Relacionado:** `odoo19_deprecations_reference.md`, `06_outputs/metricas/dashboard_2025-11.json`

---

### 3. Desarrollo Odoo 19

#### odoo19_patterns.md
**Propósito:** Patrones desarrollo correctos Odoo 19 CE

**Contiene:**
- Models (ORM, fields, compute, constraints)
- Views (QWeb, XML, widgets)
- Controllers (HTTP routes, JSONRPC)
- Security (access rights, record rules)
- Testing (pytest, Odoo framework)
- Performance (N+1 queries, caching, indexes)

**Cuándo usar:**
- Desarrollar nueva funcionalidad
- Refactoring código legacy
- Code reviews
- Onboarding nuevos desarrolladores

**Relacionado:** `docker_odoo_command_reference.md`, `project_architecture.md`

---

### 4. Arquitectura Proyecto

#### project_architecture.md
**Propósito:** Decisiones arquitectónicas EERGYGROUP

**Contiene:**
- Estructura proyecto (addons/localization, custom)
- Módulos principales (DTE, Payroll, Financial, AI)
- Integraciones externas (SII, Previred, Claude API)
- Flujos de datos críticos
- Decisiones técnicas documentadas

**Cuándo usar:**
- Entender "el por qué" de decisiones técnicas
- Planning nuevas features
- Evaluar impacto cambios arquitectónicos
- Documentar nuevas decisiones

**Relacionado:** `odoo19_patterns.md`, `sii_regulatory_context.md`

---

### 5. Compliance Legal Chile

#### sii_regulatory_context.md
**Propósito:** Normativas legales chilenas aplicables

**Contiene:**
- SII (Documentos Tributarios Electrónicos 33/34/52/56/61)
- Previred (nómina electrónica, validaciones 105)
- Código del Trabajo (cálculos laborales)
- Validaciones RUT, direcciones, montos
- Formatos archivos (.xml, .txt)

**Cuándo usar:**
- Desarrollar funcionalidad DTE
- Implementar cálculos nómina
- Validar compliance legal
- Troubleshooting rechazos SII/Previred

**Relacionado:** `compliance_status.md`, `project_architecture.md`

---

## 🗺️ MAPA DE USO POR CASO

### Caso 1: Onboarding Desarrollador Nuevo

**Leer en orden:**
1. `deployment_environment.md` - Entender el stack
2. `docker_odoo_command_reference.md` - Comandos esenciales
3. `odoo19_patterns.md` - Cómo desarrollar correctamente
4. `odoo19_deprecations_reference.md` - Qué NO hacer
5. `project_architecture.md` - Decisiones arquitectónicas
6. `compliance_status.md` - Estado actual proyecto

**Tiempo estimado:** 4-6 horas lectura + práctica

---

### Caso 2: Auditoría Compliance Módulo

**Leer en orden:**
1. `compliance_status.md` - Entender contexto global
2. `odoo19_deprecations_reference.md` - Patrones a buscar
3. `docker_odoo_command_reference.md` - Comandos validación
4. `02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md` - Checklist completo

**Usar templates:**
- `04_templates/TEMPLATE_AUDITORIA.md`
- `04_templates/TEMPLATE_P4_DEEP_ANALYSIS.md`

---

### Caso 3: Desarrollo Feature DTE

**Leer:**
1. `sii_regulatory_context.md` - Normativa SII
2. `odoo19_patterns.md` - Cómo implementar
3. `project_architecture.md` - Integración actual DTE
4. `docker_odoo_command_reference.md` - Testing

**Validar contra:**
- `odoo19_deprecations_reference.md` - No usar técnicas obsoletas
- `compliance_status.md` - Evitar patrones con deprecaciones pendientes

---

### Caso 4: Cierre Brecha Compliance

**Leer:**
1. `compliance_status.md` - Identificar brecha a cerrar
2. `odoo19_deprecations_reference.md` - Patrón correcto
3. `odoo19_patterns.md` - Implementación detallada
4. `docker_odoo_command_reference.md` - Testing

**Usar template:**
- `04_templates/TEMPLATE_CIERRE_BRECHA.md`

---

### Caso 5: Troubleshooting Producción

**Leer:**
1. `deployment_environment.md` - Arquitectura stack
2. `docker_odoo_command_reference.md` - Debugging + logs
3. `project_architecture.md` - Flujos de datos

**Comandos clave:**
```bash
# Ver logs
docker compose logs -f odoo | grep ERROR

# Shell debugging
docker compose exec odoo odoo-bin shell -d odoo19_db --debug

# DB queries lentas
docker compose exec db psql -U odoo -d odoo19_db -c \
  "SELECT pid, query_start, state, query FROM pg_stat_activity WHERE state != 'idle';"
```

---

## 🔗 RELACIONES CON OTRAS CARPETAS

```
docs/prompts/
│
├── 00_knowledge_base/           ← Esta carpeta (documentación técnica base)
│   └── [7 archivos fundamentales]
│
├── 01_fundamentos/              → Estrategias prompting, guías selección
├── 02_compliance/               → Checklists Odoo 19 (dependen de 00_knowledge_base/)
├── 03_maximas/                  → Reglas no negociables
├── 04_templates/                → Templates prompts (usan 00_knowledge_base/)
├── 05_prompts_produccion/       → Prompts validados (generados con 00_knowledge_base/)
├── 06_outputs/                  → Resultados ejecuciones
├── 07_historico/                → Archivos obsoletos
└── 08_scripts/                  → Automatización (generan prompts con 00_knowledge_base/)
```

**Flujo información:**
```
00_knowledge_base (fuente verdad)
    ↓
02_compliance (checklists basados en knowledge)
    ↓
04_templates (templates usan knowledge + compliance)
    ↓
05_prompts_produccion (prompts generados desde templates)
    ↓
06_outputs (resultados de prompts)
```

---

### 8. Orchestration System ✨ **NUEVO v2.2.0**

#### CLI_AGENTS_SYSTEM_CONTEXT.md
**Propósito:** Contexto completo para CLI agents (Copilot, Gemini, Codex) en sistema de orquestación multi-agente

**Contiene:**
- Rol de cada CLI agent en el sistema
- Arquitectura multi-agente (Claude Code como Orchestrator Maestro)
- Permisos pre-autorizados (autonomía máxima)
- Operaciones que requieren confirmación
- Docker constraints (TODAS las operaciones Odoo via Docker)
- Output format standards para CLIOutputParser
- 7 fases de orquestación y responsabilidades
- Budget awareness y pricing por modelo
- Specialization por CLI tool (Copilot vs Gemini vs Codex)
- Ejemplos de interacción y troubleshooting

**Cuándo usar:**
- **CRÍTICO:** CLI agents DEBEN leer este archivo antes de ejecutar tareas
- Entender el rol en el sistema de orquestación
- Conocer permisos pre-autorizados (evitar consultas innecesarias)
- Seguir formatos de output esperados
- Operar con autonomía dentro de límites

**Relacionado:** `../ORQUESTACION_CLAUDE_CODE.md`, `../RESUMEN_IMPLEMENTACION_ORQUESTACION_V1.0.md`

---

#### ORQUESTACION_CLAUDE_CODE.md (fuera de Knowledge Base)
**Propósito:** Contrato completo del sistema de orquestación multi-agente v1.0

**Ubicación:** `docs/prompts/ORQUESTACION_CLAUDE_CODE.md`

**Contiene:**
- Contrato completo entre usuario y Claude Code como Orchestrator Maestro
- Arquitectura del sistema (diagrams, flujos)
- 7 fases detalladas: Discovery → Audit → Close Gaps → Enhance → Dev → Test → Re-audit
- OrchestrationConfig y OrchestrationSession (dataclasses)
- Budget tracking con pricing por modelo (Claude, GPT-4o, Gemini, Codex)
- Sistema de confirmaciones para operaciones críticas
- Templates mapping (6 dimensiones de auditoría)
- Métricas y reporting (formato de reportes finales)
- CI/CD integration (GitHub Actions workflow)
- Error recovery strategies
- Ejemplos de uso (3 casos prácticos completos)
- Best practices y roadmap v1.1-v2.0

**Cuándo usar:**
- **CRÍTICO:** Claude Code DEBE seguir este contrato cuando actúa como Orchestrator Maestro
- Entender el flujo completo de orquestación
- Configurar orquestaciones complejas
- Integrar con CI/CD
- Personalizar budgets y límites
- Troubleshooting del sistema de orquestación

**Relacionado:** `CLI_AGENTS_SYSTEM_CONTEXT.md`, `../RESUMEN_IMPLEMENTACION_ORQUESTACION_V1.0.md`

---

#### RESUMEN_IMPLEMENTACION_ORQUESTACION_V1.0.md (fuera de Knowledge Base)
**Propósito:** Resumen ejecutivo de la implementación del sistema de orquestación autónoma

**Ubicación:** `docs/prompts/RESUMEN_IMPLEMENTACION_ORQUESTACION_V1.0.md`

**Contiene:**
- Resumen ejecutivo del sistema implementado
- Métricas de implementación (4,105 líneas, 130KB código + docs)
- Componentes implementados:
  - CLIOutputParser (817 líneas) by Codex GPT-4-turbo
  - IterativeOrchestrator (+843 líneas) by Copilot GPT-4o
  - Documentación completa (2,415 líneas) by Claude Code
- Tests y calidad (40+ tests, 90%+ coverage, 100% passing)
- Docker compliance verification
- ROI esperado ($6,900-14,900/año)
- Archivos entregados y próximos pasos
- Ejemplos de uso inmediato

**Cuándo usar:**
- Revisar el estado de la implementación
- Entender qué fue construido y por quién
- Ver métricas y ROI del sistema
- Planificar próximos pasos
- Onboarding de nuevos desarrolladores al sistema

**Relacionado:** `../ORQUESTACION_CLAUDE_CODE.md`, `CLI_AGENTS_SYSTEM_CONTEXT.md`

---

## 📊 MÉTRICAS KNOWLEDGE BASE

| Métrica | Valor |
|---------|-------|
| **Archivos totales** | 10 (8 en Knowledge Base + 2 referencias externas) |
| **Líneas documentación** | ~6,400 |
| **Temas cubiertos** | 8 (Stack, Compliance, Desarrollo, Arquitectura, Legal, Comandos, Orquestación, CLI Agents) |
| **Autosostenibilidad** | 100% |
| **Dependencias externas** | 0 |
| **Última actualización** | 2025-11-13 |

**Cobertura por área:**
- ✅ **Deployment & DevOps:** 100% (deployment_environment.md + docker_odoo_command_reference.md)
- ✅ **Compliance Odoo 19:** 100% (odoo19_deprecations_reference.md + compliance_status.md)
- ✅ **Desarrollo Odoo:** 100% (odoo19_patterns.md)
- ✅ **Arquitectura:** 100% (project_architecture.md)
- ✅ **Compliance Legal Chile:** 100% (sii_regulatory_context.md)
- ✅ **Orquestación Multi-Agente:** 100% (CLI_AGENTS_SYSTEM_CONTEXT.md + ORQUESTACION_CLAUDE_CODE.md + RESUMEN_IMPLEMENTACION) ✨ **NUEVO**

---

## ✅ CHECKLIST AUTOSOSTENIBILIDAD

**Esta Knowledge Base es autosostenida si:**

- [x] Cero dependencias archivos fuera de `docs/prompts/`
- [x] Toda documentación técnica crítica presente
- [x] Comandos ejecutables documentados
- [x] Ejemplos completos (antes/después)
- [x] Troubleshooting para problemas comunes
- [x] Referencias cruzadas internas válidas
- [x] Actualización regular (revisión mensual)

**CUMPLE: 100% autosostenibilidad ✅**

---

## 🔄 MANTENIMIENTO

### Frecuencia Actualización

| Archivo | Frecuencia | Próxima Revisión |
|---------|------------|------------------|
| deployment_environment.md | Trimestral | 2026-02-12 |
| docker_odoo_command_reference.md | Semestral | 2026-05-12 |
| odoo19_deprecations_reference.md | Fija (no cambia) | - |
| compliance_status.md | **Semanal** | 2025-11-19 |
| odoo19_patterns.md | Semestral | 2026-05-12 |
| project_architecture.md | Por cambio arquitectónico | As-needed |
| sii_regulatory_context.md | Anual | 2026-11-12 |

**Responsable mantenimiento:** Pedro Troncoso (@pwills85)

---

### Proceso Actualización

1. **Revisar cambios proyecto** (código, stack, compliance)
2. **Actualizar archivos afectados**
3. **Validar referencias cruzadas** (no links rotos)
4. **Actualizar versión** (semver en header)
5. **Commit con mensaje descriptivo**
6. **Actualizar fecha "Próxima Revisión"**

---

## 📚 REFERENCIAS EXTERNAS (Opcional)

**Documentación oficial Odoo 19:**
- https://www.odoo.com/documentation/19.0/

**Documentación oficial Python/PostgreSQL/Redis:**
- https://docs.python.org/3.12/
- https://www.postgresql.org/docs/15/
- https://redis.io/docs/

**Normativas Chile:**
- SII: https://www.sii.cl
- Previred: https://www.previred.com

**NOTA:** Referencias externas son complementarias. Esta Knowledge Base es completa sin ellas.

---

## 🎯 QUICK REFERENCE

**Duda sobre...** → **Leer archivo...**

- Stack Docker → `deployment_environment.md`
- Comandos Odoo → `docker_odoo_command_reference.md`
- Deprecaciones → `odoo19_deprecations_reference.md`
- Estado compliance → `compliance_status.md`
- Cómo desarrollar → `odoo19_patterns.md`
- Decisiones arquitectura → `project_architecture.md`
- Normativas Chile → `sii_regulatory_context.md`
- **Sistema orquestación (Claude Code)** → `../ORQUESTACION_CLAUDE_CODE.md` ✨ **NUEVO**
- **Contexto CLI agents (Copilot/Gemini/Codex)** → `CLI_AGENTS_SYSTEM_CONTEXT.md` ✨ **NUEVO**
- **Resumen implementación orquestación** → `../RESUMEN_IMPLEMENTACION_ORQUESTACION_V1.0.md` ✨ **NUEVO**

---

**Versión:** 1.1.0 (Orquestación Autónoma)
**Creado:** 2025-11-12
**Última Actualización:** 2025-11-13
**Mantenedor:** Pedro Troncoso (@pwills85)
**Status:** ✅ AUTOSOSTENIDO 100%
