# 📚 ÍNDICE MAESTRO - Documentación Odoo 19 CE Chile

**Última actualización:** 2025-10-23  
**Proyecto:** Facturación Electrónica Chilena + Nóminas  
**Stack:** Odoo 19 CE + Microservicios + IA

---

## 🚀 PARA EMPEZAR

### Nuevos Desarrolladores
- **[Quick Start](../QUICK_START.md)** - Setup en 5 minutos
- **[Team Onboarding](../TEAM_ONBOARDING.md)** - Guía completa (15 min)
- **[README Principal](../README.md)** - Documentación completa del proyecto

### Agentes IA
- **[AI Agent Instructions](../AI_AGENT_INSTRUCTIONS.md)** - Instrucciones para Claude, GPT-4, Copilot
- **[AI Agents Folder](ai-agents/)** - Contexto, reglas, patrones, workflows

---

## 📂 ESTRUCTURA DE DOCUMENTACIÓN

### 🏗️ [architecture/](architecture/) - Arquitectura y Diseño
Documentación de arquitectura técnica, diagramas y decisiones de diseño.

**Documentos principales:**
- `REPORTE_ARQUITECTURA_GRAFICO_PROFESIONAL.md` - Arquitectura completa con diagramas
- `INTEGRATION_PATTERNS_API_EXAMPLES.md` - Patrones de integración
- `INTEGRACION_CLASE_MUNDIAL_ANALITICA_COMPRAS_IA.md` - Integración proyectos + IA
- `ADR/` - Architecture Decision Records

### 📖 [guides/](guides/) - Guías Técnicas
Guías de desarrollo, testing, deployment y configuración.

**Documentos principales:**
- `CLI_TESTING_EXPERT_PLAN.md` - Plan de testing completo
- `GUIA_TESTING_FUNCIONAL_UI.md` - Testing funcional UI
- `DESPLIEGUE_INTEGRACION_PROYECTOS.md` - Deployment
- `SII_MONITORING_README.md` - Monitoreo SII
- `VALIDATION_TESTING_CHECKLIST.md` - Checklist validación
- `CLAUDE.md` - Integración Claude AI
- `ESPECIFICACIONES_IMAGENES_MODULO_ODOO19.md` - Especificaciones módulo

### 📡 [api/](api/) - Documentación APIs
Documentación de endpoints y APIs de los microservicios.

**APIs disponibles:**
- **DTE Service:** http://localhost:8001/docs (Swagger)
- **AI Service:** http://localhost:8002/docs (Swagger)
- **Odoo XML-RPC:** Puerto 8069

### 📋 [planning/](planning/) - Planes y Roadmaps
Planes de implementación, roadmaps y estrategias.

**Subdirectorios:**
- `historical/` - Planes históricos y completados

**Documentos principales:**
- Planes de implementación DTE
- Estrategias de IA
- Roadmaps de desarrollo
- Planes de integración

### 📊 [status/](status/) - Estados del Proyecto
Estados actuales y reportes de progreso.

**Documentos principales:**
- `ESTADO_FINAL_Y_PROXIMOS_PASOS.md` - Estado final
- `ESTADO_PROYECTO.md` - Estado actual
- `INFORME_FINAL_INTEGRACION_EXITOSA_2025-10-23.md` - Informe integración
- `SPRINT2_COMPLETION_SUMMARY.md` - Sprint 2
- `SPRINT3_PROGRESS_REPORT.md` - Sprint 3
- `SPRINT3_REFACTORING_ANALYTIC_ACCOUNTS.md` - Refactoring

### 🤖 [ai-agents/](ai-agents/) - Instrucciones para Agentes IA
Contexto, reglas y patrones para agentes IA (Claude, GPT-4, Copilot).

**Documentos principales:**
- `AI_AGENT_INSTRUCTIONS.md` - Instrucciones completas
- Contexto del proyecto
- Reglas de desarrollo
- Patrones de código
- Flujos de trabajo

### 📦 [archive/](archive/) - Archivo Histórico
Análisis históricos, auditorías y documentación de sesiones pasadas.

**Subdirectorios:**
- `2025-10-22/` - Documentos del 22 de octubre
- `2025-10-23/` - Documentos del 23 de octubre

**Contenido:**
- Análisis comparativos Odoo 18 vs 19
- Auditorías enterprise
- Sesiones de desarrollo
- Implementaciones completadas
- Resúmenes ejecutivos históricos

### 📚 [odoo19_official/](odoo19_official/) - Documentación Oficial Odoo 19
Documentación oficial de Odoo 19 CE extraída del código fuente.

**Subdirectorios:**
- `01_developer/` - Developer docs
- `02_models_base/` - Modelos base (account, purchase, stock)
- `03_localization/` - Localización Chile
- `04_views_ui/` - Views y UI
- `05_security/` - Seguridad
- `06_reports/` - Reportes
- `07_controllers/` - Controllers
- `08_testing/` - Testing
- `09_data_files/` - Data files
- `10_api_reference/` - API reference

---

## 🔍 BUSCAR DOCUMENTACIÓN

### Por Tema

| Tema | Ubicación |
|------|-----------|
| **Setup inicial** | [../QUICK_START.md](../QUICK_START.md) |
| **Onboarding** | [../TEAM_ONBOARDING.md](../TEAM_ONBOARDING.md) |
| **Arquitectura** | [architecture/](architecture/) |
| **Testing** | [guides/CLI_TESTING_EXPERT_PLAN.md](guides/CLI_TESTING_EXPERT_PLAN.md) |
| **Deployment** | [guides/DESPLIEGUE_INTEGRACION_PROYECTOS.md](guides/DESPLIEGUE_INTEGRACION_PROYECTOS.md) |
| **APIs** | [api/](api/) + Swagger (8001, 8002) |
| **IA/Claude** | [guides/CLAUDE.md](guides/CLAUDE.md) |
| **Monitoreo SII** | [guides/SII_MONITORING_README.md](guides/SII_MONITORING_README.md) |
| **Estado actual** | [status/](status/) |
| **Planes** | [planning/](planning/) |
| **Histórico** | [archive/](archive/) |

### Por Rol

| Rol | Documentos Recomendados |
|-----|-------------------------|
| **Nuevo Desarrollador** | QUICK_START → TEAM_ONBOARDING → README |
| **Arquitecto** | architecture/ → API docs → Odoo official |
| **DevOps** | guides/DESPLIEGUE_* → docker-compose.yml |
| **QA/Tester** | guides/*TESTING* → Validation checklist |
| **Agente IA** | AI_AGENT_INSTRUCTIONS → ai-agents/ |
| **Project Manager** | status/ → planning/ → README |

---

## 📊 ESTADÍSTICAS

```
Total documentos:     100+
Líneas de código:     50,000+
Líneas documentación: 30,000+
Archivos en raíz:     8 (esenciales)
Archivos organizados: 90+ (en /docs/)
```

---

## 🔗 ENLACES RÁPIDOS

### Documentación Principal
- [README.md](../README.md) - Documentación completa
- [START_HERE.md](../START_HERE.md) - Punto de entrada
- [QUICK_START.md](../QUICK_START.md) - Setup rápido
- [TEAM_ONBOARDING.md](../TEAM_ONBOARDING.md) - Onboarding

### Evaluación y Planes
- [EVALUACION_CONTEXTO_PROYECTO.md](../EVALUACION_CONTEXTO_PROYECTO.md) - Evaluación completa
- [PLAN_REORGANIZACION_SEGURA.md](../PLAN_REORGANIZACION_SEGURA.md) - Plan reorganización
- [RESUMEN_PLAN_REORGANIZACION.md](../RESUMEN_PLAN_REORGANIZACION.md) - Resumen ejecutivo

### Para Agentes IA
- [AI_AGENT_INSTRUCTIONS.md](../AI_AGENT_INSTRUCTIONS.md) - Instrucciones completas
- [ai-agents/](ai-agents/) - Carpeta agentes IA

### APIs (Swagger)
- DTE Service: http://localhost:8001/docs
- AI Service: http://localhost:8002/docs

---

## 📞 SOPORTE

**Desarrollador Principal:**  
Ing. Pedro Troncoso Willz  
Email: contacto@eergygroup.cl  
Empresa: EERGYGROUP  
Website: https://www.eergygroup.com

---

## 📝 CONTRIBUIR

Para contribuir al proyecto:
1. Lee [TEAM_ONBOARDING.md](../TEAM_ONBOARDING.md)
2. Sigue [AI_AGENT_INSTRUCTIONS.md](../AI_AGENT_INSTRUCTIONS.md) (patrones y reglas)
3. Ejecuta tests antes de commit
4. Documenta cambios

---

**Última reorganización:** 2025-10-23  
**Mantenido por:** Ing. Pedro Troncoso Willz  
**Licencia:** LGPL-3.0
