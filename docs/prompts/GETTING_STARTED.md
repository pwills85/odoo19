# 🚀 GETTING STARTED - Sistema PROMPTs Odoo 19

**Versión:** v2.2
**Fecha:** 2025-11-12
**Templates Disponibles:** 8
**Scripts Automatizados:** 3
**Cobertura Casos Uso:** 100%

---

## 📖 Overview

Sistema profesional multi-agente para auditoría, investigación, cierre de brechas y re-validación en Odoo 19 CE.

**Características principales:**
- 🤖 Orquestación inteligente de modelos AI (Haiku 4.5, Sonnet 4, Sonnet 4.5, GPT-5)
- 📊 Tracking histórico de métricas y ROI
- 🔄 Validación cruzada automática
- 📈 Dashboard visual de evolución
- ⚡ Automatización completa con scripts Bash

---

## ⚡ Quick Start (5 minutos)

### 1. Ejecutar Primera Auditoría Completa

```bash
cd /Users/pedro/Documents/odoo19/docs/prompts

# Opción A: Script automatizado (recomendado - próximamente)
chmod +x 08_scripts/ciclo_completo_auditoria.sh
./08_scripts/ciclo_completo_auditoria.sh 1

# Opción B: Manual con Copilot CLI
copilot -p "Audita compliance Odoo 19 siguiendo TEMPLATE_AUDITORIA.md" \
  --model claude-haiku-4.5 --allow-all-paths

copilot -p "Audita backend Python siguiendo TEMPLATE_P4_DEEP_ANALYSIS.md" \
  --model claude-sonnet-4.5 --allow-all-paths

copilot -p "Audita frontend QWeb/XML/JS siguiendo TEMPLATE_AUDITORIA.md" \
  --model claude-sonnet-4 --allow-all-paths
```

**Output esperado:**
- 3 reportes detallados en `06_outputs/2025-11/auditorias/`
- Score por dominio (Compliance, Backend, Frontend)
- Lista hallazgos priorizados (P0, P1, P2)

### 2. Ver Resultados

```bash
# Dashboard métricas
cat 06_outputs/METRICS_DASHBOARD.md

# Último reporte consolidado (cuando esté disponible)
ls -t 06_outputs/*/consolidados/*.md | head -1 | xargs cat
```

---

## 📚 Casos de Uso Principales

### Caso 1: Auditoría Técnica Completa (BASELINE)

**Objetivo:** Establecer baseline del proyecto antes de mejoras

**Template:** `TEMPLATE_AUDITORIA.md` (P3)
**Agente:** Agent_Auditor (Sonnet 4.5)
**Duración:** 5-8 minutos
**Costo:** ~$1.00 Premium

```bash
copilot -p "$(cat 04_templates/TEMPLATE_AUDITORIA.md)

MÓDULO: addons/localization/l10n_cl_dte/
DIMENSIONES: Compliance, Backend, Frontend, Seguridad
OUTPUT: docs/prompts/06_outputs/2025-11/auditorias/compliance_report_2025-11-12.md" \
  --model claude-sonnet-4.5 --allow-all-paths
```

**Output:**
- Tabla hallazgos con prioridad, archivo:línea, esfuerzo estimado
- Score global /100
- Plan acción 3 Sprints

---

### Caso 2: Investigación Módulo (ONBOARDING)

**Objetivo:** Entender arquitectura para nuevo desarrollador

**Template:** `TEMPLATE_INVESTIGACION_P2.md` (P2)
**Agente:** Agent_Explorer (Sonnet 4 / Haiku 4.5)
**Duración:** 4-6 minutos
**Costo:** ~$0.50 Premium

```bash
copilot -p "Investiga arquitectura l10n_cl_dte siguiendo TEMPLATE_INVESTIGACION_P2.md:

OBJETIVO: Onboarding nuevo dev - documentar flujo DTE end-to-end
OUTPUT: Diagramas Mermaid + guía navegación código + decisiones técnicas" \
  --model claude-sonnet-4 --allow-all-paths
```

**Output:**
- Diagrama secuencia flujo principal
- Tabla componentes (LOC, complejidad, responsabilidad)
- Decisiones técnicas justificadas
- Guía "¿Por dónde empezar?"

---

### Caso 3: Feature Discovery (ROADMAP)

**Objetivo:** Identificar features alto valor para roadmap producto

**Template:** `TEMPLATE_FEATURE_DISCOVERY.md` (P3)
**Agente:** Agent_Strategist (Sonnet 4.5 / GPT-5)
**Duración:** 8-12 minutos
**Costo:** ~$1.50 Premium

```bash
copilot -p "Descubre features alto valor siguiendo TEMPLATE_FEATURE_DISCOVERY.md:

ANÁLISIS:
- Competidores: SAP B1 Chile, Buk, Defontana
- Tickets soporte últimos 6 meses
- Regulaciones SII 2026

OUTPUT: Top 3 features priorizadas + matriz impacto/esfuerzo + roadmap Q1 2026" \
  --model claude-sonnet-4.5 --allow-all-paths
```

**Output:**
- Análisis gaps competitivos
- Scoring features (ROI-driven)
- Roadmap priorizado por quarter
- Business case con ROI estimado

---

### Caso 4: Re-Auditoría Post-Sprint (VALIDACIÓN ROI)

**Objetivo:** Validar mejoras post-Sprint, calcular ROI real, detectar regresiones

**Template:** `TEMPLATE_RE_AUDITORIA_COMPARATIVA.md` (P4)
**Agente:** Agent_Validator (Haiku 4.5)
**Duración:** 3-5 minutos
**Costo:** ~$0.33 Premium

```bash
# Después de completar Sprint de cierre de brechas
./08_scripts/re_auditoria.sh 1
```

**Output:**
- Tabla comparativa pre/post (scores, hallazgos, compliance)
- ROI validado (1 mes, 1 año)
- Regresiones detectadas
- Recomendación: APROBAR merge o REVISAR

---

## 🗂️ Estructura Directorios

```
docs/prompts/
├── 00_knowledge_base/           # Docs referencia (SII, Odoo 19)
│   ├── odoo19_deprecations.md
│   └── sii_dte_specifications.md
│
├── 01_cierre_brechas/           # Prompts cierre generados automáticamente
│   └── sprint_1/
│       ├── P0_attrs_migration.md
│       └── P0_complexity_refactor.md
│
├── 02_compliance/               # Checklists validación
│   └── CHECKLIST_ODOO19_VALIDACIONES.md
│
├── 03_phase_prompts/            # Prompts por fase (P1-P4)
│
├── 04_templates/                # 8 templates sistema v2.2
│   ├── TEMPLATE_AUDITORIA.md
│   ├── TEMPLATE_CIERRE_BRECHA.md
│   ├── TEMPLATE_INVESTIGACION_P2.md
│   ├── TEMPLATE_FEATURE_DISCOVERY.md
│   ├── TEMPLATE_RE_AUDITORIA_COMPARATIVA.md
│   ├── TEMPLATE_MULTI_AGENT_ORCHESTRATION.md
│   ├── TEMPLATE_P4_DEEP_ANALYSIS.md
│   └── TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md
│
├── 06_outputs/                  # Reportes generados
│   ├── 2025-11/
│   │   ├── auditorias/         # Reportes iniciales
│   │   ├── consolidados/       # Reportes consolidados multi-agente
│   │   └── re_auditorias/      # Validaciones post-Sprint
│   ├── metrics_history.json    # Tracking histórico JSON
│   └── METRICS_DASHBOARD.md    # Dashboard visual evolución
│
├── 08_scripts/                  # Scripts automatización
│   ├── ciclo_completo_auditoria.sh   # Ciclo completo automatizado
│   ├── re_auditoria.sh               # Re-auditoría post-Sprint
│   └── update_metrics.py             # Actualizar métricas JSON
│
├── GETTING_STARTED.md          # Esta guía
└── README.md                   # Documentación principal
```

---

## 🎯 Matriz Decisión: ¿Qué Template Usar?

| Necesitas... | Template | Nivel | Agente | Duración | Costo |
|-------------|----------|-------|--------|----------|-------|
| **Establecer baseline proyecto** | TEMPLATE_AUDITORIA | P3 | Sonnet 4.5 | 5-8min | $1.00 |
| **Onboarding nuevo dev** | TEMPLATE_INVESTIGACION_P2 | P2 | Sonnet 4 | 4-6min | $0.50 |
| **Planificar roadmap features** | TEMPLATE_FEATURE_DISCOVERY | P3 | Sonnet 4.5 | 8-12min | $1.50 |
| **Validar Sprint completado** | TEMPLATE_RE_AUDITORIA_COMPARATIVA | P4 | Haiku 4.5 | 3-5min | $0.33 |
| **Cerrar brecha específica** | TEMPLATE_CIERRE_BRECHA | P3 | Sonnet 4 | 4-6min | $1.00 |
| **Análisis profundo backend** | TEMPLATE_P4_DEEP_ANALYSIS | P4 | Sonnet 4.5 | 5-10min | $1.00 |
| **Auditar infraestructura** | TEMPLATE_P4_INFRASTRUCTURE_AUDIT | P4 | Sonnet 4.5 | 5-10min | $1.00 |
| **Orquestar multi-agente** | TEMPLATE_MULTI_AGENT_ORCHESTRATION | P4 | Sonnet 4.5 | 15-20min | $3.00 |

---

## 💡 Best Practices

### ✅ DO (Recomendaciones):

1. **Baseline antes de cambios:** Ejecuta ciclo completo auditoría antes de implementar mejoras
2. **Re-auditar siempre:** Después de cada Sprint, valida con RE-AUDITORIA_COMPARATIVA
3. **Usa scripts:** Preferir automatización vs comandos manuales (consistencia)
4. **Revisa métricas regularmente:** Dashboard muestra tendencias y ROI
5. **Validación cruzada GPT-5:** Para consolidaciones críticas, usa doble-check

### ❌ DON'T (Evitar):

1. **Saltar compliance P0:** Bloqueante para producción (deadline 2025-03-01)
2. **Modificar templates sin versionar:** Puede romper workflows existentes
3. **Cerrar issues sin re-auditar:** Riesgo regresiones no detectadas
4. **Ignorar warnings scripts:** Permisos, timeouts → revisar logs
5. **Mezclar templates:** Auditoría ≠ Investigación (propósitos diferentes)

---

## 🔧 Troubleshooting

### Error: "Permission denied" en scripts

**Solución:**
```bash
chmod +x docs/prompts/08_scripts/*.sh
chmod +x docs/prompts/08_scripts/*.py
```

### Error: "Copilot CLI not found"

**Solución:**
```bash
# Instalar Copilot CLI
npm install -g @githubnext/github-copilot-cli

# O vía gh extension
gh extension install github/gh-copilot
```

### Timeout agentes (>15 min)

**Posibles causas:**
- Scope muy grande (ej: auditar 10 módulos simultáneamente)
- Modelo lento (Sonnet 4.5 vs Haiku 4.5)

**Soluciones:**
1. Reducir scope (1-2 módulos por vez)
2. Usar Haiku 4.5 para auditorías rápidas
3. Aumentar timeout en script (default: 15min)

### Output incompleto o vacío

**Checklist:**
- ¿Template existe en ruta correcta?
- ¿Módulo/path especificado es válido?
- ¿Permisos lectura archivos proyecto?
- Revisar logs Copilot: `~/.copilot/logs/`

---

## 📊 Sistema de Métricas (v2.2)

### Tracking Histórico

El sistema guarda métricas JSON para comparar evolución Sprint vs Sprint:

```json
{
  "sprints": [
    {
      "sprint_id": 1,
      "date": "2025-11-12",
      "scores": {"global": 77, "compliance": 80, "backend": 78, "frontend": 73},
      "findings": {"p0": 25, "p1": 28, "p2": 20, "total": 73}
    }
  ],
  "trends": {
    "score_evolution": [77],
    "findings_evolution": [73],
    "compliance_evolution": [80.4]
  }
}
```

### Actualizar Métricas

```bash
# Después de auditoría
python3 08_scripts/update_metrics.py \
  06_outputs/2025-11/consolidados/CONSOLIDATED_REPORT_360_2025-11-12.md \
  1 \
  initial

# Después de Sprint
python3 08_scripts/update_metrics.py \
  06_outputs/2025-11/re_auditorias/RE_AUDIT_SPRINT_1_2025-11-19.md \
  2 \
  re_audit
```

**Output:**
- Actualiza `metrics_history.json`
- Regenera `METRICS_DASHBOARD.md` automáticamente

---

## 🎓 Workflow Recomendado (Primera Vez)

### Semana 1: Baseline

**Día 1-2:** Auditoría inicial
```bash
./08_scripts/ciclo_completo_auditoria.sh 1
```

**Día 3:** Revisar reporte consolidado
- Identificar Top 10 hallazgos P0/P1
- Estimar esfuerzo total
- Definir Sprints

**Día 4-5:** Investigación módulos críticos (opcional)
- Onboarding en módulos que tendrán más cambios
- Documentar arquitectura actual

### Semana 2-3: Sprint 1 (P0 Críticos)

**Inicio Sprint:** Generar prompts cierre
```bash
# Automático en ciclo completo, o manual:
copilot -p "Lee CONSOLIDATED_REPORT y genera prompts cierre top 5 P0" \
  --model claude-sonnet-4
```

**Durante Sprint:** Implementar fixes
- Usar prompts generados como guía
- Tests + documentación

**Fin Sprint:** Re-auditoría
```bash
./08_scripts/re_auditoria.sh 1
```

**Validar:**
- ¿Score mejoró?
- ¿P0 cerrados al 100%?
- ¿ROI positivo?
- ¿0 regresiones?

### Semanas siguientes: Sprint 2, 3...

Repetir ciclo hasta Score objetivo (ej: 90/100)

---

## 📞 Soporte y Recursos

**Documentación:**
- README principal: `docs/prompts/README.md`
- Templates detallados: `docs/prompts/04_templates/`
- Ejemplos outputs: `docs/prompts/06_outputs/2025-11/`

**Issues y Bugs:**
- GitHub Issues: [Crear issue](https://github.com/tu-repo/issues)
- Logs sistema: `~/.copilot/logs/`

**Referencias Externas:**
- Odoo 19 Deprecations: https://odoo.com/documentation/19.0/developer/reference/upgrades.html
- SII Regulaciones: https://sii.cl/

---

## ⚖️ Versiones Sistema

### v2.2 (Actual - 2025-11-12)

**Nuevas features:**
- ✅ TEMPLATE_RE_AUDITORIA_COMPARATIVA (validación ROI post-Sprint)
- ✅ TEMPLATE_INVESTIGACION_P2 (onboarding/documentación)
- ✅ TEMPLATE_FEATURE_DISCOVERY (roadmap estratégico)
- ✅ Sistema métricas JSON centralizado
- ✅ Dashboard visual evolución
- ✅ Validación cruzada GPT-5
- ✅ Scripts automatización (ciclo completo + re-auditoría)
- ✅ Documentación completa (esta guía)

**Cobertura:** 100% casos uso (vs 50% en v2.1)
**Templates:** 8 (vs 5 en v2.1)

### v2.1 (Anterior - 2025-11-10)

**Features:**
- 5 templates básicos
- Auditoría manual
- Sin tracking histórico
- Sin ROI validation

---

## 🚀 Próximos Pasos Sugeridos

1. **Ahora:** Ejecuta primera auditoría baseline
2. **Hoy:** Revisa dashboard métricas
3. **Esta semana:** Cierra P0 críticos (Sprint 1)
4. **Próxima semana:** Re-auditoría + validación ROI
5. **Mes 1:** Score objetivo >85/100, Compliance P0 = 100%

---

**Última actualización:** 2025-11-12
**Versión sistema:** v2.2
**Mantenedor:** Sistema Multi-Agente Autónomo
**Generado con:** MEJORA_7 (FASE 2)
