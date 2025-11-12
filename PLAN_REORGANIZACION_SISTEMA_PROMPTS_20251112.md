# 🎯 Plan de Reorganización: Sistema de Prompts Profesional

**Fecha:** 2025-11-12  
**Objetivo:** Fusionar y estructurar `docs/prompts_desarrollo/` + `experimentos/` en sistema profesional  
**Status:** 🟡 EN EJECUCIÓN

---

## 📊 Auditoría Situación Actual

### Inventario Archivos

**`docs/prompts_desarrollo/`:**
- 73 archivos totales
- 60+ archivos .md en raíz (DESORDEN)
- 7 subdirectorios (cierre/, consolidacion/, ejemplos/, etc.)
- Mezcla: templates, estrategias, prompts históricos, outputs

**`experimentos/`:**
- 46 archivos .md
- 2 subdirectorios (outputs/, prompts/)
- Mezcla: auditorías, investigaciones, resúmenes

**Problema:** ~120 archivos markdown sin estructura clara, duplicación, difícil navegación

---

## 🎯 Nueva Estructura Profesional (Target)

```
docs/prompts/                              # NUEVO (reemplaza prompts_desarrollo + experimentos)
│
├── README.md                              # Índice navegable completo
│
├── 01_fundamentos/                        # Teoría y estrategias
│   ├── ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
│   ├── ESTRATEGIA_PROMPTING_EFECTIVO.md
│   ├── MEJORAS_ESTRATEGIA_GPT5_CLAUDE.md
│   ├── GUIA_SELECCION_TEMPLATE_P4.md
│   ├── CONTEXTO_GLOBAL_MODULOS.md
│   └── EJEMPLOS_PROMPTS_POR_NIVEL.md     # P1, P2, P3, P4
│
├── 02_compliance/                         # Odoo 19 CE + Legal
│   ├── CHECKLIST_ODOO19_VALIDACIONES.md  # Deprecaciones P0/P1/P2
│   ├── ACTUALIZACION_SISTEMA_PROMPTS_ODOO19_20251112.md
│   └── SII_PREVIRED_COMPLIANCE.md        # Normativas chilenas
│
├── 03_maximas/                            # Reglas no negociables
│   ├── MAXIMAS_DESARROLLO.md             # 17 máximas desarrollo
│   ├── MAXIMAS_AUDITORIA.md              # 12 máximas auditoría
│   └── MAXIMAS_COMPLIANCE.md             # Odoo 19 + Legal
│
├── 04_templates/                          # Plantillas reutilizables
│   ├── TEMPLATE_AUDITORIA.md             # Auditoría módulo
│   ├── TEMPLATE_CIERRE_BRECHA.md         # Cierre brecha específica
│   ├── TEMPLATE_P4_DEEP.md               # Análisis arquitectónico
│   ├── TEMPLATE_P4_INFRASTRUCTURE.md     # Análisis infraestructura
│   ├── TEMPLATE_P4_EXTENDED.md           # Auditoría 360°
│   └── TEMPLATE_DOCKER_ODOO_DEV.md       # Comandos desarrollo
│
├── 05_prompts_produccion/                 # Prompts validados en uso
│   ├── modulos/                           # Por módulo
│   │   ├── l10n_cl_dte/
│   │   │   ├── AUDIT_DTE_20251111.md
│   │   │   ├── CIERRE_BRECHAS_DTE_20251111.md
│   │   │   └── P4_DEEP_DTE_VALIDADO.md
│   │   ├── l10n_cl_hr_payroll/
│   │   │   ├── AUDIT_PAYROLL_20251111.md
│   │   │   └── CIERRE_BRECHAS_PAYROLL.md
│   │   ├── l10n_cl_financial_reports/
│   │   │   └── AUDIT_FINANCIAL_20251111.md
│   │   └── ai_service/
│   │       └── AUDIT_AI_SERVICE_20251111.md
│   │
│   ├── integraciones/                     # Auditorías integraciones
│   │   ├── AUDIT_ODOO_AI_20251112.md
│   │   ├── AUDIT_DTE_SII_20251112.md
│   │   └── AUDIT_PAYROLL_PREVIRED_20251112.md
│   │
│   └── consolidacion/                     # Cierre multi-módulo
│       ├── CIERRE_TOTAL_P0_P1_20251111.md
│       └── CONSOLIDACION_HALLAZGOS_20251112.md
│
├── 06_outputs/                            # Salidas documentadas
│   ├── 2025-11/                           # Por mes
│   │   ├── auditorias/
│   │   │   ├── 20251111_AUDIT_DTE_DEEP.md
│   │   │   ├── 20251111_AUDIT_PAYROLL.md
│   │   │   ├── 20251112_AUDIT_CIERRE_TOTAL.md
│   │   │   └── 20251112_CONSOLIDACION_HALLAZGOS.md
│   │   ├── cierres/
│   │   │   ├── 20251111_CIERRE_H1_H5.md
│   │   │   └── 20251112_CIERRE_H2_H6_H7.md
│   │   └── investigaciones/
│   │       ├── 20251111_P4_MICROSERVICIO_AI.md
│   │       └── 20251112_EVALUACION_ESTRATEGIA_PROMPTS.md
│   │
│   └── metricas/                          # Análisis cuantitativos
│       ├── METRICAS_P4_VALIDADAS.json
│       └── COMPLIANCE_DASHBOARD.md
│
├── 07_historico/                          # Archivos históricos
│   ├── 2025-10/                           # Por mes (si aplica)
│   └── 2025-11/
│       ├── prompts_obsoletos/             # Prompts superados
│       └── experimentos/                  # Investigaciones finalizadas
│
└── 08_scripts/                            # Herramientas automatización
    ├── generar_prompt_desde_template.sh
    ├── validar_compliance_odoo19.sh
    └── archivar_prompts_antiguos.sh
```

---

## 📋 Plan de Migración (5 Fases)

### Fase 1: Crear Estructura Base (15 min)

```bash
# Crear directorios nuevos
mkdir -p docs/prompts/{01_fundamentos,02_compliance,03_maximas,04_templates}
mkdir -p docs/prompts/{05_prompts_produccion/{modulos/{l10n_cl_dte,l10n_cl_hr_payroll,l10n_cl_financial_reports,ai_service},integraciones,consolidacion}}
mkdir -p docs/prompts/{06_outputs/2025-11/{auditorias,cierres,investigaciones},06_outputs/metricas}
mkdir -p docs/prompts/{07_historico/2025-11/{prompts_obsoletos,experimentos}}
mkdir -p docs/prompts/08_scripts
```

**Checklist:**
- [ ] Estructura directorios creada
- [ ] README.md raíz creado

---

### Fase 2: Migrar Fundamentos y Compliance (30 min)

**Fundamentos (01_fundamentos/):**
```bash
# Mover estrategias
mv docs/prompts_desarrollo/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md docs/prompts/01_fundamentos/
mv docs/prompts_desarrollo/ESTRATEGIA_PROMPTING_EFECTIVO.md docs/prompts/01_fundamentos/
mv docs/prompts_desarrollo/MEJORAS_ESTRATEGIA_GPT5_CLAUDE.md docs/prompts/01_fundamentos/
mv docs/prompts_desarrollo/GUIA_SELECCION_TEMPLATE_P4.md docs/prompts/01_fundamentos/
mv docs/prompts_desarrollo/CONTEXTO_GLOBAL_MODULOS.md docs/prompts/01_fundamentos/
mv docs/prompts_desarrollo/EJEMPLOS_PROMPTS_POR_NIVEL.md docs/prompts/01_fundamentos/
```

**Compliance (02_compliance/):**
```bash
# Mover compliance Odoo 19
mv docs/prompts_desarrollo/CHECKLIST_ODOO19_VALIDACIONES.md docs/prompts/02_compliance/
mv docs/prompts_desarrollo/ACTUALIZACION_SISTEMA_PROMPTS_ODOO19_20251112.md docs/prompts/02_compliance/
```

**Máximas (03_maximas/):**
```bash
# Mover máximas
mv docs/prompts_desarrollo/MAXIMAS_DESARROLLO.md docs/prompts/03_maximas/
mv docs/prompts_desarrollo/MAXIMAS_AUDITORIA.md docs/prompts/03_maximas/
```

**Checklist:**
- [ ] 6 archivos fundamentos migrados
- [ ] 2 archivos compliance migrados
- [ ] 2 archivos máximas migrados

---

### Fase 3: Migrar Templates y Renombrar (20 min)

**Templates (04_templates/):**
```bash
# Renombrar y mover plantillas
mv docs/prompts_desarrollo/plantilla_prompt_auditoria.md \
   docs/prompts/04_templates/TEMPLATE_AUDITORIA.md

mv docs/prompts_desarrollo/plantilla_prompt_cierre_brechas.md \
   docs/prompts/04_templates/TEMPLATE_CIERRE_BRECHA.md
```

**Crear templates P4 (desde experimentos/prompts/):**
```bash
# Estos serán creados en Fase 3 si no existen como archivos separados
# TEMPLATE_P4_DEEP.md
# TEMPLATE_P4_INFRASTRUCTURE.md
# TEMPLATE_P4_EXTENDED.md
# TEMPLATE_DOCKER_ODOO_DEV.md
```

**Checklist:**
- [ ] 2 plantillas renombradas y migradas
- [ ] 4 templates P4 creados/migrados

---

### Fase 4: Clasificar y Migrar Prompts Producción (60 min)

**Criterio clasificación:**
- **Producción:** Prompts validados, con fecha 20251111-20251112, alta calidad
- **Histórico:** Prompts obsoletos, superados por versiones nuevas

**Prompts Producción por Módulo:**

**DTE (05_prompts_produccion/modulos/l10n_cl_dte/):**
```bash
# Auditorías DTE validadas
mv experimentos/auditoria_dte_v3_20251111_193948.md \
   docs/prompts/05_prompts_produccion/modulos/l10n_cl_dte/AUDIT_DTE_P4_DEEP_20251111.md

mv docs/prompts_desarrollo/20251111_PROMPT_AUDIT_DTE_MODULE_COMPLETE.md \
   docs/prompts/05_prompts_produccion/modulos/l10n_cl_dte/AUDIT_DTE_COMPLETE_20251111.md

# Cierre brechas DTE
mv docs/prompts_desarrollo/20251111_PROMPT_CIERRE_BRECHAS_DTE_AUDIT.md \
   docs/prompts/05_prompts_produccion/modulos/l10n_cl_dte/CIERRE_BRECHAS_DTE_20251111.md
```

**Payroll (05_prompts_produccion/modulos/l10n_cl_hr_payroll/):**
```bash
mv experimentos/auditoria_payroll_20251111_202156.md \
   docs/prompts/05_prompts_produccion/modulos/l10n_cl_hr_payroll/AUDIT_PAYROLL_20251111.md

mv docs/prompts_desarrollo/prompt_desarrollo_nomina_cierre_final_p0.md \
   docs/prompts/05_prompts_produccion/modulos/l10n_cl_hr_payroll/CIERRE_P0_PAYROLL.md
```

**Financial Reports (05_prompts_produccion/modulos/l10n_cl_financial_reports/):**
```bash
mv experimentos/auditoria_financial_manual_20251111_204417.md \
   docs/prompts/05_prompts_produccion/modulos/l10n_cl_financial_reports/AUDIT_FINANCIAL_20251111.md
```

**AI Service (05_prompts_produccion/modulos/ai_service/):**
```bash
mv experimentos/auditoria_aiservice_20251111_203816.md \
   docs/prompts/05_prompts_produccion/modulos/ai_service/AUDIT_AI_SERVICE_20251111.md
```

**Integraciones (05_prompts_produccion/integraciones/):**
```bash
mv experimentos/auditoria_integracion_odoo_ai_20251112_114041.md \
   docs/prompts/05_prompts_produccion/integraciones/AUDIT_ODOO_AI_20251112.md

mv experimentos/auditoria_integracion_dte_sii_20251112_115420.md \
   docs/prompts/05_prompts_produccion/integraciones/AUDIT_DTE_SII_20251112.md

mv experimentos/auditoria_integracion_payroll_previred_20251112_120042.md \
   docs/prompts/05_prompts_produccion/integraciones/AUDIT_PAYROLL_PREVIRED_20251112.md
```

**Consolidación (05_prompts_produccion/consolidacion/):**
```bash
mv docs/prompts_desarrollo/20251111_PROMPT_DEFINITIVO_CIERRE_TOTAL_BRECHAS.md \
   docs/prompts/05_prompts_produccion/consolidacion/CIERRE_TOTAL_P0_P1_20251111.md

mv experimentos/consolidacion_hallazgos_criticos_20251112_121433.md \
   docs/prompts/05_prompts_produccion/consolidacion/CONSOLIDACION_HALLAZGOS_20251112.md
```

**Checklist:**
- [ ] Prompts DTE clasificados (3-5 archivos)
- [ ] Prompts Payroll clasificados (2-3 archivos)
- [ ] Prompts Financial clasificados (1-2 archivos)
- [ ] Prompts AI Service clasificados (1 archivo)
- [ ] Prompts Integraciones clasificados (3 archivos)
- [ ] Prompts Consolidación clasificados (2 archivos)

---

### Fase 5: Migrar Outputs y Archivar Históricos (45 min)

**Outputs Noviembre 2025 (06_outputs/2025-11/):**

**Auditorías:**
```bash
# Outputs auditorías validadas
cp experimentos/auditoria_dte_v3_20251111_193948.md \
   docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_DTE_DEEP.md

cp experimentos/auditoria_payroll_20251111_202156.md \
   docs/prompts/06_outputs/2025-11/auditorias/20251111_AUDIT_PAYROLL.md

cp experimentos/outputs/AUDITORIA_CIERRE_TOTAL_20251112_FINAL.md \
   docs/prompts/06_outputs/2025-11/auditorias/20251112_AUDIT_CIERRE_TOTAL.md
```

**Cierres:**
```bash
cp docs/prompts_desarrollo/20251111_INFORME_P4_CIERRE_BRECHAS_DTE_EVIDENCIA.md \
   docs/prompts/06_outputs/2025-11/cierres/20251111_CIERRE_H1_H5.md
```

**Investigaciones:**
```bash
cp experimentos/INVESTIGACION_PROMPT_P4_2_MICROSERVICIO_AI.md \
   docs/prompts/06_outputs/2025-11/investigaciones/20251111_P4_MICROSERVICIO_AI.md

cp experimentos/EVALUACION_ESTRATEGIA_PROMPTS_POST_AUDITORIA_360.md \
   docs/prompts/06_outputs/2025-11/investigaciones/20251112_EVALUACION_ESTRATEGIA_PROMPTS.md
```

**Métricas:**
```bash
# Si existen archivos JSON de métricas
cp experimentos/analysis/*.json docs/prompts/06_outputs/metricas/ 2>/dev/null || true
```

**Histórico (07_historico/2025-11/):**
```bash
# Mover prompts obsoletos (versiones antiguas, superadas)
mv docs/prompts_desarrollo/prompt_desarrollo_dte_fase_2.md \
   docs/prompts/07_historico/2025-11/prompts_obsoletos/

mv docs/prompts_desarrollo/prompt_desarrollo_nomina_fase_p1_cierre_total_brechas_preparacion_p2.md \
   docs/prompts/07_historico/2025-11/prompts_obsoletos/

# Mover experimentos finalizados
mv experimentos/FEEDBACK_AGENTE_MEJORADOR_PROMPTS.txt \
   docs/prompts/07_historico/2025-11/experimentos/

mv experimentos/META_PROMPT_DECISION_ESTRATEGICA.md \
   docs/prompts/07_historico/2025-11/experimentos/
```

**Checklist:**
- [ ] Outputs auditorías copiados (3-5 archivos)
- [ ] Outputs cierres copiados (1-2 archivos)
- [ ] Outputs investigaciones copiados (2-3 archivos)
- [ ] Archivos históricos migrados (30+ archivos)

---

### Fase 6: Crear README Navegable y Scripts (30 min)

**README.md Principal:**
```markdown
# 📚 Sistema de Prompts Profesional - Odoo 19 CE

Navegación completa del sistema de prompts del proyecto.

## 🗂️ Estructura

- **01_fundamentos/**: Estrategias, guías, contexto
- **02_compliance/**: Odoo 19 CE deprecaciones + legal
- **03_maximas/**: Reglas no negociables
- **04_templates/**: Plantillas reutilizables
- **05_prompts_produccion/**: Prompts validados en uso
- **06_outputs/**: Salidas documentadas por fecha
- **07_historico/**: Archivos obsoletos archivados
- **08_scripts/**: Herramientas automatización

[... índice completo con links internos]
```

**Scripts (08_scripts/):**

1. **`generar_prompt_desde_template.sh`**: Crear nuevo prompt desde template
2. **`validar_compliance_odoo19.sh`**: Validar prompt incluye checklist
3. **`archivar_prompts_antiguos.sh`**: Mover prompts obsoletos a histórico

**Checklist:**
- [ ] README.md creado con índice completo
- [ ] 3 scripts de automatización creados
- [ ] Scripts testeados y funcionales

---

## 📊 Métricas de Éxito

| Métrica | Antes | Después | Mejora |
|---------|-------|---------|--------|
| **Archivos en raíz** | 60+ | 0 | 100% |
| **Niveles jerarquía** | 2-3 | 4-5 (organizado) | +100% |
| **Navegación** | Caótica | README índice | ∞ |
| **Prompts históricos** | Mezclados | Archivados | 100% |
| **Tiempo localizar archivo** | 5-10 min | 30s | -90% |

---

## ⚠️ Precauciones

1. **NO ELIMINAR archivos**: Solo mover/copiar (seguro)
2. **Backup previo**: `git commit` antes de reorganización
3. **Validar links**: Actualizar referencias cruzadas en archivos movidos
4. **Probar navegación**: Verificar README índice funcional

---

## 🚀 Ejecución

**Comando completo:**
```bash
# Ejecutar fases 1-6 secuencialmente
./scripts/reorganizar_sistema_prompts.sh --execute-all --verbose

# O ejecutar fase por fase
./scripts/reorganizar_sistema_prompts.sh --fase 1
```

**Tiempo estimado total:** 3-4 horas

---

**Status:** 🟡 Plan aprobado - Listo para ejecución  
**Mantenedor:** Pedro Troncoso (@pwills85)  
**Fecha creación:** 2025-11-12
