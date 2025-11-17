# 📑 Índice de Scripts - Sistema de Orquestación y Auditoría

**Versión:** 2.1.0  
**Fecha:** 2025-11-13  
**Mantenedor:** Pedro Troncoso (@pwills85)

---

## 🎯 Propósito

Este directorio contiene todos los scripts de orquestación, auditoría y automatización del framework de prompts de máxima precisión.

---

## 📂 Estructura de Archivos

### 🤖 Orquestación Multi-CLI (CMO v2.1)

| Archivo | Descripción | LOC | Status |
|---------|-------------|-----|--------|
| **orchestrate_cmo.sh** | Orquestador Context-Minimal v2.1 con multi-CLI | 590 | ✅ Actualizado |
| **AI_CLI_USAGE.md** | Guía completa uso CLI (Copilot, Codex, Gemini) | 340 | ✅ Nuevo |
| **REFACTOR_MULTI_CLI_SUMMARY.md** | Resumen ejecutivo refactorización | 250 | ✅ Nuevo |
| **quick_test_multi_cli.sh** | Testing automatizado 3 CLIs | 180 | ✅ Nuevo |

**Referencia completa:** `orchestrate_cmo.sh` es la versión actualizada con soporte multi-CLI que reemplaza al orquestador legacy en `scripts/` (raíz proyecto).

---

### 🔍 Auditoría Automatizada (Copilot CLI)

| Archivo | Descripción | Tipo | Duración |
|---------|-------------|------|----------|
| **audit_compliance_copilot.sh** | Validación 8 patrones Odoo 19 | Compliance | 1-2 min |
| **audit_p4_deep_copilot.sh** | Análisis arquitectónico 10 dimensiones | Deep Audit | 5-10 min |

---

### 🧪 Testing y Validación

| Archivo | Descripción | Uso |
|---------|-------------|-----|
| **test_cli_benchmark.sh** | Benchmark performance CLIs | Testing |
| **test_cli_rapido.sh** | Test rápido Copilot CLI | Testing |
| **test_cli_simple.sh** | Test básico conectividad | Testing |
| **test_copilot_codex.sh** | Comparativa Copilot vs Codex | Testing |
| **test_validate_templates.py** | Tests unitarios validación templates | pytest |

---

### 🛠️ Utilidades y Helpers

| Archivo | Descripción | Lenguaje |
|---------|-------------|----------|
| **validate_templates.py** | Validador templates (scoring) | Python |
| **generate_html_report.py** | Generador reportes HTML | Python |
| **cache_manager.py** | Sistema caché respuestas LLM | Python |
| **notify.py** | Sistema notificaciones (Slack, Email) | Python |
| **prompts_cli.py** | CLI interactivo prompts | Python |

---

### 🔄 Ciclo Completo Auditoría

| Archivo | Descripción | Componentes |
|---------|-------------|-------------|
| **ciclo_completo_auditoria.sh** | Orquestador ciclo v1.0 | 4 fases |
| **ciclo_completo_auditoria_v2.sh** | Orquestador ciclo v2.0 mejorado | 6 fases |
| **orquestar_auditoria_dte_360.sh** | Auditoría 360° módulo DTE | Especializado |

---

### ⚙️ State Machine y Control

| Archivo | Descripción | Uso |
|---------|-------------|-----|
| **state_machine_cmo.sh** | Máquina estados CMO | Core |
| **generate_consigna.sh** | Generador CONSIGNA (200 tokens) | Core |
| **parse_conclusion.sh** | Parser CONCLUSIÓN (50 tokens) | Core |
| **generate_prompt.sh** | Generador prompts desde templates | Core |
| **validate_prompt.sh** | Validador calidad prompts | QA |

---

### 📊 Fases Paralelas (CMO)

| Archivo | Descripción | Paralelismo |
|---------|-------------|-------------|
| **phase_1_discovery.sh** | Fase 1: Auto-discovery componentes | Secuencial |
| **phase_2_parallel_audit.sh** | Fase 2: Auditoría paralela | Paralelo 4x |
| **phase_3_close_gaps.sh** | Fase 3: Cierre brechas | Secuencial |
| **phase_6_test.sh** | Fase 6: Testing masivo | Paralelo 3x |

---

### 🔄 Control y Sincronización

| Archivo | Descripción | Uso |
|---------|-------------|-----|
| **wait_for_audit_reports.sh** | Sincronización auditorías paralelas | Barrier |
| **update_metrics.py** | Actualización métricas tiempo real | Monitoring |

---

### 📋 Configuración y Data

| Archivo | Descripción | Formato |
|---------|-------------|---------|
| **cli_config.yaml** | Configuración CLIs (Copilot, Codex, Gemini) | YAML |
| **cache_config.yaml** | Configuración sistema caché | YAML |
| **notify_config.yaml** | Configuración notificaciones | YAML |
| **requirements.txt** | Dependencias Python scripts | Texto |
| **validation_report.json** | Reporte validación templates | JSON |

---

## 🚀 Uso Rápido por Caso

### Caso 1: Orquestar Módulo Completo

```bash
# Multi-CLI con Copilot (predeterminado)
./orchestrate_cmo.sh addons/localization/l10n_cl_dte 95 10 5.0

# Multi-CLI con Codex (compliance crítico)
AI_CLI=codex ./orchestrate_cmo.sh addons/localization/l10n_cl_dte 100 15 8.0

# Multi-CLI con Gemini (AI Service)
AI_CLI=gemini ./orchestrate_cmo.sh ai-service 90 5 3.0
```

---

### Caso 2: Auditoría Rápida Pre-Commit

```bash
# Compliance Odoo 19 (1-2 min)
./audit_compliance_copilot.sh l10n_cl_dte

# Si pasa → commitear
# Si falla → revisar reporte en docs/prompts/06_outputs/
```

---

### Caso 3: Auditoría Profunda Arquitectónica

```bash
# P4-Deep 10 dimensiones (5-10 min)
./audit_p4_deep_copilot.sh l10n_cl_hr_payroll

# Revisar hallazgos críticos P0+P1
cat ../06_outputs/2025-11/auditorias/YYYYMMDD_AUDIT_l10n_cl_hr_payroll_P4_DEEP_COPILOT.md
```

---

### Caso 4: Validar Templates Antes de Commit

```bash
# Validar todos los templates
python3 validate_templates.py --all

# Generar reporte HTML
python3 validate_templates.py --all --json validation_report.json
python3 generate_html_report.py --input validation_report.json

# Ver reporte
open ../06_outputs/TEMPLATES_VALIDATION_REPORT.html
```

---

### Caso 5: Testing Multi-CLI Automatizado

```bash
# Test 3 CLIs + invalid CLI (negative test)
./quick_test_multi_cli.sh ai-service 85 2 1.0

# Expected output:
# ✅ Test Copilot: SUCCESS
# ✅ Test Codex: SUCCESS (si instalado)
# ✅ Test Gemini: SUCCESS (si instalado)
# ✅ Test Invalid CLI: SUCCESS (falló correctamente)
```

---

## 📊 Métricas de Scripts

### Token Efficiency (CMO v2.1)

| Versión | Tokens/10 iter | Reducción | Compaction |
|---------|----------------|-----------|------------|
| v1.0 Clásica | 250K | - | CRÍTICO |
| v1.1 LEAN | 80K | -68% | ALTO |
| v2.0 Bash Master | 50K | -80% | MEDIO |
| **v2.1 CMO** | **2K** | **-99.2%** | **NULO** ✅ |

### ROI Tiempo Auditorías

| Auditoría | Manual | Script | Ahorro |
|-----------|--------|--------|--------|
| Compliance 8 patrones | 15-20 min | 1-2 min | **-90%** |
| P4-Deep 10 dimensiones | 3-4 horas | 5-10 min | **-95%** |
| Ciclo completo 6 fases | 8-12 horas | 15-25 min | **-97%** |

---

## 🔗 Referencias

### Documentación Core

- **README principal:** `README.md` (este directorio)
- **Guía Multi-CLI:** `AI_CLI_USAGE.md` (340 LOC)
- **Resumen CMO:** `REFACTOR_MULTI_CLI_SUMMARY.md`

### Documentación Framework

- **Estrategia Prompting:** `../01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`
- **Compliance Odoo 19:** `../02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
- **Máximas Auditoría:** `../03_maximas/MAXIMAS_AUDITORIA.md`
- **Templates:** `../04_templates/` (8 templates profesionales)

### Documentación Orquestación

- **Ciclos Autónomos:** `../09_ciclos_autonomos/README.md`
- **Copilot CLI Autónomo:** `../COPILOT_CLI_AUTONOMO.md`
- **Gemini CLI Autónomo:** `../GEMINI_CLI_AUTONOMO.md`
- **Arquitectura CMO:** `../ARQUITECTURA_CONTEXT_MINIMAL_ORCHESTRATION.md`

---

## 🛡️ Pre-Commit Hooks

Scripts integrados en `.git/hooks/pre-commit`:

1. **validate_templates.py** - Valida templates staged (score ≥70)
2. **audit_compliance_copilot.sh** - Valida compliance Odoo 19 (opcional)

Ver configuración completa en: `.git/hooks/pre-commit`

---

## 🔜 Roadmap

### En Desarrollo (P0)

- [ ] `auto_select_best_cli.sh` - Selección automática CLI según tarea
- [ ] `benchmark_cli_precision.sh` - Benchmark precisión Copilot vs Codex vs Gemini
- [ ] `orchestrate_parallel_modules.sh` - Orquestación paralela múltiples módulos

### Planificados (P1)

- [ ] `generate_cli_report.sh` - Reporte métricas uso CLIs
- [ ] `audit_security_scan.sh` - Scan seguridad (XXE, SQL injection, API keys)
- [ ] `audit_performance_scan.sh` - Scan performance (N+1, índices, batch)

---

## 📞 Soporte

**Issues:** Crear issue en GitHub con tag `[scripts]`  
**Mantenedor:** Pedro Troncoso (@pwills85)  
**Email:** pedro.troncoso@eergygroup.com

---

**Última actualización:** 2025-11-13  
**Versión:** 2.1.0
