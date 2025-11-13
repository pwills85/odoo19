# 🛠️ Scripts Automatización - Sistema de Prompts

**Versión:** 1.0.0  
**Fecha:** 2025-11-12  
**Mantenedor:** Pedro Troncoso (@pwills85)

---

## 📋 Scripts Disponibles

### 🤖 Scripts Copilot CLI (Ejecución Autónoma)

#### 1. `audit_compliance_copilot.sh` - Auditoría Compliance Odoo 19

**Propósito:** Validación autónoma de 8 patrones deprecación P0/P1/P2

**Uso:**
```bash
# Auditar módulo específico
./audit_compliance_copilot.sh l10n_cl_dte

# Auditar módulo payroll
./audit_compliance_copilot.sh l10n_cl_hr_payroll

# Auditar módulo por defecto (l10n_cl_dte)
./audit_compliance_copilot.sh
```

**Output:**
- Reporte: `docs/prompts/06_outputs/YYYY-MM/auditorias/YYYYMMDD_AUDIT_[MODULO]_COMPLIANCE_COPILOT.md`
- Duración: 1-2 minutos
- Contenido:
  - Tabla 8 patrones con counts
  - Compliance rate (P0, P1, Global)
  - Archivos críticos pendientes
  - Verificaciones reproducibles

**Requisitos:**
- Copilot CLI instalado (`copilot --version`)
- Autenticación válida (`GITHUB_TOKEN` en env)
- Módulo existe en `addons/localization/[MODULO]/`

---

#### 2. `audit_p4_deep_copilot.sh` - Auditoría P4-Deep Arquitectónica

**Propósito:** Análisis arquitectónico profundo con 10 dimensiones (A-J)

**Uso:**
```bash
# Auditar módulo payroll
./audit_p4_deep_copilot.sh l10n_cl_hr_payroll

# Auditar módulo financial reports
./audit_p4_deep_copilot.sh l10n_cl_financial_reports

# Auditar módulo por defecto (l10n_cl_hr_payroll)
./audit_p4_deep_copilot.sh
```

**Output:**
- Reporte: `docs/prompts/06_outputs/YYYY-MM/auditorias/YYYYMMDD_AUDIT_[MODULO]_P4_DEEP_COPILOT.md`
- Duración: 5-10 minutos
- Contenido:
  - Resumen ejecutivo (top 5 hallazgos)
  - 10 dimensiones analizadas (A-J)
  - ≥30 referencias código (archivo:línea)
  - ≥6 verificaciones reproducibles
  - Matriz hallazgos priorizados (P0/P1/P2)
  - Métricas cuantitativas

**Requisitos:**
- Copilot CLI instalado y autenticado
- Módulo existe
- Documentación estrategia disponible (`docs/prompts/01_fundamentos/`)

---

### 🔧 Instalación y Configuración

#### Instalar Copilot CLI

```bash
# Instalar globalmente
npm install -g @github/copilot

# Verificar instalación
copilot --version
# Esperado: 0.0.354 o superior

# Autenticar (primera vez)
copilot
> /login
[Sigue instrucciones OAuth en navegador]
```

#### Configurar Token GitHub

```bash
# Verificar token configurado
env | grep GITHUB_TOKEN

# Si no existe, configurar
export GITHUB_TOKEN="ghp_XXXXXXXXX"

# Agregar a ~/.zshrc o ~/.bashrc (persistente)
echo 'export GITHUB_TOKEN="ghp_XXXXXXXXX"' >> ~/.zshrc
source ~/.zshrc
```

#### Hacer Scripts Ejecutables

```bash
cd docs/prompts/08_scripts/
chmod +x audit_compliance_copilot.sh
chmod +x audit_p4_deep_copilot.sh
```

---

## 🎯 Casos de Uso

### Caso 1: Auditoría Rápida Pre-Commit

**Objetivo:** Validar compliance antes de commitear cambios

```bash
# En directorio raíz proyecto
./docs/prompts/08_scripts/audit_compliance_copilot.sh l10n_cl_dte

# Si compliance OK: commitear
git add .
git commit -m "feat: implementa feature X"

# Si compliance FAIL: corregir primero
# Ver reporte en docs/prompts/06_outputs/2025-11/auditorias/
```

---

### Caso 2: Auditoría Profunda Módulo Completo

**Objetivo:** Análisis arquitectónico antes de refactoring

```bash
# Ejecutar P4-Deep en módulo target
./docs/prompts/08_scripts/audit_p4_deep_copilot.sh l10n_cl_hr_payroll

# Revisar hallazgos críticos P0+P1
cat docs/prompts/06_outputs/2025-11/auditorias/YYYYMMDD_AUDIT_l10n_cl_hr_payroll_P4_DEEP_COPILOT.md

# Priorizar correcciones según matriz hallazgos
```

---

### Caso 3: Auditoría Batch Múltiples Módulos

**Objetivo:** Auditar todos los módulos del proyecto

```bash
# Script batch (crear si no existe)
for MODULE in l10n_cl_dte l10n_cl_hr_payroll l10n_cl_financial_reports; do
  echo "Auditando $MODULE..."
  ./docs/prompts/08_scripts/audit_compliance_copilot.sh "$MODULE"
done

echo "✅ Auditorías completadas"
ls -lh docs/prompts/06_outputs/2025-11/auditorias/
```

---

### Caso 4: Integración CI/CD

**Objetivo:** Validación automática en GitHub Actions

```yaml
# .github/workflows/audit-compliance.yml
- name: Audit Compliance Odoo 19
  run: |
    ./docs/prompts/08_scripts/audit_compliance_copilot.sh l10n_cl_dte
    # Exit 1 si encuentra deprecaciones críticas
```

---

## ⚠️ Troubleshooting

### Error: "Copilot CLI no instalado"

```bash
# Solución
npm install -g @github/copilot

# Verificar
which copilot
# Esperado: /usr/local/bin/copilot o similar
```

---

### Error: "GITHUB_TOKEN no configurado"

```bash
# Solución 1: Variable entorno temporal
export GITHUB_TOKEN="ghp_XXXXXXXXX"

# Solución 2: Autenticar con Copilot CLI
copilot
> /login

# Solución 3: Usar GitHub CLI
gh auth login
```

---

### Error: "Módulo no existe"

```bash
# Verificar módulo existe
ls -la addons/localization/l10n_cl_dte/

# Si no existe, usar módulo correcto
./audit_compliance_copilot.sh l10n_cl_hr_payroll
```

---

### Error: "Permission denied"

```bash
# Hacer script ejecutable
chmod +x audit_compliance_copilot.sh

# Verificar permisos
ls -l audit_compliance_copilot.sh
# Esperado: -rwxr-xr-x (x = ejecutable)
```

---

### Output Incompleto o Vacío

**Causas posibles:**
1. Prompt demasiado complejo → Simplificar
2. Timeout Copilot CLI → Dividir tarea en sub-tareas
3. Módulo muy grande → Usar P4-Infrastructure (más liviano)

**Solución:**
```bash
# Ejecutar modo interactivo para debug
copilot
> Audita compliance Odoo 19 en addons/localization/l10n_cl_dte/
> [Revisar comandos ejecutados paso a paso]
```

---

## 📊 Métricas de Performance

### Tiempos Promedio

| Script | Duración | Comandos Shell | Tokens Input | Tokens Output |
|--------|----------|----------------|--------------|---------------|
| `audit_compliance_copilot.sh` | 1-2 min | 10-15 | ~50k | ~2k |
| `audit_p4_deep_copilot.sh` | 5-10 min | 40-60 | ~300k | ~8k |

### ROI Tiempo

| Tarea | Manual | Copilot CLI Autónomo | Ahorro |
|-------|--------|---------------------|--------|
| Compliance 8 patrones | 15-20 min | 1-2 min | **-90%** |
| P4-Deep 10 dimensiones | 3-4 horas | 5-10 min | **-95%** |
| Consolidación 4 módulos | 2-3 horas | 5-8 min | **-96%** |

---

## 📚 Referencias

- **Guía completa Copilot CLI:** [COPILOT_CLI_AUTONOMO.md](../COPILOT_CLI_AUTONOMO.md)
- **Estrategia P4-Deep:** [01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md](../01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md)
- **Checklist Compliance:** [02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md](../02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md)
- **Máximas Auditoría:** [03_maximas/MAXIMAS_AUDITORIA.md](../03_maximas/MAXIMAS_AUDITORIA.md)

---

## 🔜 Próximos Scripts (Roadmap)

### En Desarrollo

- [ ] `generate_prompt_from_template.sh` - Generar prompt desde template
- [ ] `validate_prompt_quality.sh` - Validar prompt contra checklist calidad
- [ ] `consolidate_audits.sh` - Consolidar múltiples auditorías en reporte único
- [ ] `pre_commit_hook_copilot.sh` - Hook Git validación compliance

### Planificados

- [ ] `audit_security_scan.sh` - Scan seguridad (API keys, SQL injection, XXE)
- [ ] `audit_performance_scan.sh` - Scan performance (N+1, índices, batch)
- [ ] `audit_testing_coverage.sh` - Análisis coverage + gaps tests
- [ ] `dashboard_metrics_generator.sh` - Generar dashboard JSON métricas

---

---

## 🛡️ Sistema Validación Templates (MEJORA 11)

### Archivos

```
docs/prompts/08_scripts/
├── validate_templates.py          # Validador principal
├── test_validate_templates.py     # Tests unitarios (pytest)
├── generate_html_report.py        # Generador reportes HTML
```

### Uso Rápido

```bash
# Validar todos los templates
python3 validate_templates.py --all

# Validar template específico
python3 validate_templates.py ../04_templates/TEMPLATE_AUDITORIA.md

# Generar reporte HTML
python3 validate_templates.py --all --json validation_report.json
python3 generate_html_report.py --input validation_report.json
open ../06_outputs/TEMPLATES_VALIDATION_REPORT.html

# Ejecutar tests
pytest test_validate_templates.py -v
```

### Validaciones

- ✅ Estructura (secciones obligatorias)
- ✅ Metadata (versión, nivel, agente)
- ✅ Variables ({{VAR}}, {VAR}, [VAR])
- ✅ Cross-references (links templates)
- ✅ Markdown syntax (headers, code blocks)
- ✅ Coherencia nivel/agente (P4 no Haiku)

### Pre-Commit Hook

El hook ya está integrado en `.git/hooks/pre-commit`. Valida automáticamente templates staged y bloquea commit si fallan.

### CI Workflow

`.github/workflows/validate-templates.yml` ejecuta validación en cada PR con cambios en templates.

### Scoring

```
Score = 100 - (errors * 20) - (warnings * 5) - (infos * 1)

90-100: EXCELENTE ✅
80-89:  BUENO ✅
70-79:  ACEPTABLE ✅
<70:    RECHAZADO ❌ (bloquea commit)
```

### Documentación Completa

Ver instrucciones detalladas en: `TEMPLATE_VALIDATION_SYSTEM.md` (en este mismo directorio)

---

**🚀 Scripts de automatización profesionales para máxima productividad**

**Mantenedor:** Pedro Troncoso (@pwills85)
**Última actualización:** 2025-11-12

