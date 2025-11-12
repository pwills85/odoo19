# 🗺️ MAPA VISUAL SISTEMA PROMPTS - NAVEGACIÓN RÁPIDA

**Versión:** 2.0  
**Fecha:** 2025-11-12  
**Ubicación:** `docs/prompts/`

---

## 🎯 Acceso Directo por Necesidad

### "Necesito crear una auditoría"

```
1. docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
   ↓ (entender estrategia P4)
2. docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
   ↓ (validaciones obligatorias)
3. docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md
   ↓ (reglas no negociables)
4. docs/prompts/04_templates/TEMPLATE_AUDITORIA.md
   ↓ (copiar plantilla)
5. docs/prompts/05_prompts_produccion/modulos/[MODULO]/AUDIT_*.md
   ↓ (ejemplos validados)
6. docs/prompts/06_outputs/2025-11/auditorias/
   ↓ (guardar resultado aquí)
```

---

### "Necesito cerrar una brecha"

```
1. docs/prompts/06_outputs/2025-11/auditorias/[FECHA]_*.md
   ↓ (leer hallazgos auditoría)
2. docs/prompts/03_maximas/MAXIMAS_DESARROLLO.md
   ↓ (reglas desarrollo)
3. docs/prompts/04_templates/TEMPLATE_CIERRE_BRECHA.md
   ↓ (copiar plantilla)
4. docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
   ↓ (si toca Odoo 19 CE)
5. docs/prompts/05_prompts_produccion/modulos/[MODULO]/CIERRE_*.md
   ↓ (ejemplos validados)
6. docs/prompts/06_outputs/2025-11/cierres/
   ↓ (guardar resultado aquí)
```

---

### "Necesito validar compliance Odoo 19"

```
docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
   ↓ (8 patrones deprecación P0/P1/P2)

Validar contra:
  - ❌ t-esc → ✅ t-out
  - ❌ type='json' → ✅ type='jsonrpc' + csrf=False
  - ❌ attrs={} → ✅ Python expressions
  - ❌ _sql_constraints → ✅ models.Constraint
  - ❌ self._cr → ✅ self.env.cr
```

---

### "Necesito entender estrategias prompting"

```
docs/prompts/01_fundamentos/
  ├── ESTRATEGIA_PROMPTING_ALTA_PRECISION.md  (estrategia P4)
  ├── ESTRATEGIA_PROMPTING_EFECTIVO.md        (buenas prácticas)
  ├── GUIA_SELECCION_TEMPLATE_P4.md           (cuándo usar cada nivel)
  └── EJEMPLOS_PROMPTS_POR_NIVEL.md           (ejemplos P1-P4)
```

---

### "Necesito ver prompts validados de un módulo"

```
docs/prompts/05_prompts_produccion/modulos/

DTE (Facturación Electrónica):
  └── l10n_cl_dte/
      ├── AUDIT_DTE_P4_DEEP_20251111.md
      ├── AUDIT_DTE_COMPLETE_20251111.md
      └── CIERRE_BRECHAS_DTE_20251111.md

Payroll (Nómina):
  └── l10n_cl_hr_payroll/
      ├── AUDIT_PAYROLL_20251111.md
      └── CIERRE_P0_PAYROLL.md

Financial Reports:
  └── l10n_cl_financial_reports/
      └── AUDIT_FINANCIAL_20251111.md

AI Service:
  └── ai_service/
      └── AUDIT_AI_SERVICE_20251111.md
```

---

### "Necesito ver integraciones cross-módulo"

```
docs/prompts/05_prompts_produccion/integraciones/
  ├── AUDIT_ODOO_AI_20251112.md          (Odoo ↔ AI Service)
  ├── AUDIT_DTE_SII_20251112.md          (DTE ↔ SII)
  └── AUDIT_PAYROLL_PREVIRED_20251112.md (Payroll ↔ Previred)
```

---

### "Necesito ver outputs de auditorías ejecutadas"

```
docs/prompts/06_outputs/2025-11/auditorias/
  ├── 20251111_AUDIT_DTE_DEEP.md           (12 hallazgos P0/P1)
  ├── 20251111_AUDIT_PAYROLL.md            (8 hallazgos P0/P1)
  ├── 20251111_AUDIT_AI_SERVICE.md         (3 hallazgos P1)
  ├── 20251111_AUDIT_FINANCIAL.md          (5 hallazgos P0/P1)
  └── 20251112_CONSOLIDACION_HALLAZGOS.md  (28 hallazgos totales)
```

---

## 🔍 Comandos Búsqueda Rápida

### Por módulo
```bash
# DTE
find docs/prompts/ -name "*DTE*"

# Payroll
find docs/prompts/ -name "*PAYROLL*"

# AI Service
find docs/prompts/ -name "*AI_SERVICE*"
```

---

### Por fecha
```bash
# 11 de noviembre
find docs/prompts/ -name "*20251111*"

# 12 de noviembre
find docs/prompts/ -name "*20251112*"

# Todo noviembre 2025
find docs/prompts/06_outputs/2025-11/ -name "*.md"
```

---

### Por tipo
```bash
# Auditorías
find docs/prompts/ -name "AUDIT*"

# Cierres de brechas
find docs/prompts/ -name "CIERRE*"

# Templates
ls docs/prompts/04_templates/TEMPLATE_*.md

# Compliance
ls docs/prompts/02_compliance/*.md
```

---

## 📊 Tabla de Decisión Rápida

| Necesito... | Ir a... | Archivo clave |
|-------------|---------|---------------|
| Crear auditoría | `04_templates/` | TEMPLATE_AUDITORIA.md |
| Cerrar brecha | `04_templates/` | TEMPLATE_CIERRE_BRECHA.md |
| Validar Odoo 19 | `02_compliance/` | CHECKLIST_ODOO19_VALIDACIONES.md |
| Ver estrategia P4 | `01_fundamentos/` | ESTRATEGIA_PROMPTING_ALTA_PRECISION.md |
| Ver máximas | `03_maximas/` | MAXIMAS_DESARROLLO.md / MAXIMAS_AUDITORIA.md |
| Ver prompts DTE | `05_prompts_produccion/modulos/l10n_cl_dte/` | AUDIT_DTE_*.md |
| Ver prompts Payroll | `05_prompts_produccion/modulos/l10n_cl_hr_payroll/` | AUDIT_PAYROLL_*.md |
| Ver outputs | `06_outputs/2025-11/auditorias/` | 20251111_AUDIT_*.md |

---

## 🎯 Flujos de Trabajo Visualizados

### Workflow Auditoría Completa (P4 Deep)

```
┌─────────────────────────────────────────────────────┐
│ 1. PREPARACIÓN                                      │
│ ↓ Leer: ESTRATEGIA_PROMPTING_ALTA_PRECISION.md     │
│ ↓ Leer: CHECKLIST_ODOO19_VALIDACIONES.md           │
│ ↓ Leer: MAXIMAS_AUDITORIA.md                       │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ 2. CREACIÓN PROMPT                                  │
│ ↓ Copiar: TEMPLATE_AUDITORIA.md                    │
│ ↓ Adaptar: Incluir checklist Odoo 19               │
│ ↓ Adaptar: Contexto módulo específico              │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ 3. EJECUCIÓN                                        │
│ ↓ Ejecutar: Copilot CLI / Claude Code              │
│ ↓ Revisar: Hallazgos P0/P1/P2                      │
│ ↓ Validar: Métricas cuantitativas                  │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ 4. DOCUMENTACIÓN                                    │
│ ↓ Guardar prompt: 05_prompts_produccion/modulos/   │
│ ↓ Guardar output: 06_outputs/2025-11/auditorias/   │
│ ↓ Actualizar: README.md si es necesario            │
└─────────────────────────────────────────────────────┘
```

---

### Workflow Cierre Brecha (P2/P3)

```
┌─────────────────────────────────────────────────────┐
│ 1. ANÁLISIS HALLAZGOS                               │
│ ↓ Leer: 06_outputs/2025-11/auditorias/[FECHA].md   │
│ ↓ Identificar: Brecha específica a cerrar          │
│ ↓ Priorizar: P0 > P1 > P2                          │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ 2. PREPARACIÓN DESARROLLO                           │
│ ↓ Leer: MAXIMAS_DESARROLLO.md                      │
│ ↓ Validar: CHECKLIST_ODOO19_VALIDACIONES.md        │
│ ↓ Copiar: TEMPLATE_CIERRE_BRECHA.md                │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ 3. EJECUCIÓN CIERRE                                 │
│ ↓ Implementar: Código solución                     │
│ ↓ Probar: Tests unitarios + integración            │
│ ↓ Validar: Compliance Odoo 19                      │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│ 4. DOCUMENTACIÓN CIERRE                             │
│ ↓ Guardar: 06_outputs/2025-11/cierres/[FECHA].md   │
│ ↓ Actualizar: Dashboard hallazgos (marcar cerrado) │
│ ↓ Commit: Git con referencia hallazgo original     │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Atajos de Teclado (CLI)

```bash
# Alias recomendados para .zshrc o .bashrc

# Navegar a prompts
alias prompts='cd /Users/pedro/Documents/odoo19/docs/prompts'

# Ver README
alias prompts-help='cat /Users/pedro/Documents/odoo19/docs/prompts/README.md | less'

# Buscar por módulo
alias prompts-dte='find /Users/pedro/Documents/odoo19/docs/prompts -name "*DTE*"'
alias prompts-payroll='find /Users/pedro/Documents/odoo19/docs/prompts -name "*PAYROLL*"'

# Ver templates
alias prompts-templates='ls /Users/pedro/Documents/odoo19/docs/prompts/04_templates/'

# Ver checklist Odoo 19
alias odoo19-check='cat /Users/pedro/Documents/odoo19/docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md'

# Ver outputs recientes
alias prompts-outputs='ls -lt /Users/pedro/Documents/odoo19/docs/prompts/06_outputs/2025-11/auditorias/ | head -10'
```

---

## 📚 Referencias Cruzadas

| Desde | Hacia | Razón |
|-------|-------|-------|
| TEMPLATE_AUDITORIA.md | CHECKLIST_ODOO19_VALIDACIONES.md | Incluye checklist obligatorio |
| MAXIMAS_DESARROLLO.md | CHECKLIST_ODOO19_VALIDACIONES.md | Máxima #0 compliance primero |
| AUDIT_DTE_*.md | CIERRE_BRECHAS_DTE_*.md | Output auditoría → input cierre |
| ESTRATEGIA_PROMPTING_ALTA_PRECISION.md | GUIA_SELECCION_TEMPLATE_P4.md | Estrategia → Selección template |

---

**🗺️ Navegación optimizada - Máxima productividad**

**Mantenedor:** Pedro Troncoso (@pwills85)  
**Última actualización:** 2025-11-12
