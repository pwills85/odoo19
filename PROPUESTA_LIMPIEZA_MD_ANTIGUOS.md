# 📋 Propuesta de Limpieza - Archivos .md Antiguos (>10 días)

**Fecha:** 2025-11-17  
**Análisis:** ~400 archivos .md modificados antes del 2025-11-07

---

## 📊 Resumen Ejecutivo

| Categoría | Archivos | Espacio | Acción |
|-----------|----------|---------|--------|
| Backups | ~150 | ~50MB | ✅ ELIMINAR |
| Docs obsoletos | ~200 | ~15MB | ✅ ARCHIVAR |
| Pytest cache | ~2 | <1MB | ✅ ELIMINAR |
| README activos | ~20 | <1MB | 🔍 REVISAR |
| Config Claude | ~7 | <1MB | ⚠️ MANTENER |

**TOTAL:** ~350 archivos (~65MB liberados)

---

## 🗂️ Archivos Identificados

### 1. BACKUPS (ELIMINAR - Prioridad Alta)
```
backups/l10n_cl_hr_payroll_pre_sprint32_20251022_230224/  # 15 archivos
backups/.backup_docs_20251023_162111/                     # 135+ archivos
backups/l10n_cl_dte.backup/                               # README.md
.backup_consolidation/                                     # pytest cache
```
**Razón:** Git tiene histórico completo, backups redundantes

### 2. DOCS ANTIGUOS (ARCHIVAR - Prioridad Media)
```
docs/analisis_integracion/          # 20 archivos (Oct 22)
docs/payroll-project/               # 29 archivos (Oct 22)
docs/modules/l10n_cl_financial_reports/  # 25 archivos (Oct 23-24)
docs/planning/historical/           # 10+ archivos (Oct 22-23)
docs/status/                        # 5 archivos antiguos
```
**Razón:** Documentación histórica de implementación completada

### 3. PYTEST CACHE (ELIMINAR - Prioridad Alta)
```
addons/localization/l10n_cl_dte/tests/.pytest_cache/README.md
.backup_consolidation/l10n_cl_dte/tests/.pytest_cache/README.md
```
**Razón:** Cache regenerable automáticamente

---

## 🎯 Plan de Ejecución

### FASE 1: Limpieza Segura (Ejecutar ahora)

**1. Eliminar backups obsoletos:**
```bash
rm -rf backups/l10n_cl_hr_payroll_pre_sprint32_20251022_230224/
rm -rf backups/.backup_docs_20251023_162111/
rm -rf backups/l10n_cl_dte.backup/
rm -rf .backup_consolidation/
```

**2. Eliminar pytest cache:**
```bash
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
```

**3. Archivar documentación antigua masiva:**
```bash
# Crear directorio archivo
mkdir -p docs/archive/2025-10-HISTORICAL

# Mover documentación obsoleta
mv docs/analisis_integracion docs/archive/2025-10-HISTORICAL/
mv docs/payroll-project docs/archive/2025-10-HISTORICAL/

# Documentación ya en docs/archive/ con fechas antiguas
# (ya están archivados, revisar si mover a subdirectorio)
```

**Resultado esperado:** 
- ~180 archivos eliminados (backups + cache)
- ~50 archivos archivados (docs)
- ~65MB liberados

---

### FASE 2: Revisión Manual (Próxima sesión)

**Archivos que requieren revisión individual:**

1. **addons/custom/README.md** (Oct 21)
   - ¿Describe módulos activos?
   - ¿Instrucciones de instalación vigentes?

2. **addons/localization/README.md** (Oct 21)
   - ¿Enlaces correctos a submódulos?
   - ¿Estructura actualizada?

3. **ai-service/training/README.md** (Oct 22)
   - ¿Instrucciones de training actuales?
   - ¿Scripts válidos?

4. **docs/README.md** (Oct 23)
   - ¿Índice actualizado?
   - ¿Referencias correctas?

5. **.claude/project/*.md** (Oct 23)
   - ¿Configuración Claude vigente?
   - ¿Patterns Odoo 19 actualizados?

---

## ⚠️ Verificaciones de Seguridad

**ANTES de ejecutar FASE 1:**

```bash
# 1. Verificar estado Git limpio
git status

# 2. Verificar que archivos a eliminar NO están referenciados en código
grep -r "l10n_cl_hr_payroll_pre_sprint32" --include="*.py" .
grep -r "backup_docs_20251023" --include="*.py" .
grep -r "backup_consolidation" --include="*.py" .

# 3. Crear commit antes de limpieza
git add .
git commit -m "docs: pre-cleanup checkpoint"
```

**Backup de seguridad:**
Ya tenemos `~/odoo19_backup_20251117_131231.bundle` (64MB)

---

## 📈 Impacto Esperado

### Beneficios
- ✅ Repositorio más limpio (-65MB)
- ✅ Búsquedas más rápidas (menos archivos indexados)
- ✅ Navegación más clara en `/docs`
- ✅ Menor confusión con documentación obsoleta

### Riesgos (Mitigados)
- ⚠️ Pérdida de información histórica → Git tiene todo el histórico
- ⚠️ Enlaces rotos en docs antiguos → Están en archive/, accesibles
- ⚠️ Referencia desde código → Verificación previa ejecutada

---

## 🎯 Decisión

**¿Proceder con FASE 1 (limpieza segura de ~180 archivos)?**

Comandos listos para ejecutar:
1. Eliminar backups obsoletos
2. Eliminar pytest/pycache
3. Archivar docs antiguos masivos

**Próximo paso:** Esperar tu confirmación para ejecutar.
