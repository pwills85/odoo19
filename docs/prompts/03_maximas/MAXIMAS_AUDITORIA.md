# Máximas de Auditoría – Odoo 19 CE (Localización Chile)

Estas máximas rigen todas las auditorías funcionales y técnicas (Nómina, DTE, Reportes).

---

## 🚨 MÁXIMA #0: Compliance Odoo 19 CE (VALIDAR PRIMERO)

**OBLIGATORIO - Ejecutar ANTES de cualquier otra auditoría**

**Checklist completo:** `docs/prompts_desarrollo/CHECKLIST_ODOO19_VALIDACIONES.md`  
**Guía deprecaciones:** `.claude/project/ODOO19_DEPRECATIONS_CRITICAL.md`

### Comando Auditoría Automática

```bash
# Auditar deprecaciones P0+P1 en módulo
python3 scripts/odoo19_migration/1_audit_deprecations.py \
  --target addons/localization/[MODULO]/

# Ver reporte detallado
cat audit_report.md
```

### Validación Manual Rápida

```bash
# Detectar deprecaciones críticas
grep -rn "t-esc\|type='json'\|attrs=\|self\._cr\|fields_view_get\|_sql_constraints\|<dashboard" \
  addons/localization/[MODULO]/ --color=always | grep -v ".backup" | grep -v "tests/"

# Esperado: 0 matches en código producción
```

### Reporte Obligatorio en Auditoría

**Sección "✅ Compliance Odoo 19 CE" debe incluir:**
- Estado validaciones P0: [X/5 OK] - Detalle por patrón
- Estado validaciones P1: [X/3 OK] - Detalle por patrón
- Compliance Rate: [XX%] = (OK / total) * 100
- Deadline P0: 2025-03-01 (109 días restantes)
- Archivos críticos pendientes: [Lista si aplica]

**Prioridad:** P0 si hay deprecaciones críticas (bloquea producción)

---

## 🚨 MÁXIMA #0.5: Validación de Instalación Real (AUDITORÍA 2 FASES)

**OBLIGATORIO - Ejecutar DESPUÉS de MÁXIMA #0, ANTES de producción**

### ⚠️ Lección Aprendida (2025-11-14)

**Problema detectado:**
- ✅ Auditoría código estático: 100% compliance (l10n_cl_dte)
- ❌ Instalación real: 3 errores críticos (XML parse, XPath, computed fields)

**Causa raíz:**
El análisis estático (grep) NO detecta:
1. Errores de instalación (views, dependencies, XPath)
2. Cambios de sintaxis Odoo 19 (`<tree>` → `<list>`)
3. Computed fields sin `store=True` en filtros search
4. Referencias a modelos/vistas inexistentes
5. Dependencias Python faltantes

**Solución:** Auditoría de 2 fases obligatoria

---

### FASE 1: Análisis Estático (Compliance Código)

**Script:** `docs/prompts/08_scripts/audit_compliance_copilot.sh [MODULO]`

**Valida:** 8 patrones deprecación (P0/P1/P2)
- ✅ t-esc, type='json', attrs={}, _sql_constraints, etc.
- ⚡ Tiempo: ~30 segundos
- 📊 Output: Compliance rate (%)

**Limitaciones conocidas:**
- ❌ NO detecta errores instalación
- ❌ NO valida sintaxis runtime
- ❌ NO verifica dependencias

---

### FASE 2: Validación Instalación Real

**Script:** `docs/prompts/08_scripts/validate_installation.sh [MODULO]`

**Comando base:**
```bash
# Test instalación en BBDD limpia
docker compose run --rm odoo odoo \
  -d test_odoo19_$(date +%Y%m%d) \
  -i [MODULO] \
  --stop-after-init \
  --log-level=warn \
  2>&1 | tee /tmp/install_[MODULO].log

# Validar resultado
grep -E "ERROR|CRITICAL" /tmp/install_[MODULO].log
# Esperado: 0 matches
```

**Validaciones obligatorias:**

#### ✅ Criterios de Éxito (0 ERRORS)
```bash
# 1. Sin errores críticos
! grep -E "ERROR|CRITICAL" /tmp/install_[MODULO].log

# 2. Módulo cargado
grep "Modules loaded" /tmp/install_[MODULO].log

# 3. Sin ParseError (XML)
! grep "ParseError" /tmp/install_[MODULO].log

# 4. Sin ImportError (Python)
! grep "ImportError" /tmp/install_[MODULO].log

# 5. Registry loaded OK
grep "Registry loaded" /tmp/install_[MODULO].log
```

#### ⚠️ Warnings Aceptables (NO bloquean)
- `DeprecationWarning: 'group_operator'` → usar `aggregator`
- `unknown parameter 'states'` → parámetro legacy funcional
- `unknown parameter 'unaccent'` → parámetro legacy funcional
- `A <i> with fa class (fa ...) must have title` → accesibilidad

**Estos warnings NO rompen funcionalidad, son deprecations suaves**

#### ❌ Errores Runtime Críticos (BLOQUEAN)

**Categoría 1: XML Parse Errors**
```
ParseError: Invalid view type: 'tree'
└─> FIX: Cambiar <tree> a <list> (Odoo 19 syntax)

ParseError: Element '<xpath expr="//field[@name='X']">' cannot be located
└─> FIX: Verificar que field existe en vista padre

ParseError: Unsearchable field "X" in domain
└─> FIX: Agregar store=True en computed field o remover de filter
```

**Categoría 2: Import Errors**
```
ImportError: cannot import name 'hr_contract_stub'
└─> FIX: Crear archivo faltante

ValueError: External ID not found: module.view_id
└─> FIX: Verificar que vista heredada existe
```

**Categoría 3: Dependency Errors**
```
MissingDependency: External dependency 'python-dotenv' not installed
└─> FIX: Agregar a requirements.txt y pip install
```

**Categoría 4: Database Constraints**
```
IntegrityError: null value in column "model_id" violates not-null constraint
└─> FIX: Limpiar CSV de modelos inexistentes
```

---

### Matriz de Detección

| Error | Fase 1 (Código) | Fase 2 (Instalación) |
|-------|-----------------|---------------------|
| `t-esc` deprecado | ✅ Detecta | ✅ Detecta |
| `attrs={}` deprecado | ✅ Detecta | ✅ Detecta |
| `<tree>` → `<list>` | ❌ NO detecta | ✅ Detecta |
| XPath inválido | ❌ NO detecta | ✅ Detecta |
| Computed field sin store | ❌ NO detecta | ✅ Detecta |
| Archivo faltante | ❌ NO detecta | ✅ Detecta |
| Dependencia Python | ❌ NO detecta | ✅ Detecta |
| CSV modelo inexistente | ❌ NO detecta | ✅ Detecta |
| View ID inexistente | ❌ NO detecta | ✅ Detecta |

**Conclusión:** Ambas fases son complementarias e indispensables.

---

### Reporte Obligatorio FASE 2

**Sección "✅ Instalación Real Odoo 19 CE" debe incluir:**

```markdown
## ✅ Instalación Real - Validación Runtime

**Método:** Instalación en BBDD limpia Odoo 19 CE
**Fecha:** YYYY-MM-DD
**Módulo:** [MODULO]
**Base:** Docker Compose con Odoo 19.0-YYYYMMDD

### Resultado

| Métrica | Valor | Status |
|---------|-------|--------|
| **Errores críticos** | 0 | ✅ OK |
| **Warnings deprecation** | X | ⚠️ Aceptable |
| **Tiempo instalación** | X.XXs | ✅ OK |
| **Queries ejecutadas** | XXXX | ✅ OK |
| **Módulos cargados** | XX | ✅ OK |

### Log de Instalación

\```bash
# Comando ejecutado
docker compose run --rm odoo odoo -d test_db -i [MODULO] --stop-after-init

# Output crítico
[últimas 50 líneas del log]
\```

### Validaciones Runtime

- ✅ XML views válidas (0 ParseError)
- ✅ Python imports OK (0 ImportError)
- ✅ Dependencias instaladas (0 MissingDependency)
- ✅ Database constraints OK (0 IntegrityError)
- ✅ Registry loaded (version X.XXs)

### Warnings Identificados (No críticos)

- ⚠️ DeprecationWarning: group_operator → aggregator (X occurrences)
- ⚠️ Unknown parameter 'states' (X fields) - Legacy funcional
- ⚠️ Accessibility: FA icons sin title (X instances)

**Acción:** Documentar en backlog P2/P3, no bloquea producción

### Certificación

✅ **Módulo [MODULO] instalable en Odoo 19 CE sin errores críticos**

**Auditor:** [NOMBRE]
**Timestamp:** [FECHA-HORA]
```

---

### Script de Validación Automatizada

Ver: `docs/prompts/08_scripts/validate_installation.sh`

**Features:**
- ✅ Crea BBDD temporal automática
- ✅ Instala módulo con todas las dependencias
- ✅ Extrae y clasifica errores/warnings
- ✅ Genera reporte markdown automático
- ✅ Limpia BBDD test al finalizar
- ✅ Exit code 0 si OK, 1 si errores

**Uso:**
```bash
./docs/prompts/08_scripts/validate_installation.sh l10n_cl_hr_payroll
# Output: docs/prompts/06_outputs/YYYY-MM/validaciones/INSTALL_[MODULO]_[DATE].md
```

---

### Checklist Pre-Producción

**Antes de marcar módulo como "Production Ready":**

- [ ] ✅ FASE 1: Compliance código ≥95% (MÁXIMA #0)
- [ ] ✅ FASE 2: Instalación real 0 errores (MÁXIMA #0.5)
- [ ] ✅ Warnings clasificados y documentados
- [ ] ✅ Dependencias Python en requirements.txt
- [ ] ✅ Stubs creados para módulos Enterprise (si aplica)
- [ ] ✅ Views syntax Odoo 19 (`<list>`, not `<tree>`)
- [ ] ✅ Computed fields con `store=True` si en filters
- [ ] ✅ XPath validados contra vistas Odoo 19 CE
- [ ] ✅ Tests de integración ejecutados (OPCIONAL P1)
- [ ] ✅ Documentación actualizada (README, CHANGELOG)

**DoD (Definition of Done):**
Un módulo NO está production-ready hasta completar ambas fases con 0 errores críticos.

---

## 1. Alcance y Trazabilidad

- Cada auditoría debe declarar objetivo, módulos, ramas, y dependencias previas.
- Todo hallazgo referencia archivo/línea o vista/acción y cómo reproducirlo.

## 2. Evidencia y Reproducibilidad

- Evidencia mínima: pasos, dataset usado, capturas/logs, y resultado esperado vs obtenido.
- Los escenarios deben ser reproducibles en ambiente limpio; evitar datos huérfanos.

## 3. Cobertura y Profundidad

- Incluir: happy path, bordes (saldos cero, sin movimientos, fechas límite), multi-compañía, i18n.
- Incluir performance y seguridad cuando aplique (no opcional en reportes y DTE).

## 4. Performance y Escalabilidad

- Definir umbrales por tipo: reportes (<3s, <50 queries en 10k-50k líneas), nómina masiva (<5m/1k empleados aprox.).
- Medición obligatoria con `QueryCounter` o registros temporizados y evidencia de tiempos.

## 5. Seguridad y Privacidad

- Revisar ACL por rol; probar acceso indebido entre compañías.
- Validar wizards y endpoints (parámetros maliciosos); no filtrar por nombre visible sino por id/permiso.

## 6. Correctitud Legal

- Ningún cálculo basado en campos obsoletos; usar vigencias (`valid_from`/`valid_until`).
- Verificar que los topes/tasas provienen de modelos paramétricos y no de constantes.

## 7. Matrices y Checklist

- Usar matrices de verificación claras por módulo/sprint.
- Cada ítem con estado (OK, Gap, N/A), severidad (P0-P3) y acción propuesta.

## 8. Reportería del Resultado

- Entregar informe con resumen ejecutivo, tabla de gaps, reproducibilidad y DoD de cierre.
- Adjuntar archivos `.md`/`.csv` con matrices o scripts si se usaron.

## 9. Definición de Hecho (DoD)

- Un gap P0/P1 no se considera cerrado sin test que pruebe el fix y documentación actualizada.
- Se exige validación por un segundo revisor cuando afecta cálculos o seguridad.

## 10. Estilo y Formato

- Estructura Markdown con front-matter consistente; headings y listas con espacios correctos.
- Idiomas: `es_CL` por defecto; aportar ejemplo/nota en inglés si es relevante.

## 11. Herramientas y Automatización

- Preferir `pytest` y fixtures para datasets; scripts utilitarios versionados.
- Registrar comandos ejecutados y versiones relevantes del entorno.

## 12. Priorización de Gaps

- P0: bloquea producción o incumple ley; P1: alto impacto o riesgo; P2: mejora; P3: cosmético.
- Orden de trabajo: P0 → P1 → preflight rendimiento/seguridad → P2/P3.
