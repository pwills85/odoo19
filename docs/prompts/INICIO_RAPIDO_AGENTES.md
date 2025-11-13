# 🚀 INICIO RÁPIDO PARA AGENTES NUEVOS

**Versión:** 1.1  
**Fecha:** 2025-11-12  
**Para:** Claude Code, Copilot CLI, Gemini, Windsurf, Cursor

---

## ⚡ Lo Esencial en 3 Minutos

**Si eres un agente nuevo, lee esto ANTES de hacer cualquier cosa:**

---

## 🤖 NOVEDAD: GitHub Copilot CLI - Ejecución Autónoma

**Copilot CLI puede ejecutar tareas complejas de forma autónoma hasta completarlas.**

### Inicio Rápido Copilot CLI

```bash
# Verificar instalación
copilot --version
# Esperado: 0.0.354 o superior

# Modo autónomo: ejecuta hasta completar tarea
copilot -p "TU_TAREA_AQUÍ" --allow-all-tools --allow-all-paths

# Modo interactivo: conversación paso a paso
copilot
> ¿Cómo instalar pytest en Docker Odoo?
> [Copilot responde, solicita aprobación para comandos]
```

### Ejemplo Real: Auditoría Compliance Autónoma

```bash
copilot -p "Audita compliance Odoo 19 CE en módulo addons/localization/l10n_cl_dte/ siguiendo checklist docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md. Valida 8 patrones P0/P1/P2. Genera reporte markdown en docs/prompts/06_outputs/2025-11/auditorias/" --allow-all-tools --allow-all-paths
```

**Output:** Reporte completo en 1-2 minutos (vs 15-20 min manual) ✅

📖 **Guía completa:** [COPILOT_CLI_AUTONOMO.md](COPILOT_CLI_AUTONOMO.md)

---

## 🏗️ 1. STACK DEL PROYECTO (CRÍTICO)

### Este proyecto es 100% Dockerizado

**NUNCA sugieras comandos de host directo. SIEMPRE usa Docker Compose.**

```yaml
Stack Completo:
  - Odoo 19 CE (imagen custom eergygroup/odoo19:chile-1.0.5)
  - PostgreSQL 15-alpine (base de datos)
  - Redis 7-alpine (sesiones + cache)
  - AI Service (FastAPI + Claude API)

Ubicación: /Users/pedro/Documents/odoo19
Platform: macOS M3 (ARM64)
Python Host: 3.14.0 (solo para scripts NO-Odoo en .venv/)
```

---

### Comandos Docker + Odoo CLI (MEMORIZA ESTO)

**Desarrollo módulos:**
```bash
# Instalar módulo
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --stop-after-init

# Actualizar módulo
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# Actualizar todos
docker compose exec odoo odoo-bin -u all -d odoo19_db --stop-after-init
```

**Testing:**
```bash
# Tests con pytest (recomendado)
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v

# Tests con Odoo framework
docker compose exec odoo odoo-bin --test-enable -i l10n_cl_dte --test-tags /l10n_cl_dte -d odoo19_db --stop-after-init

# Tests con coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ --cov=l10n_cl_dte --cov-report=term-missing
```

**Shell y debugging:**
```bash
# Acceder a shell Odoo (contexto completo ORM)
docker compose exec odoo odoo-bin shell -d odoo19_db

# Shell con debug
docker compose exec odoo odoo-bin shell -d odoo19_db --debug --log-level=debug

# Ejecutar código Python en contexto Odoo
docker compose exec odoo odoo-bin shell -d odoo19_db -c "print('Test')" --stop-after-init
```

**Base de datos:**
```bash
# Backup
docker compose exec db pg_dump -U odoo -h db odoo19_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore
docker compose exec db psql -U odoo -h db odoo19_db < backup.sql

# Verificar conexión
docker compose exec db psql -U odoo -h db -l
```

**Logs y monitoring:**
```bash
# Ver logs en tiempo real
docker compose logs -f odoo

# Ver logs de errores
docker compose logs odoo | grep ERROR

# Health check
docker compose ps
```

---

### Comandos Host Python (SOLO scripts NO-Odoo)

**✅ Scripts que SÍ se ejecutan en host (con .venv):**
```bash
# Verificación setup
.venv/bin/python scripts/verify_production_readiness.py

# Análisis estático (no requiere instancia Odoo)
.venv/bin/python scripts/compliance_check.py
.venv/bin/python scripts/validate_odoo19_standards.py
```

**❌ Scripts que NO se ejecutan en host (requieren Odoo container):**
```bash
# ❌ NUNCA en host - Scripts que importan 'odoo'
python scripts/create_smoke_test_data.py

# ✅ CORRECTO - Ejecutar en container
docker compose exec odoo odoo-bin shell -d odoo19_db < scripts/create_smoke_test_data.py
```

**Regla de Oro:**
- ✅ Scripts análisis estático → `.venv/bin/python`
- ✅ Scripts que importan `odoo` → `docker compose exec odoo`
- ❌ NUNCA `python` sin `.venv/bin/` (usa Python incorrecto)

---

### 📋 Referencia Completa Comandos

**Archivo maestro:**  
`.github/agents/knowledge/docker_odoo_command_reference.md`

**Contiene:**
- 10 categorías comandos (gestión módulos, testing, shell, DB, etc.)
- Comandos profesionales Odoo CLI
- Troubleshooting Docker + Odoo
- Ejemplos por caso de uso

---

## 🚨 2. COMPLIANCE ODOO 19 CE (BLOQUEANTE)

### Máxima #0 (Prioridad Absoluta)

> **"Validar compliance Odoo 19 CE PRIMERO. Ninguna implementación procede sin pasar checklist deprecaciones P0/P1."**

---

### Deprecaciones Críticas (MEMORIZA)

**P0 Breaking Changes (Deadline: 2025-03-01):**

1. **QWeb Templates:**
   - ❌ `<span t-esc="variable" />`
   - ✅ `<span t-out="variable" />`

2. **HTTP Controllers:**
   - ❌ `@http.route('/api/endpoint', type='json', auth='user')`
   - ✅ `@http.route('/api/endpoint', type='jsonrpc', auth='user', csrf=False)`

3. **XML Views:**
   - ❌ `<field name="state" attrs="{'invisible': [('type', '=', 'manual')]}" />`
   - ✅ `<field name="state" invisible="type == 'manual'" />`

4. **ORM Constraints:**
   - ❌ `_sql_constraints = [('unique_folio', 'unique(folio)', 'Folio must be unique')]`
   - ✅ `_sql_constraints = [models.Constraint('unique(folio)', 'Folio must be unique')]`

---

**P1 High Priority (Deadline: 2025-06-01):**

5. **Database Access:**
   - ❌ `self._cr.execute("SELECT * FROM table")`
   - ✅ `self.env.cr.execute("SELECT * FROM table")`

6. **View Methods:**
   - ❌ `self.fields_view_get(view_id, view_type)`
   - ✅ `self.get_view(view_id, view_type)`

---

### Checklist Completo (OBLIGATORIO)

**Archivo:**  
`docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`

**Contiene:**
- 8 patrones deprecación (P0/P1/P2)
- Comandos validación automatizada
- Ejemplos antes/después
- 650 líneas documentación

**SIEMPRE incluir checklist en prompts auditoría.**

---

### Status Migración Actual

**Archivo:**  
`CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md`

**Métricas:**
- ✅ 137 deprecaciones corregidas automáticamente
- ⚠️ 27 deprecaciones manuales pendientes
- 🔴 17 deprecaciones P0+P1 bloqueantes
- 📊 80.4% P0 cerradas

**Antes de desarrollar, verificar que tu área NO tiene deprecaciones pendientes.**

---

## 📚 3. DOCUMENTACIÓN OBLIGATORIA

### Leer ANTES de crear prompts/auditorías/desarrollo

**1. Estrategia Prompting P4:**  
`docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`

**2. Checklist Odoo 19 CE:**  
`docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md` ← **CRÍTICO**

**3. Máximas Proyecto:**
- `docs/prompts/03_maximas/MAXIMAS_DESARROLLO.md` (17 máximas)
- `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md` (12 máximas)

**4. Arquitectura Stack:**  
`.github/agents/knowledge/deployment_environment.md` (Docker completo)

**5. Patrones Odoo 19:**  
`.github/agents/knowledge/odoo19_patterns.md` (NO Odoo 11-16!)

**6. Deprecaciones Odoo 19:**  
`.github/agents/knowledge/odoo19_deprecations_reference.md`

**7. Regulatory Context:**  
`.github/agents/knowledge/sii_regulatory_context.md` (SII + Previred + Código Trabajo)

---

### Knowledge Base Completo

**Ubicación:** `.github/agents/knowledge/`

**Archivos clave:**
- `odoo19_deprecations_reference.md` ← **LEER PRIMERO**
- `odoo19_patterns.md` (modelos, decoradores, testing)
- `sii_regulatory_context.md` (DTE 33/34/52/56/61, RUT validación)
- `project_architecture.md` (decisiones arquitectura EERGYGROUP)
- `deployment_environment.md` (Docker stack completo)
- `docker_odoo_command_reference.md` (comandos profesionales)

---

## 🎯 4. WORKFLOWS POR NECESIDAD

### Workflow A: Crear Auditoría Módulo

```
PASO 1: Preparación (15 min)
  └─ Leer: docs/prompts/01_fundamentos/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
  └─ Leer: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
  └─ Leer: docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md

PASO 2: Creación Prompt (20 min)
  └─ Copiar: docs/prompts/04_templates/TEMPLATE_AUDITORIA.md
  └─ Adaptar: Incluir checklist Odoo 19 CE (8 patrones)
  └─ Adaptar: Contexto módulo específico

PASO 3: Revisar Ejemplos (10 min)
  └─ Ver: docs/prompts/05_prompts_produccion/modulos/[MODULO]/AUDIT_*.md

PASO 4: Ejecución (2-4h)
  └─ Ejecutar: Copilot CLI / Claude Code
  └─ Revisar: Hallazgos P0/P1/P2
  └─ Validar: Métricas cuantitativas

PASO 5: Documentación (15 min)
  └─ Guardar prompt: docs/prompts/05_prompts_produccion/modulos/[MODULO]/
  └─ Guardar output: docs/prompts/06_outputs/2025-11/auditorias/
  └─ Actualizar: README.md (si necesario)
```

---

### Workflow B: Desarrollar Feature/Fix

```
PASO 1: Validación Compliance (10 min)
  └─ Leer: docs/prompts/03_maximas/MAXIMAS_DESARROLLO.md
  └─ Validar: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md
  └─ Verificar: CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md (área sin deprecaciones)

PASO 2: Análisis Código Actual (30 min)
  └─ Buscar deprecaciones:
      docker compose exec odoo grep -r "t-esc" addons/localization/[modulo]/
      docker compose exec odoo grep -r "self._cr" addons/localization/[modulo]/
  └─ Revisar patrones: .github/agents/knowledge/odoo19_patterns.md

PASO 3: Desarrollo (variable)
  └─ Usar comandos Docker (ver sección 1)
  └─ Seguir patrones Odoo 19 CE
  └─ NO usar técnicas obsoletas

PASO 4: Testing (30 min)
  └─ Tests unitarios:
      docker compose exec odoo pytest /mnt/extra-addons/localization/[modulo]/tests/ -v
  └─ Tests integración:
      docker compose exec odoo odoo-bin --test-enable -i [modulo] --test-tags /[modulo] -d odoo19_db --stop-after-init
  └─ Coverage:
      docker compose exec odoo pytest /mnt/extra-addons/localization/[modulo]/tests/ --cov=[modulo] --cov-report=term-missing

PASO 5: Validación Final (15 min)
  └─ Re-validar checklist Odoo 19 CE
  └─ Verificar no introduces deprecaciones
  └─ Commit con mensaje descriptivo
```

---

### Workflow C: Cerrar Brecha de Auditoría

```
PASO 1: Análisis Hallazgo (15 min)
  └─ Leer: docs/prompts/06_outputs/2025-11/auditorias/[FECHA]_*.md
  └─ Identificar: Brecha específica (P0 > P1 > P2)
  └─ Entender: Impacto y contexto

PASO 2: Preparación (15 min)
  └─ Leer: docs/prompts/03_maximas/MAXIMAS_DESARROLLO.md
  └─ Copiar: docs/prompts/04_templates/TEMPLATE_CIERRE_BRECHA.md
  └─ Validar: Checklist Odoo 19 CE (si aplica)

PASO 3: Implementación (variable según complejidad)
  └─ Desarrollar solución (ver Workflow B)
  └─ Probar exhaustivamente
  └─ Validar compliance

PASO 4: Documentación Cierre (15 min)
  └─ Guardar: docs/prompts/06_outputs/2025-11/cierres/[FECHA]_*.md
  └─ Actualizar: Dashboard hallazgos (marcar cerrado)
  └─ Commit: Git con referencia hallazgo original
```

---

### Workflow D: Validar Compliance Odoo 19 CE

```
PASO 1: Abrir Checklist (5 min)
  └─ Leer: docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md

PASO 2: Ejecutar Validaciones (15 min)
  └─ P0-1: t-esc → t-out
      docker compose exec odoo grep -r "t-esc" addons/localization/
  └─ P0-2: type='json' → type='jsonrpc'
      docker compose exec odoo grep -r "type='json'" addons/localization/
  └─ P0-3: attrs={} → Python expressions
      docker compose exec odoo grep -r "attrs=" addons/localization/
  └─ P0-4: _sql_constraints → models.Constraint
      docker compose exec odoo grep -r "_sql_constraints" addons/localization/
  └─ P1-5: self._cr → self.env.cr
      docker compose exec odoo grep -r "self._cr" addons/localization/

PASO 3: Corregir Hallazgos (variable)
  └─ Aplicar patrones correctos (ver checklist)
  └─ Probar cambios
  └─ Re-validar

PASO 4: Documentar (10 min)
  └─ Actualizar: CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md
  └─ Commit: Git con mensaje descriptivo
```

---

## 🔍 5. BÚSQUEDA RÁPIDA

### Por módulo
```bash
# DTE (Facturación Electrónica)
find docs/prompts/ -name "*DTE*"

# Payroll (Nómina)
find docs/prompts/ -name "*PAYROLL*"

# Financial Reports
find docs/prompts/ -name "*FINANCIAL*"

# AI Service
find docs/prompts/ -name "*AI_SERVICE*"
```

---

### Por fecha
```bash
# 11 de noviembre
find docs/prompts/ -name "*20251111*"

# 12 de noviembre (hoy)
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

## 📊 6. ESTRUCTURA SISTEMA PROMPTS

```
docs/prompts/
├── README.md                      ← Índice maestro completo
├── INICIO_RAPIDO_AGENTES.md       ← Este archivo
├── MAPA_NAVEGACION_VISUAL.md      ← Guía navegación visual
│
├── 01_fundamentos/                (6 archivos - estrategias)
├── 02_compliance/                 (2 archivos - Odoo 19 CE)
├── 03_maximas/                    (2 archivos - reglas no negociables)
├── 04_templates/                  (2 archivos - plantillas base)
├── 05_prompts_produccion/         (12 archivos - prompts validados)
│   ├── modulos/                   DTE, Payroll, Financial, AI
│   ├── integraciones/             Cross-módulo (3 archivos)
│   └── consolidacion/             Cierre total (2 archivos)
├── 06_outputs/                    (8 archivos - outputs documentados)
│   └── 2025-11/                   Auditorías, cierres, investigaciones
├── 07_historico/                  (pendiente - archivos obsoletos)
└── 08_scripts/                    (pendiente - automatización)
```

---

## 🚨 7. ERRORES COMUNES A EVITAR

### ❌ Error #1: Comandos Host Directo

**MAL:**
```bash
odoo-bin -u l10n_cl_dte -d odoo19_db
python scripts/test.py
psql -h localhost -U odoo
```

**BIEN:**
```bash
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init
.venv/bin/python scripts/test.py  # SOLO si NO importa 'odoo'
docker compose exec db psql -U odoo -h db odoo19_db
```

---

### ❌ Error #2: Usar Patrones Odoo 11-16

**MAL:**
```python
@api.one
def _compute_total(self):
    self.total = sum(self.line_ids.mapped('amount'))
```

**BIEN:**
```python
@api.depends('line_ids.amount')
def _compute_total(self):
    for record in self:
        record.total = sum(record.line_ids.mapped('amount'))
```

---

### ❌ Error #3: Ignorar Deprecaciones Odoo 19

**MAL:**
```xml
<field name="state" attrs="{'invisible': [('type', '=', 'manual')]}" />
```

**BIEN:**
```xml
<field name="state" invisible="type == 'manual'" />
```

---

### ❌ Error #4: No Validar Compliance ANTES

**MAL:**
```
1. Desarrollar feature
2. Probar
3. Commit
4. (Olvidar validar Odoo 19 CE)
```

**BIEN:**
```
1. Leer checklist Odoo 19 CE
2. Validar área sin deprecaciones
3. Desarrollar feature (patrones correctos)
4. Probar
5. Re-validar compliance
6. Commit
```

---

### ❌ Error #5: No Leer Documentación Obligatoria

**MAL:**
```
1. Empezar a codear directamente
2. Usar lo que "creo que funciona"
3. Generar código con técnicas obsoletas
```

**BIEN:**
```
1. Leer: ESTRATEGIA_PROMPTING_ALTA_PRECISION.md
2. Leer: CHECKLIST_ODOO19_VALIDACIONES.md
3. Leer: MAXIMAS_DESARROLLO.md
4. Revisar: odoo19_patterns.md
5. Entonces codear con técnicas correctas
```

---

## ✅ 8. CHECKLIST INICIO SESIÓN

**Antes de empezar a trabajar, verifica:**

- [ ] Leí `docs/prompts/INICIO_RAPIDO_AGENTES.md` (este archivo)
- [ ] Entiendo que el stack es 100% Docker (comandos `docker compose exec odoo`)
- [ ] Leí `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
- [ ] Conozco las 8 deprecaciones críticas Odoo 19 CE (P0/P1)
- [ ] Sé dónde buscar comandos Docker+Odoo (`.github/agents/knowledge/docker_odoo_command_reference.md`)
- [ ] Entiendo patrones Odoo 19 CE (`.github/agents/knowledge/odoo19_patterns.md`)
- [ ] Conozco las máximas proyecto (`docs/prompts/03_maximas/`)
- [ ] Sé cómo buscar prompts/templates (`docs/prompts/README.md`)

**Si marcaste ✅ todas, estás listo para operar al 100%.**

---

## 📞 Soporte

**README maestro:**  
`docs/prompts/README.md`

**Mapa navegación:**  
`docs/prompts/MAPA_NAVEGACION_VISUAL.md`

**Knowledge base:**  
`.github/agents/knowledge/`

**Comandos Docker+Odoo:**  
`.github/agents/knowledge/docker_odoo_command_reference.md`

---

**🚀 SISTEMA PROFESIONAL - LISTO PARA MÁXIMA PRODUCTIVIDAD**

**Mantenedor:** Pedro Troncoso (@pwills85)  
**Última actualización:** 2025-11-12
