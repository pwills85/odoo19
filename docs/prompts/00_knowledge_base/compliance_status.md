# 📊 COMPLIANCE STATUS - Odoo 19 CE Migration

**Versión:** 1.0.0
**Fecha Actualización:** 2025-11-12
**Proyecto:** Odoo 19 CE EERGYGROUP
**Fuente:** Extracto de auditorías y cierres de brechas

---

## 🎯 RESUMEN EJECUTIVO

**Estado Global Compliance Odoo 19 CE:**

| Prioridad | Total | Cerradas | Pendientes | % Cierre | Deadline |
|-----------|-------|----------|------------|----------|----------|
| **P0** (Bloqueante) | 19 | 5 | 14 | 26.3% | 2025-03-01 |
| **P1** (Alta) | 25 | 8 | 17 | 32.0% | 2025-06-01 |
| **P2** (Media) | 17 | 5 | 12 | 29.4% | 2025-12-01 |
| **TOTAL** | **61** | **18** | **43** | **29.5%** | - |

**⚠️ CRÍTICO:** 14 deprecaciones P0 deben cerrarse antes de 2025-03-01 (3.5 meses restantes)

---

## 📋 DEPRECACIONES POR PATRÓN (P0/P1/P2)

### P0-1: QWeb Templates (t-esc → t-out)

```python
# ❌ DEPRECADO (Odoo ≤18)
<span t-esc="partner.name" />

# ✅ CORRECTO (Odoo 19+)
<span t-out="partner.name" />
```

**Estado:**
- **Ocurrencias detectadas:** 12
- **Cerradas:** 4
- **Pendientes:** 8
- **Módulos afectados:** l10n_cl_dte (5), l10n_cl_hr_payroll (2), l10n_cl_financial_reports (1)
- **Esfuerzo estimado:** 8 horas
- **Deadline:** 2025-03-01 (P0)

**Comando validación:**
```bash
docker compose exec odoo grep -r "t-esc" /mnt/extra-addons/localization/ --include="*.xml"
```

---

### P0-2: HTTP Controllers (type='json' → type='jsonrpc')

```python
# ❌ DEPRECADO
@http.route('/api/dte/validate', type='json', auth='user')
def validate_dte(self, **kwargs):
    ...

# ✅ CORRECTO
@http.route('/api/dte/validate', type='jsonrpc', auth='user', csrf=False)
def validate_dte(self, **kwargs):
    ...
```

**Estado:**
- **Ocurrencias detectadas:** 3
- **Cerradas:** 1
- **Pendientes:** 2
- **Módulos afectados:** l10n_cl_dte (2)
- **Esfuerzo estimado:** 2 horas
- **Deadline:** 2025-03-01 (P0)

**Comando validación:**
```bash
docker compose exec odoo grep -r "type='json'" /mnt/extra-addons/localization/ --include="*.py"
```

---

### P0-3: XML Views (attrs → Python expressions)

```xml
<!-- ❌ DEPRECADO -->
<field name="state" attrs="{'invisible': [('type', '=', 'manual')]}" />

<!-- ✅ CORRECTO -->
<field name="state" invisible="type == 'manual'" />
```

**Estado:**
- **Ocurrencias detectadas:** 24
- **Cerradas:** 0
- **Pendientes:** 24
- **Módulos afectados:** l10n_cl_dte (15), l10n_cl_hr_payroll (7), l10n_cl_financial_reports (2)
- **Esfuerzo estimado:** 24 horas (requiere conversión lógica compleja)
- **Deadline:** 2025-03-01 (P0)

**Comando validación:**
```bash
docker compose exec odoo grep -r 'attrs=' /mnt/extra-addons/localization/ --include="*.xml"
```

**⚠️ BLOQUEANTE CRÍTICO:** Mayor cantidad de ocurrencias P0

---

### P0-4: ORM Constraints (_sql_constraints → models.Constraint)

```python
# ❌ DEPRECADO
_sql_constraints = [
    ('unique_folio', 'unique(folio)', 'El folio debe ser único')
]

# ✅ CORRECTO
from odoo import models

_sql_constraints = [
    models.Constraint('unique(folio)', 'El folio debe ser único')
]
```

**Estado:**
- **Ocurrencias detectadas:** 8
- **Cerradas:** 0
- **Pendientes:** 8
- **Módulos afectados:** l10n_cl_dte (5), l10n_cl_hr_payroll (3)
- **Esfuerzo estimado:** 4 horas
- **Deadline:** 2025-03-01 (P0)

**Comando validación:**
```bash
docker compose exec odoo grep -r "_sql_constraints" /mnt/extra-addons/localization/ --include="*.py"
```

---

### P1-5: Database Access (self._cr → self.env.cr)

```python
# ❌ DEPRECADO
self._cr.execute("SELECT id FROM table WHERE field = %s", (value,))

# ✅ CORRECTO
self.env.cr.execute("SELECT id FROM table WHERE field = %s", (value,))
```

**Estado:**
- **Ocurrencias detectadas:** 18
- **Cerradas:** 5
- **Pendientes:** 13
- **Módulos afectados:** l10n_cl_dte (8), l10n_cl_hr_payroll (5)
- **Esfuerzo estimado:** 6 horas
- **Deadline:** 2025-06-01 (P1)

**Comando validación:**
```bash
docker compose exec odoo grep -r "self\._cr" /mnt/extra-addons/localization/ --include="*.py"
```

---

### P1-6: View Methods (fields_view_get → get_view)

```python
# ❌ DEPRECADO
view = self.fields_view_get(view_id, view_type='form')

# ✅ CORRECTO
view = self.get_view(view_id, view_type='form')
```

**Estado:**
- **Ocurrencias detectadas:** 7
- **Cerradas:** 3
- **Pendientes:** 4
- **Módulos afectados:** l10n_cl_dte (2), l10n_cl_hr_payroll (1), l10n_cl_financial_reports (1)
- **Esfuerzo estimado:** 4 horas
- **Deadline:** 2025-06-01 (P1)

**Comando validación:**
```bash
docker compose exec odoo grep -r "fields_view_get" /mnt/extra-addons/localization/ --include="*.py"
```

---

### P2-7: Decorators (@api.one → @api.depends)

```python
# ❌ DEPRECADO (Odoo ≤16)
@api.one
def _compute_total(self):
    self.total = sum(self.line_ids.mapped('amount'))

# ✅ CORRECTO (Odoo 19)
@api.depends('line_ids.amount')
def _compute_total(self):
    for record in self:
        record.total = sum(record.line_ids.mapped('amount'))
```

**Estado:**
- **Ocurrencias detectadas:** 12
- **Cerradas:** 4
- **Pendientes:** 8
- **Módulos afectados:** l10n_cl_dte (5), l10n_cl_hr_payroll (3)
- **Esfuerzo estimado:** 8 horas
- **Deadline:** 2025-12-01 (P2)

**Comando validación:**
```bash
docker compose exec odoo grep -r "@api\.one\|@api\.multi" /mnt/extra-addons/localization/ --include="*.py"
```

---

### P2-8: Deprecated Imports

```python
# ❌ DEPRECADO
from odoo.exceptions import Warning

# ✅ CORRECTO
from odoo.exceptions import UserError
```

**Estado:**
- **Ocurrencias detectadas:** 5
- **Cerradas:** 1
- **Pendientes:** 4
- **Módulos afectados:** l10n_cl_dte (2), l10n_cl_hr_payroll (2)
- **Esfuerzo estimado:** 2 horas
- **Deadline:** 2025-12-01 (P2)

**Comando validación:**
```bash
docker compose exec odoo grep -r "from odoo.exceptions import Warning" /mnt/extra-addons/localization/ --include="*.py"
```

---

## 📊 PROGRESO POR MÓDULO

### l10n_cl_dte (Facturación Electrónica)

| Patrón | Ocurrencias | Cerradas | Pendientes | % Cierre |
|--------|-------------|----------|------------|----------|
| P0-1: t-esc | 5 | 2 | 3 | 40% |
| P0-2: type='json' | 2 | 1 | 1 | 50% |
| P0-3: attrs={} | 15 | 0 | 15 | 0% |
| P0-4: _sql_constraints | 5 | 0 | 5 | 0% |
| P1-5: self._cr | 8 | 3 | 5 | 38% |
| P1-6: fields_view_get | 2 | 1 | 1 | 50% |
| P2-7: @api.one | 5 | 2 | 3 | 40% |
| P2-8: Warning import | 2 | 1 | 1 | 50% |
| **TOTAL DTE** | **44** | **10** | **34** | **22.7%** |

**⚠️ Crítico:** attrs={} es el mayor bloqueo (15 ocurrencias sin cerrar)

---

### l10n_cl_hr_payroll (Nómina)

| Patrón | Ocurrencias | Cerradas | Pendientes | % Cierre |
|--------|-------------|----------|------------|----------|
| P0-1: t-esc | 2 | 1 | 1 | 50% |
| P0-3: attrs={} | 7 | 0 | 7 | 0% |
| P0-4: _sql_constraints | 3 | 0 | 3 | 0% |
| P1-5: self._cr | 5 | 2 | 3 | 40% |
| P1-6: fields_view_get | 1 | 1 | 0 | 100% |
| P2-7: @api.one | 3 | 1 | 2 | 33% |
| P2-8: Warning import | 2 | 0 | 2 | 0% |
| **TOTAL PAYROLL** | **23** | **5** | **18** | **21.7%** |

---

### l10n_cl_financial_reports (Reportes Financieros)

| Patrón | Ocurrencias | Cerradas | Pendientes | % Cierre |
|--------|-------------|----------|------------|----------|
| P0-1: t-esc | 1 | 1 | 0 | 100% |
| P0-3: attrs={} | 2 | 0 | 2 | 0% |
| P1-6: fields_view_get | 1 | 1 | 0 | 100% |
| **TOTAL FINANCIAL** | **4** | **2** | **2** | **50%** |

**✅ Mejor ratio cierre:** 50% (módulo menos afectado)

---

## 🎯 PLAN ACCIÓN PRIORIZADO

### Sprint 1 (2 semanas) - P0 Crítico

**Objetivo:** Cerrar P0-3 (attrs={}) en l10n_cl_dte (bloqueante mayor)

- [ ] Migrar 15 ocurrencias attrs={} en DTE (24h)
- [ ] Migrar 5 _sql_constraints en DTE (4h)
- [ ] Migrar 3 t-esc pendientes en DTE (2h)
- [ ] Testing exhaustivo post-migración (8h)

**Esfuerzo:** 38 horas (2 desarrolladores @ 6h/día = 3.2 días)
**Deadline:** 2025-11-30

---

### Sprint 2 (2 semanas) - P0 Resto

**Objetivo:** Cerrar P0 en Payroll + Financial

- [ ] Migrar 7 attrs={} en Payroll (8h)
- [ ] Migrar 3 _sql_constraints en Payroll (2h)
- [ ] Migrar 2 attrs={} en Financial (2h)
- [ ] Migrar 1 type='json' pendiente en DTE (1h)
- [ ] Testing (6h)

**Esfuerzo:** 19 horas (1 desarrollador @ 6h/día = 3.2 días)
**Deadline:** 2025-12-15

---

### Sprint 3 (3 semanas) - P1

**Objetivo:** Cerrar self._cr + fields_view_get

- [ ] Migrar 13 self._cr pendientes (6h)
- [ ] Migrar 4 fields_view_get pendientes (4h)
- [ ] Testing (4h)

**Esfuerzo:** 14 horas (1 desarrollador @ 6h/día = 2.3 días)
**Deadline:** 2026-01-15

---

### Sprint 4 (2 semanas) - P2

**Objetivo:** Limpieza @api.one + imports

- [ ] Migrar 8 @api.one pendientes (8h)
- [ ] Migrar 4 Warning imports (2h)
- [ ] Testing final (4h)

**Esfuerzo:** 14 horas
**Deadline:** 2026-02-01

---

## 📈 MÉTRICAS OBJETIVO

| Métrica | Actual | Target Feb 2026 |
|---------|--------|-----------------|
| P0 cerradas | 26.3% | **100%** |
| P1 cerradas | 32.0% | **90%** |
| P2 cerradas | 29.4% | **80%** |
| Cierre global | 29.5% | **90%+** |

---

## 🚨 RIESGOS IDENTIFICADOS

### Riesgo 1: Complejidad attrs={} (P0-3)

**Descripción:** 24 ocurrencias requieren conversión de lógica XML a Python expressions
**Impacto:** ALTO (bloqueante P0)
**Mitigación:**
- Priorizar Sprint 1 completo a esto
- Revisar cada conversión manualmente (QA estricto)
- Tests exhaustivos post-migración

---

### Riesgo 2: Deadline P0 (2025-03-01)

**Descripción:** Solo 3.5 meses para cerrar 14 deprecaciones P0
**Impacto:** ALTO (proyecto bloqueado si no se cumple)
**Mitigación:**
- Ejecutar Sprints 1-2 sin demoras
- Asignar 2 desarrolladores full-time
- Revisión semanal progreso

---

### Riesgo 3: Testing Insuficiente

**Descripción:** Migraciones masivas pueden introducir bugs
**Impacto:** MEDIO
**Mitigación:**
- Coverage mínimo 80% post-migración
- Tests regression antes/después cada sprint
- Smoke tests en staging pre-producción

---

## 🔍 VALIDACIÓN CONTINUA

**Comandos automatizados (ejecutar semanalmente):**

```bash
#!/bin/bash
# validate_compliance.sh

echo "=== P0-1: t-esc ===="
docker compose exec odoo grep -r "t-esc" /mnt/extra-addons/localization/ --include="*.xml" | wc -l

echo "=== P0-2: type='json' ===="
docker compose exec odoo grep -r "type='json'" /mnt/extra-addons/localization/ --include="*.py" | wc -l

echo "=== P0-3: attrs={} ===="
docker compose exec odoo grep -r 'attrs=' /mnt/extra-addons/localization/ --include="*.xml" | wc -l

echo "=== P0-4: _sql_constraints ===="
docker compose exec odoo grep -r "_sql_constraints" /mnt/extra-addons/localization/ --include="*.py" | grep -v "models.Constraint" | wc -l

echo "=== P1-5: self._cr ===="
docker compose exec odoo grep -r "self\._cr" /mnt/extra-addons/localization/ --include="*.py" | wc -l

echo "=== P1-6: fields_view_get ===="
docker compose exec odoo grep -r "fields_view_get" /mnt/extra-addons/localization/ --include="*.py" | wc -l
```

**Guardar como:** `scripts/validate_compliance.sh`

**Ejecutar:**
```bash
bash scripts/validate_compliance.sh
```

---

## 📚 REFERENCIAS

**Documentación Compliance:**
- `02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md` - Checklist completo 8 patrones
- `03_maximas/MAXIMAS_DESARROLLO.md` - Máxima #0: Compliance primero
- `04_templates/TEMPLATE_CIERRE_BRECHA.md` - Template cierre brechas

**Auditorías Ejecutadas:**
- `06_outputs/2025-11/auditorias/20251111_AUDIT_DTE_DEEP.md`
- `06_outputs/2025-11/auditorias/20251111_AUDIT_PAYROLL.md`
- `06_outputs/2025-11/auditorias/20251111_AUDIT_FINANCIAL.md`
- `06_outputs/2025-11/auditorias/20251112_CONSOLIDACION_HALLAZGOS.md`

**Cierres Documentados:**
- `06_outputs/2025-11/cierres/20251111_CIERRE_H1_H5_DTE.md`

---

## ✅ CHECKLIST VALIDACIÓN PRE-DEPLOY

Antes de deploy a producción, validar:

- [ ] 100% P0 cerradas (14 deprecaciones)
- [ ] 90%+ P1 cerradas (23 deprecaciones)
- [ ] Test coverage >80% todos los módulos afectados
- [ ] Smoke tests passed en staging
- [ ] Backup DB pre-deploy
- [ ] Rollback plan documentado
- [ ] Logs monitoreo habilitados
- [ ] Health checks operativos

---

**Versión:** 1.0.0
**Última actualización:** 2025-11-12
**Próxima revisión:** 2025-11-19 (semanal)
**Mantenedor:** Pedro Troncoso (@pwills85)
