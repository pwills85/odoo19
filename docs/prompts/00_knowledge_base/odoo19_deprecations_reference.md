# Odoo 19 CE Deprecations - Quick Reference

**Status:** Sistema migrado (2025-11-11) | 137 automáticas ✅ | 27 manuales ⚠️

---

## 🚨 VALIDACIÓN OBLIGATORIA

**Antes de commitear código Odoo, verificar contra:**
- `.claude/project/ODOO19_DEPRECATIONS_CRITICAL.md` (guía completa)
- `scripts/odoo19_migration/config/deprecations.yaml` (config técnica)

---

## Quick Rules

| ❌ DEPRECATED | ✅ USE INSTEAD | Priority |
|--------------|----------------|----------|
| `t-esc` | `t-out` | P0 🔴 |
| `type='json'` | `type='jsonrpc'` + `csrf=False` | P0 🔴 |
| `attrs={}` | Python expressions | P0 🔴 |
| `_sql_constraints` | `models.Constraint` | P0 🔴 |
| `self._cr` | `self.env.cr` | P1 🟡 |
| `fields_view_get()` | `get_view()` | P1 🟡 |

---

**P0 Deadline:** 2025-03-01 (BREAKING)  
**P1 Deadline:** 2025-06-01 (Warnings)

**Compliance:** 80.4% P0 | 8.8% P1

