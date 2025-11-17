# TASK 2.5 - Multi-Company Setup Status

**Fecha:** 2025-11-09
**Estado:** PARCIALMENTE COMPLETADO (requiere investigación adicional)

## Problema Encontrado

Los tests de multi-company (`test_p0_multi_company.py`) fallan debido a cambios en la API de grupos de Odoo 19:

### Error Original
```
ValueError: Invalid field 'groups_id' in 'res.users' 
```

### Intentos de Solución

1. **Cambio `groups_id` → `groups`**: Mismo error
2. **Asignación post-creación con write()**: Mismo error  
3. **Modificar grupos desde res.groups.users**: Campo `users` no existe en Odoo 19
4. **Uso de sudo() para creación**: Resuelve creación de usuarios pero no asigna permisos

## Cambios Realizados

### test_p0_multi_company.py

**Correcciones Exitosas:**
- ✅ Usuarios se crean correctamente con `sudo().create()`
- ✅ Empleados, contratos y payslips se crean con `sudo()`
- ✅ Evita errores de AccessError durante setUp

**Problema Pendiente:**
- ❌ No se pueden asignar grupos a usuarios
- ❌ Tests de búsqueda/lectura fallan por falta de permisos ACL

### Tests Afectados

| Test | Estado | Razón |
|------|--------|-------|
| `test_ir_rule_payslip_exists` | ❌ ERROR | setUp falla en asignación grupos |
| `test_ir_rule_payslip_run_exists` | ❌ ERROR | setUp falla en asignación grupos |
| `test_user_a_sees_only_company_a_payslips` | ❌ ERROR | setUp falla + AccessError |
| `test_user_b_sees_only_company_b_payslips` | ❌ ERROR | setUp falla + AccessError |
| `test_user_a_cannot_read_company_b_payslip` | ❌ ERROR | setUp falla |
| `test_user_b_cannot_write_company_a_payslip` | ❌ ERROR | setUp falla |
| `test_user_a_cannot_unlink_company_b_payslip` | ❌ ERROR | setUp falla |
| `test_shared_master_data_visible_to_all` | ❌ ERROR | setUp falla |

## Análisis Técnico

### API de Grupos en Odoo 19

En Odoo 19, la API para asignar grupos a usuarios ha cambiado:
- ❌ `groups_id` no existe en res.users durante create()
- ❌ `groups` no existe en res.users
- ❌ `users` no existe en res.groups

### Posibles Soluciones (Requieren Investigación)

1. **Usar `implied_ids` o selection fields:**
   ```python
   'sel_groups_X_Y_Z': group_id
   ```

2. **Modificar tabla many2many directamente:**
   ```python
   self.env.cr.execute("""
       INSERT INTO res_groups_users_rel (gid, uid)
       VALUES (%s, %s)
   """, (group_id, user_id))
   ```

3. **Usar setUpClass y copiar usuario demo:**
   ```python
   demo_user = self.env.ref('base.user_demo')
   user_a = demo_user.copy({'login': 'user_a@test.com', ...})
   ```

4. **Revisar documentación Odoo 19 CE:**
   - Buscar cambios en API de permisos
   - Verificar si hay nuevos métodos para asignar grupos

## Impacto en Cobertura

- Tests multi-company: 8 tests (~5% del total)
- Funcionalidad crítica P0-3 (aislamiento multi-compañía)
- **Recomendación:** Investigar solución definitiva antes de producción

## Próximos Pasos

1. **Opción A (Rápida):** Skip tests temporalmente con `@unittest.skip`
2. **Opción B (Investigación):** Estudiar API Odoo 19 para grupos
3. **Opción C (Alternativa):** Reescribir tests usando sudo() completo

## Tiempo Invertido

- Depuración: 30 minutos
- Intentos de corrección: 6 approaches diferentes
- **Total:** 1 hora

---

**Decisión:** Marcar como TODO y continuar con TASK 2.6B (cálculos precision)
