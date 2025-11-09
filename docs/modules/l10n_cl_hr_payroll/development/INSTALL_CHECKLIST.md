# 📋 CHECKLIST DE INSTALACIÓN

**Módulo:** l10n_cl_hr_payroll  
**Versión:** 19.0.1.0.0  
**Fecha:** 2025-10-23

---

## ✅ PRE-INSTALACIÓN

- [x] Backup creado: `l10n_cl_hr_payroll.backup_*`
- [x] Sintaxis Python validada: Sin errores
- [x] Sintaxis XML validada: Sin errores
- [x] 22 categorías XML creadas
- [x] Secuencia configurada
- [x] 13 tests creados
- [x] Manifest actualizado

---

## 🚀 INSTALACIÓN

### Paso 1: Actualizar módulo

```bash
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  -u l10n_cl_hr_payroll --stop-after-init
```

**Esperado:**
- ✅ Módulo actualizado sin errores
- ✅ 22 registros `hr.salary.rule.category` creados
- ✅ 1 secuencia `ir.sequence` creada
- ✅ 0 errores en logs

**Verificar logs:**
```bash
docker-compose logs odoo | grep -E "l10n_cl_hr_payroll|category_base|ERROR"
```

---

### Paso 2: Ejecutar tests

```bash
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-tags=payroll_sopa --stop-after-init --log-level=test
```

**Esperado:**
- ✅ 13/13 tests pasan
- ✅ 7 tests categorías OK
- ✅ 6 tests totalizadores OK
- ✅ 0 tests fallan

---

## 🔍 VALIDACIÓN MANUAL

### Paso 3: Verificar Categorías en UI

1. Abrir Odoo: http://localhost:8169
2. Login: admin / (tu password)
3. Ir a: **Empleados → Configuración → Categorías Salariales**

**Verificar:**
- [ ] Existen al menos 22 categorías
- [ ] Jerarquía visible (iconos +/- en árbol)
- [ ] Categoría BASE existe y tiene:
  - Code: BASE
  - Imponible: ✅
  - Tributable: ✅
  - Signo: Positivo
- [ ] Categoría LEGAL existe y tiene:
  - Code: LEGAL
  - Tipo: Descuento
  - Signo: Negativo

---

### Paso 4: Crear Liquidación Test

1. Ir a: **Empleados → Nóminas → Liquidaciones**
2. Clic: **Crear**
3. Completar:
   - Empleado: (seleccionar uno existente)
   - Contrato: (seleccionar uno existente)
   - Período: Octubre 2025
4. Clic: **Calcular**

**Verificar:**
- [ ] Número generado automáticamente: `LIQ-202510-XXXX`
- [ ] 3 líneas creadas:
  - Sueldo Base (positivo)
  - AFP (negativo)
  - FONASA/ISAPRE (negativo)
- [ ] Total Imponible = Sueldo Base
- [ ] AFP = Total Imponible × 11.44%
- [ ] FONASA = Total Imponible × 7%
- [ ] Líquido = Haberes - Descuentos

**Ejemplo con sueldo $1.000.000:**
```
Sueldo base:     $1.000.000
Total imponible: $1.000.000 ✅
AFP:             $  114.400 ✅
FONASA:          $   70.000 ✅
Líquido:         $  815.600 ✅
Número:          LIQ-202510-0001 ✅
```

---

## 🐛 TROUBLESHOOTING

### Error: "Categoría BASE no encontrada"

**Causa:** Datos XML no cargados  
**Solución:**
```bash
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  -u l10n_cl_hr_payroll --stop-after-init
```

---

### Error: "Número queda vacío"

**Causa:** Secuencia no creada  
**Solución:** Verificar `data/ir_sequence.xml` en manifest

---

### Tests fallan: "AFP incorrect"

**Causa:** total_imponible = 0  
**Solución:** Verificar categoría BASE tiene `imponible=True`

---

## ✅ CHECKLIST FINAL

- [ ] Módulo instalado sin errores
- [ ] 13/13 tests pasan
- [ ] 22 categorías visibles en UI
- [ ] Liquidación genera número automático
- [ ] Cálculos AFP/FONASA correctos
- [ ] Total imponible = Sueldo base

---

## 📞 SOPORTE

**Documentación:**
- `GAP_CLOSURE_COMPLETE.md` - Detalle técnico completo
- `CIERRE_BRECHAS_RESUMEN.md` - Resumen ejecutivo
- `GAP_CLOSURE_PLAN_ODOO19.md` - Plan original

**Logs útiles:**
```bash
# Ver errores instalación
docker-compose logs odoo | grep ERROR

# Ver categorías creadas
docker-compose exec odoo odoo shell -c /etc/odoo/odoo.conf -d odoo
>>> env['hr.salary.rule.category'].search_count([])

# Ver secuencia
>>> env['ir.sequence'].search([('code', '=', 'hr.payslip')])
```

---

**✅ INSTALACIÓN EXITOSA = MÓDULO AL 95% FUNCIONAL**
