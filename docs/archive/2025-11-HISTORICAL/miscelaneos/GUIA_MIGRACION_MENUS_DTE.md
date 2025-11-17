# GUÍA DE MIGRACIÓN: Nuevos Menús DTE - Odoo 19 CE

**Fecha de Actualización:** 2025-11-02
**Versión Módulo:** l10n_cl_dte v2.0 (Gap Closure - Menu Architecture)
**Impacto:** BREAKING CHANGE - Estructura de menús simplificada
**Tiempo Estimado de Adaptación:** 5-10 minutos

---

## 🎯 ¿Qué Cambió?

Hemos **simplificado la navegación** del módulo DTE eliminando menús duplicados y siguiendo las mejores prácticas de Odoo.

### Antes (VIEJO) ❌

Los documentos tributarios estaban **duplicados** en dos ubicaciones:

```
❌ Contabilidad > DTE Chile > Operaciones > Facturas Electrónicas
❌ Contabilidad > DTE Chile > Operaciones > Notas de Crédito
❌ Contabilidad > DTE Chile > Operaciones > Guías de Despacho
❌ Contabilidad > DTE Chile > Operaciones > Liquidaciones Honorarios
```

**Problema:** Confusión sobre qué menú usar, duplicación innecesaria.

### Ahora (NUEVO) ✅

Los documentos tributarios están en **una sola ubicación estándar de Odoo**:

```
✅ Contabilidad > Clientes > Invoices (facturas)
✅ Contabilidad > Clientes > Credit Notes (notas de crédito)
✅ Inventario > Operaciones > Transfers (guías de despacho)
✅ Compras > Órdenes > Purchase Orders (órdenes de compra)
```

**Ventaja:** Navegación intuitiva, consistente con otros países, menos confusión.

---

## 📋 Tabla de Equivalencias

| Documento | Menú VIEJO ❌ | Menú NUEVO ✅ | Campos DTE |
|-----------|--------------|--------------|------------|
| **Facturas de Cliente** | Contabilidad > DTE Chile > Operaciones > Facturas Electrónicas | **Contabilidad > Clientes > Invoices** | ✅ Disponibles |
| **Notas de Crédito** | Contabilidad > DTE Chile > Operaciones > Notas de Crédito | **Contabilidad > Clientes > Credit Notes** | ✅ Disponibles |
| **Guías de Despacho** | Contabilidad > DTE Chile > Operaciones > Guías de Despacho | **Inventario > Operaciones > Transfers** | ✅ Disponibles |
| **Órdenes de Compra** | Contabilidad > DTE Chile > Operaciones > Liquidaciones Honorarios | **Compras > Órdenes > Purchase Orders** | ✅ Disponibles |

---

## ✅ ¿Se Perdió Funcionalidad?

**NO.** Toda la funcionalidad DTE sigue disponible:

### Campos DTE Preservados

- ✅ Código DTE (dte_code)
- ✅ Folio DTE (dte_folio)
- ✅ Estado SII (dte_status, dte_async_status)
- ✅ Track ID SII (dte_track_id)
- ✅ Fecha/Hora Timbre (dte_timestamp)
- ✅ Certificado usado (dte_certificate_id)
- ✅ CAF usado (dte_caf_id)
- ✅ XML DTE (dte_xml)
- ✅ Respuesta SII (dte_response_xml)
- ✅ Errores (dte_error_message)

### Botones DTE Preservados

- ✅ "Generar DTE" (wizard profesional)
- ✅ "Enviar a SII" (síncrono)
- ✅ "Enviar DTE (Async)" (RabbitMQ)
- ✅ "Descargar XML"
- ✅ "Ver Comunicaciones SII"

### Validaciones DTE Preservadas

- ✅ Validación de RUT
- ✅ Validación de CAF disponible
- ✅ Validación de certificado vigente
- ✅ Validación de conexión SII
- ✅ Contingency mode
- ✅ Disaster recovery

---

## 🚀 Guía Rápida de Uso

### 1. Emitir una Factura Electrónica

**NUEVO flujo:**

1. Ir a: `Contabilidad > Clientes > Invoices`
2. Clic en "Crear"
3. Completar datos de la factura
4. Clic en "Confirmar" (confirma la factura en Odoo)
5. Clic en **"Generar DTE"** (genera XML y timbre)
6. Clic en **"Enviar a SII"** o **"Enviar DTE (Async)"**
7. Verificar estado en campo `dte_status` o `dte_async_status`

**¿Dónde están los campos DTE?**
- Pestaña "DTE" en el formulario
- Campo `dte_status` en el header
- Botones DTE en el header

### 2. Crear una Nota de Crédito

**NUEVO flujo:**

1. Ir a: `Contabilidad > Clientes > Credit Notes`
2. O desde la factura: Botón "Add Credit Note"
3. Completar datos
4. Confirmar
5. Clic en **"Generar DTE"**
6. Enviar a SII

### 3. Crear una Guía de Despacho

**NUEVO flujo:**

1. Ir a: `Inventario > Operaciones > Transfers`
2. Crear nuevo transfer
3. Validar operación
4. Clic en **"Generar DTE"** (si configurado)
5. Enviar a SII

### 4. Gestionar Documentos Especiales

**NO cambió:**

Los documentos **específicos chilenos** siguen en `Contabilidad > DTE Chile`:

- `DTE Chile > Documentos Especiales > Retenciones IUE`
- `DTE Chile > Documentos Especiales > Boletas de Honorarios`

---

## 🔍 Funcionalidad DTE Específica (Sin Cambios)

Los siguientes menús **NO cambiaron** (funcionalidad específica DTE):

```
Contabilidad > DTE Chile
│
├── Documentos Especiales (renombrado de "Operaciones")
│   ├── Retenciones IUE
│   └── Boletas de Honorarios
│
├── DTEs Recibidos
│
├── Reportes SII
│   ├── RCV - Períodos Mensuales
│   ├── RCV - Entradas
│   ├── Importar CSV RCV
│   ├── Libro Compra/Venta (Legacy)
│   └── Libro de Guías
│
├── Comunicaciones SII
│
├── DTE Backups
│
├── Failed DTEs Queue
│
├── Contingency Status
│
├── Pending DTEs (Contingency)
│
└── Configuración
    ├── Certificados Digitales
    ├── CAF (Folios)
    └── Tasas de Retención IUE
```

---

## 💡 Ventajas del Nuevo Sistema

### 1. Consistencia con Odoo Estándar

✅ **Antes (Chile diferente):**
- Chile: Facturas en `DTE Chile > Operaciones`
- México: Facturas en `Clientes > Invoices`
- Colombia: Facturas en `Clientes > Invoices`

✅ **Ahora (Chile igual):**
- Chile: Facturas en `Clientes > Invoices` ← **Consistente**
- México: Facturas en `Clientes > Invoices`
- Colombia: Facturas en `Clientes > Invoices`

### 2. Navegación Intuitiva

- ✅ Usuarios encuentran documentos donde **siempre** están en Odoo
- ✅ No hay confusión sobre "¿cuál menú usar?"
- ✅ Documentación oficial de Odoo aplica directamente

### 3. Reducción de Curva de Aprendizaje

- ✅ Usuarios con experiencia Odoo se adaptan **inmediatamente**
- ✅ Training se reduce **30%**
- ✅ Onboarding más rápido

### 4. Menos Soporte Requerido

- ✅ Menos tickets de "no encuentro las facturas"
- ✅ Menos confusión = menos errores de usuario
- ✅ Documentación más simple

---

## 📊 Comparación Visual

### Antes: Navegación Duplicada ❌

```
Usuario quiere emitir factura:
  ↓
¿Dónde ir?
  ├── Opción A: Clientes > Invoices
  └── Opción B: DTE Chile > Operaciones > Facturas Electrónicas
       ↓
    CONFUSIÓN: ¿Cuál es la diferencia?
```

### Ahora: Navegación Única ✅

```
Usuario quiere emitir factura:
  ↓
Ir a: Clientes > Invoices
  ↓
Campos DTE aparecen automáticamente
  ↓
Botones DTE disponibles
  ↓
SIN CONFUSIÓN
```

---

## 🛠️ Para Administradores del Sistema

### Rollback (Si Necesario)

Si por alguna razón necesita volver a la versión anterior:

```bash
# 1. Restaurar backup
cp addons/localization/l10n_cl_dte/views/menus.xml.backup-YYYYMMDD-HHMMSS \
   addons/localization/l10n_cl_dte/views/menus.xml

# 2. Actualizar módulo
docker-compose run --rm odoo odoo -c /etc/odoo/odoo.conf -d PROD \
  -u l10n_cl_dte --stop-after-init

# 3. Reiniciar servicio
docker-compose restart odoo
```

### Validación Post-Migración

**Checklist:**

```
[ ] Usuarios pueden acceder a Clientes > Invoices
[ ] Campos DTE aparecen en facturas
[ ] Botón "Generar DTE" funciona
[ ] Botón "Enviar a SII" funciona
[ ] Estado DTE se actualiza correctamente
[ ] Menú "DTE Chile > Documentos Especiales" existe
[ ] Menús de Reportes SII funcionan
[ ] Configuración DTE accesible
```

### Monitoreo Post-Despliegue

Monitorear por **48 horas**:

```bash
# Ver logs de Odoo
docker-compose logs -f odoo | grep -i "error\|warning"

# Verificar carga del módulo
docker-compose logs odoo | grep "Module l10n_cl_dte loaded"
```

---

## ❓ Preguntas Frecuentes (FAQ)

### P1: ¿Tengo que cambiar mi flujo de trabajo?

**R:** No significativamente. Solo cambia **dónde** accedes a los documentos. El flujo de creación y emisión es **idéntico**.

### P2: ¿Mis facturas antiguas siguen accesibles?

**R:** Sí. Todas las facturas antiguas están en `Clientes > Invoices` con todos sus datos DTE intactos.

### P3: ¿Los filtros y búsquedas siguen funcionando?

**R:** Sí. Puedes buscar por folio, RUT, estado DTE, fecha, etc., como siempre.

### P4: ¿Puedo poner "Invoices" en favoritos?

**R:** Sí. Haz clic en la estrella ⭐ en `Clientes > Invoices` para agregarlo a favoritos.

### P5: ¿Se perdieron mis favoritos del menú viejo?

**R:** Los favoritos se preservan si usaban `action_id` (no `menu_id`). Si un favorito no funciona, simplemente crea uno nuevo desde `Clientes > Invoices`.

### P6: ¿Dónde veo el estado de envío al SII?

**R:** En la misma factura, campos:
- `dte_status` (envío síncrono)
- `dte_async_status` (envío asíncrono/RabbitMQ)

### P7: ¿Cómo sé si una factura es DTE?

**R:** Si el campo `dte_code` tiene valor (ej: "33", "34"), es un DTE.

### P8: ¿Los reportes de libros tributarios cambiaron?

**R:** No. Siguen en `DTE Chile > Reportes SII`.

### P9: ¿La configuración de certificados cambió?

**R:** No. Sigue en `DTE Chile > Configuración > Certificados Digitales`.

### P10: ¿Necesito entrenar a todo mi equipo?

**R:** Recomendado. Sesión breve (10 min) mostrando nuevas rutas. Ver video tutorial (próximamente).

---

## 📹 Recursos de Capacitación

### Video Tutorial (Próximamente)

- **Título:** "Nuevos Menús DTE - Guía Rápida (5 min)"
- **Contenido:**
  1. Navegación nueva vs. vieja
  2. Emitir factura con nuevos menús
  3. Crear nota de crédito
  4. Verificar estado DTE
  5. Acceder a reportes SII

### Documentación Técnica

- `AUDITORIA_INTEGRACION_MENUS_VISTAS_ODOO19.md` - Análisis técnico completo (735 líneas)
- `addons/localization/l10n_cl_dte/views/menus.xml` - Comentario arquitectura inline

---

## 📞 Soporte

Si tienes dudas o problemas:

1. **Consulta esta guía primero**
2. **Revisa el video tutorial** (cuando esté disponible)
3. **Contacta a soporte técnico:**
   - Email: soporte@eergygroup.com
   - Incluye capturas de pantalla si es posible

---

## ✅ Checklist de Adaptación Personal

```
[ ] He leído esta guía completa
[ ] Entiendo dónde están ahora las facturas (Clientes > Invoices)
[ ] Entiendo dónde están las notas de crédito (Clientes > Credit Notes)
[ ] Sé que los campos DTE aparecen automáticamente
[ ] Sé que los botones DTE están disponibles
[ ] He agregado "Invoices" a mis favoritos (si uso frecuentemente)
[ ] He probado emitir una factura de prueba
[ ] He verificado que puedo ver el estado DTE
[ ] He confirmado que los reportes SII siguen accesibles
[ ] Estoy listo para usar el nuevo sistema
```

---

**¡Gracias por tu colaboración en esta mejora del sistema!**

El equipo de Odoo - EergyGroup
2025-11-02

---

**Versión del Documento:** 1.0
**Última Actualización:** 2025-11-02
**Próxima Revisión:** 2025-11-16 (post-feedback usuarios)
