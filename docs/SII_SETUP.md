# Configuración de Facturación Electrónica - SII

## 📋 Introducción

Esta guía proporciona los pasos necesarios para configurar la facturación electrónica en Odoo 19 CE según las regulaciones del Servicio de Impuestos Internos (SII) de Chile.

## 🔑 Conceptos Clave

### Documentos Tributarios Electrónicos (DTE)
- **Factura Electrónica (33)**: Documento de venta de bienes o servicios
- **Boleta Electrónica (39)**: Documento de venta a consumidor final
- **Nota de Crédito Electrónica (61)**: Devolución o descuento
- **Nota de Débito Electrónica (56)**: Cobro adicional

## 📦 Módulos Requeridos

### l10n_cl
- Configuración contable básica de Chile
- Plan de cuentas chileno
- Impuestos y retenciones
- Regulaciones fiscales

### l10n_cl_edi
- Generación de DTE
- Integración con servicios web del SII
- Validación de documentos
- Firma digital

### l10n_cl_reports
- Reportes tributarios
- Propuesta F29
- Balance Tributario

## ⚙️ Pasos de Configuración

### 1. Configuración Inicial de la Empresa

#### Acceso
1. Ir a **Contabilidad** → **Configuración** → **Localización Chilena**
2. O desde **Configuración** → **Compañías** → Editar empresa

#### Datos Requeridos
```
Nombre de la Empresa:        [Nombre legal]
RUT:                         [RUT sin puntos, con guión]
Giro/Actividad:              [Código SII de actividad económica]
Dirección:                   [Dirección completa]
Teléfono:                    [Teléfono de contacto]
Email:                       [Email principal]
Logo:                        [Logotipo de la empresa]
```

### 2. Configuración de Certificado Digital

#### Obtener Certificado
1. Acceder a [Registro SII](https://www.sii.cl/)
2. Descargar certificado digital (formato .p12 o .pfx)
3. Guardar con contraseña segura

#### Cargar en Odoo
```bash
# Copiar certificado a la carpeta de configuración
cp /ruta/al/certificado.p12 addons/localization/data/
```

### 3. Configuración de Ambientes

#### Producción (Ambiente Real)
```
URL SII: https://palena.sii.cl/
Environment: production
Use CA Certificate: Sí
```

#### Desarrollo/Testing
```
URL SII: https://maullin.sii.cl/ (ambiente de pruebas)
Environment: test
Use CA Certificate: No
```

### 4. Parámetros de Secuencia

En **Contabilidad** → **Configuración** → **Secuencias**

```
Nombre:         Invoices - 19.0
Código:         account.move
Prefijo:        F
Sufijo:         (vacío)
Próximo número: 1
Incremento:     1
```

### 5. Configuración de Cuentas Contables

#### Cuentas de Ingresos
- 2110 Ventas de Bienes y Servicios
- 2111 Ventas a Contribuyentes
- 2120 Devoluciones, Descuentos

#### Cuentas de Gastos
- 2110 Compras de Bienes
- 2120 Compras de Servicios

#### Cuentas de Impuestos
- 1170 IVA (Crédito Fiscal)
- 2130 IVA (Débito Fiscal)
- 2140 IVA Retenido

### 6. Configuración de Impuestos

#### IVA (19%)
```
Nombre:         IVA 19%
Tipo:           Sale/Purchase
Tasa:           19%
Etiqueta:       IVA
Aplicable en:   Productos y Servicios
```

#### Impuesto Específico (Bebidas Alcohólicas)
```
Nombre:         Impuesto Específico
Tasa:           Según producto
Aplicable en:   Categorías específicas
```

### 7. Configuración de Tipos de Documento

```
Factura Electrónica (DTE 33):
- Tipo: Factura
- Código: 33
- Formato: DTE

Boleta Electrónica (DTE 39):
- Tipo: Boleta
- Código: 39
- Formato: DTE

Nota de Crédito (DTE 61):
- Tipo: Devolución
- Código: 61
- Formato: DTE
```

### 8. Configuración de Email

Para recibir confirmaciones del SII y notificaciones:

```
Servidor SMTP:      smtp.gmail.com (o tu proveedor)
Puerto:             587
Usuario:            tu_email@empresa.cl
Contraseña:         [contraseña de aplicación]
Usar TLS:           Sí
Usar SSL:           No
```

## 🚀 Emisión de DTE

### 1. Crear Factura

1. Ir a **Ventas** → **Facturas**
2. Crear nueva factura
3. Completar datos:
   - Cliente (RUT con guión)
   - Productos/Servicios
   - Moneda (CLP)
   - Fecha

### 2. Validación

Sistema valida automáticamente:
- Formato RUT cliente
- Secuencia de numeración
- Cálculo de impuestos
- Totales

### 3. Emisión a SII

```bash
# Opción 1: Interfaz web
1. Factura → Acción → Enviar a SII

# Opción 2: Línea de comandos
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    -u l10n_cl_edi \
    --dev=reload
```

### 4. Estados del DTE

| Estado | Descripción |
|--------|------------|
| Borrador | Documento en construcción |
| Firmado | Documento firmado digitalmente |
| Enviado | Enviado a SII |
| Aceptado | SII aceptó el documento |
| Rechazado | SII rechazó el documento |
| Cancelado | Documento anulado |

## 📊 Reportes Tributarios

### Propuesta F29

```bash
# Acceder a través de:
1. Contabilidad → Reportes → Propuesta F29
2. Seleccionar período
3. Generar PDF/Excel
```

Incluye:
- Ventas del período
- Compras del período
- IVA a pagar/recuperar
- Retenciones

### Balance Tributario

```bash
# Acceder a través de:
1. Contabilidad → Reportes → Balance Tributario 8 Columnas
2. Seleccionar período
3. Generar PDF
```

## 🔐 Seguridad

### Certificado Digital

1. **Guardar en lugar seguro**
   ```bash
   chmod 600 certificado.p12
   ```

2. **Proteger contraseña**
   - No compartir contraseña
   - Usar contraseñas seguras
   - Cambiar periódicamente

### Auditoría

```sql
-- Ver últimos cambios en DTE
SELECT * FROM account_move_edi 
WHERE create_date > NOW() - INTERVAL 7 DAY
ORDER BY create_date DESC;
```

## 🐛 Resolución de Problemas

### Error: "Certificado inválido"

**Solución:**
1. Verificar que certificado no está expirado
2. Verificar que contraseña es correcta
3. Verificar formato (debe ser .p12)

### Error: "RUT cliente inválido"

**Solución:**
1. RUT debe incluir guión (ej: 12345678-9)
2. Verificar dígito verificador
3. RUT no debe tener puntos

### Error: "Conexión con SII rechazada"

**Solución:**
1. Verificar conexión a internet
2. Verificar URL del SII es correcta
3. Verificar firewall permite conexión
4. Verificar certificado SSL

### Documento no aparece en SII

**Pasos:**
```bash
# 1. Verificar estado
SELECT folio, edi_status, edi_error FROM account_move WHERE id = <id>;

# 2. Reintentar envío
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    --init=l10n_cl_edi \
    --stop-after-init
```

## 📞 Contacto SII

- **Sitio Web**: https://www.sii.cl/
- **Correo**: consultas@sii.cl
- **Teléfono**: 2-26713000
- **Mesa de Ayuda SII**: https://www.sii.cl/portal/aprendiendo-sii

## 📚 Referencias

- [Documentación Odoo - Localización Chile](https://www.odoo.com/documentation/16.0/applications/finance/fiscal_localizations/chile.html)
- [Manual DTE SII](https://www.sii.cl/portales/basedatos/documentos/manual_dte.pdf)
- [RUC - Radicador Único Código SII](https://www.ruc.sii.cl/)

## ⚠️ Notas Importantes

1. **Certificado Digital**: Es obligatorio tener certificado digital válido para emitir DTE
2. **Ambiente de Pruebas**: Utilizar ambiente de pruebas (maullin) para validaciones antes de producción
3. **Secuencia de Numeración**: No saltar números en secuencia (Resolución No. 6 SII)
4. **Plazo de Emisión**: Los DTE deben emitirse antes de las 23:59:59 del día de operación
5. **Respaldo de Información**: Mantener respaldos diarios de la base de datos

## ✅ Checklist Pre-Producción

- [ ] Certificado digital instalado y validado
- [ ] Empresa configurada en módulo de localización
- [ ] Plan de cuentas configurado
- [ ] Impuestos configurados correctamente
- [ ] Secuencias de numeración definidas
- [ ] Email de notificaciones configurado
- [ ] Pruebas en ambiente de testing realizadas
- [ ] Respaldos de base de datos configurados
- [ ] Equipo capacitado en uso del sistema
- [ ] Documentación interna generada

---

**Última actualización**: 2025-10-21  
**Versión**: Odoo 19 CE
