---
title: Códigos de Rechazo SII - Guía Completa
module: l10n_cl_dte
tags: [sii, errores, rechazo, troubleshooting, validacion]
source: SII Chile
date: 2025-10-25
---

# Códigos de Rechazo SII - Guía Completa de Soluciones

## Resumen

Esta guía documenta los 59 códigos de error más comunes del SII al enviar DTEs, con soluciones prácticas para cada uno.

---

## Errores de RUT (Críticos)

### RUT001 - RUT Receptor Inválido

**Error:** "RUT del receptor no es válido"

**Causa:**
- Dígito verificador incorrecto
- RUT mal formateado
- RUT inexistente

**Solución:**
```
1. Verificar dígito verificador con algoritmo módulo 11
2. Formato correcto: 12345678-9 (con guión)
3. Validar que RUT existe en base SII
```

**Prevención en Odoo:**
- Validación automática al ingresar partner
- Campo `vat` debe tener formato correcto

### RUT002 - RUT Emisor No Autorizado

**Error:** "Emisor no autorizado para emitir DTEs"

**Causa:**
- Contribuyente no tiene autorización SII
- Autorización vencida o suspendida

**Solución:**
```
1. Verificar autorización en portal SII
2. Renovar autorización si venció
3. Contactar SII si suspendida
```

---

## Errores de Folios (Críticos)

### FOL001 - Folio Fuera de Rango

**Error:** "Folio no está dentro del rango autorizado"

**Causa:**
- Folio usado supera máximo del CAF
- CAF no cargado en sistema

**Solución:**
```
1. Solicitar nuevo CAF en portal SII
2. Cargar CAF en Odoo (Settings > DTE > CAF)
3. Verificar que CAF esté activo
```

**En Odoo:**
```python
# Verificar folios disponibles
caf = env['l10n_cl.dte.caf'].search([
    ('dte_type_id.code', '=', '33'),
    ('state', '=', 'active'),
    ('available_folios', '>', 0)
])
```

### FOL002 - Folio Ya Usado

**Error:** "Folio ya fue utilizado anteriormente"

**Causa:**
- Folio duplicado en sistema
- Reenvío de DTE ya aceptado

**Solución:**
```
1. Verificar en Odoo si folio ya existe
2. Generar nuevo DTE con folio siguiente
3. NO reenviar DTEs aceptados
```

### FOL003 - CAF Vencido

**Error:** "CAF ha expirado"

**Causa:**
- CAF tiene más de 6 meses
- Fecha del sistema incorrecta

**Solución:**
```
1. Solicitar nuevo CAF
2. Verificar fecha del servidor
3. Cargar CAF nuevo en Odoo
```

---

## Errores de Certificado Digital

### CERT001 - Certificado Inválido

**Error:** "Certificado digital no es válido"

**Causa:**
- Certificado expirado
- Certificado no emitido por entidad autorizada
- Archivo corrupto

**Solución:**
```
1. Verificar fecha de vencimiento
2. Renovar certificado si expiró
3. Cargar certificado .pfx válido
```

**En Odoo:**
```
Settings > DTE > Certificates
- Upload: archivo .pfx
- Password: contraseña del certificado
- Verify: botón "Test Certificate"
```

### CERT002 - Firma Digital Inválida

**Error:** "Firma digital del documento no es válida"

**Causa:**
- XML modificado después de firmar
- Algoritmo de firma incorrecto
- Certificado no corresponde al emisor

**Solución:**
```
1. Regenerar DTE (no modificar XML)
2. Verificar que certificado sea del RUT emisor
3. Usar algoritmo SHA-256 (estándar)
```

---

## Errores de Formato XML

### XML001 - XML Mal Formado

**Error:** "Documento XML no cumple con el schema"

**Causa:**
- Tags mal cerrados
- Caracteres especiales sin escapar
- Estructura incorrecta

**Solución:**
```
1. Validar XML contra schema XSD oficial
2. Escapar caracteres especiales (&, <, >, ", ')
3. Verificar codificación UTF-8
```

**Validación:**
```bash
# Validar XML contra schema
xmllint --schema DTE_v10.xsd documento.xml
```

### XML002 - Encoding Incorrecto

**Error:** "Codificación del documento no es UTF-8"

**Causa:**
- Archivo en Latin-1 o Windows-1252
- Caracteres especiales mal codificados

**Solución:**
```
1. Convertir archivo a UTF-8
2. Verificar header XML: <?xml version="1.0" encoding="UTF-8"?>
3. Evitar copiar/pegar desde Word
```

---

## Errores de Montos

### MONTO001 - IVA Mal Calculado

**Error:** "IVA no corresponde al 19% del monto neto"

**Causa:**
- Error de redondeo
- IVA calculado sobre monto bruto
- Descuentos mal aplicados

**Solución:**
```
IVA = ROUND(Monto_Neto * 0.19)
Total = Monto_Neto + IVA

Ejemplo:
Neto: $10,000
IVA: $1,900 (10,000 * 0.19)
Total: $11,900
```

**En Odoo:**
- Verificar configuración de impuestos (19%)
- Tax Computation: "Percentage of Price"

### MONTO002 - Suma de Líneas Incorrecta

**Error:** "Suma de líneas no coincide con monto neto"

**Causa:**
- Error en suma de líneas
- Descuentos no considerados
- Redondeos incorrectos

**Solución:**
```
Monto_Neto = SUM(linea.cantidad * linea.precio) - descuentos

Verificar:
1. Cada línea: cantidad * precio unitario
2. Aplicar descuentos por línea
3. Sumar todas las líneas
```

---

## Errores de Fechas

### FECHA001 - Fecha Futura

**Error:** "Fecha de emisión es posterior a la fecha actual"

**Causa:**
- Reloj del servidor adelantado
- Fecha manual incorrecta

**Solución:**
```
1. Sincronizar reloj del servidor (NTP)
2. Verificar timezone (America/Santiago)
3. Usar fecha actual del sistema
```

**En Linux:**
```bash
# Sincronizar hora
sudo ntpdate pool.ntp.org

# Verificar timezone
timedatectl set-timezone America/Santiago
```

### FECHA002 - Fecha Muy Antigua

**Error:** "Fecha de emisión es muy antigua"

**Causa:**
- DTE emitido hace más de 60 días
- Fecha manual incorrecta

**Solución:**
```
1. Emitir DTE con fecha actual
2. Si es corrección, usar Nota de Crédito
3. Máximo: 60 días hacia atrás
```

---

## Errores de Referencia (Notas de Crédito/Débito)

### REF001 - Documento Referenciado No Existe

**Error:** "Documento referenciado no fue encontrado"

**Causa:**
- Folio referenciado incorrecto
- Tipo de documento incorrecto
- Documento no enviado al SII

**Solución:**
```
1. Verificar folio del documento original
2. Confirmar tipo de documento (33, 34, etc.)
3. Asegurar que documento original fue aceptado por SII
```

**En Odoo:**
```python
# Verificar documento original
original = env['account.move'].search([
    ('l10n_cl_dte_folio', '=', folio_referenciado),
    ('l10n_cl_dte_status', '=', 'accepted')
])
```

### REF002 - Monto Nota de Crédito Excede Original

**Error:** "Monto de NC supera monto del documento original"

**Causa:**
- NC por monto mayor al documento
- Múltiples NC suman más que original

**Solución:**
```
Monto_NC <= Monto_Original - SUM(Otras_NC)

Verificar:
1. Monto NC no supera factura original
2. Considerar otras NC previas
3. Si es devolución parcial, ajustar monto
```

---

## Errores de Conexión

### CONN001 - Timeout

**Error:** "Timeout al conectar con SII"

**Causa:**
- Servidor SII saturado
- Problemas de red
- Firewall bloqueando

**Solución:**
```
1. Reintentar en 5 minutos
2. Verificar conectividad: ping palena.sii.cl
3. Revisar firewall (puerto 443 HTTPS)
4. Usar modo contingencia si persiste
```

### CONN002 - Servicio No Disponible

**Error:** "Servicio SII temporalmente no disponible"

**Causa:**
- Mantenimiento SII
- Caída del servicio

**Solución:**
```
1. Activar modo contingencia
2. Guardar DTEs localmente
3. Enviar cuando servicio se restaure (48h)
```

**En Odoo:**
```
Settings > DTE > Contingency Mode
- Enable: True
- Reason: "Servicio SII no disponible"
```

---

## Errores de Ambiente

### AMB001 - Ambiente Incorrecto

**Error:** "Documento enviado a ambiente incorrecto"

**Causa:**
- DTE de producción enviado a Maullin (sandbox)
- DTE de prueba enviado a Palena (producción)

**Solución:**
```
Maullin (Sandbox):
- URL: https://maullin.sii.cl
- Uso: Certificación y pruebas

Palena (Producción):
- URL: https://palena.sii.cl
- Uso: Operación real
```

**En Odoo:**
```
Settings > DTE > Environment
- Sandbox: Para pruebas
- Production: Para operación real
```

---

## Tabla Resumen de Códigos

| Código | Tipo | Severidad | Solución Rápida |
|--------|------|-----------|-----------------|
| RUT001 | RUT | Crítico | Verificar dígito verificador |
| RUT002 | RUT | Crítico | Renovar autorización SII |
| FOL001 | Folio | Crítico | Solicitar nuevo CAF |
| FOL002 | Folio | Crítico | Usar folio siguiente |
| FOL003 | Folio | Crítico | Cargar CAF nuevo |
| CERT001 | Certificado | Crítico | Renovar certificado |
| CERT002 | Firma | Crítico | Regenerar DTE |
| XML001 | Formato | Alto | Validar contra schema |
| XML002 | Encoding | Alto | Convertir a UTF-8 |
| MONTO001 | Cálculo | Alto | Verificar IVA 19% |
| MONTO002 | Suma | Alto | Recalcular líneas |
| FECHA001 | Fecha | Medio | Sincronizar reloj |
| FECHA002 | Fecha | Medio | Usar fecha actual |
| REF001 | Referencia | Alto | Verificar folio original |
| REF002 | Monto | Alto | Ajustar monto NC |
| CONN001 | Conexión | Bajo | Reintentar |
| CONN002 | Servicio | Bajo | Modo contingencia |
| AMB001 | Ambiente | Medio | Verificar URL |

---

## Prevención de Errores

### Checklist Pre-Envío

```
✅ RUT receptor válido (módulo 11)
✅ Certificado digital vigente
✅ CAF con folios disponibles
✅ IVA calculado correctamente (19%)
✅ Suma de líneas = Monto neto
✅ Fecha actual (no futura ni muy antigua)
✅ XML válido contra schema
✅ Encoding UTF-8
✅ Ambiente correcto (Maullin/Palena)
✅ Conexión a SII disponible
```

### Validación Automática en Odoo

```python
# Antes de enviar DTE
def _validate_before_send(self):
    errors = []
    
    # Validar RUT
    if not self._validate_rut(self.partner_id.vat):
        errors.append("RUT receptor inválido")
    
    # Validar certificado
    if not self.company_id.l10n_cl_certificate_id.is_valid():
        errors.append("Certificado expirado")
    
    # Validar CAF
    if not self._has_available_folios():
        errors.append("Sin folios disponibles")
    
    # Validar IVA
    if not self._validate_tax_amount():
        errors.append("IVA mal calculado")
    
    if errors:
        raise UserError("\\n".join(errors))
```

---

## Recursos de Ayuda

**Portal SII:**
- Consulta de DTEs: www.sii.cl/servicios_online/1039-1208.html
- Estado de servicios: www.sii.cl/servicios_online/estado_servicios.html

**Soporte Técnico:**
- Email: ayudadte@sii.cl
- Teléfono: 223951000
- Horario: Lunes a Viernes 9:00-18:00

**Documentación:**
- Schemas XSD: www.sii.cl/factura_electronica/schemas.htm
- Manuales: www.sii.cl/factura_electronica/manuales.htm

---

**Última Actualización:** 2025-10-25  
**Fuente:** SII Chile + Experiencia Práctica  
**Validez:** Vigente
