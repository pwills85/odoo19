---
title: Resolución 80 (2014) - Factura Electrónica
module: l10n_cl_dte
tags: [normativa, sii, resolucion, dte, factura, 33, 34, 52, 56, 61]
source: SII Chile
date: 2014-10-01
---

# Resolución Exenta N° 80 (2014) - Sistema de Facturación Electrónica

## Resumen Ejecutivo

La Resolución Exenta N° 80 del SII establece el marco normativo para la emisión de Documentos Tributarios Electrónicos (DTEs) en Chile.

**Fecha:** 22 de octubre de 2014  
**Vigencia:** Desde 01/11/2014  
**Alcance:** Todos los contribuyentes autorizados para emitir DTEs

---

## Documentos Tributarios Electrónicos Autorizados

### 1. Factura Electrónica (Código 33)

**Uso:**
- Venta de bienes o servicios afectos a IVA
- Cliente es contribuyente de IVA
- Operaciones gravadas con impuestos

**Requisitos Obligatorios:**
- RUT emisor y receptor
- Razón social completa
- Giro del negocio
- Dirección y comuna
- Folio único y correlativo
- Fecha de emisión
- Detalle de productos/servicios
- Monto neto, IVA (19%), total
- Timbre electrónico SII

**Formato:**
- XML según schema oficial SII
- Firma digital con certificado autorizado
- Codificación UTF-8

### 2. Factura Exenta Electrónica (Código 34)

**Uso:**
- Operaciones exentas de IVA
- Ventas a organismos públicos
- Productos/servicios exentos por ley

**Diferencias con Código 33:**
- No incluye IVA
- Debe indicar artículo de exención
- Monto total = Monto neto

### 3. Nota de Crédito Electrónica (Código 61)

**Uso:**
- Anular o modificar facturas emitidas
- Devoluciones de mercadería
- Descuentos posteriores a la venta
- Corrección de errores

**Requisitos Especiales:**
- Debe referenciar documento original (tipo, folio, fecha)
- Razón de la nota de crédito
- No puede superar monto del documento original

### 4. Nota de Débito Electrónica (Código 56)

**Uso:**
- Aumentar monto de factura original
- Cobros de intereses
- Gastos adicionales no incluidos

**Requisitos Especiales:**
- Debe referenciar documento original
- Justificación del cargo adicional

### 5. Guía de Despacho Electrónica (Código 52)

**Uso:**
- Traslado de mercaderías sin venta
- Envío en consignación
- Traslado entre bodegas propias

**Requisitos Especiales:**
- Indicar tipo de traslado
- Dirección origen y destino
- Patente del vehículo (si aplica)
- RUT del transportista

---

## Proceso de Emisión de DTEs

### 1. Autorización Previa

**Requisitos:**
1. Ser contribuyente de IVA
2. Tener certificado digital vigente
3. Solicitar autorización en sitio SII
4. Obtener CAF (Código de Autorización de Folios)

### 2. Generación del DTE

**Pasos:**
1. Crear documento en sistema certificado
2. Asignar folio desde CAF autorizado
3. Completar todos los campos obligatorios
4. Generar XML según schema SII
5. Firmar digitalmente con certificado

### 3. Envío al SII

**Métodos:**
- **Set de Pruebas:** Ambiente Maullin (certificación)
- **Producción:** Ambiente Palena (operación real)

**Proceso:**
1. Enviar XML firmado vía SOAP
2. SII valida formato y firma
3. SII retorna Track ID
4. Consultar estado con Track ID

### 4. Entrega al Receptor

**Obligaciones:**
1. Enviar DTE al receptor (email, portal)
2. Incluir representación impresa (PDF)
3. Receptor debe aceptar o reclamar (8 días)

---

## Validaciones del SII

### Validaciones Automáticas

El SII valida automáticamente:

1. **Formato XML:**
   - Cumplimiento schema XSD oficial
   - Codificación UTF-8
   - Estructura correcta

2. **Firma Digital:**
   - Certificado vigente
   - Firma válida
   - Emisor autorizado

3. **Folios:**
   - Folio dentro de rango CAF
   - Folio no usado previamente
   - CAF vigente

4. **RUT:**
   - RUT emisor autorizado para DTE
   - RUT receptor válido (módulo 11)
   - Emisor y receptor diferentes

5. **Montos:**
   - IVA calculado correctamente (19%)
   - Suma de líneas = Monto neto
   - Redondeos según normativa

### Códigos de Rechazo Comunes

| Código | Descripción | Solución |
|--------|-------------|----------|
| **RUT001** | RUT receptor inválido | Verificar dígito verificador |
| **FOL001** | Folio fuera de rango | Solicitar nuevo CAF |
| **FIRMA01** | Firma digital inválida | Renovar certificado |
| **MONTO01** | IVA mal calculado | Verificar cálculo 19% |
| **XML001** | XML mal formado | Validar contra schema |

---

## Plazos y Obligaciones

### Emisión

- **Plazo:** Mismo día de la operación
- **Excepción:** Hasta 5to día hábil del mes siguiente (servicios periódicos)

### Envío al SII

- **Plazo:** Dentro de las 24 horas siguientes a la emisión
- **Modo Contingencia:** Hasta 48 horas después de restaurado el servicio

### Libros Electrónicos

- **Libro Compras:** Hasta día 13 del mes siguiente
- **Libro Ventas:** Hasta día 13 del mes siguiente
- **Libro Guías:** Hasta día 13 del mes siguiente

### Conservación

- **Digital:** Mínimo 6 años
- **Respaldo:** Recomendado backup diario
- **Acceso:** Disponible para fiscalización SII

---

## Sanciones por Incumplimiento

### Infracciones Graves

1. **No emitir DTE:** Multa 1 UTM por documento
2. **Emisión tardía:** Multa 0.2 UTM por documento
3. **Datos falsos:** Multa 2-10 UTM + clausura
4. **No enviar al SII:** Multa 1 UTM por documento

### Infracciones Leves

1. **Errores formales:** Amonestación escrita
2. **Retraso libros:** Multa 0.5 UTM
3. **No conservar:** Multa 1 UTM

---

## Referencias Legales

- **Resolución Exenta N° 80 (2014):** Marco normativo DTEs
- **Circular N° 45 (2021):** Boletas electrónicas
- **Ley sobre Impuesto a las Ventas y Servicios (DL 825)**
- **Código Tributario:** Obligaciones y sanciones

---

## Actualizaciones Importantes

### 2020 - Resolución 93
- Modo contingencia obligatorio
- Backup local de DTEs

### 2021 - Circular 45
- Boletas electrónicas obligatorias
- Integración con caja registradora

### 2023 - Resolución 11
- Factura de Compra Electrónica (código 46)
- Nuevos campos opcionales

---

## Recursos Oficiales

- **Portal SII:** www.sii.cl
- **Documentación Técnica:** www.sii.cl/factura_electronica
- **Schemas XSD:** Disponibles en portal SII
- **Certificación:** Ambiente Maullin (maullin.sii.cl)
- **Producción:** Ambiente Palena (palena.sii.cl)

---

**Última Actualización:** 2025-10-25  
**Fuente:** Servicio de Impuestos Internos (SII) Chile  
**Validez:** Vigente
