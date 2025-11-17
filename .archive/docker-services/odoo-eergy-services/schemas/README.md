# Esquemas XSD del SII

Esta carpeta debe contener los esquemas XSD oficiales del SII para validación de DTEs.

## ⭐ FASE 7 COMPLETADA: Validadores Implementados

Se han implementado 3 validadores según normativa SII:

1. ✅ **XSDValidator** - Valida contra esquemas XSD oficiales
2. ✅ **TEDValidator** - Valida estructura TED (Res. Ex. SII N° 45/2003)
3. ✅ **DTEStructureValidator** - Valida elementos requeridos por tipo DTE

## Archivos Requeridos

Descargar desde: https://www.sii.cl/factura_electronica/schemas/

1. `DTE_v10.xsd` - Esquema principal para DTEs
2. `EnvioDTE_v10.xsd` - Esquema para envío de DTEs
3. `ConsumoFolios_v10.xsd` - Esquema para consumo de folios
4. `LibroCompraVenta_v10.xsd` - Esquema para libros de compra/venta
5. `SiiTypes_v10.xsd` - Tipos de datos SII

## Instalación

```bash
cd dte-service/schemas

# Opción 1: Descargar directamente del SII
wget https://www.sii.cl/factura_electronica/schemas/DTE_v10.xsd
wget https://www.sii.cl/factura_electronica/schemas/EnvioDTE_v10.xsd
wget https://www.sii.cl/factura_electronica/schemas/ConsumoFolios_v10.xsd
wget https://www.sii.cl/factura_electronica/schemas/LibroCompraVenta_v10.xsd
wget https://www.sii.cl/factura_electronica/schemas/SiiTypes_v10.xsd

# Opción 2: Usar curl
curl -O https://www.sii.cl/factura_electronica/schemas/DTE_v10.xsd
curl -O https://www.sii.cl/factura_electronica/schemas/EnvioDTE_v10.xsd
curl -O https://www.sii.cl/factura_electronica/schemas/ConsumoFolios_v10.xsd
curl -O https://www.sii.cl/factura_electronica/schemas/LibroCompraVenta_v10.xsd
curl -O https://www.sii.cl/factura_electronica/schemas/SiiTypes_v10.xsd
```

## Validaciones Implementadas

### 1. XSD Validator
- Valida XML contra esquemas oficiales del SII
- Graceful degradation si XSD no disponible
- Logging estructurado de errores

### 2. TED Validator
- Valida estructura TED completa
- Verifica presencia de CAF
- Valida algoritmo de firma (SHA1withRSA)
- Valida formato de datos (RUT, montos)

### 3. DTE Structure Validator
- Valida elementos requeridos por tipo DTE (33, 34, 52, 56, 61)
- Validaciones específicas por tipo
- Warnings para elementos opcionales

## Flujo de Validación

```
DTE XML
  ↓
1. XSD Validation (opcional)
  ↓
2. Structure Validation (obligatoria)
  ↓
3. TED Validation (obligatoria)
  ↓
Si todas pasan → Firmar y enviar a SII
Si alguna falla → Retornar error con detalles
```

## Nota Importante

**Graceful Degradation:** Los esquemas XSD son opcionales. Si no están presentes:
- XSDValidator retorna `True` con warning
- TEDValidator y DTEStructureValidator siguen validando
- Sistema funciona sin XSD pero con menos validaciones

**Recomendación:** Descargar XSD para validación completa en producción.

## Notas

- Los XSD evolucionan (actualmente v10)
- Verificar versión actual en SII
- Sistema funciona sin XSD (validación se omite gracefully)
- Con XSD: Mayor confianza en DTEs generados

## Estado Actual

⚠️ **XSD no incluidos en el repositorio**

Razones:
1. Copyright del SII
2. Pueden actualizarse
3. Sistema funciona sin ellos (validación opcional)

**Para producción:** Descargar XSD oficiales y colocar en esta carpeta.

