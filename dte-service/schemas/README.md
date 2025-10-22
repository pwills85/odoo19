# Esquemas XSD del SII Chile

## Archivos XSD Oficiales

Para validación completa, descargar desde el SII:

**URL oficial:** http://www.sii.cl/factura_electronica/

**Archivos requeridos:**
1. `DTE_v10.xsd` - Esquema principal de DTEs
2. `EnvioDTE_v10.xsd` - Esquema de envío
3. `ConsumoFolios_v10.xsd` - Esquema de consumo de folios
4. `LibroCompraVenta_v10.xsd` - Esquema de libros

## Cómo obtenerlos

### Opción A: Descarga directa desde SII
```bash
# Acceder a:
# http://www.sii.cl/factura_electronica/formato_dte.pdf
# Anexos contienen los XSD
```

### Opción B: Desde repositorios oficiales
```bash
# Algunos XSD están en GitHub (no oficial pero actualizados)
# Verificar siempre con versión del SII
```

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

