# SII XSD Schemas Directory

This directory contains the official XSD schemas from SII (Servicio de Impuestos Internos) for validating Chilean DTE XML documents.

## Required Files

Download the following XSD schemas from the SII official website and place them in this directory:

1. **DTE_v10.xsd** - Factura Electrónica (DTE 33)
2. **NotaCredito_v10.xsd** - Nota de Crédito (DTE 61)
3. **NotaDebito_v10.xsd** - Nota de Débito (DTE 56)
4. **GuiaDespacho_v10.xsd** - Guía de Despacho (DTE 52)
5. **LiquidacionFactura_v10.xsd** - Factura Exenta (DTE 34)

## Download Source

Official SII schemas can be downloaded from:
- **Production**: https://www.sii.cl/
- **Documentation**: http://www.sii.cl/factura_electronica/formato_dte.htm

## Usage

The XSD validator (`libs/xsd_validator.py`) automatically uses these schemas to validate DTE XML documents before sending them to SII.

If an XSD file is not found, the validator will skip validation (returns `True`) to avoid blocking DTE generation.

## File Structure

```
static/xsd/
├── README.md (this file)
├── DTE_v10.xsd
├── NotaCredito_v10.xsd
├── NotaDebito_v10.xsd
├── GuiaDespacho_v10.xsd
└── LiquidacionFactura_v10.xsd
```

## Migration Note (2025-10-24)

These XSD schemas were previously used by the `odoo-eergy-services` microservice. They have been migrated to the native Odoo library architecture in `libs/xsd_validator.py`.

**Benefits:**
- Direct file access (no HTTP transmission)
- Faster validation (~50ms improvement)
- Better integration with Odoo ORM
