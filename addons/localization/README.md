# Módulos de Localización Chilena

Este directorio contiene los módulos de localización oficiales de Odoo para Chile.

## 📦 Módulos Instalados

### l10n_cl
Módulo base de localización contable para Chile.

**Características:**
- Plan de cuentas chileno
- Impuestos y retenciones
- Configuración fiscal según normativas SII
- Moneda CLP (Peso Chileno)

**Dependencias:**
- base
- account

### l10n_cl_edi
Módulo de facturación electrónica para Chile.

**Características:**
- Generación de DTE (Documentos Tributarios Electrónicos)
- Integración con servicios web del SII
- Firma digital de documentos
- Validación automática de secuencias

**Dependencias:**
- l10n_cl
- account
- web_unseen

### l10n_cl_reports
Módulo de reportes tributarios para Chile.

**Características:**
- Propuesta F29 (Declaración de impuesto)
- Balance Tributario (8 columnas)
- Reportes de movimiento fiscal
- Exportación a Excel

**Dependencias:**
- l10n_cl
- account_reports

## 🔄 Instalación

Los módulos se instalan automáticamente mediante el script `scripts/init-db.sh`:

```bash
./scripts/init-db.sh
```

O manualmente:

```bash
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    --addons-path=/opt/odoo/addons,/opt/odoo/server/addons \
    --init=l10n_cl,l10n_cl_edi,l10n_cl_reports \
    --stop-after-init
```

## 📝 Configuración Inicial

### 1. Localización de Empresa
1. Ir a **Contabilidad** → **Configuración** → **Localización Chilena**
2. Completar datos de la empresa:
   - RUT (sin puntos, con guión)
   - Actividad económica
   - Datos de contacto

### 2. Plan de Cuentas
El plan de cuentas chileno se carga automáticamente.

### 3. Impuestos
Los impuestos se configuran según la actividad económica:
- IVA 19%
- Impuesto Específico
- Retenciones

## 📚 Documentación

Para más información sobre configuración y uso:
- Ver [docs/SII_SETUP.md](../../docs/SII_SETUP.md)
- Ver [docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md)

## 🔗 Enlaces Útiles

- [Odoo Community - Chile](https://github.com/odoo-chile)
- [SII - Chile](https://www.sii.cl/)
- [Documentación Oficial Odoo](https://www.odoo.com/documentation/19.0/)

## ⚠️ Notas Importantes

- Los módulos requieren certificado digital para emitir DTE
- Se recomienda usar ambiente de pruebas (maullin.sii.cl) antes de producción
- Mantener respaldos regulares de la base de datos

---

**Última actualización**: 2025-10-21
