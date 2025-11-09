# Certificado Maullin (Staging/Certificación)

## Descripción

Este directorio contiene el certificado digital oficial del servidor **Maullin** del SII de Chile, utilizado para el ambiente de certificación y testing.

## Información del Servidor

- **Nombre**: Maullin
- **Tipo**: Certificación / Testing / Sandbox
- **URL Base**: https://maullin.sii.cl
- **Uso**: Desarrollo, testing, validación antes de producción

## Cómo Obtener el Certificado

### Opción 1: Download Automático (Recomendado)

```bash
# Desde el directorio raíz del módulo
cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/data/certificates/staging

# Download directo desde SII
curl -o sii_cert_maullin.pem https://maullin.sii.cl/cgi_rtc/RTC/RTCCertif.cgi

# Verificar certificado descargado
openssl x509 -in sii_cert_maullin.pem -text -noout
```

### Opción 2: Download Manual

1. Visita en tu navegador:
   ```
   https://maullin.sii.cl/cgi_rtc/RTC/RTCCertif.cgi
   ```

2. El navegador descargará automáticamente el certificado

3. Si el archivo descargado es `.cer` o `.der`, conviértelo a PEM:
   ```bash
   openssl x509 -inform DER -in RTCCertif.cgi -out sii_cert_maullin.pem
   ```

4. Mueve el archivo a este directorio:
   ```bash
   mv sii_cert_maullin.pem /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/data/certificates/staging/
   ```

## Verificación del Certificado

Una vez descargado, verifica que el certificado es válido:

```bash
# Ver información completa del certificado
openssl x509 -in sii_cert_maullin.pem -text -noout

# Ver fechas de validez
openssl x509 -in sii_cert_maullin.pem -noout -dates

# Ver Subject y Issuer
openssl x509 -in sii_cert_maullin.pem -noout -subject -issuer

# Ver fingerprint SHA256
openssl x509 -in sii_cert_maullin.pem -noout -fingerprint -sha256
```

**Output Esperado (ejemplo):**
```
Issuer: C=CL, O=Servicio de Impuestos Internos, ...
Subject: C=CL, O=Servicio de Impuestos Internos, ...
Not Before: [fecha]
Not After: [fecha]
```

## Configuración en Odoo

Una vez descargado el certificado, configura Odoo para usar el ambiente **staging**:

1. Ve a: **Settings → Technical → Parameters → System Parameters**

2. Busca la clave: `l10n_cl_dte.sii_environment`

3. Configura el valor a uno de:
   - `sandbox` (staging)
   - `testing` (staging)
   - `certification` (staging)

4. Reinicia Odoo:
   ```bash
   docker-compose restart odoo
   ```

## Solución de Problemas

### Error: "Certificado SII no encontrado"

**Causa**: El archivo `sii_cert_maullin.pem` no existe en este directorio

**Solución**: Descarga el certificado siguiendo las instrucciones arriba

### Error: "Certificado SII inválido"

**Causa**: El archivo no es un certificado PEM válido

**Solución**:
1. Verifica que el archivo comienza con `-----BEGIN CERTIFICATE-----`
2. Verifica que termina con `-----END CERTIFICATE-----`
3. Si descargaste un `.cer`, conviértelo con openssl (ver arriba)

### Error: "El certificado SII ha expirado"

**Causa**: El certificado del SII ha vencido (poco común en Maullin)

**Solución**:
1. Descarga nuevamente el certificado desde el SII
2. El SII renueva sus certificados automáticamente

## Referencias

- [Factura Electrónica SII](https://www.sii.cl/factura_electronica/)
- [Servidor Maullin (Certificación)](https://maullin.sii.cl)
- [Documentación Técnica SII](https://www.sii.cl/servicios_online/1039-1233.html)

## Metadata

- **Última Actualización**: 2025-11-09
- **Sprint**: H10 (P1 High Priority) - Official SII Certificate Management
- **Autor**: EERGYGROUP - Ing. Pedro Troncoso Willz
