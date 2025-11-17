# Certificado Palena (Production)

## Descripción

Este directorio contiene el certificado digital oficial del servidor **Palena** del SII de Chile, utilizado para el ambiente de **PRODUCCIÓN**.

⚠️ **IMPORTANTE**: Este es el ambiente REAL del SII. Todos los DTEs enviados aquí tienen validez legal y tributaria.

## Información del Servidor

- **Nombre**: Palena
- **Tipo**: PRODUCCIÓN (REAL)
- **URL Base**: https://palena.sii.cl
- **Uso**: Operaciones reales, DTEs con validez legal

## Cómo Obtener el Certificado

### Opción 1: Download Automático (Recomendado)

```bash
# Desde el directorio raíz del módulo
cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/data/certificates/production

# Download directo desde SII
curl -o sii_cert_palena.pem https://palena.sii.cl/cgi_rtc/RTC/RTCCertif.cgi

# Verificar certificado descargado
openssl x509 -in sii_cert_palena.pem -text -noout
```

### Opción 2: Download Manual

1. Visita en tu navegador:
   ```
   https://palena.sii.cl/cgi_rtc/RTC/RTCCertif.cgi
   ```

2. El navegador descargará automáticamente el certificado

3. Si el archivo descargado es `.cer` o `.der`, conviértelo a PEM:
   ```bash
   openssl x509 -inform DER -in RTCCertif.cgi -out sii_cert_palena.pem
   ```

4. Mueve el archivo a este directorio:
   ```bash
   mv sii_cert_palena.pem /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/data/certificates/production/
   ```

## Verificación del Certificado

Una vez descargado, verifica que el certificado es válido:

```bash
# Ver información completa del certificado
openssl x509 -in sii_cert_palena.pem -text -noout

# Ver fechas de validez
openssl x509 -in sii_cert_palena.pem -noout -dates

# Ver Subject y Issuer
openssl x509 -in sii_cert_palena.pem -noout -subject -issuer

# Ver fingerprint SHA256
openssl x509 -in sii_cert_palena.pem -noout -fingerprint -sha256
```

**Output Esperado (ejemplo):**
```
Issuer: C=CL, O=Servicio de Impuestos Internos, ...
Subject: C=CL, O=Servicio de Impuestos Internos, ...
Not Before: [fecha]
Not After: [fecha]
```

## Configuración en Odoo

⚠️ **PRECAUCIÓN**: Solo configura Odoo en modo PRODUCTION cuando:
- Hayas completado todas las pruebas en Maullin (staging)
- Tengas autorización para operar en el ambiente real del SII
- Tengas respaldos de toda la configuración

Para configurar Odoo en ambiente PRODUCTION:

1. Ve a: **Settings → Technical → Parameters → System Parameters**

2. Busca la clave: `l10n_cl_dte.sii_environment`

3. Configura el valor a: **`production`**

4. Reinicia Odoo:
   ```bash
   docker-compose restart odoo
   ```

5. Verifica en logs que se cargó el certificado Palena:
   ```bash
   docker-compose logs odoo | grep "Palena"
   ```

## Validación del Certificado en Production

El sistema validará automáticamente que el certificado NO esté expirado cuando `sii_environment = production`.

Si el certificado está expirado, recibirás un error:
```
ValueError: El certificado SII ha expirado: válido hasta [fecha]
```

**Solución**: Descarga nuevamente el certificado actualizado del SII.

## Solución de Problemas

### Error: "Certificado SII no encontrado"

**Causa**: El archivo `sii_cert_palena.pem` no existe en este directorio

**Solución**: Descarga el certificado siguiendo las instrucciones arriba

### Error: "Certificado SII inválido"

**Causa**: El archivo no es un certificado PEM válido

**Solución**:
1. Verifica que el archivo comienza con `-----BEGIN CERTIFICATE-----`
2. Verifica que termina con `-----END CERTIFICATE-----`
3. Si descargaste un `.cer`, conviértelo con openssl (ver arriba)

### Error: "El certificado SII ha expirado"

**Causa**: El certificado del SII ha vencido

**Solución**:
1. Descarga nuevamente el certificado desde el SII
2. El SII renueva sus certificados regularmente
3. Reemplaza el archivo existente
4. Reinicia Odoo

### DTEs rechazados en Palena

**Causa**: Posibles causas múltiples

**Diagnóstico**:
1. Verifica que el certificado de tu empresa sea válido para producción
2. Verifica que los CAFs sean de producción (no de certificación)
3. Revisa logs de Odoo para errores específicos:
   ```bash
   docker-compose logs odoo | grep -i "error\|failed"
   ```

## Checklist Pre-Producción

Antes de cambiar a ambiente PRODUCTION, verifica:

- [ ] Todos los tests pasaron en Maullin (staging)
- [ ] Certificado digital de empresa es válido y autorizado
- [ ] CAFs de producción descargados y validados
- [ ] Usuarios capacitados en el sistema
- [ ] Plan de respaldo configurado
- [ ] Monitoreo de errores configurado
- [ ] Soporte técnico disponible

## Referencias

- [Factura Electrónica SII](https://www.sii.cl/factura_electronica/)
- [Servidor Palena (Producción)](https://palena.sii.cl)
- [Documentación Técnica SII](https://www.sii.cl/servicios_online/1039-1233.html)
- [Mesa de Ayuda SII](https://www.sii.cl/ayudas/ayudas_por_temas/1953-tramites-4313.html)

## Metadata

- **Última Actualización**: 2025-11-09
- **Sprint**: H10 (P1 High Priority) - Official SII Certificate Management
- **Autor**: EERGYGROUP - Ing. Pedro Troncoso Willz
- **Compliance**: Resolución Exenta SII N°11 (2003)
