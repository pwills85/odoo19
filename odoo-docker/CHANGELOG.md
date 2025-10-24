# Changelog - Odoo 19 CE + Chile Localization Docker

Todos los cambios notables en las imágenes Docker serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

---

## [19.0.1.0.0] - 2025-10-24

### 🎉 Lanzamiento Inicial - Reorganización Profesional

#### Added
- ✅ **Arquitectura multi-stage** con 3 stages (base, chile, development)
- ✅ **Stage base**: Imagen oficial Odoo 19.0.20251021 sin modificaciones
- ✅ **Stage chile**: Localización completa para Chile con 25 dependencias Python
- ✅ **Stage development**: Herramientas de testing, linting y debugging
- ✅ **Scripts oficiales Odoo** preservados (entrypoint.sh, wait-for-psql.py)
- ✅ **Versionado semántico** implementado (MAJOR.MINOR.PATCH)
- ✅ **Script de build automatizado** (`scripts/build.sh`)
- ✅ **Documentación completa** (README.md, CHANGELOG.md)
- ✅ **.dockerignore** optimizado

#### Dependencies - l10n_cl_dte (6/6)
- lxml>=4.9.0 (Procesamiento XML)
- requests>=2.28.0 (HTTP)
- pyOpenSSL>=21.0.0 (Firma digital)
- cryptography>=3.4.8 (Criptografía)
- zeep>=4.2.0 (SOAP SII)
- pika>=1.3.0 (RabbitMQ)

#### Dependencies - l10n_cl_financial_reports (6/6)
- xlsxwriter>=3.0.0 (Excel)
- python-dateutil>=2.8.2 (Fechas)
- numpy>=1.24.0 (ML)
- scikit-learn>=1.2.0 (ML)
- joblib>=1.2.0 (ML)
- PyJWT>=2.6.0 (API)

#### Dependencies - l10n_cl_hr_payroll (1/1)
- requests>=2.28.0 (compartida)

#### Dependencies - Compartidas (12)
- xmlsec, defusedxml, asn1crypto (Seguridad XML)
- urllib3, qrcode, pillow (Utilidades)
- phonenumbers, email-validator (Validación)
- reportlab, weasyprint (PDFs)
- pytz, pycryptodome, bcrypt, structlog (Utilidades)

#### System Dependencies (12 paquetes apt)
- **Firma digital:** libssl-dev, libffi-dev, libxmlsec1-dev, libxmlsec1-openssl
- **Imágenes:** libjpeg-dev, zlib1g-dev
- **Reportes:** ghostscript, libgeos-dev, libgeoip-dev
- **XML:** libxslt1-dev, libxml2-dev
- **Códigos de barras:** libzbar0, libzbar-dev
- **Compilación:** build-essential

#### Fixed
- ✅ **Permisos correctos** en `/var/lib/odoo/sessions`
- ✅ **PyPDF2 conflict** resuelto (ya incluido en base Odoo)
- ✅ **Duplicación de código** eliminada (consolidación de 2 Dockerfiles en 1)

#### Changed
- 🔄 **Migración** de `docker/Dockerfile` + `odoo-docker-base/19.0/Dockerfile` → `odoo-docker/Dockerfile`
- 🔄 **Consolidación** de requirements en `localization/chile/requirements.txt`
- 🔄 **Optimización** de layers con multi-stage build
- 🔄 **Separación clara** entre base oficial y customización Chile

#### Removed
- ❌ Dockerfile antiguo `docker/Dockerfile`
- ❌ Dockerfile base antiguo `odoo-docker-base/19.0/Dockerfile`
- ❌ Duplicación de dependencias

---

## Estructura de Versiones

```
MAJOR.MINOR.PATCH.FEATURE.HOTFIX

19.0.1.0.0
│  │ │ │ └─ Hotfix (0)
│  │ │ └─── Feature (0)
│  │ └───── Minor Odoo (1)
│  └─────── Major Odoo (0)
└────────── Odoo Version (19)
```

### Incremento de Versiones

- **MAJOR (19)**: Cambio de versión mayor de Odoo (19 → 20)
- **MINOR (0)**: Cambio de versión menor de Odoo (19.0 → 19.1)
- **PATCH (1)**: Actualización de release de Odoo o cambios importantes
- **FEATURE (0)**: Nuevas features en customización Chile
- **HOTFIX (0)**: Fixes urgentes sin cambios de features

---

## Imágenes Generadas

### Producción
```
eergygroup/odoo19:chile              (latest chile)
eergygroup/odoo19:chile-19.0.1.0.0   (versión específica)
eergygroup/odoo19:latest             (apunta a chile)
```

### Base
```
eergygroup/odoo19:base               (latest base)
eergygroup/odoo19:base-19.0.1.0.0    (versión específica)
```

### Development
```
eergygroup/odoo19:chile-dev          (latest dev)
eergygroup/odoo19:chile-19.0.1.0.0-dev (versión específica)
```

---

## Build Information

### Build Time
- **Primera vez:** ~15-20 minutos
- **Con cache:** ~5-10 minutos

### Image Sizes
- **base:** 2.16GB
- **chile:** 3.09GB (+930MB de deps Chile)
- **chile-dev:** 3.11GB (+20MB de dev tools)

---

## Testing

### Dependencias Verificadas ✅
```bash
✓ lxml: 5.2.1
✓ zeep: 4.2.1
✓ pika: 1.3.2
✓ xlsxwriter: 3.1.9
✓ numpy: 2.3.4
✓ scikit-learn: 1.7.2
✓ PyJWT: 2.10.1
✓ cryptography: 41.0.7
```

### Stack Operativo ✅
```
odoo19_app    eergygroup/odoo19:chile-1.0.0   Up (healthy)
odoo19_db     postgres:15-alpine              Up (healthy)
odoo19_redis  redis:7-alpine                  Up (healthy)
```

---

## Migration Notes

### De v1 (antigua) a 19.0.1.0.0

**Cambios importantes:**
1. Nueva estructura multi-stage
2. Scripts oficiales Odoo sin modificaciones
3. Versionado semántico implementado
4. Todas las dependencias consolidadas
5. Permisos correctos configurados

**Pasos de migración:**
1. Detener stack: `docker-compose down`
2. Eliminar imagen antigua: `docker rmi eergygroup/odoo19:v1`
3. Build nueva imagen: `cd odoo-docker && ./scripts/build.sh`
4. Actualizar docker-compose.yml: `image: eergygroup/odoo19:chile-1.0.0`
5. Levantar stack: `docker-compose up -d`

---

## Contributors

- **Cascade AI** - Reorganización y profesionalización Docker
- **EERGYGROUP** - Localización Chile y módulos

---

## Links

- [README.md](./README.md) - Documentación de uso
- [Dockerfile](./Dockerfile) - Dockerfile multi-stage
- [Build Script](./scripts/build.sh) - Script de build automatizado

---

**Fecha de creación:** 2025-10-24  
**Última actualización:** 2025-10-24
