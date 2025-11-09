# Odoo 19 CE + Chile Localization - Docker

**Version:** 19.0.1.0.0  
**Maintainer:** EERGYGROUP <info@eergygroup.com>  
**Based on:** [Official Odoo Docker](https://github.com/odoo/docker)

---

## 📋 Descripción

Imagen Docker multi-stage profesional de Odoo 19 Community Edition con localización completa para Chile, incluyendo:

- ✅ **DTE** (Documentos Tributarios Electrónicos)
- ✅ **Reportes Financieros** avanzados con ML
- ✅ **Nómina y Previred**
- ✅ **Todas las dependencias** Python y sistema necesarias

---

## 🏗️ Arquitectura Multi-Stage

### **Stage 1: base**
Imagen base oficial de Odoo 19 CE sin modificaciones.

- Basada en Ubuntu Noble
- Odoo 19.0.20251021
- Scripts oficiales (entrypoint.sh, wait-for-psql.py)
- Configuración base

### **Stage 2: chile**
Imagen con localización Chile completa.

- Base Odoo + dependencias sistema Chile
- Dependencias Python para DTE/SII
- Dependencias Python para reportes financieros
- Dependencias Python para nómina
- Configuración optimizada para Chile

### **Stage 3: development**
Imagen con herramientas de desarrollo.

- Chile + herramientas testing (pytest, pytest-cov)
- Linting y formateo (black, flake8, pylint)
- Debugging (ipython, ipdb)

---

## 🚀 Build

### Build todas las imágenes

```bash
cd odoo-docker
./scripts/build.sh
```

### Build manual

```bash
# Base
docker build --target base -t eergygroup/odoo19:base .

# Chile
docker build --target chile -t eergygroup/odoo19:chile .

# Development
docker build --target development -t eergygroup/odoo19:chile-dev .
```

---

## 📦 Imágenes Disponibles

```
eergygroup/odoo19:base              # Base Odoo oficial
eergygroup/odoo19:base-19.0.1.0.0   # Base versionada
eergygroup/odoo19:chile             # Chile localization
eergygroup/odoo19:chile-19.0.1.0.0  # Chile versionada
eergygroup/odoo19:latest            # -> chile
eergygroup/odoo19:chile-dev         # Development
```

---

## 🔧 Uso

### Con docker-compose

```yaml
services:
  odoo:
    image: eergygroup/odoo19:chile-19.0.1.0.0
    # o para desarrollo:
    # image: eergygroup/odoo19:chile-dev
```

### Standalone

```bash
docker run -d \
  --name odoo \
  -p 8069:8069 \
  -e HOST=db \
  -e USER=odoo \
  -e PASSWORD=odoo \
  eergygroup/odoo19:chile
```

---

## 📁 Estructura

```
odoo-docker/
├── Dockerfile                  # Multi-stage Dockerfile
├── .dockerignore
├── README.md                   # Este archivo
│
├── base/                       # Stage 1: Base Odoo oficial
│   ├── entrypoint.sh
│   ├── wait-for-psql.py
│   └── odoo.conf
│
├── localization/               # Stage 2: Customizaciones
│   └── chile/
│       ├── requirements.txt    # Python deps Chile
│       └── config/
│           └── odoo.conf       # Config Chile
│
└── scripts/                    # Scripts de build
    └── build.sh
```

---

## 🔍 Dependencias

### Sistema (apt)

**Base Odoo:**
- ca-certificates, curl, fonts-noto-cjk
- python3-pip, python3-setuptools
- postgresql-client
- wkhtmltopdf
- node-less, rtlcss

**Chile:**
- libssl-dev, libffi-dev, libxmlsec1-dev (firma digital)
- libjpeg-dev, zlib1g-dev (imágenes)
- ghostscript, libgeos-dev (reportes)
- build-essential (compilación)

### Python

**l10n_cl_dte:**
- lxml, requests, pyOpenSSL, cryptography
- zeep (SOAP SII)
- pika (RabbitMQ)
- qrcode, pillow

**l10n_cl_financial_reports:**
- xlsxwriter (Excel)
- numpy, scikit-learn (ML)
- PyJWT (API)

**l10n_cl_hr_payroll:**
- requests (microservicios)

Ver `localization/chile/requirements.txt` para lista completa.

---

## 🎯 Versionado

Seguimos **Semantic Versioning**:

```
MAJOR.MINOR.PATCH

19.0.1.0.0
│  │ │ │ └─ Hotfix (0)
│  │ │ └─── Feature (0)
│  │ └───── Minor Odoo (1)
│  └─────── Major Odoo (0)
└────────── Odoo Version (19)
```

---

## 🧪 Testing

```bash
# Verificar imagen
docker run --rm eergygroup/odoo19:chile odoo --version

# Verificar dependencias
docker run --rm eergygroup/odoo19:chile python3 -c "import lxml; print('lxml OK')"
docker run --rm eergygroup/odoo19:chile python3 -c "import zeep; print('zeep OK')"
```

---

## 📚 Documentación Adicional

- [Análisis Estructura Docker](../docs/ANALISIS_ESTRUCTURA_DOCKER.md)
- [Propuesta Reorganización](../docs/PROPUESTA_REORGANIZACION_DOCKER.md)
- [Dockerfile Dependencias](../docs/DOCKERFILE_DEPENDENCIAS_ACTUALIZADAS.md)

---

## 🔄 Actualización

Para actualizar la versión de Odoo:

1. Editar `Dockerfile`:
   ```dockerfile
   ARG ODOO_RELEASE=20251021  # Nueva release
   ARG ODOO_SHA=...           # Nuevo SHA
   ```

2. Rebuild:
   ```bash
   ./scripts/build.sh
   ```

---

## 🐛 Troubleshooting

### Error: "ModuleNotFoundError"

Verificar que la dependencia esté en `localization/chile/requirements.txt`.

### Error: Build falla en stage chile

Verificar que las dependencias del sistema estén instaladas correctamente.

### Imagen muy grande

Usar multi-stage build y .dockerignore para excluir archivos innecesarios.

---

## 📞 Soporte

- **Email:** info@eergygroup.com
- **Website:** https://www.eergygroup.com

---

## 📄 Licencia

LGPL-3 (GNU Lesser General Public License v3.0)  
Compatible con Odoo Community Edition

---

**Desarrollado por EERGYGROUP**  
**Fecha:** 2025-10-24
