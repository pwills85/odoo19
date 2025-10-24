# 🏗️ Propuesta de Reorganización Docker - Implementación

**Fecha:** 2025-10-24  
**Tiempo estimado:** 4-5 horas  
**Impacto:** ⚠️ Medio  
**Beneficio:** ✅ Alto

---

## 📋 Resumen Ejecutivo

Reorganizar la estructura Docker actual (2 Dockerfiles duplicados) en una arquitectura **multi-stage profesional** con versionado semántico, separación clara de responsabilidades y fácil mantenimiento.

---

## 🎯 Objetivos

1. ✅ Eliminar duplicación de código
2. ✅ Separar base oficial Odoo vs customización Chile
3. ✅ Implementar versionado semántico
4. ✅ Optimizar build time con multi-stage
5. ✅ Documentar arquitectura completa

---

## 🏗️ Nueva Estructura Propuesta

```
odoo19/
├── odoo-docker/                    # ⭐ NUEVA CARPETA CONSOLIDADA
│   ├── Dockerfile                  # Multi-stage: base + chile + dev
│   ├── .dockerignore
│   ├── README.md                   # Documentación completa
│   │
│   ├── base/                       # Stage 1: Base Odoo oficial
│   │   ├── entrypoint.sh
│   │   ├── wait-for-psql.py
│   │   └── odoo.conf
│   │
│   ├── localization/               # Stage 2: Customizaciones
│   │   └── chile/
│   │       ├── requirements.txt    # Python deps Chile
│   │       ├── config/
│   │       │   └── odoo.conf       # Config Chile
│   │       └── README.md
│   │
│   └── scripts/                    # Scripts de build
│       ├── build.sh
│       ├── push.sh
│       └── test.sh
│
├── docker/                         # ⚠️ DEPRECAR (mantener backup)
│   └── Dockerfile.backup
│
├── odoo-docker-base/               # ⚠️ DEPRECAR (mantener backup)
│   └── 19.0/
│       └── ...
│
├── docker-compose.yml              # ✅ ACTUALIZAR
├── requirements-localization.txt   # ⚠️ MOVER a odoo-docker/localization/chile/
└── ...
```

---

## 📄 Dockerfile Multi-Stage Consolidado

### **Archivo: `odoo-docker/Dockerfile`**

```dockerfile
# ══════════════════════════════════════════════════════════════════════════════
# Multi-Stage Dockerfile - Odoo 19 CE + Chile Localization
# ══════════════════════════════════════════════════════════════════════════════
# Maintainer: EERGYGROUP <info@eergygroup.com>
# Version: 19.0.1.0.0
# Description: Professional multi-stage build for Odoo 19 with Chile localization
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1: BASE ODOO (Oficial Odoo S.A.)
# ══════════════════════════════════════════════════════════════════════════════
FROM ubuntu:noble AS base

LABEL maintainer="Odoo S.A. <info@odoo.com>"
LABEL org.opencontainers.image.source="https://github.com/odoo/docker"
LABEL stage="base"

SHELL ["/bin/bash", "-xo", "pipefail", "-c"]

ENV LANG=en_US.UTF-8

ARG TARGETARCH

# ────────────────────────────────────────────────────────────────────────────
# Dependencias base Odoo
# ────────────────────────────────────────────────────────────────────────────
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dirmngr \
        fonts-noto-cjk \
        gnupg \
        libssl-dev \
        node-less \
        npm \
        python3-magic \
        python3-num2words \
        python3-odf \
        python3-pdfminer \
        python3-pip \
        python3-phonenumbers \
        python3-pyldap \
        python3-qrcode \
        python3-renderpm \
        python3-setuptools \
        python3-slugify \
        python3-vobject \
        python3-watchdog \
        python3-xlrd \
        python3-xlwt \
        xz-utils && \
    if [ -z "${TARGETARCH}" ]; then \
        TARGETARCH="$(dpkg --print-architecture)"; \
    fi; \
    WKHTMLTOPDF_ARCH=${TARGETARCH} && \
    case ${TARGETARCH} in \
    "amd64") WKHTMLTOPDF_ARCH=amd64 && WKHTMLTOPDF_SHA=967390a759707337b46d1c02452e2bb6b2dc6d59  ;; \
    "arm64")  WKHTMLTOPDF_SHA=90f6e69896d51ef77339d3f3a20f8582bdf496cc  ;; \
    "ppc64le" | "ppc64el") WKHTMLTOPDF_ARCH=ppc64el && WKHTMLTOPDF_SHA=5312d7d34a25b321282929df82e3574319aed25c  ;; \
    esac \
    && curl -o wkhtmltox.deb -sSL https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.jammy_${WKHTMLTOPDF_ARCH}.deb \
    && echo ${WKHTMLTOPDF_SHA} wkhtmltox.deb | sha1sum -c - \
    && apt-get install -y --no-install-recommends ./wkhtmltox.deb \
    && rm -rf /var/lib/apt/lists/* wkhtmltox.deb

# ────────────────────────────────────────────────────────────────────────────
# PostgreSQL client
# ────────────────────────────────────────────────────────────────────────────
RUN echo 'deb http://apt.postgresql.org/pub/repos/apt/ noble-pgdg main' > /etc/apt/sources.list.d/pgdg.list \
    && GNUPGHOME="$(mktemp -d)" \
    && export GNUPGHOME \
    && repokey='B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8' \
    && gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "${repokey}" \
    && gpg --batch --armor --export "${repokey}" > /etc/apt/trusted.gpg.d/pgdg.gpg.asc \
    && gpgconf --kill all \
    && rm -rf "$GNUPGHOME" \
    && apt-get update  \
    && apt-get install --no-install-recommends -y postgresql-client \
    && rm -f /etc/apt/sources.list.d/pgdg.list \
    && rm -rf /var/lib/apt/lists/*

# ────────────────────────────────────────────────────────────────────────────
# rtlcss para idiomas RTL
# ────────────────────────────────────────────────────────────────────────────
RUN npm install -g rtlcss

# ────────────────────────────────────────────────────────────────────────────
# Instalar Odoo 19 CE
# ────────────────────────────────────────────────────────────────────────────
ENV ODOO_VERSION=19.0
ARG ODOO_RELEASE=20251021
ARG ODOO_SHA=eeba5130e7d34caa1c8459df926f1a207c314857

RUN curl -o odoo.deb -sSL http://nightly.odoo.com/${ODOO_VERSION}/nightly/deb/odoo_${ODOO_VERSION}.${ODOO_RELEASE}_all.deb \
    && echo "${ODOO_SHA} odoo.deb" | sha1sum -c - \
    && apt-get update \
    && apt-get -y install --no-install-recommends ./odoo.deb \
    && rm -rf /var/lib/apt/lists/* odoo.deb

# ────────────────────────────────────────────────────────────────────────────
# Scripts y configuración base
# ────────────────────────────────────────────────────────────────────────────
COPY base/entrypoint.sh /
COPY base/wait-for-psql.py /usr/local/bin/wait-for-psql.py
COPY base/odoo.conf /etc/odoo/odoo.conf

RUN chown odoo /etc/odoo/odoo.conf \
    && chmod +x /entrypoint.sh \
    && chmod +x /usr/local/bin/wait-for-psql.py \
    && mkdir -p /mnt/extra-addons \
    && chown -R odoo /mnt/extra-addons

VOLUME ["/var/lib/odoo", "/mnt/extra-addons"]
EXPOSE 8069 8071 8072

ENV ODOO_RC=/etc/odoo/odoo.conf

USER odoo
ENTRYPOINT ["/entrypoint.sh"]
CMD ["odoo"]

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2: CHILE LOCALIZATION
# ══════════════════════════════════════════════════════════════════════════════
FROM base AS chile

LABEL maintainer="EERGYGROUP <info@eergygroup.com>"
LABEL version="19.0.1.0.0"
LABEL description="Odoo 19 CE + Chile Localization (DTE, Financial Reports, Payroll)"
LABEL stage="chile"

USER root

# ────────────────────────────────────────────────────────────────────────────
# Dependencias sistema para Chile
# ────────────────────────────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # DTE/SII: Firma digital y XML
        libffi-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        \
        # Reportes: Imágenes y códigos de barras
        libjpeg-dev \
        zlib1g-dev \
        ghostscript \
        libgeos-dev \
        libgeoip-dev \
        libxslt1-dev \
        libxml2-dev \
        libzbar0 \
        libzbar-dev \
        \
        # Compilación
        build-essential && \
    rm -rf /var/lib/apt/lists/*

# ────────────────────────────────────────────────────────────────────────────
# Dependencias Python para Chile
# ────────────────────────────────────────────────────────────────────────────
COPY localization/chile/requirements.txt /tmp/requirements-chile.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements-chile.txt \
    && rm /tmp/requirements-chile.txt

# ────────────────────────────────────────────────────────────────────────────
# Configuración Chile
# ────────────────────────────────────────────────────────────────────────────
COPY localization/chile/config/odoo.conf /etc/odoo/odoo.conf
RUN chown odoo:odoo /etc/odoo/odoo.conf

USER odoo

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3: DEVELOPMENT (Opcional)
# ══════════════════════════════════════════════════════════════════════════════
FROM chile AS development

LABEL stage="development"

USER root

# ────────────────────────────────────────────────────────────────────────────
# Herramientas desarrollo y testing
# ────────────────────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages \
    # Testing
    pytest>=7.0.0 \
    pytest-cov>=4.0.0 \
    pytest-mock>=3.10.0 \
    responses>=0.20.0 \
    \
    # Linting y formateo
    black>=23.0.0 \
    flake8>=6.0.0 \
    pylint>=2.17.0 \
    mypy>=1.0.0 \
    \
    # Debugging
    ipython>=8.0.0 \
    ipdb>=0.13.0 \
    \
    # Profiling
    py-spy>=0.3.0 \
    memory-profiler>=0.60.0

# Habilitar modo desarrollo
ENV DEV_MODE=True
ENV LOG_LEVEL=debug

USER odoo
```

---

## 📦 Scripts de Build

### **Archivo: `odoo-docker/scripts/build.sh`**

```bash
#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Build Script - Odoo Docker Images
# ══════════════════════════════════════════════════════════════════════════════

set -e

VERSION="19.0.1.0.0"
REGISTRY="eergygroup"
IMAGE_NAME="odoo19"

cd "$(dirname "$0")/.."

echo "🏗️  Building Odoo Docker Images..."
echo ""

# ────────────────────────────────────────────────────────────────────────────
# Build Base
# ────────────────────────────────────────────────────────────────────────────
echo "📦 [1/3] Building base image..."
docker build \
    --target base \
    --tag ${REGISTRY}/${IMAGE_NAME}:base \
    --tag ${REGISTRY}/${IMAGE_NAME}:base-${VERSION} \
    .

echo "✅ Base image built"
echo ""

# ────────────────────────────────────────────────────────────────────────────
# Build Chile
# ────────────────────────────────────────────────────────────────────────────
echo "📦 [2/3] Building chile image..."
docker build \
    --target chile \
    --tag ${REGISTRY}/${IMAGE_NAME}:chile \
    --tag ${REGISTRY}/${IMAGE_NAME}:chile-${VERSION} \
    --tag ${REGISTRY}/${IMAGE_NAME}:latest \
    .

echo "✅ Chile image built"
echo ""

# ────────────────────────────────────────────────────────────────────────────
# Build Development
# ────────────────────────────────────────────────────────────────────────────
echo "📦 [3/3] Building development image..."
docker build \
    --target development \
    --tag ${REGISTRY}/${IMAGE_NAME}:chile-dev \
    --tag ${REGISTRY}/${IMAGE_NAME}:chile-${VERSION}-dev \
    .

echo "✅ Development image built"
echo ""

# ────────────────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────────────────
echo "🎉 Build complete!"
echo ""
echo "Images created:"
echo "  - ${REGISTRY}/${IMAGE_NAME}:base"
echo "  - ${REGISTRY}/${IMAGE_NAME}:base-${VERSION}"
echo "  - ${REGISTRY}/${IMAGE_NAME}:chile"
echo "  - ${REGISTRY}/${IMAGE_NAME}:chile-${VERSION}"
echo "  - ${REGISTRY}/${IMAGE_NAME}:latest"
echo "  - ${REGISTRY}/${IMAGE_NAME}:chile-dev"
echo "  - ${REGISTRY}/${IMAGE_NAME}:chile-${VERSION}-dev"
echo ""
echo "Next steps:"
echo "  1. Test: ./scripts/test.sh"
echo "  2. Push: ./scripts/push.sh"
```

---

## 🔄 Actualización docker-compose.yml

```yaml
services:
  odoo:
    build:
      context: ./odoo-docker
      dockerfile: Dockerfile
      target: chile  # Cambiar a 'development' para dev
      args:
        ODOO_VERSION: "19.0"
        ODOO_RELEASE: "20251021"
    image: eergygroup/odoo19:chile-1.0.0
    container_name: odoo19_app
    # ... resto sin cambios
```

---

## 📋 Plan de Migración

### **Fase 1: Preparación** (30 min)

```bash
# 1. Crear nueva estructura
mkdir -p odoo-docker/{base,localization/chile/config,scripts}

# 2. Mover archivos base oficial
cp odoo-docker-base/19.0/entrypoint.sh odoo-docker/base/
cp odoo-docker-base/19.0/wait-for-psql.py odoo-docker/base/
cp odoo-docker-base/19.0/odoo.conf odoo-docker/base/

# 3. Mover requirements Chile
mv requirements-localization.txt odoo-docker/localization/chile/requirements.txt

# 4. Copiar config Chile
cp config/odoo.conf odoo-docker/localization/chile/config/

# 5. Backup de Dockerfiles antiguos
mv docker/Dockerfile docker/Dockerfile.backup
mv odoo-docker-base odoo-docker-base.backup
```

### **Fase 2: Implementación** (2 horas)

```bash
# 1. Crear Dockerfile multi-stage
# (Copiar contenido propuesto arriba)

# 2. Crear scripts de build
chmod +x odoo-docker/scripts/*.sh

# 3. Crear .dockerignore
# 4. Crear README.md
# 5. Actualizar docker-compose.yml
```

### **Fase 3: Testing** (1 hora)

```bash
# 1. Build de imágenes
cd odoo-docker
./scripts/build.sh

# 2. Test básico
docker run --rm eergygroup/odoo19:chile odoo --version

# 3. Test con docker-compose
docker-compose build
docker-compose up -d
docker-compose exec odoo odoo --version

# 4. Test de instalación módulos
./scripts/test_install_l10n_cl_dte.sh
```

### **Fase 4: Documentación** (1 hora)

```bash
# 1. README.md principal
# 2. README.md por stage
# 3. Guía de versionado
# 4. Troubleshooting
```

---

## ✅ Checklist de Implementación

### Preparación
- [ ] Crear estructura odoo-docker/
- [ ] Mover archivos base oficial
- [ ] Mover requirements Chile
- [ ] Backup Dockerfiles antiguos

### Implementación
- [ ] Crear Dockerfile multi-stage
- [ ] Crear scripts de build
- [ ] Crear .dockerignore
- [ ] Actualizar docker-compose.yml

### Testing
- [ ] Build imagen base
- [ ] Build imagen chile
- [ ] Build imagen development
- [ ] Test instalación módulos
- [ ] Validar dependencias

### Documentación
- [ ] README.md principal
- [ ] Guía de build
- [ ] Guía de versionado
- [ ] Changelog

### Limpieza
- [ ] Deprecar docker/
- [ ] Deprecar odoo-docker-base/
- [ ] Actualizar .gitignore
- [ ] Commit y push

---

## 🎯 Resultado Esperado

**Estructura final:**

```
odoo19/
├── odoo-docker/                    # ✅ Estructura profesional
│   ├── Dockerfile                  # ✅ Multi-stage consolidado
│   ├── base/                       # ✅ Base oficial Odoo
│   ├── localization/chile/         # ✅ Customización Chile
│   └── scripts/                    # ✅ Scripts automatizados
│
├── docker.backup/                  # ⚠️ Backup (eliminar después)
├── odoo-docker-base.backup/        # ⚠️ Backup (eliminar después)
└── docker-compose.yml              # ✅ Actualizado
```

**Imágenes Docker:**

```
eergygroup/odoo19:base              # Base Odoo oficial
eergygroup/odoo19:base-19.0.1.0.0
eergygroup/odoo19:chile             # Chile localization
eergygroup/odoo19:chile-19.0.1.0.0
eergygroup/odoo19:latest            # -> chile
eergygroup/odoo19:chile-dev         # Development
```

---

## 💡 Beneficios

1. ✅ **Mantenibilidad**: Estructura clara y organizada
2. ✅ **Versionado**: Semántico y profesional
3. ✅ **Performance**: Build más rápido con cache
4. ✅ **Flexibilidad**: Fácil agregar nuevas localizaciones
5. ✅ **Documentación**: Completa y actualizada

---

**¿Proceder con la implementación?**

**Tiempo:** 4-5 horas  
**Riesgo:** ⚠️ Medio (requiere rebuild)  
**Beneficio:** ✅ Alto
