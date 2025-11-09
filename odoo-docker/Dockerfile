# ══════════════════════════════════════════════════════════════════════════════
# Multi-Stage Dockerfile - Odoo 19 CE + Chile Localization
# ══════════════════════════════════════════════════════════════════════════════
# Maintainer: EERGYGROUP <info@eergygroup.com>
# Version: 19.0.1.0.4
# Description: Professional multi-stage build for Odoo 19 with Chile localization
# Based on: Official Odoo Docker (https://github.com/odoo/docker)
#
# Changelog:
#   - 2025-11-07 (v1.0.4): Added ML/Data Science libraries for Financial Reports
#     * numpy 1.24.4 (numerical computing for financial ratios)
#     * scikit-learn 1.3.2 (ML models for trend analysis)
#     * joblib 1.3.2 (ML model serialization)
#     * PyJWT 2.8.0 (JWT authentication for APIs)
#   - 2025-10-29 (v1.0.3): Updated PDF libraries for PDF417 barcode support
#     * reportlab 3.6.0 → 4.0.4 (PDF417 barcode for TED)
#     * qrcode 7.3.0 → 7.4.2 (improved QR generation)
#     * pillow 9.0.0 → 10.0.0 (image processing)
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1: BASE ODOO (Oficial Odoo S.A.)
# ══════════════════════════════════════════════════════════════════════════════
FROM ubuntu:noble AS base

LABEL maintainer="Odoo S.A. <info@odoo.com>"
LABEL org.opencontainers.image.source="https://github.com/odoo/docker"
LABEL stage="base"

SHELL ["/bin/bash", "-xo", "pipefail", "-c"]

# Generate locale C.UTF-8 for postgres and general locale data
ENV LANG=en_US.UTF-8

# Retrieve the target architecture to install the correct wkhtmltopdf package
ARG TARGETARCH

# ────────────────────────────────────────────────────────────────────────────
# Install some deps, lessc and less-plugin-clean-css, and wkhtmltopdf
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
# Install latest postgresql-client
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
# Install rtlcss (on Debian noble)
# ────────────────────────────────────────────────────────────────────────────
RUN npm install -g rtlcss

# ────────────────────────────────────────────────────────────────────────────
# Install Odoo
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
# Copy entrypoint script and Odoo configuration file
# ────────────────────────────────────────────────────────────────────────────
COPY base/entrypoint.sh /
COPY base/wait-for-psql.py /usr/local/bin/wait-for-psql.py
COPY base/odoo.conf /etc/odoo/odoo.conf

# ────────────────────────────────────────────────────────────────────────────
# Set permissions and Mount /var/lib/odoo to allow restoring filestore
# and /mnt/extra-addons for users addons
RUN chown odoo /etc/odoo/odoo.conf \
    && chmod +x /entrypoint.sh \
    && chmod +x /usr/local/bin/wait-for-psql.py \
    && mkdir -p /mnt/extra-addons \
    && chown -R odoo /mnt/extra-addons \
    && mkdir -p /var/lib/odoo/sessions \
    && chown -R odoo:odoo /var/lib/odoo

VOLUME ["/var/lib/odoo", "/mnt/extra-addons"]

# Expose Odoo services
EXPOSE 8069 8071 8072

# Set the default config file
ENV ODOO_RC=/etc/odoo/odoo.conf

# Set default user when running the container
USER odoo

ENTRYPOINT ["/entrypoint.sh"]
CMD ["odoo"]

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2: CHILE LOCALIZATION
# ══════════════════════════════════════════════════════════════════════════════
FROM base AS chile

LABEL maintainer="EERGYGROUP <info@eergygroup.com>"
LABEL version="19.0.1.0.4"
LABEL description="Odoo 19 CE + Chile Localization (DTE, Financial Reports, Payroll) + PDF417 + ML"
LABEL stage="chile"
LABEL changelog="2025-11-07: ML/DS libs (numpy 1.24.4, scikit-learn 1.3.2, joblib 1.3.2, PyJWT 2.8.0)"

USER root

# ────────────────────────────────────────────────────────────────────────────
# PERSONALIZACIÓN PARA CHILE - Dependencias del Sistema
# ────────────────────────────────────────────────────────────────────────────
# Herramientas base para localización y generación de reportes
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ghostscript \
        libgeos-dev \
        libgeoip-dev \
        libxslt1-dev \
        libxml2-dev \
        libzbar0 \
        libzbar-dev && \
    rm -rf /var/lib/apt/lists/*

# Librerías críticas para facturación electrónica (DTE/SII)
# Firma digital, XML, certificados, comunicación SOAP
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # Firma digital y criptografía (CRÍTICO)
        libffi-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        \
        # Imágenes y códigos de barras (CRÍTICO)
        libjpeg-dev \
        zlib1g-dev \
        \
        # Compilación (CRÍTICO)
        build-essential && \
    rm -rf /var/lib/apt/lists/*

# ────────────────────────────────────────────────────────────────────────────
# PERSONALIZACIÓN PARA CHILE - Dependencias Python
# ────────────────────────────────────────────────────────────────────────────
# Instalar dependencias Python para módulos de localización Chile
# Ver: localization/chile/requirements.txt para detalles
COPY localization/chile/requirements.txt /tmp/requirements-chile.txt
RUN pip3 install --no-cache-dir --break-system-packages --ignore-installed -r /tmp/requirements-chile.txt \
    && rm /tmp/requirements-chile.txt

# ────────────────────────────────────────────────────────────────────────────
# PERSONALIZACIÓN PARA CHILE - Configuración
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
    \
    # Debugging
    ipython>=8.0.0 \
    ipdb>=0.13.0

# Habilitar modo desarrollo
ENV DEV_MODE=True
ENV LOG_LEVEL=debug

USER odoo
