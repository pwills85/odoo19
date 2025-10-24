FROM ubuntu:noble

MAINTAINER Eergygroup <info@eergygroup.com>

LABEL version="19.0"
LABEL description="Odoo 19 Community Edition with Chile localization support"
LABEL image="eergygroup/odoo19:v1"

SHELL ["/bin/bash", "-xo", "pipefail", "-c"]

# Generate locale C.UTF-8 for postgres and general locale data
ENV LANG en_US.UTF-8

# Retrieve the target architecture to install the correct wkhtmltopdf package
ARG TARGETARCH

# ====================================
# Instalación de dependencias base
# ====================================

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

# ====================================
# Instalar PostgreSQL client
# ====================================

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

# ====================================
# Instalar rtlcss (para idiomas RTL)
# ====================================

RUN npm install -g rtlcss

# ====================================
# PERSONALIZACIÓN PARA CHILE - FASE 1
# ====================================
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

# ====================================
# PERSONALIZACIÓN PARA CHILE - FASE 2
# ====================================
# Librerías críticas para facturación electrónica (DTE/SII)
# Firma digital, XML, certificados, comunicación SOAP

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # Firma digital y criptografía (CRÍTICO)
        libssl-dev \
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

# ====================================
# Instalar Odoo 19 CE
# ====================================

ENV ODOO_VERSION 19.0
ARG ODOO_RELEASE=20251021
ARG ODOO_SHA=eeba5130e7d34caa1c8459df926f1a207c314857

RUN curl -o odoo.deb -sSL http://nightly.odoo.com/${ODOO_VERSION}/nightly/deb/odoo_${ODOO_VERSION}.${ODOO_RELEASE}_all.deb \
    && echo "${ODOO_SHA} odoo.deb" | sha1sum -c - \
    && apt-get update \
    && apt-get -y install --no-install-recommends ./odoo.deb \
    && rm -rf /var/lib/apt/lists/* odoo.deb

# ====================================
# Instalar dependencias Python
# ====================================
# Librerías necesarias para módulo l10n_cl_dte sin duplicar Odoo base

RUN pip install --no-cache-dir --break-system-packages \
    # Firma Digital y Certificados PKI (CRÍTICO)
    pyOpenSSL>=21.0.0 \
    cryptography>=3.4.8 \
    asn1crypto>=1.5.1 \
    \
    # Procesamiento XML (CRÍTICO)
    lxml>=4.9.0 \
    xmlsec>=1.1.25 \
    defusedxml>=0.0.1 \
    \
    # SOAP y Comunicación HTTP (CRÍTICO)
    zeep>=4.2.0 \
    requests>=2.28.0 \
    urllib3>=1.26.0 \
    \
    # RabbitMQ Client (CRÍTICO - Para integración con dte-service)
    pika>=1.3.0 \
    \
    # Códigos QR (CRÍTICO)
    qrcode[pil]>=7.3.0 \
    pillow>=9.0.0 \
    \
    # Validación de Datos (RECOMENDADO)
    phonenumbers>=8.12.0 \
    email-validator>=1.1.5 \
    \
    # Generación de PDFs (RECOMENDADO)
    reportlab>=3.6.0 \
    PyPDF2>=3.0.0 \
    weasyprint>=54.0 \
    \
    # Fecha/Hora (RECOMENDADO)
    python-dateutil>=2.8.2 \
    pytz>=2022.1 \
    \
    # Encriptación (RECOMENDADO)
    pycryptodome>=3.15.0 \
    bcrypt>=4.0.0 \
    \
    # Logging (RECOMENDADO)
    structlog>=22.1.0 \
    \
    # Testing (RECOMENDADO)
    pytest>=7.0.0 \
    pytest-mock>=3.10.0 \
    responses>=0.20.0

# ====================================
# CONFIGURACIÓN Y SCRIPTS
# ====================================

# Copiar scripts desde rama oficial
COPY ./odoo-docker-base/19.0/entrypoint.sh /
COPY ./odoo-docker-base/19.0/wait-for-psql.py /usr/local/bin/wait-for-psql.py

# Copiar configuración personalizada para Chile
COPY ./config/odoo.conf /etc/odoo/odoo.conf

# Set permissions and Mount /var/lib/odoo to allow restoring filestore 
# and /mnt/extra-addons for users addons
RUN chown odoo /etc/odoo/odoo.conf \
    && chmod +x /entrypoint.sh \
    && chmod +x /usr/local/bin/wait-for-psql.py \
    && mkdir -p /mnt/extra-addons \
    && chown -R odoo /mnt/extra-addons

VOLUME ["/var/lib/odoo", "/mnt/extra-addons"]

# ====================================
# PUERTOS Y CONFIGURACIÓN FINAL
# ====================================

# Expose Odoo services
EXPOSE 8069 8071 8072

# Set the default config file
ENV ODOO_RC /etc/odoo/odoo.conf

# Set default user when running the container
USER odoo

# Entrypoint que maneja la conexión BD y arranque
ENTRYPOINT ["/entrypoint.sh"]
CMD ["odoo"]
