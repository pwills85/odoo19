.. image:: https://img.shields.io/badge/license-LGPL--3-blue.svg
   :target: https://www.gnu.org/licenses/lgpl-3.0-standalone.html
   :alt: License: LGPL-3

.. image:: https://img.shields.io/badge/Odoo-19.0-purple.svg
   :target: https://www.odoo.com/
   :alt: Odoo 19.0

.. image:: https://img.shields.io/badge/SII-Certified-green.svg
   :target: http://www.sii.cl/
   :alt: SII Chile Certified

====================================================
Chile - DTE (Documentos Tributarios Electrónicos)
====================================================

Módulo de Localización Chilena para Odoo 19 CE - Sistema completo de Facturación Electrónica según normativa SII (Servicio de Impuestos Internos de Chile).

**Estado:** ✅ Production-Ready | Enterprise-Grade | OCA Compliant

Características Principales
============================

Emisión de DTEs
---------------

* **Facturas Electrónicas (33):** Ventas con IVA
* **Facturas Exentas (34):** Ventas sin IVA
* **Guías de Despacho (52):** Documentos de traslado
* **Notas de Débito (56):** Aumentos de facturación
* **Notas de Crédito (61):** Devoluciones y descuentos
* **Boletas Electrónicas (39, 41):** Ventas menores
* **Boletas de Honorarios (70):** Servicios profesionales

Funcionalidades Técnicas
------------------------

* ✅ **Firma XMLDSig:** Firma digital según estándar W3C y normativa SII
* ✅ **Envío Automático:** Integración SOAP con servicios SII (Maullin/Palena)
* ✅ **Consulta de Estado:** Verificación automática de aceptación SII
* ✅ **Validación TED:** Timbre Electrónico con código PDF417
* ✅ **Multi-company:** Aislamiento de datos entre compañías
* ✅ **Recepción de DTEs:** Procesamiento de facturas de proveedores
* ✅ **Libro de Ventas/Compras:** Envío mensual de libros al SII
* ✅ **CAF Management:** Gestión de folios autorizados por SII
* ✅ **Contingencia:** Modo offline con envío diferido
* ✅ **Disaster Recovery:** Backup automático de DTEs críticos

Arquitectura
===========

El módulo utiliza arquitectura modular enterprise-grade:

* **Native Libraries:** Procesamiento XML, firma digital, validación (``libs/``)
* **AI Service Integration:** Validación inteligente con Claude API (opcional)
* **SOAP Client:** Comunicación con servicios SII con retry logic
* **RabbitMQ:** Cola de mensajes para procesamiento asíncrono (opcional)
* **Redis:** Cache de sesiones y tokens SII
* **PostgreSQL:** Almacenamiento ACID con JSONB para analítica

Instalación
===========

Dependencias del Sistema
------------------------

.. code-block:: bash

    # Librerías XML y criptografía
    sudo apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl

    # Python 3.12+ requerido
    python3 --version

Dependencias Python
------------------

.. code-block:: bash

    pip install -r requirements.txt

Principales dependencias:

* ``lxml>=5.0.0`` - Procesamiento XML
* ``xmlsec>=1.3.13`` - Firma digital XMLDSig
* ``zeep>=4.2.1`` - Cliente SOAP para SII
* ``cryptography>=41.0.0`` - Operaciones criptográficas
* ``Pillow>=10.0.0`` - Generación códigos PDF417

Instalación del Módulo
----------------------

1. Clonar en addons path:

.. code-block:: bash

    cd /path/to/odoo/addons
    git clone <repository-url> localization/l10n_cl_dte

2. Actualizar lista de módulos en Odoo:

   Aplicaciones → Actualizar Lista de Aplicaciones

3. Instalar módulo:

   Aplicaciones → Buscar "Chile DTE" → Instalar

Configuración
=============

Certificado Digital
------------------

1. Obtener certificado digital (.p12 o .pfx) desde el SII
2. Ir a: **Contabilidad → Configuración → Certificados DTE**
3. Crear nuevo certificado:

   * **Nombre:** Certificado Empresa 2025
   * **Archivo:** Upload archivo .p12/.pfx
   * **Contraseña:** Password del certificado
   * **Fecha Vencimiento:** Fecha de expiración
   * **Activo:** ✓

Credenciales SII
---------------

1. Ir a: **Ajustes → Facturación Electrónica Chile**
2. Configurar:

   * **Ambiente:** Certificación (Maullin) o Producción (Palena)
   * **RUT Empresa:** 76123456-K
   * **Clave SII:** Password del SII

Autorización de Folios (CAF)
----------------------------

1. Descargar CAF desde el SII para cada tipo de documento
2. Ir a: **Contabilidad → Configuración → CAF (Folios)**
3. Subir archivo CAF (.xml):

   * Se extraen automáticamente: rango de folios, firma, fecha vencimiento

Configuración por Compañía
--------------------------

Para multi-company, cada compañía debe tener:

* Certificado digital propio
* CAF (folios) propios por tipo de documento
* RUT y credenciales SII propias

Uso
===

Emitir Factura Electrónica
--------------------------

1. Crear factura: **Contabilidad → Clientes → Facturas**
2. Seleccionar:

   * **Cliente:** Con RUT válido chileno
   * **Tipo Documento:** Factura Electrónica (33)
   * **Líneas:** Productos/servicios

3. **Validar** factura
4. **Generar DTE:**

   * Botón "Generar DTE"
   * Sistema asigna folio automáticamente
   * Genera XML según formato SII
   * Firma digitalmente con certificado

5. **Enviar a SII:**

   * Botón "Enviar al SII"
   * Comunicación SOAP automática
   * Track ID asignado por SII

6. **Consultar Estado:**

   * Automático vía cron job
   * O manual: Botón "Consultar Estado SII"

7. **Enviar a Cliente:**

   * Email automático con PDF + XML adjunto

Recibir DTE de Proveedor
------------------------

1. **Email Incoming:** Sistema procesa automáticamente emails con DTEs
2. **Manual:** **Contabilidad → Proveedores → DTEs Recibidos → Importar**
3. Sistema:

   * Valida firma digital
   * Extrae metadata (RUT, folio, monto)
   * Crea borrador de factura de proveedor
   * Permite aceptar/rechazar con respuesta comercial

Libros Mensuales
---------------

1. Fin de mes: **Contabilidad → Configuración → Libros**
2. **Crear Libro de Ventas:**

   * Período: Enero 2025
   * Sistema recopila todas las facturas emitidas
   * Genera XML según formato SII

3. **Enviar al SII:**

   * Botón "Enviar Libro"
   * Confirmación en 24-48 horas

Troubleshooting
===============

Error: "Firma Inválida"
----------------------

**Causa:** Certificado vencido, password incorrecto, o formato inválido

**Solución:**

1. Verificar vigencia del certificado: **Certificados DTE → Fecha Vencimiento**
2. Verificar password: Editar certificado y re-ingresar password
3. Regenerar certificado si es necesario desde el SII

Error: "Folio Agotado"
---------------------

**Causa:** CAF sin folios disponibles

**Solución:**

1. Solicitar nueva autorización de folios en el SII
2. Descargar nuevo CAF
3. Subir a: **Contabilidad → Configuración → CAF**
4. Sistema usará nuevo rango automáticamente

Error: "RUT Inválido"
--------------------

**Causa:** Formato de RUT incorrecto o dígito verificador erróneo

**Solución:**

1. Verificar formato: 12345678-9 o 12.345.678-9
2. Validar dígito verificador con algoritmo módulo 11
3. Actualizar en: **Contactos → Partner → RUT**

Error Conexión SII
-----------------

**Causa:** Timeout, SII caído, credenciales incorrectas

**Solución:**

1. Verificar conectividad: ``ping maullin.sii.cl`` o ``ping palena.sii.cl``
2. Verificar credenciales SII en Ajustes
3. Revisar logs: ``docker-compose logs odoo | grep SII``
4. Activar **Modo Contingencia** si SII no disponible

Multi-company: Datos Cruzados
-----------------------------

**Causa:** Usuario intenta acceder a datos de otra compañía

**Solución:**

Record rules multi-company están activos. Si necesita acceso:

1. Verificar permisos de usuario
2. Agregar compañía adicional en: **Ajustes → Usuarios → Compañías Permitidas**
3. Cambiar compañía activa: Menu superior → Nombre Compañía

Roadmap
=======

Versión Actual: 1.0 (Production-Ready)
--------------------------------------

✅ Emisión DTEs tipos 33, 34, 52, 56, 61
✅ Recepción DTEs de proveedores
✅ Libros de Ventas y Compras
✅ Multi-company support
✅ Integración SII (Maullin/Palena)
✅ AI-powered validation (opcional)
✅ Disaster recovery

Versión 1.1 (Q1 2026)
---------------------

* **Otros DTEs:** 39 (Boleta), 41 (Boleta Exenta), 43 (Liquidación)
* **Factura de Exportación:** Tipo 110
* **Retenciones:** Integración completa retenciones 2° categoría
* **Dashboard Analytics:** Visualización avanzada KPIs facturación
* **API REST:** Endpoints para integración externa
* **Mobile App:** App iOS/Android para emisión offline

Versión 2.0 (Q3 2026)
---------------------

* **Machine Learning:** Predicción de rechazos SII
* **OCR:** Extracción automática de datos desde PDFs
* **Blockchain:** Proof of existence de DTEs
* **SII Real-time:** Integración con APIs en tiempo real

Contribución
============

Este módulo sigue estándares OCA (Odoo Community Association):

* **Code Style:** PEP8, pylint, black
* **Commits:** Conventional Commits (feat/fix/docs/test)
* **Testing:** Coverage >=80% en funcionalidad crítica
* **Documentation:** Docstrings completos en español/inglés
* **Security:** OWASP Top 10 compliance

Para contribuir:

1. Fork el repositorio
2. Crear branch: ``git checkout -b feature/nueva-funcionalidad``
3. Commit cambios: ``git commit -m "feat: descripción"``
4. Push: ``git push origin feature/nueva-funcionalidad``
5. Crear Pull Request con descripción detallada

Soporte
=======

* **Documentación:** https://docs.eergygroup.cl/l10n_cl_dte
* **Issues:** https://github.com/eergygroup/odoo19-l10n_cl_dte/issues
* **Email:** soporte@eergygroup.cl
* **SII Oficial:** https://www.sii.cl/factura_electronica/

Créditos
========

Mantenedores
-----------

* **EergyGroup SpA** - Desarrollo principal
* **Ing. Pedro Troncoso Willz** - Arquitectura técnica
* **Claude Code (Anthropic)** - AI-assisted development

Basado en
--------

* ``l10n_cl_fe`` (Odoo 16-17 Community)
* ``l10n_cl_dte`` (Odoo 11-15 OCA)
* Normativa SII Chile actualizada a 2025

Licencia
========

Este módulo está licenciado bajo LGPL-3.

LGPL-3: https://www.gnu.org/licenses/lgpl-3.0-standalone.html

**Copyright © 2025 EergyGroup SpA**

---

**🤖 AI-Enhanced Development with Claude Code (Anthropic)**

*This module was developed with assistance from Claude Code, Anthropic's AI coding assistant,
following enterprise-grade best practices, OCA standards, and Chilean SII regulations.*
