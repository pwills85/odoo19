# 📊 MAPEO INTEGRAL: DTE Chile - Herramientas, Funciones y Responsabilidades

**Versión:** 1.0  
**Fecha:** 2025-10-21  
**Propósito:** Tabla única consolidada de la facturación electrónica chilena

---

## 🎯 VISIÓN GENERAL

Este documento consolida **TODO** el análisis de facturación electrónica chilena en una única tabla que muestra:
- ✅ Qué herramientas se necesitan
- ✅ Qué funciones ejecutan
- ✅ Qué responsabilidades tienen
- ✅ Dónde se implementan (Odoo módulo vs DTE Service microservicio)

---

## 📋 TABLA MAESTRA: COMPONENTES DTE CHILE

| # | Herramienta/Función | Tipo | Responsabilidad Principal | Ubicación | Dependencias | Entrada | Proceso Clave | Salida | Tests |
|---|---|---|---|---|---|---|---|---|---|
| **GENERACIÓN XML** |
| 1 | DTEGenerator | Componente | Generar XML según formato SII | DTE Service | lxml, defusedxml | Datos factura (Odoo) | Mapeo datos → XML válido | XML sin firmar | ✅ |
| 2 | XMLValidator | Función | Validar XML contra XSD SII | DTE Service | lxml, xmlschema | XML generado | Comparar vs schema SII | Valid/Invalid | ✅ |
| 3 | TemplateEngine | Función | Renderizar template XML | DTE Service | Jinja2 | Variables factura | Template substitution | XML raw | ✅ |
| **FIRMA DIGITAL (PKI)** |
| 4 | DTESigner | Componente | Firmar XML digitalmente (PKCS#1) | DTE Service | pyOpenSSL, cryptography | XML + Certificado | RSA + SHA256 hash | XML firmado | ✅ |
| 5 | CertificateManager | Componente | Gestionar certificados .pfx | DTE Service | pyOpenSSL, asn1crypto | Archivo .pfx | Parseo, validación, expiración | Cert en memoria | ✅ |
| 6 | CertValidator | Función | Validar certificado vigencia | DTE Service | cryptography | Certificado | Check fecha expiración | Valid/Expired | ✅ |
| 7 | KeyExtractor | Función | Extraer private key de .pfx | DTE Service | pyOpenSSL | Archivo .pfx + password | PKCS#12 parsing | Private key | ✅ |
| **CÓDIGOS & VALIDACIÓN CHILENA** |
| 8 | RUTValidator | Función | Validar RUT chileno (formato + DV) | Odoo + DTE | Algoritmo DV modulo 11 | RUT string | Verificar dígito verificador | Valid/Invalid | ✅ |
| 9 | SIICodeMapper | Función | Mapear códigos SII (DTE types, impuestos) | Odoo | Dict/DB | Tipo transacción | Lookup table | Código SII | ✅ |
| 10 | TaxCodeResolver | Función | Resolver código impuesto SII | Odoo | Tabla impuestos | Impuesto Odoo | Match con SII | Código + % | ✅ |
| 11 | DTETypeSelector | Función | Seleccionar tipo DTE según contexto | Odoo | Lógica negocio | Tipo movimiento | If/switch (venta=33, etc) | DTE type code | ✅ |
| **CÓDIGOS QR** |
| 12 | TimbreXMLGenerator | Función | Generar TimbreXML (URL QR) | DTE Service | qrcode, pillow | Track ID + datos | Concatenar datos | TimbreXML string | ✅ |
| 13 | QRCodeGenerator | Función | Generar código QR imagen | DTE Service | qrcode, PIL | TimbreXML | QR encoding | PNG/SVG | ✅ |
| **COMUNICACIÓN SOAP (SII)** |
| 14 | DTESender | Componente | Enviar DTE a SII via SOAP | DTE Service | zeep, requests | XML firmado | SOAP request (GetStatus) | Track ID | ✅ |
| 15 | SOAPClient | Función | Cliente SOAP genérico | DTE Service | zeep | WSDL URL, payload | SOAP protocol | Response XML | ✅ |
| 16 | ErrorHandler | Función | Procesar errores SOAP de SII | DTE Service | zeep, logging | Response SOAP | Parse error codes | Error details | ✅ |
| 17 | RetryPolicy | Función | Reintentar SOAP en timeout | DTE Service | exponential backoff | SOAP error | Wait + retry (max 3x) | Success/Fail | ✅ |
| **DESCARGA DE COMPRAS (DTEs recibidos)** |
| 18 | DTEReceiver | Componente | Descargar DTEs recibidos de SII | DTE Service | zeep | RUT empresa, rango fecha | SOAP GetContribDetalle | XML firmado compras | ✅ |
| 19 | DTEParser | Función | Parsear XML de DTE recibido | DTE Service | lxml, defusedxml | XML compra recibida | Parse y extraer campos | Dict datos | ✅ |
| 20 | CompraReconciliation | Función | Reconciliar compra con BOM | Odoo | SQL, Odoo ORM | XML compra + linea Odoo | Match RUT + monto | Link/Error | ✅ |
| **VALIDACIÓN INTEGRAL** |
| 21 | DataValidator | Componente | Validar datos negocio antes envío | Odoo | Lógica custom | Factura Odoo | Check campos obligatorios | Valid/Invalid | ✅ |
| 22 | AmountValidator | Función | Validar coherencia de montos | Odoo | Math | Líneas + totales | Σ líneas = total | OK/Error | ✅ |
| 23 | TaxValidator | Función | Validar cálculo impuestos | Odoo | account.tax | Impuestos | Recalcular vs Odoo | Match/Mismatch | ✅ |
| 24 | PartnerValidator | Función | Validar cliente/proveedor | Odoo | partner exists | RUT cliente | Lookup en res.partner | Exists/Not | ✅ |
| 25 | DTESequenceValidator | Función | Validar no hay gap en folios | Odoo | Sequence model | Folio nuevo | Compare con anterior | No gap/Gap! | ✅ |
| **PDF & REPRESENTACIÓN** |
| 26 | DTEPDFGenerator | Componente | Generar PDF representación factura | Odoo | reportlab, weasyprint | Datos + QR | HTML → PDF | PDF bytes | ✅ |
| 27 | HTMLTemplate | Función | Template HTML factura | Odoo | Jinja2 | Datos factura | Render template | HTML | ✅ |
| 28 | QRImageEmbedder | Función | Incrustar QR en PDF | Odoo | PIL, reportlab | QR PNG + PDF | Insert image | PDF con QR | ✅ |
| **PERSISTENCIA & AUDITORÍA** |
| 29 | DTEAuditLog | Modelo | Log cada operación DTE | Odoo | models.Model | Evento DTE | Insert registro | Audit trail | ✅ |
| 30 | CertificateStorage | Modelo | Almacenar certs encriptados | Odoo | Binary(encrypted=True) | Archivo .pfx | Encrypt + store BD | Acceso controlado | ✅ |
| 31 | DTEDocument | Modelo | Registro DTE procesado | Odoo | models.Model | XML enviado | Guardar metadatos | DTE record | ✅ |
| 32 | CommunicationLog | Modelo | Log comunicaciones SII | Odoo | models.Model | Request/Response SOAP | Insert + timestamp | Communication trail | ✅ |
| **ORQUESTACIÓN & FLUJOS** |
| 33 | DTEOrchestrator | Función | Orquestar flujo completo envío | Odoo/DTE Service | Async tasks | Factura validada | 1)Validar 2)Generar 3)Firmar 4)Enviar | Track ID grabado | ✅ |
| 34 | StateTransition | Función | Gestionar cambios estado factura | Odoo | Workflow | Estado actual | Check transiciones válidas | Estado nuevo | ✅ |
| 35 | NotificationService | Función | Notificar usuario eventos DTE | Odoo | mail.message | Evento importante | Enviar email/SMS | User informed | ✅ |
| **CONFIGURACIÓN & SETUP** |
| 36 | CompanyDTEConfig | Modelo | Config empresa (RUT, certs, etc) | Odoo | models.Model | Parámetros | Almacenar settings | Config global | ✅ |
| 37 | JournalDTEConfig | Modelo | Config diario (folios, SII env) | Odoo | models.Model | Parámetros | Almacenar settings | Config journal | ✅ |
| 38 | TaxDTEMapping | Modelo | Mapping Odoo tax → SII codes | Odoo | models.Model | Impuesto Odoo | Link → código SII | Mapping table | ✅ |
| **INTEGRACIÓN ODOO BASE** |
| 39 | AccountMoveDTE | Extensión | Extender account.move (DTE fields) | Odoo | _inherit | account.move | Agregar campos DTE | Move con DTE | ✅ |
| 40 | AccountJournalDTE | Extensión | Extender journal (folios, config) | Odoo | _inherit | account.journal | Agregar config DTE | Journal config | ✅ |
| 41 | ResPartnerDTE | Extensión | Extender partner (validar RUT) | Odoo | _inherit | res.partner | Validar RUT entrada | Partner validado | ✅ |
| 42 | ResCompanyDTE | Extensión | Extender company (datos tributarios) | Odoo | _inherit | res.company | Almacenar datos SII | Company config | ✅ |
| 43 | AccountTaxDTE | Extensión | Extender tax (SII codes) | Odoo | _inherit | account.tax | Mapping → SII | Tax con código | ✅ |
| **UI/UX & VISTAS** |
| 44 | DTEFacturaView | Vista | Interfaz captura factura DTE | Odoo | form.xml | Campos DTE | Mostrar + edit | DTE fields | ✅ |
| 45 | DTEStatusView | Vista | Dashboard estado DTEs | Odoo | form.xml | Estado procesados | List + filtros | Status overview | ✅ |
| 46 | CertificateUploadWizard | Wizard | Asistente carga certificado | Odoo | Transient model | File upload | Parse + validar | Cert en BD | ✅ |
| 47 | DTEBatchSendWizard | Wizard | Asistente envío masivo | Odoo | Transient model | Select facturas | Batch send | Track IDs | ✅ |
| **REPORTES** |
| 48 | DTEInvoiceReport | Reporte | PDF representación factura | Odoo | QWeb template | Datos move | Render template | PDF + QR | ✅ |
| 49 | DTEStatusReport | Reporte | Reporte estado DTEs | Odoo | Python report | Move IDs | Aggregate status | Excel/PDF | ✅ |
| 50 | SIICommunicationReport | Reporte | Log comunicaciones SII | Odoo | QWeb | Audit logs | Query + render | PDF report | ✅ |
| **MANTENIMIENTO & OPERACIONES** |
| 51 | CertificateExpiry Monitor | Cron | Alerta expiración certificados | Odoo | ir.cron | Certs en BD | Check fecha + notify | Alert user | ✅ |
| 52 | DTEStatusPoller | Cron | Poll Track ID status SII | DTE Service | Async job | DTEs en "sent" | GetStatus SOAP | Update status | ✅ |
| 53 | FolioGapDetector | Cron | Detectar gap en folios | Odoo | ir.cron | Sequence journal | Compare gaps | Alert + log | ✅ |
| 54 | DTECleanup | Cron | Limpieza logs antiguos | Odoo | ir.cron | Audit logs > 90d | Delete old | Cleanup done | ✅ |

---

## 🏗️ TABLA 2: DISTRIBUCIÓN ARQUITECTÓNICA

| Componente | Cantidad | Odoo Módulo | DTE Service | Compartida | Responsable |
|---|---|---|---|---|---|
| **Generación** | 3 | - | DTEGenerator, XMLValidator, TemplateEngine | - | DTE Service |
| **Firma Digital** | 4 | - | DTESigner, CertificateManager, CertValidator, KeyExtractor | - | DTE Service |
| **Validación Chile** | 4 | RUTValidator (dual), SIICodeMapper, TaxCodeResolver, DTETypeSelector | - | RUTValidator | Ambos |
| **Códigos QR** | 2 | - | TimbreXMLGenerator, QRCodeGenerator | - | DTE Service |
| **SOAP/SII** | 4 | - | DTESender, SOAPClient, ErrorHandler, RetryPolicy | - | DTE Service |
| **Descarga Compras** | 3 | - | DTEReceiver, DTEParser | CompraReconciliation | Ambos |
| **Validación Integral** | 5 | DataValidator, AmountValidator, TaxValidator, PartnerValidator, DTESequenceValidator | - | - | Odoo |
| **PDF & UI** | 3 | DTEPDFGenerator, HTMLTemplate, QRImageEmbedder | - | - | Odoo |
| **Persistencia** | 4 | DTEAuditLog, CertificateStorage, DTEDocument, CommunicationLog | - | - | Odoo |
| **Orquestación** | 3 | DTEOrchestrator (partial), StateTransition, NotificationService | DTEOrchestrator (partial) | DTEOrchestrator | Ambos |
| **Configuración** | 3 | CompanyDTEConfig, JournalDTEConfig, TaxDTEMapping | - | - | Odoo |
| **Extensiones Odoo** | 5 | AccountMoveDTE, AccountJournalDTE, ResPartnerDTE, ResCompanyDTE, AccountTaxDTE | - | - | Odoo |
| **Vistas & UI** | 3 | DTEFacturaView, DTEStatusView, CertificateUploadWizard, DTEBatchSendWizard | - | - | Odoo |
| **Reportes** | 3 | DTEInvoiceReport, DTEStatusReport, SIICommunicationReport | - | - | Odoo |
| **Mantenimiento** | 4 | CertificateExpiryMonitor, FolioGapDetector, DTECleanup | DTEStatusPoller | - | Ambos |
| **TOTAL** | 54 | 31 (57%) | 15 (28%) | 8 (15%) | - |

---

## 🔄 TABLA 3: FLUJO COMPLETO - ENVÍO DTE

```
PASO 1: USUARIO CREA FACTURA (Odoo UI)
├─ CompName: Pedro
├─ CustomerName: Empresa ABC
├─ Items: 10x Producto A @ $1,000
└─ UI: DTEFacturaView (form.xml)

PASO 2: VALIDACIONES PRE-ENVÍO (Odoo)
├─ 1. DataValidator: campos obligatorios ✅
├─ 2. RUTValidator: RUT empresa + cliente ✅
├─ 3. PartnerValidator: cliente existe ✅
├─ 4. AmountValidator: líneas = total ✅
├─ 5. TaxValidator: impuestos correctos ✅
├─ 6. DTESequenceValidator: folio sin gap ✅
└─ Estado: draft → ready_to_send

PASO 3: USUARIO ENVÍA (Odoo click "Enviar a SII")
├─ AccountMoveDTE.action_send_to_sii()
├─ Retrieve: Certificado, empresa RUT, cliente RUT
└─ REST POST → DTE Service: http://dte-service:5000/api/dte/generate

PASO 4: GENERACIÓN XML (DTE Service)
├─ DTEGenerator.generate()
│  ├─ Input: Líneas, montos, impuestos, RUT, fecha
│  ├─ SIICodeMapper: tipo factura → DTE code (33=Factura)
│  ├─ TemplateEngine: Render XML template
│  └─ Output: XML raw (sin firmar)
├─ XMLValidator.validate(xml)
│  └─ Compare vs XSD schema SII ✅
└─ XML stored temp

PASO 5: FIRMA DIGITAL (DTE Service)
├─ KeyExtractor.extract(cert_pfx, password)
│  └─ PKCS#12 parsing → private key
├─ DTESigner.sign(xml, private_key)
│  ├─ Hash XML: SHA256
│  ├─ RSA encrypt: 4096-bit
│  └─ Output: XML FIRMADO
├─ CertValidator.check_expiry(cert)
│  └─ Verify no expirado ✅
└─ Signed XML ready

PASO 6: ENVÍO SOAP A SII (DTE Service)
├─ TimbreXMLGenerator.generate(track_id_temp)
│  └─ Create: URL QR string
├─ DTESender.send_to_sii(xml_signed)
│  ├─ SOAP request: http://zeuslb.sii.cl/dte/services/...
│  ├─ SOAPClient.call(wsdl_url, method, payload)
│  ├─ ErrorHandler.process_response()
│  └─ Response: track_id="2024001234567"
├─ RetryPolicy: retry 3x if timeout
└─ DTE Service retorna a Odoo:
   {
     "success": true,
     "track_id": "2024001234567",
     "folio": "1234567",
     "timestamp": "2025-10-21T14:30:00"
   }

PASO 7: ACTUALIZAR FACTURA (Odoo)
├─ AccountMoveDTE.update()
├─ dte_track_id = "2024001234567" ✅
├─ dte_folio = "1234567" ✅
├─ dte_status = "sent" ✅
├─ dte_timestamp = grabado ✅
└─ DTEAuditLog.create(action="send_to_sii", status="success")

PASO 8: POLL STATUS (Cron - DTE Service)
├─ Cada 5 minutos: DTEStatusPoller
├─ Track ID "sent" → GetStatus SOAP
├─ SII respuesta: "Aceptado" | "Rechazado" | "Pendiente"
├─ Actualizar BD: dte_status = "accepted"
└─ Notificar Odoo via webhook/API

PASO 9: NOTIFICAR USUARIO (Odoo)
├─ DTEAuditLog: operación completada
├─ NotificationService: enviar email
├─ DTEStatusView: mostrar ✅ green
└─ Usuario: "DTE enviado exitosamente"

OUTPUT FINAL:
├─ Factura estado: "sent"
├─ Track ID: grabado y visible
├─ PDF con QR: descargable
├─ Log auditoría: completo
└─ SII: DTE aceptado ✅
```

---

## 📦 TABLA 4: DEPENDENCIAS EXTERNAS

| Librería | Tipo | Función | Ubicación | Versión | Crítica |
|---|---|---|---|---|---|
| **lxml** | XML | Generar/parsear XML | DTE Service | >=4.9.0 | ✅ SÍ |
| **xmlsec** | XML Signing | Firmar XML digitalmente | DTE Service | >=1.1.25 | ✅ SÍ |
| **defusedxml** | Security | Prevenir XXE attacks | DTE Service | >=0.0.1 | ✅ SÍ |
| **pyOpenSSL** | PKI | Manejo certificados | DTE Service | >=21.0.0 | ✅ SÍ |
| **cryptography** | Crypto | RSA, hashing | DTE Service | >=3.4.8 | ✅ SÍ |
| **asn1crypto** | ASN.1 | Parseo X.509 | DTE Service | >=1.5.1 | ✅ SÍ |
| **zeep** | SOAP | Cliente SOAP para SII | DTE Service | >=4.2.0 | ✅ SÍ |
| **requests** | HTTP | Cliente HTTP | DTE Service | >=2.28.0 | ✅ SÍ |
| **qrcode** | QR | Generar QR codes | DTE Service | >=7.3.0 | ✅ SÍ |
| **pillow** | Imaging | Procesar imágenes QR | DTE Service | >=9.0.0 | ✅ SÍ |
| **reportlab** | PDF | Generar PDFs | Odoo | >=3.6.0 | ⚠️ RECOM |
| **weasyprint** | PDF | HTML5 → PDF | Odoo | >=54.0 | ⚠️ RECOM |
| **python-dateutil** | DateTime | Parseo fechas | Ambos | >=2.8.2 | ⚠️ RECOM |
| **pytz** | TimeZones | Zonas horarias | Ambos | >=2022.1 | ⚠️ RECOM |
| **pycryptodome** | Crypto | Encriptación datos | Odoo | >=3.15.0 | ⚠️ RECOM |
| **pytest** | Testing | Unit tests | Ambos | >=7.0.0 | ⚠️ RECOM |
| **pytest-mock** | Testing | Mocking | Ambos | >=3.10.0 | ⚠️ RECOM |
| **responses** | Testing | Mock HTTP | Ambos | >=0.20.0 | ⚠️ RECOM |

---

## 🛠️ TABLA 5: HERRAMIENTAS DEL SISTEMA (apt-get)

| Paquete | Función | Ubicación | Instalado | Crítica |
|---|---|---|---|---|
| **libssl-dev** | OpenSSL headers | Docker | ✅ SÍ | ✅ |
| **libxml2-dev** | XML headers | Docker | ✅ SÍ | ✅ |
| **libxslt1-dev** | XSLT headers | Docker | ✅ SÍ | ✅ |
| **libxmlsec1-dev** | XML security headers | Docker | ✅ SÍ | ✅ |
| **libxmlsec1-openssl** | XML security runtime | Docker | ✅ SÍ | ✅ |
| **libffi-dev** | Foreign Function Interface | Docker | ✅ SÍ | ⚠️ |
| **libjpeg-dev** | JPEG support | Docker | ✅ SÍ | ⚠️ |
| **zlib1g-dev** | Compression | Docker | ✅ SÍ | ⚠️ |
| **build-essential** | Compiladores | Docker | ✅ SÍ | ⚠️ |
| **ghostscript** | PDF rendering | Docker | ✅ SÍ | ⚠️ |
| **libgeos-dev** | Geometría GIS | Docker | ✅ SÍ | ❌ No |
| **libgeoip-dev** | Geolocalización | Docker | ✅ SÍ | ❌ No |
| **libzbar-dev** | Códigos de barras | Docker | ✅ SÍ | ❌ No |

---

## 📊 TABLA 6: FLUJOS DE NEGOCIO - ACTORES Y RESPONSABILIDADES

| Flujo | Actor | Función | Herramienta | Entrada | Salida | Validación |
|---|---|---|---|---|---|---|
| **Emisión DTE** | Usuario Odoo | Crear factura | DTEFacturaView | Datos | Draft | DataValidator |
| **Validación Pre-envío** | Sistema Odoo | Validar coherencia | DataValidator, RUTValidator, etc | Draft | Ready | Multi-paso |
| **Envío a SII** | DTE Service | Enviar SOAP | DTESender, SOAPClient | Ready | Track ID | ErrorHandler |
| **Monitoreo Status** | DTE Service Cron | Poll SII | DTEStatusPoller | Track ID | Status (Aceptado/Rechazado) | SOAPClient |
| **Recepción Compras** | DTE Service Cron | Descargar DTEs recibidos | DTEReceiver | RUT empresa | XML compras | DTEParser |
| **Reconciliación Compra** | Odoo Cron | Crear factura compra | CompraReconciliation | XML recibido | PO línea creada | PartnerValidator |
| **Certificado Expiry** | Odoo Cron | Monitorear expiración | CertificateExpiryMonitor | Fecha actual | Alert email | Date check |
| **Anulación DTE** | Usuario Odoo | Anular factura emitida | AccountMove.cancel() | Move | Cancelado | StateTransition |

---

## 📈 TABLA 7: EVOLUCIÓN POR FASES

| Fase | Semanas | Componentes a Implementar | Validación | MVP? |
|---|---|---|---|---|
| **Fase 1: Infraestructura** | 1-2 | Modelos Odoo, Config, Extensiones | Unit tests | ❌ |
| **Fase 2: Validación** | 3-4 | DataValidator, RUTValidator, TaxValidator | Integration tests | ❌ |
| **Fase 3: Generación XML** | 5-6 | DTEGenerator, XMLValidator, TemplateEngine | Mock SII | ⚠️ Partial |
| **Fase 4: Firma Digital** | 7-8 | DTESigner, CertificateManager, KeyExtractor | Unit + mocking | ✅ YES |
| **Fase 5: SOAP/SII** | 9-11 | DTESender, SOAPClient, ErrorHandler, RetryPolicy | Mock SII SOAP | ✅ YES |
| **Fase 6: Recepción** | 12-13 | DTEReceiver, DTEParser, CompraReconciliation | Mock response | ⚠️ Partial |
| **Fase 7: UI/Reportes** | 14-15 | Vistas, Wizards, PDFs, Reportes | E2E tests | ✅ YES |
| **Fase 8: Testing** | 16-18 | Coverage >85%, Load testing, Security | Full suite | ✅ YES |

---

## 🎯 TABLA 8: MATRIZ RESPONSABILIDADES

| Aspecto | Odoo Módulo | DTE Service | Comentario |
|---|---|---|---|
| **Captura de datos** | ✅ 100% | - | UI user |
| **Validación básica** | ✅ 100% | - | RUT, montos, campos |
| **Validación SII** | ⚠️ 50% | ⚠️ 50% | Odoo validación básica, DTE servicio rigurosa |
| **Generación XML** | - | ✅ 100% | Pure XML generation |
| **Firma digital** | - | ✅ 100% | PKI/crypto intensivo |
| **Comunicación SOAP** | - | ✅ 100% | Network I/O |
| **Almacenamiento certs** | ✅ 100% | - | Encrypted BD field |
| **PDF generation** | ✅ 100% | - | Odoo reports |
| **Auditoría/logs** | ✅ 100% | ⚠️ 50% | Odoo central, DTE logs propios |
| **Notificaciones** | ✅ 100% | - | Email via Odoo |
| **Crons/scheduling** | ✅ 100% | ⚠️ 50% | Odoo crons, DTE async jobs |
| **Estado/workflows** | ✅ 100% | - | State machine Odoo |

---

## 💾 TABLA 9: MODELOS DE DATOS

| Modelo Odoo | Campos Principales | Relaciones | Propósito |
|---|---|---|---|
| **account.move (extendido)** | dte_folio, dte_track_id, dte_status, dte_timestamp, dte_type | link account_journal_dte | Factura DTE |
| **account.journal (extendido)** | dte_enabled, dte_certificate_id, dte_environment, folio_start, folio_end | link dte_certificate | Config diario |
| **dte_certificate** | name, cert_file, password_hash, expiry_date, company_id | M2O company | Certs PKI |
| **dte_audit_log** | action, move_id, status, details, user_id, timestamp | M2O move, M2O user | Auditoría |
| **dte_communication** | track_id, move_id, request_xml, response_xml, status, sii_error | M2O move | Logs SOAP |
| **res.partner (extendido)** | dte_validated_rut, dte_last_check_date | - | Partner chile |
| **res.company (extendido)** | dte_rut, dte_business_name, dte_sii_environment | - | Config empresa |
| **account.tax (extendido)** | sii_tax_code, sii_additional_type | - | Mapping impuestos |

---

## 🔐 TABLA 10: SEGURIDAD POR COMPONENTE

| Componente | Riesgo | Mitigación | Implementado |
|---|---|---|---|
| **CertificateManager** | Private key exposure | Encrypted BD field, Memory clearing | ⚠️ Parcial |
| **DTESigner** | Forge signatures | Use pyOpenSSL validated | ✅ SÍ |
| **SOAPClient** | Man-in-the-middle | TLS verification, cert pinning | ⚠️ TLS pending |
| **DTEGenerator** | XXE injection | defusedxml parser | ✅ SÍ |
| **DTEAuditLog** | Log tampering | Immutable logs (future) | ❌ No |
| **Data at rest** | Unauthorized access | Encryption (future) | ❌ No |

---

## 📝 RESUMEN EJECUTIVO

**54 componentes identificados:**
- 🟢 **Odoo Módulo:** 31 (57%)
- 🔵 **DTE Service:** 15 (28%)
- 🟣 **Compartidas:** 8 (15%)

**Dependencias:**
- ✅ **25+ librerías Python** instaladas
- ✅ **12+ librerías sistema** instaladas
- ✅ **Todas críticas para DTE** presentes

**Flujo completo:** Desde captura hasta PDF + QR en ~15 segundos

**Esfuerzo:** 18 semanas (8 fases)

**MVP:** Fase 4-5 (11 semanas)

**Producción:** Fase 1-8 (18 semanas) + 14 sem adicionales (operaciones, seguridad, compliance)
