# Auditoría de Cumplimiento SII – Módulo DTE Odoo 19 (29-10-2025)

Este informe analiza el módulo `l10n_cl_dte` en desarrollo y compara sus capacidades con las exigencias del SII de Chile para facturación electrónica (DTE). Se identifican brechas técnicas y funcionales, su severidad y recomendaciones de cierre.

## Resumen ejecutivo

- El módulo tiene base sólida: modelos clave (certificados, CAF, diario, account.move), generación XML parcial, firma XML, y vistas/procesos de recepción DTE.
- Sin embargo, persisten brechas críticas para cumplir 100% SII en emisión y recepción:
  - Falta de empaquetado EnvioDTE con Carátula y firma de envío.
  - Ausencia de autenticación SII (getSeed/getToken) y cabeceras de seguridad.
  - TED (FRMT) no se firma ni se incrusta en el Documento.
  - Validación XSD deshabilitada por falta de esquemas.
  - Procesos Libros y Consumo de Folios con placeholders (no envían a SII).
  - Respuestas comerciales (ACEPTA/RECLAMA) dependen de microservicio eliminado.
- Recomendación: 2 sprints para cierre P0-P1, priorizando envío EnvioDTE, autenticación SII y TED.

## Alcance actual del módulo (hallazgos)

- Emisión DTE: `account_move_dte.py` usa libs nativas (`xml_generator`, `xml_signer`, `sii_soap_client`, `xsd_validator`).
- Certificados y CAF: modelos y vistas completas (`dte_certificate.py`, `dte_caf.py`).
- Recepción DTE: `dte_inbox.py` con validación nativa y asistida por IA, y wizard de respuesta comercial.
- Libros y Consumo de Folios: modelos presentes (`dte_libro.py`, `dte_consumo_folios.py`) con acciones de envío aún pendientes.
- Reporte PDF: plantilla profesional con PDF417/QR, pero depende de campo TED no existente.

## Matriz de cumplimiento SII (resumen)

- Firma de Documento (XMLDSig): Parcial. Se firma el Documento, pero sin TED ni firma de Envío.
- Envoltorio EnvioDTE + Carátula: No implementado.
- Autenticación SII (getSeed/getToken, WS-Security/Cookies/Headers según endpoint): No implementado.
- TED (DD + FRMT firmado con CAF) y código de barras (PDF417): TED generado sin FRMT firmado ni campo guardado; PDF417/QR en reporte pero sin fuente TED.
- CAF y folios: Gestión presente; embedding CAF en Documento/TED no implementado.
- Validación XSD con esquemas oficiales: Librería lista, pero sin XSD en `static/xsd` (skip efectivo).
- Tipos soportados (33, 34, 52, 56, 61): Generadores parcialmente implementados; datos esperados no calzan con preparación desde `account.move` (p. ej. 34/52/56/61).
- Consulta de estado SII: Método presente pero con bug de nombre y sin autenticación.
- Recepción DTE y respuestas comerciales (AEC/claim): UI y modelo listos; envío depende de microservicio eliminado.
- Libros Compra/Venta (LEC) y Consumo de Folios (RCOF/RVF): Placeholders, no envían a SII.
- Cesión de Facturas (factoring): No observado.
- Boletas (39/41) y RCOF de Boletas: No implementadas (se gestiona BHE aparte).

## Brechas por severidad (P0 crítico → P3 menor)

### P0 – Críticas (bloquean operación en SII)

1. Empaquetado EnvioDTE y firma de Envío

- Archivos: `libs/xml_generator.py` (no genera EnvioDTE/Carátula), `models/account_move_dte.py`.
- Qué falta: Estructura EnvioDTE, Carátula (RutEmisor/RutEnvia/RutReceptor/FchResol/NroResol/TmstFirmaEnv), firma del Envio con certificado.
- Cierre: Implementar generador `EnvioDTE` (1 Documento → 1 Envio), firmar envolvente, y ajustar envío SOAP a enviar ‘archivo’ base64 del EnvioDTE (a veces zip según doc SII).

1. Autenticación SII (getSeed/getToken y headers)

- Archivos: `libs/sii_soap_client.py`.
- Qué falta: Flujo getSeed → firma semilla → getToken → uso de token/cookie/headers. Actualmente se llama EnvioDTE sin auth.
- Cierre: Implementar cliente para Seed/Token (SOAP antiguos o REST si aplica), almacenar token temporal y adjuntar a cada llamada.

1. TED (FRMT firmado con CAF) incrustado en Documento

- Archivos: `libs/ted_generator.py`, `libs/xml_generator.py`.
- Qué falta: Firmar FRMT con llave privada del CAF y añadir `<TED>` a `DTE/Documento` (y PDF417 en reporte). Campo `dte_ted_xml` no existe.
- Cierre: Implementar firmado FRMT con CAF, almacenar `dte_ted_xml` en `account.move`, y conectar con helpers del reporte.

1. Validación XSD con esquemas oficiales

- Archivos: `libs/xsd_validator.py`, `static/xsd/`.
- Qué falta: XSDs oficiales (DTE_v10.xsd, NotaCredito_v10.xsd, NotaDebito_v10.xsd, GuiaDespacho_v10.xsd, LiquidacionFactura_v10.xsd).
- Cierre: Incorporar XSDs a `static/xsd` y habilitar validación obligatoria en entorno producción.

### P1 – Altas (funciona parcialmente, riesgo alto)

1. Generación de tipos 34/52/56/61 – alineación de datos

- Archivos: `libs/xml_generator.py`, `models/account_move_dte.py`.
- Problema: `_prepare_dte_data_native()` no entrega claves esperadas por generadores (p. ej. usa `lineas/subtotal`, generadores esperan `productos/monto_total` en algunos casos).
- Cierre: Normalizar contrato de datos por tipo (entradas requeridas por cada `_generate_dte_xx`). Agregar referencias obligatorias para 56/61.

1. Consulta de estado SII

- Archivos: `models/account_move_dte.py`, `libs/sii_soap_client.py`.
- Problemas: Método redefine `query_dte_status` y llama a `query_status_sii` (inexistente). Sin autenticación.
- Cierre: Corregir nombres, unificar a un solo método (e.g., `soap_query_dte_status`), agregar token.

1. Respuestas comerciales (aceptar/rechazar/reclamar)

- Archivos: `wizards/dte_commercial_response_wizard.py`.
- Problema: Depende de microservicio `odoo-eergy-services` eliminado en `docker-compose.yml`.
- Cierre: Reemplazar por llamadas nativas a SII (o restaurar microservicio), incluyendo autenticación.

### P2 – Medias (mejora de calidad/confiabilidad)

1. Reporte PDF – TED PDF417/QR

- Archivos: `report/account_move_dte_report.py`, `report/report_invoice_dte_document.xml`.
- Problema: Usa `invoice.dte_ted_xml` que no existe; fallback QR/PDF417 sin fuente.
- Cierre: Crear campo `dte_ted_xml` en `account.move` y alimentar desde generador TED.

1. Tiempo de espera SOAP

- Archivos: `libs/sii_soap_client.py`.
- Problema: `requests.Session.timeout` no aplica a zeep; se debe usar `Transport(timeout=<s>)`.
- Cierre: Ajustar creación de `Transport` con `timeout=...` y/o manejo granular por request.

1. Unicidad por SQL constraints

- Archivos: `models/dte_certificate.py`, `models/dte_caf.py`.
- Problema: Se declara `models.Constraint(...)` (no API de Odoo). No se aplican constraints.
- Cierre: Usar `_sql_constraints = [("uniq_x", "unique(field1,field2)", "msg")]`.

### P3 – Menores (UX/robustez)

1. `account.move` extensión con `_name`

- Archivos: `models/account_move_dte.py`.
- Problema: Se define `_name = 'account.move'` con `_inherit=[...]`. En Odoo para extender se omite `_name`.
- Cierre: Retirar `_name` y mantener `_inherit=['account.move', ...]`.

1. Embedding CAF en Documento

- Archivos: `libs/xml_generator.py`.
- Nota: Asegurar inclusión de `<CAF>` dentro de `<TED>` o donde corresponda según formato SII.

1. Manejo de boletas (39/41) y RCOF boletas

- Alcance: No implementado en emisión; receptores sí considerados.
- Cierre: Evaluar si es requisito del proyecto (retail/consumo masivo). Si aplica, planificar soporte y RCOF.

## Bugs puntuales detectados

- `account_move_dte.py`: Redefine `query_dte_status` y llama a método inexistente `query_status_sii`.
- `xml_generator.py` (DTE 33): usa `line['monto_total']` pero `_prepare_invoice_lines()` entrega `subtotal`.
- `report/account_move_dte_report.py`: requiere `invoice.dte_ted_xml` (campo no existe).
- `libs/sii_soap_client.py`: sin autenticación SII; timeout mal configurado.
- Constraints mal declaradas con `models.Constraint` (no efectivas en Odoo).

## Recomendación de cierre por sprint

- Sprint A (P0):
  1) Autenticación SII (Seed/Token) + firma EnvioDTE + envío SOAP con EnvioDTE firmado.
  2) TED completo (FRMT firmado con CAF) + campo `dte_ted_xml` + PDF417/QR en reporte.
  3) XSD oficiales en `static/xsd` + validación obligatoria en producción.

- Sprint B (P1):
  4) Normalizar contrato de datos por tipo (33/34/52/56/61) y referencias obligatorias (56/61).
  5) Consulta de estado corregida + autenticación.
  6) Respuestas comerciales nativas (o restaurar microservicio temporalmente).

- Sprint C (P2-P3):
  7) Constraints SQL, timeout zeep, limpieza `_name` en `account.move`.
  8) Libros y Consumo de Folios: generación y envío real a SII.
  9) Decidir alcance boletas (39/41) y cesión de facturas.

## Referencias de código (claves)

- Emisión: `models/account_move_dte.py`, `libs/xml_generator.py`, `libs/xml_signer.py`, `libs/sii_soap_client.py`.
- CAF: `models/dte_caf.py`.
- Certificados: `models/dte_certificate.py`.
- Recepción: `models/dte_inbox.py`, `wizards/dte_commercial_response_wizard.py`.
- Validación XSD: `libs/xsd_validator.py`, `static/xsd/`.
- Reporte: `report/account_move_dte_report.py`, `report/report_invoice_dte_document.xml`.

---

Si deseas, puedo priorizar e implementar el cierre de P0 en este repo (autenticación + EnvioDTE + TED firmado) y dejar pruebas mínimas automatizadas para validar contra sandbox.
