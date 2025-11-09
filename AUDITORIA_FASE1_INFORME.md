# Auditoría Fase 1 — Análisis estático del módulo DTE (Odoo 19 CE)

Fecha: 2025-10-30
Alcance: addons/localization/l10n_cl_dte (libs, models, wizards, reports, static/xsd)

## Resumen ejecutivo

Estado general: sólido. Están implementados los bloques P0 clave (EnvioDTE + Carátula, firmas XMLDSig en nodos correctos, autenticación Seed/Token, validación XSD obligatoria, TED con FRMT firmado + campo `dte_ted_xml`).

Hallazgos relevantes de Fase 1 (estático):

- P0. Firma: discordancia de campos/estado en certificado vs firmador (rompe firma actualmente).
- P1. Datos: contratos de datos no alineados para DTE 34/52/56/61 (riesgo de XML inválido en esos tipos).
- P1. Reporte: desajuste de binding entre helper y plantilla; uso de `o.dte_type` en lugar de `o.dte_code`.
- P2. Modelo: extensión de `account.move` define `_name` (estilo no recomendado); legado RMQ presente pero no crítico.

## Inventario y arquitectura (en repo)

- Libs DTE:
  - `libs/xml_generator.py`, `libs/envio_dte_generator.py`, `libs/xml_signer.py`, `libs/ted_generator.py`, `libs/xsd_validator.py`, `libs/sii_soap_client.py`, `libs/sii_authenticator.py`, `libs/commercial_response_generator.py`.
- Modelos clave:
  - `models/account_move_dte.py`, `models/dte_certificate.py`, `models/dte_caf.py`, `models/res_company_dte.py`, `models/dte_inbox.py`, `models/account_journal_dte.py`.
- Wizards/Reportes:
  - `wizards/dte_commercial_response_wizard.py`.
  - `reports/dte_invoice_report.xml` + helper `report/account_move_dte_report.py`.
- XSDs oficiales: `static/xsd/DTE_v10.xsd`, `EnvioDTE_v10.xsd`, `SiiTypes_v10.xsd`, `xmldsignature_v10.xsd`.

## Evidencias técnicas y hallazgos

1. Firma XML — uso del certificado (P0)

- Evidencia:
  - `libs/xml_signer.py`: usa `certificate.certificate_file` y `certificate.password` (líneas ~93–94), y verifica `certificate.state == 'active'` (línea ~79).
  - `models/dte_certificate.py`: define `cert_file` (Binary) y `cert_password` (compute/inverse encriptado), y estados: `valid`, `expiring_soon`, `expired`, `revoked`.
- Impacto:
  - La firma fallará: los campos esperados por el firmador no existen y el estado válido no es `active`.
- Cierre recomendado:
  - Cambiar a `certificate.cert_file` y `certificate.cert_password` en el firmador.
  - Aceptar `state in ('valid','expiring_soon')` para firmar.

1. Contratos de datos por tipo DTE (P1)

- Evidencia:
  - `models/account_move_dte.py`: `_prepare_dte_data_native()` retorna `totales` + `lineas` (claves: `monto_neto`, `iva`, `monto_total`, y `lineas[].subtotal`).
  - `libs/xml_generator.py`:
    - DTE 33 usa `totales` + `lineas` (OK).
    - DTE 34 espera `montos` + `productos` y usa `MntExe` (exento) (no calza).
    - DTE 52 espera `productos`, `transporte`, y totales opcionales.
    - DTE 56/61 esperan `lineas` pero también `documento_referencia` obligatorio y ciertos campos.
- Impacto:
  - Generación para 34/52/56/61 puede fallar o producir XML no conforme.
- Cierre recomendado:
  - Normalizar `_prepare_dte_data_native()` por tipo o agregar adaptadores antes de `generate_dte_xml`.
  - Validar presencia/estructura de `documento_referencia` en 56/61.

1. Reporte PDF/QWeb (P1)

- Evidencia:
  - `reports/dte_invoice_report.xml`: usa `object.dte_type` y muestra `o.dte_type` (línea ~23), pero el modelo define `dte_code` (relacionado a `l10n_latam_document_type_id.code`).
  - `ir.actions.report.report_name = 'l10n_cl_dte.report_invoice_dte_document'`, por convención el helper debería llamarse `report.l10n_cl_dte.report_invoice_dte_document`.
  - `report/account_move_dte_report.py`: `_name = 'report.l10n_cl_dte.report_invoice_dte'` (mismatch).
- Impacto:
  - El helper puede no ser invocado; el nombre del archivo podría formarse con campo inexistente.
- Cierre recomendado:
  - Cambiar helper a `_name = 'report.l10n_cl_dte.report_invoice_dte_document'`.
  - En QWeb/print_report_name, reemplazar `dte_type` por `dte_code`.

1. Extensión de `account.move` (P2)

- Evidencia: `models/account_move_dte.py` define `_name = 'account.move'` con `_inherit=[...]` (línea ~35).
- Impacto: estilo no recomendado; puede causar conflictos en herencia.
- Cierre: eliminar `_name` y mantener solo `_inherit`.

1. SOAP/Autenticación/Timeouts (Info, a validar runtime)

- Evidencia:
  - Envío y consulta usan token SII (headers Cookie/TOKEN) y `Transport(timeout=...)` (OK).
  - Método consulta: `QueryEstDte` (línea ~308 en `libs/sii_soap_client.py`), depende del WSDL específico; validar contra Maullín.
- Recomendación:
  - Mantener timeout configurable (ya lo está) y revisar método contra WSDL actual.

1. TED + EnvioDTE + Firmas (OK)

- Evidencia:
  - `account_move_dte.py`: inserta TED en `Documento`, firma `Documento` con `URI=#DTE-<folio>` y firma `SetDTE` con `URI=#SetDTE`. Envoltorio `EnvioDTE` generado y firmado.
- Nota: Excelente, alineado con SII.

1. XSDs y validación (OK)

- Evidencia:
  - `static/xsd/` con `DTE_v10.xsd`, `EnvioDTE_v10.xsd`, `SiiTypes_v10.xsd`, `xmldsignature_v10.xsd`.
  - `libs/xsd_validator.py`: validación obligatoria y reporte de errores detallado.

1. Legado RabbitMQ (P2)

- Evidencia: métodos de publicación en `account_move_dte.py` y `models/rabbitmq_helper.py`.
- Impacto: no crítico si no se usan; conviene aislar o eliminar para claridad.

## Checklist Fase 1 — Resultado

- Modelos/constraints: PASS (constraints correctas en `dte_certificate.py`, `dte_caf.py`).
- Firmas XML/Refs: PASS (posicionamiento en `Documento`/`SetDTE` con `URI`).
- Autenticación SII: PASS (token aplicado en envío y consulta).
- XSDs y validación: PASS (obligatoria, esquemas presentes).
- Reportes: FAIL (binding/helper name y `dte_type` vs `dte_code`).
- Contratos de datos tipos 34/52/56/61: FAIL (no alineados).
- Estilo herencia modelo: WARN (`_name` en extensión `account.move`).
- Seguridad/Secretos: PASS (password encriptada; sin logs sensibles aparente).

## Acciones recomendadas (orden sugerido)

1. Firma/Certificado (P0)

- En `libs/xml_signer.py`:
  - Usar `certificate.cert_file` y `certificate.cert_password`.
  - Aceptar `state in ('valid','expiring_soon')` como condición para firmar.

1. Datos por tipo DTE (P1)

- Ajustar `_prepare_dte_data_native()` o crear adaptadores por tipo para:
  - 34: `montos` + `productos` y uso de `MntExe`.
  - 52: `productos`, `transporte`, totales opcionales.
  - 56/61: `documento_referencia` obligatorio + `lineas` acorde.

1. Reportes (P1)

- Cambiar `_name` del helper a `report.l10n_cl_dte.report_invoice_dte_document`.
- En `dte_invoice_report.xml`, usar `o.dte_code` y en `print_report_name` también.

1. Herencia `account.move` (P2)

- Remover `_name` en `account_move_dte.py`.

1. Limpieza legado (P2)

- Aislar/eliminar RMQ si no se usa; mantener solo `ir.cron`.

## Cierre Fase 1

- Documentación y hallazgos listos. Recomendado pasar a correcciones rápidas (P0/P1) y luego ejecutar pruebas mínimas (validación XSD local y, si es posible, pruebas en Maullín).

