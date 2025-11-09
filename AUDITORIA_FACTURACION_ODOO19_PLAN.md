# Auditoría de Excelencia – Módulo de Facturación en Odoo 19 CE

Este documento define las dimensiones (dominios) a auditar y un plan detallado, enfocado en un análisis duro del código del módulo de facturación y sus extensiones (incl. DTE), para alcanzar robustez, cumplimiento y mantenibilidad de clase mundial.

---

## 1) Dominios de auditoría (qué vamos a evaluar)

1. Funcional y de negocio
   - Cobertura funcional de facturación: emisión, cobro, notas de crédito/débito, cancelaciones, conciliación, pagos parciales, anticipos.
   - Integración Ventas/Compras/Inventario/Proyectos: documentos origen/destino, referencias y trazabilidad.
   - Multi-empresa, multi-moneda, impuestos (IVA, exento, retenciones), prorrateos y reglas locales l10n_cl.

2. Cumplimiento fiscal y DTE (SII)
   - Emisión DTE: XML, TED/FRMT con CAF, EnvioDTE + Carátula, firma XMLDSig, autenticación SII (seed/token), envío/consulta estado.
   - Recepción DTE y respuestas comerciales (RecepciónDTE, RCD, RechazoMercaderías).
   - XSDs oficiales y validación estricta; Libros/RCOF; folios/CAF; reportes PDF (PDF417/QR) conformes.

3. Modelo de datos e integridad
   - `_sql_constraints`, `ondelete`, índices; integridad referencial lógica; claves de negocio (folios, track_id, unicidades).
   - Campos computed/store y dependencias; migraciones; tamaños de campos y normalización.

4. Workflows y transacciones
   - Estados, transiciones, idempotencia, reintentos seguros.
   - Aislamiento transaccional y consistencia ante fallos (commit/rollback), crons y colas.

5. Seguridad y permisos
   - Reglas de acceso (ir.model.access, record rules), uso de `sudo()`, control de escritura/lectura.
   - Protección de secretos (certificados, contraseñas), cifrado de adjuntos, logs sin datos sensibles.

6. Rendimiento y escalabilidad
   - Query patterns (prefetch/read_group), índices; n+1; tamaños de lotes; costos en crons.
   - Performance de rutas críticas: emisión DTE, consultas de estado, reportes, conciliación masiva.

7. Resiliencia y observabilidad
   - Manejo de errores (granular, mensajes para usuario), reintentos con backoff, colas de fallos.
   - Logging estructurado, métricas (duración, tasas de error), trazas; alertas.

8. Calidad de código y mantenibilidad
   - Estilo, complejidad ciclomática, duplicación; arquitectura (acoplamiento/cohesión).
   - Tests (unit/integration/E2E), fixtures realistas, cobertura, estrategia CI/CD.

9. UX y configurabilidad
   - Vistas coherentes, botones/acciones seguras; asistencia al usuario en errores y estados.
   - Parámetros de sistema (`ir.config_parameter`), valores por defecto, validación de setup.

10. Operación y DR (disaster recovery)

- Backups de XMLs/EnvioDTE y evidencias; modo contingencia; procedimientos de recuperación.
- Runbooks operativos, timeouts y límites; toggles de características.

---

## 2) Plan de auditoría por fases (cómo lo haremos)

Fase 0 — Preparación (0.5-1 día)

- Alcance y artefactos del módulo (facturación base + extensiones DTE/localización).
- Mapa de dependencias (addons y librerías: lxml, xmlsec, zeep, reportlab, cryptography, etc.).
- Dataset de prueba (fixtures) y entornos (dev, Maullín, prod simulado).

Fase 1 — Análisis estático de código (2-3 días)

- Estructura y arquitectura: capas libs/models/tools/report/wizards; patrones de diseño.
- Chequeos sistemáticos:
  - Integridad de modelos: `_sql_constraints`, índices, `ondelete`, `selection` coherentes.
  - Validaciones/constraints vs. onchanges; compute/store y `@depends`.
  - Seguridad: record rules, `sudo()`, acceso a adjuntos, exposición de rutas web.
  - Errores silenciosos: `except: pass`, `try/except` muy amplios, logging pobre.
  - Firmas XML y referencias `URI="#ID"`, posición de `Signature` (DTE/SetDTE), algoritmos.
  - Contratos de datos entre helpers y generadores (diccionarios de líneas/cabeceras).
  - Gestión de certificados/CAF: extracción de claves, cifrado, expiración, coincidencia con RUT.
- Herramientas/criterios:
  - Pylint (pylint-odoo), flake8; radon (complejidad), xenon (umbrales), detect-duplicates.
  - Greps dirigidos y revisiones manuales por archivo crítico.

Fase 2 — Validación fiscal/DTE (2-3 días)

- Batería de casos DTE: 33 (neto), 34 (exento), 52, 56, 61.
- Validación XSD local + pruebas contra Maullín (EnvioDTE, token, consulta estado).
- Verificaciones TED/FRMT con CAF, QR/PDF417 en reporte, folios/CAF por diario.
- Respuestas comerciales y recepción DTE (parseo, matching, creación de compras si aplica).

Fase 3 — Pruebas funcionales y de regresión (2 días)

- Escenarios de negocio: emisión, anulación, NC/ND con referencias, pagos, conciliación.
- Multi-empresa, multi-moneda, impuestos variados, descuentos y notas.
- Integraciones: Ventas/Compras/Inventario → Facturas/Guías/Referencias.

Fase 4 — No funcionales (2-3 días)

- Rendimiento: p95/p99 en emisión y consulta; lotes (50-500 documentos). Índices y n+1.
- Resiliencia: cortes de red, timeouts, reintentos, colas de fallos, modo contingencia.
- Seguridad: permisos por rol, inyección en vistas/campos, secretos en repositorio/logs.

Fase 5 — Operación y DR (1-2 días)

- Backups de XML/EnvioDTE/CAF; restauración; rehacer envíos con evidencia.
- Runbooks: renovar certificados/CAF, cambiar entornos SII, contingencia, soporte L1/L2.

Fase 6 — Cierre y hardening (1-2 días)

- Correcciones priorizadas P0→P2 y re-ejecución de suites.
- Documentación técnica y guía de despliegue; checklist de aceptación.

---

## 3) Checklist de análisis duro (por capa)

Modelos (account.move, diarios, CAF, certificados, inbox, etc.)

- [ ] `_sql_constraints` para unicidades (folio+tipo+empresa, track_id, cert_rut+company).
- [ ] `ondelete` correctos en M2O/M2M; `index=True` en campos de búsqueda.
- [ ] Campos computed/store con `@depends` completos; evitar recomputes costosos.
- [ ] Estados/selecciones alineados con vistas y acciones.

Servicios/libs (XML, firmas, SOAP, XSD, TED/CAF)

- [ ] Firmas XMLDSig: referencia `#DocumentoID` y `#SetDTE`; ubicación de `Signature` correcta.
- [ ] Algoritmo configurable (RSA-SHA1/RSA-SHA256) según endpoint.
- [ ] Autenticación SII (seed/token) aplicada en envío y consulta (headers Cookie/TOKEN).
- [ ] XSDs presentes y validador obligatorio en prod; logs detallados de errores XSD.
- [ ] Extracción segura de claves (cert y CAF); expiraciones y coincidencias de RUT.

Flujos y transacciones

- [ ] Idempotencia en reintentos; detección de duplicados por track_id/folio.
- [ ] Manejo de errores con mensajes para usuario y logging técnico (stack/track_id).
- [ ] Crons con límites de tiempo/lotes; replanificación en caso de errores.

Seguridad y secretos

- [ ] No hay secretos en claro; contraseñas cifradas; adjuntos cifrados si aplica.
- [ ] Record rules adecuadas para lectura de DTEs/adjuntos; rutas web autenticadas.

Rendimiento

- [ ] Sin n+1; uso de `read_group`, `prefetch`, dominios indexados; `limit` en listados.
- [ ] Pruebas de carga: tiempos de envío y de consulta; colas dimensionadas.

Reportes/UX

- [ ] `dte_ted_xml` presente; PDF417/QR con fallback; campos correctos en QWeb.
- [ ] Plantillas consistentes; papel y márgenes; nombres de archivos.

Tests

- [ ] Unitarios de generadores y validadores; integración de emisión y recepción.
- [ ] E2E Maullín: envío y consulta por cada tipo DTE; respuestas comerciales.
- [ ] Cobertura objetivo ≥ 85% en libs críticas.

---

## 4) Métricas y criterios de aceptación

- Calidad código: sin `except: pass`, complejidad por función ≤ 10 (radon), duplicación < 5% críticas.
- Seguridad: 0 hallazgos P0; secretos cifrados; record rules verificadas; auditoría de acceso a adjuntos.
- Fiscal: 100% casos DTE pasan XSD; Maullín acepta envíos; consultas devuelven estado esperado.
- Rendimiento: p95 emisión DTE ≤ 2.5s; consulta estado ≤ 1.0s; lote 100 DTEs < 5 min.
- Resiliencia: reintentos correctos ante timeouts; cola de fallos operativa; contingencia almacena EnvioDTE.
- Operación: runbooks completos; backup/restore de evidencias y DTEs probado.

---

## 5) Artefactos y entregables

- Informe de hallazgos con severidad (P0–P3) y parches propuestos.
- Suite de pruebas automatizadas (unit/integration/E2E) y dataset de fixtures.
- Dashboards básicos de métricas (logs, tiempos, tasas de error) y alertas.
- Documentación técnica: arquitectura, flujos, firmas, DR/operación.

---

## 6) Scripted checks (ejemplos a incorporar al pipeline)

- Greps de higiene: `except:`, `sudo()`, `@api.depends` incompletos, `_sql_constraints` faltantes.
- Validación de firmas: presencia de `ID` y referencias `URI` correctas; posición de `Signature`.
- Coherencia de contratos: llaves esperadas por generadores vs. data preparada.
- Reglas de acceso: modelos DTE y adjuntos con ACLs y record rules presentes.

---

## 7) Plan de ejecución y tiempos (estimado)

- F0 Prep: 0.5–1 d
- F1 Estático: 2–3 d
- F2 Fiscal/DTE: 2–3 d
- F3 Funcional: 2 d
- F4 No funcional: 2–3 d
- F5 Operación/DR: 1–2 d
- F6 Cierre/Hardening: 1–2 d

Total: 11–16 días (según alcance y hallazgos). Se trabaja iterativo con cortes P0 tempranos.

---

## 8) Riesgos y mitigaciones

- Cambios en endpoints SII: parametrizar WSDL/algoritmos; feature flags.
- Certificados incompatibles: validación previa clase/uso; fallback SHA1.
- Cargas masivas: pruebas de volumen incremental; índices y particiones si aplica.
- Dependencias nativas (xmlsec, zeep): pinning de versiones y smoke tests en CI.

---

## 9) Siguientes pasos inmediatos

1) Ejecutar Fase 1 (estático) con los checks definidos y producir informe P0/P1.
2) Preparar fixtures y sandbox Maullín para Fase 2 (fiscal/DTE).
3) Montar pipeline con greps y linters + umbrales (radon/xenon) y reporte de cobertura.
