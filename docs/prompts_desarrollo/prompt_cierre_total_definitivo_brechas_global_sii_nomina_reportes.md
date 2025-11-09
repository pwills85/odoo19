---
id: cierre-total-definitivo-brechas-global
type: orquestacion
module: global (DTE + Nómina + Reportes)
phase: cierre_total_definitivo
requires:
  - MAXIMAS_DESARROLLO.md
  - MAXIMAS_AUDITORIA.md
  - CONTEXTO_GLOBAL_MODULOS.md
  - ai-service/knowledge/nomina/README.md
  - ANALISIS_COMPLETO_L10N_CL_DTE_ODOO19.md
  - AUDITORIA_PROFUNDA_LIBS_NATIVAS_DTE_2025-11-07.md
  - AUDITORIA_NOMINA_CHILENA_EXHAUSTIVA_2025-11-07.md
  - AUDITORIA_ODOO19_STANDARDS_L10N_CL_DTE.md
  - prompt_cierre_P0_cross_modulos_sii_nomina_reportes.md
  - prompt_desarrollo_dte_fase_2_1_cierre_brechas_dashboard_sii.md
  - prompt_desarrollo_nomina_fase_p1_cierre_total_brechas_preparacion_p2.md
  - prompt_auditoria_regulatoria_sii_nomina_fase_dev_migracion_odo11_verificacion.md
deliverables:
  - Matriz de brechas cerradas (global) con evidencias vinculadas
  - PRs por dominio (DTE, Nómina, Reportes) con tests, migraciones y docs
  - Suite de pruebas unificada (pytest) con rendimiento y cobertura reportados
  - Script/chequeo de compliance transversal (pre-merge y manual)
  - Documentación de release, notas de migración Odoo 11→19 y manual de operación
---

# Prompt integral: Cierre total y definitivo de brechas (Global)

## Objetivo

Ejecutar el cierre total y definitivo de brechas funcionales, regulatorias, de rendimiento, seguridad, i18n, integridad de datos y UX en los módulos DTE, Nómina Chilena y Reportes Financieros, coordinando a todos los agentes bajo un contrato de éxito único y criterios de aceptación verificables.

## Alcance

- Incluye: DTE (emisión/recepción, dashboard, contingencias), Nómina (cálculo, topes, tablas, auditoría), Reportes (Plan SII, Balance 8 Columnas), migración Odoo 11→19, multi-compañía, ACL/record rules, i18n, pruebas y CI, documentación y operación.
- Excluye: Integraciones externas no documentadas en esta repo y cambios de arquitectura mayor fuera de Odoo 19 CE.

## Éxito (KPIs y Definition of Done)

- Legal/regulatorio: 0 brechas abiertas críticas/altas. XSD/formatos y tablas vigentes parametrizadas con ventanas de validez (valid_from/valid_until) y sin hardcodear valores legales.
- Rendimiento: dashboards < 2 s inicial, reportes contables < 5 s con dataset de referencia, < 50 consultas por acción; sin N+1. Presupuesto explícito y tests con QueryCounter.
- Seguridad: aislamiento multi-compañía, record rules consistentes, sin elevación de privilegios; acciones de servidor seguras (sin eval inseguro). Acceso a datos de nómina minimizado por roles.
- i18n: es_CL y en_US con > 95% strings traducibles; sin literales duros en vistas/JS.
- Calidad: cobertura ≥ 85% en módulos tocados; 0 errores E/F (flake8/ruff), 0 pylint critical. Pruebas negativas incluidas.
- Migración: scripts idempotentes Odoo 11→19, reconciliaciones y mapeos verificados, sin pérdidas de integridad (partners, impuestos, cuentas, adjuntos).
- Observabilidad/auditoría: logs de auditoría para cálculos críticos (nómina), bitácora de eventos DTE clave, métricas básicas.
- Documentación: CHANGELOG, notas de versión, guía de operación, y procedimientos de contingencia actualizados.

## Orquestación de agentes y handoffs

- Agente DTE (Desarrollo + Auditoría)
  - Cierre dashboard: net billing/ingresos netos, aging, alertas de CAF/certificados y colas, CE-safe; i18n completo.
  - Emisión/recepción: validaciones contra XSD vigente, fallback de contingencia, manejo de estados y reintentos.
  - Entregables: PR con tests (KPIs, acciones, XML válido), datasets y documentación de contingencia.
- Agente Nómina (Desarrollo + Auditoría)
  - Reglas y topes: UF/UTM/topes imponibles, SIS; tablas con vigencias; constraints de solapes.
  - Auditoría y negativas: bitácora por cálculo, trazabilidad por empleado/periodo, pruebas negativas y límites.
  - Rendimiento: dataset sintético escalable; presupuesto y tests de rendimiento.
  - Entregables: PR con migraciones de datos paramétricas, tests, docs de mantenimiento de tablas.
- Agente Reportes (Desarrollo)
  - P0-5: Plan de Cuentas SII mapeado y parametrizable (account.report), códigos SII y vistas XLSX/PDF.
  - P0-6: Balance 8 Columnas (definiciones, filtros, agrupaciones), exportaciones y performance.
  - Entregables: PR con pruebas de integridad de saldos, fixtures y documentación de uso.
- Agente Migración/Integridad de datos
  - ETL idempotente Odoo 11→19, mapeos de impuestos/diarios/cuentas/partners; verificación de adjuntos y estados.
  - Entregables: scripts, checks de consistencia y reporte de diferencias aceptadas.
- Agente QA/CI/Seguridad/i18n
  - CI: pipeline de tests, lint y performance; compliance_check transversal (pre-merge/manual).
  - Seguridad: revisión de record rules y accesos; escaneo básico de dependencias.
  - i18n: extracción, traducciones y verificación de cobertura.

## Matriz de brechas (plantilla)

- Columna: dominio (DTE/Nómina/Reportes/Migración/Seguridad/CI), severidad, descripción, causa raíz, plan, responsable, evidencia, PR, estado (abierta/cerrada/verificada), fecha cierre.
- Entregable: archivo CSV/MD y referencia en AUDITORIA_MATRIZ_BRECHAS_YYYY-MM-DD.csv.

## Plan técnico por dominio (resumen ejecutable)

- DTE
  - Dashboard: KPIs regulatorios, net billing, aging por estado, alertas parametrizadas; CE-safe; i18n; pruebas de acciones y consultas.
  - Emisión/recepción: soporte XSD vigente y versionado; valid_from/valid_until en configuraciones; manejo de colas y reintentos; auditoría de eventos.
- Nómina
  - Tablas regulatorias: UF/UTM/topes/SIS con vigencias y no solapadas; comandos de actualización controlada.
  - Cálculo: impuesto único, tope imponible, licencias, ausencias; auditoría por línea; negativas y límites.
  - Multi-compañía y permisos: aislamiento de registros; vistas con dominios por compañía; reglas finas por rol.
- Reportes
  - Plan SII: mapeo de cuentas↔códigos SII; vistas account.report; export XLSX/PDF; pruebas de cruce con saldos.
  - Balance 8 Columnas: definiciones estándar, filtros, totales; performance con dataset de referencia.
- Migración
  - Mapeos Odoo 11→19: impuestos, cuentas, diarios, partners, UoM; reconciliaciones; adjuntos (XML/PDF) preservados.
  - Idempotencia y bitácora: re-ejecutar sin duplicar; reporte de diferencias y aceptaciones firmadas.
- Seguridad y i18n
  - Record rules consistentes; sin elevaciones; revisión de server actions.
  - i18n completa es_CL/en_US; sin literales; cobertura reportada.

## Pruebas y performance (presupuesto mínimo)

- Unitarias/Integración: casos felices y negativos; dataset escalable para stress.
- QueryCounter: límites por acción (< 50 consultas); sin N+1.
- Tiempos objetivo: dashboards < 2 s; reportes < 5 s; cálculo de nómina por empleado < 500 ms en dataset de referencia.
- Concurrencia básica: cola DTE y ejecución de nómina simultánea sin deadlocks en pruebas.

## Evidencias requeridas

- Capturas/artefactos: dashboard con KPIs; XMLs validados; reportes XLSX/PDF; bitácoras de nómina; matriz de brechas.
- Resultados: salida de pytest con tiempos/QueryCounter; cobertura por módulo; logs de migración con conteos.
- Documentos: CHANGELOG y notas de versión; guía de operación; procedimientos de contingencia DTE.

## Procedimiento de verificación final (gate de merge)

1. Matriz de brechas: 0 abiertas críticas/altas; medias con plan aceptado.
1. Tests: todos verdes; cobertura ≥ 85%; performance dentro de presupuesto.
1. Seguridad/i18n: revisión aprobada; cobertura i18n ≥ 95% en strings tocados.
1. Migración: corrida de validación sin pérdidas; diferencias documentadas y aceptadas.
1. Documentación: actualizada y revisada; usuarios clave validados.

## Entregables y formatos

1. Branches: feature/`nombre-dominio`-cierre-total; conv. commits.
1. PRs: plantilla con: objetivo, cambios, riesgos, pruebas, métricas, evidencias, screenshots, checklist.
1. Artefactos: directorio de evidencias por dominio; actualización de `AUDITORIA_*` y `CHECKLIST_*`.

## Cronograma sugerido

- Fase 1 (48 h): cierre DTE dashboard y tablas Nómina; matriz actualizada; primeras PRs.
- Fase 2 (72 h): Reportes P0-5/6, migración y QA/CI; performance y negativas.
- Fase 3 (24 h): verificación integral, documentación y release.

## Riesgos y mitigaciones

- Cambios regulatorios: parametrización con vigencias y feature flags.
- Rendimiento: presupuestos con tests y cachés selectivas; evitar re-cómputos.
- Seguridad: revisión de record rules y acciones; principio de mínimo privilegio.

## Instrucciones para comenzar

- Leer MAXIMAS_* y CONTEXTO_GLOBAL_MODULOS.md.
- Sincronizar matriz de brechas global con estado actual.
- Abrir PRs por dominio con objetivos, presupuesto de rendimiento y plan de pruebas.
- Ejecutar compliance_check transversal al cerrar cada PR y adjuntar reporte.
