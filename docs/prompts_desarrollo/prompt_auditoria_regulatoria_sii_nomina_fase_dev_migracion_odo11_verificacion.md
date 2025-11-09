---
id: auditoria_regulatoria_sii_nomina_fase_dev_migracion_odo11_verificacion
type: auditoria
module: cross (l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports)
phase: desarrollo
requires:
  - docs/prompts_desarrollo/MAXIMAS_AUDITORIA.md
  - docs/prompts_desarrollo/MAXIMAS_DESARROLLO.md
  - docs/prompts_desarrollo/CONTEXTO_GLOBAL_MODULOS.md
  - ai-service/knowledge/normativa/
  - ai-service/knowledge/nomina/
deliverables:
  - matrices/REGULATORIA_SII_CHECKLIST.csv
  - matrices/NOMINA_NORMATIVA_CHECKLIST.csv
  - informes/AUDITORIA_REGULATORIA_DEV_MIGRACION_O11_A_O19.md
  - evidencias/<capturas|logs|datasets>
---

# Auditoría Regulatoria Integral (SII + Nómina) – Fase Desarrollo con Migración Odoo 11 → 19

Objetivo: verificar que los módulos actuales y planes de migración cumplen exigencias regulatorias chilenas en facturación electrónica (SII) y nómina, y que la parametría legal está correctamente modelada con vigencias y sin hardcoding.

## Alcance

- Facturación electrónica (DTE): `l10n_cl_dte` nativo y/o integraciones asociadas.
- Nómina Chile: reglas salariales, LRE/Previred, topes/tasas, retenciones.
- Reportes financieros: coherencia con SII (cuando aplique) y `account.report`.
- Migración desde instancia Odoo 11 local (docker) a Odoo 19 CE.

## Entradas y fuentes

- Código y docs: `docs/facturacion_electronica/`, `ai-service/knowledge/normativa/`, `docs/payroll-project/`, `ai-service/payroll/previred_scraper.py`, `ai-service/knowledge/nomina/`.
- Instancia Odoo 11 local (docker): extraer datos paramétricos, catálogos y evidencias de flujos productivos.
- Normativa oficial: SII (DTE, CAF, certificados), Previred, Superintendencia de Pensiones, tablas de impuesto único.

## Entregables (DoD)

- Matrices CSV SII y Nómina con estado (OK/Gap/N.A.), severidad (P0–P3), evidencia y acción.
- Informe MD con hallazgos, riesgos, pasos de cierre y verificación.
- Fixtures o scripts de validación para reproducibilidad (sin datos sensibles).
- Confirmación de parametría legal con vigencias activas y sin hardcoding.

## Metodología

1. Descubrimiento y validación documental

- Inventariar conocimiento local: `ai-service/knowledge/normativa/` (SII) y `ai-service/knowledge/nomina/` (completar archivos base si faltan: UF/UTM, topes imponibles AFP/Salud/SC, SIS, tramos impuesto único, retención honorarios).
- Confirmar correspondencia entre documentación y modelos/menús en Odoo 19.

1. Extracción de referencia Odoo 11 (docker)

- Exportar catálogos y parámetros usados en producción: certificados (.p12), CAF, tipos DTE, diarios y cuentas DTE, reglas y tasas nómina (topes, UTM/UF, SIS, SC, tramos).
- Tomar muestra de DTEs reales (XML anonimizados) y liquidaciones representativas.

1. Gap analysis técnico-funcional

- SII/DTE: tipos soportados (33, 34, 52, 56, 61), gestión de CAF, certificados, modo contingencia, consulta estado, rechazo/aceptación, trazabilidad, idempotencia, XML XSD (RespSII_v10), mapeos campos.
- Nómina: uso exclusivo de parámetros con `valid_from`/`valid_until` (sin campo `year`), topes imponibles correctos, UF/UTM centralizados, LRE export (Previred), ACL/roles, i18n.
- Reportes: uso de `account.report`, PDF dinámico, multi-compañía, bordes (saldos cero, sin movimientos), rendimiento (QueryCounter).

1. Pruebas y reproducibilidad

- Preparar datasets sintéticos y/o anonimizados para replicar flujos clave: generación DTE, rechazo común SII, liquidación con topes y sin topes, LRE.
- Tests unitarios/funcionales declarativos con evidencia (logs/capturas) y umbrales (tiempo/queries).

## Matrices de verificación (columnas sugeridas)

- `item`, `regla/tema`, `referencia legal`, `implementación (ruta archivo/menú)`, `estado`, `severidad`, `evidencia`, `acción`, `responsable`, `fecha objetivo`.

### SII / DTE (muestra de ítems)

- Tipos DTE implementados (33, 34, 52, 56, 61)
- Gestión CAF (carga, rango, consumo, expiración)
- Certificados digitales (.p12, vigencia, clase)
- Modo contingencia (operación offline, batch reenvío)
- Consulta de estado SII (polling / manual)
- Validación XSD, firmas, timbraje
- Idempotencia y reintentos
- Multicompañía y ACL de menús
- i18n en UI/QWeb

### Nómina (muestra de ítems)

- Topes imponibles AFP/Salud/SC por vigencia
- UF/UTM como parámetros, sin hardcoding
- Tramos Impuesto Único (tasas + rebajas)
- SIS y cotización adicional
- Export LRE (Previred) y validación de formato
- Reglas salariales sin `year` obsoleto; uso de `valid_from`/`valid_until`
- ACL de wizards/reportes nómina
- i18n (es_CL/en_US)
- Rendimiento: cálculo masivo y exportación

### Reportes

- `account.report` como framework único
- PDF/QWeb dinámico (sin placeholders fijos)
- Bordes (saldos cero, sin movimientos)
- Multi-compañía y seguridad
- Rendimiento y número de queries

## Evidencia mínima por gap

- Cómo reproducir (pasos/dataset)
- Capturas/logs/archivos XML/CSV (anonimizados si corresponde)
- Archivo/función/clase afectados
- Test propuesto (pre y post-fix)

## Criterios de severidad

- P0: incumplimiento legal o bloqueo productivo
- P1: alto impacto/riesgo
- P2: mejora/optimizaciones
- P3: cosmético/documentación

## Plan de corrección (resumen)

- Orden: P0 → P1 → preflight rendimiento/seguridad → P2/P3
- Cada fix con test que fallaba antes, y documentación actualizada
- Validación cruzada por segundo revisor en cálculos/seguridad

## Artefactos sugeridos (rutas)

- `matrices/REGULATORIA_SII_CHECKLIST.csv`
- `matrices/NOMINA_NORMATIVA_CHECKLIST.csv`
- `datasets/` (sintéticos/anonimizados)
- `informes/AUDITORIA_REGULATORIA_DEV_MIGRACION_O11_A_O19.md`

## Notas para el agente

- Referencias clave: `MAXIMAS_AUDITORIA.md`, `MAXIMAS_DESARROLLO.md`, `CONTEXTO_GLOBAL_MODULOS.md`.
- Usar la KB local en `ai-service/knowledge/**`; completar nómina si faltan archivos base.
- No usar scraping en producción; en dev/CI sí, pero documentar la fuente y la fecha.
- Mantener reproducibilidad (scripts, seeds, versiones).
