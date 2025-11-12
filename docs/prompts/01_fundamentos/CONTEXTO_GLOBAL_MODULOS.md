# Contexto Global de Módulos – Odoo 19 CE (Chile)

Visión transversal para alinear diseño, auditorías y desarrollo entre Nómina, DTE y Reportes.

## 1. Módulos Principales

- Nómina (`l10n_cl_hr_payroll`): reglas salariales, topes legales, LRE/previred, asistentes.
- DTE (`l10n_cl_dte`/relacionados): emisión/recepción, firma, intercambio y estados SII.
- Reportes Financieros (`l10n_cl_financial_reports`): `account.report` para Balance/PyG/8 Columnas.

## 2. Dependencias y Contratos

- Reportes consumen asientos/etiquetas contables estandarizados; evitar campos ad hoc.
- Nómina publica totales contables con cuentas configurables; trazabilidad a diario.
- DTE integra con contabilidad y estados tributarios; idempotencia en reintentos.

## 3. Datos Paramétricos y Vigencias

- Indicadores legales (UF, UTM, topes, tasas) viven en modelos centralizados con `valid_from`/`valid_until`.
- Nunca hardcodear parámetros; exponer menús de mantenimiento y carga inicial.

## 4. Multi-Compañía y Seguridad

- Toda consulta filtrada por `company_id` y reglas record; compartir catálogos sólo si procede.
- Wizards y controladores validan permisos y compañía activa.

## 5. Reportería y PDFs

- Estándar `account.report`; PDF QWeb con datos dinámicos (no placeholders estáticos).
- Export XLSX cuando aplica; mantener coherencia de columnas y filtros.

## 6. Rendimiento

- Metas guía: reportes <3s en 10k-50k líneas, nómina <5m/1k empleados.
- Usar `QueryCounter`, prefetch y agregaciones; documentar excepciones.

## 7. Internacionalización

- `es_CL` y `en_US` mínimo; strings traducibles en UI/QWeb.
- Evitar concatenaciones no traducibles; usar placeholders en `_()`.

## 8. Naming y Front-Matter de Prompts

- Convención: `prompt_[auditoria|desarrollo]_[modulo]_[fase|sprint|rango]_[verificacion|informe|cierre|preflight].md`.
- Front-matter YAML: `id`, `type`, `module`, `phase/sprint`, `requires`, `deliverables`.

## 9. Entornos

- Dev: datos de prueba deterministas; CI: headless con seeds conocidos; Stage: copia parcial anonimiz.
- Registrar versiones de Odoo, módulos y Python en informes.

## 10. Matrices y DoD

- Toda fase/sprint con matriz de verificación y DoD explícito (tests, cobertura, i18n, ACL, performance).
- Sin DoD cumplido, no se cierra el hito.
