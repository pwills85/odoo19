# Auditoría Fase 9 - Comparación Odoo 11 Producción vs Odoo 19 Desarrollo

## Resumen Ejecutivo
- ⚠️ La versión Odoo 19 (`l10n_cl_dte`) se define explícitamente como solución B2B limitada a DTE 33, 34, 52, 56 y 61, excluyendo boletas y factura de compra (46), mientras que la instancia Odoo 11 en producción emite y recibe boletas, libros de boletas y factoring completo. `addons/localization/l10n_cl_dte/__manifest__.py:16`, `l10n_cl_fe/README.md:11`
- ⚠️ Módulos críticos de producción (factoring, bancos SBIF, indicadores financieros) no tienen contraparte en el árbol `addons/localization` descrito para Odoo 19, lo que implica pérdida directa de funcionalidades y datos maestros. `l10n_cl_dte_factoring/__manifest__.py:3`, `addons/localization/README.md:7`
- ⚠️ La nómina en Odoo 19 depende de microservicios externos para cálculos avanzados y afirma cubrir la Reforma 2025, mientras que la versión Odoo 11 es 100 % on-prem; sin una estrategia clara se corre el riesgo de duplicar lógicas o introducir nuevos puntos de falla. `addons/localization/l10n_cl_hr_payroll/__manifest__.py:20`, `addons/localization/l10n_cl_hr_payroll/__manifest__.py:51`

## Comparación Detallada

| Área / Feature | Producción Odoo 11 (Comprobado) | Desarrollo Odoo 19 | Riesgo / Acción |
|----------------|---------------------------------|--------------------|-----------------|
| **Cobertura DTE** | `l10n_cl_fe` maneja boletas (39/41), notas asociadas, guías, factoring y recepción XML; README enumera cada documento operativo. | `l10n_cl_dte` declara alcance B2B limitado a cinco DTE y explicita “Alcance EERGYGROUP B2B: Excluye Boletas (39,41,70) y Factura Compra (46)”. | Implementar boletas y factura compra en Odoo 19 o mantener módulo Odoo 11 para B2C hasta portar. `l10n_cl_fe/README.md:11`, `addons/localization/l10n_cl_dte/__manifest__.py:16` |
| **Factoring / Cesiones** | Módulo dedicado `l10n_cl_dte_factoring` agrega campos y colas para cesión, esencial para Ley 19.983. | README de `addons/localization` solo lista `l10n_cl`, `l10n_cl_edi`, `l10n_cl_reports`, `l10n_cl_hr_payroll`; no existe módulo factoring en el stack Odoo 19. | Portar `l10n_cl_dte_factoring` o incluir funcionalidades equivalentes dentro de `l10n_cl_dte`. `l10n_cl_dte_factoring/__manifest__.py:3`, `addons/localization/README.md:7` |
| **Indicadores financieros (UF/UTM)** | Módulo `l10n_cl_financial_indicators` actualiza UF/UTM vía SBIF y crea monedas UF/UTM. | El árbol de Odoo 19 no incluye un módulo equivalente; README solo menciona `l10n_cl_reports`. | Reimplementar actualizador (idealmente contra CMF) o migrar módulo existente. `l10n_cl_financial_indicators/__manifest__.py:21`, `addons/localization/README.md:34` |
| **Catálogo bancos SBIF / Balance 8 columnas** | Módulos `l10n_cl_banks_sbif` y `l10n_cl_balance` proveen bancos oficiales y reporte 8 columnas. | No hay referencia a estos módulos en `addons/localization`; solo se usa `l10n_cl` genérico. | Migrar CSV de bancos SBIF y layouts de balance para mantener reportes contables locales. `l10n_cl_banks_sbif/README.md:9`, `addons/localization/README.md:7` |
| **Nómina chilena** | `l10n_cl_hr` es autónomo (sin microservicios) y actualmente carece de Reforma 2025 (ver Fase 8). | `l10n_cl_hr_payroll` afirma soporte a la reforma y requiere “Payroll Microservice (FastAPI)” y “AI Service” para validaciones. | Evaluar si se migrará al modelo con microservicios; de lo contrario, portar reglas existentes y ampliar para reforma en un solo stack on-prem. `addons/localization/l10n_cl_hr_payroll/__manifest__.py:20`, `addons/localization/l10n_cl_hr_payroll/__manifest__.py:51` |
| **Previred** | Wizard clásico (`wizard_export_csv_previred`) genera archivo CSV y se integra con menús Odoo. | No se identificó wizard equivalente en `l10n_cl_hr_payroll` (depende del microservicio); documentación enfatiza exportación 105 campos fuera de Odoo. | Garantizar que Odoo 19 mantenga exportación directa o diseñar fallback mientras se integra el microservicio. `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:4`, `addons/localization/l10n_cl_hr_payroll/__manifest__.py:22` |

## Riesgos Prioritarios
1. **B2C bloqueado en Odoo 19:** Sin boletas y factoring se perdería la mitad del alcance operativo actual; requiere definir si se amplía `l10n_cl_dte` o se migra `l10n_cl_fe` completo.
2. **Datos maestros incompletos:** Bancos SBIF, indicadores financieros y balance 8 columnas son necesarios para conciliaciones y reportes regulatorios; su ausencia implica reprocesos manuales.
3. **Dependencia de microservicios para nómina:** Introduce nuevos componentes que no existen hoy; es imprescindible definir SLA, monitoreo y planes de contingencia antes de adoptar el flujo.

## Recomendaciones
- Elaborar plan de portabilidad módulo por módulo, comenzando por los de mayor impacto (boletas y factoring) y documentar las historias funcionales asociadas.
- Inventariar todos los datasets (bancos, AFP, ISAPRE, indicadores) y confirmar versiones en Odoo 19; donde no existan, preparar scripts de migración.
- Decidir si la empresa adoptará el modelo de microservicios para nómina; de lo contrario, adaptar `l10n_cl_hr` clásico a Odoo 19 y extenderlo para Ley 21.735.
