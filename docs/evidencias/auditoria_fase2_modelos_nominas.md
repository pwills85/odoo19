# Auditoría Fase 2 - Modelos Funcionales de Nómina Chilena

## Resumen Ejecutivo
- ✅ El módulo `l10n_cl_hr` amplía empleados y contratos con los parámetros exigidos por la legislación chilena (AFP, ISAPRE, APV, cargas familiares, tipo de trabajador, centros de costo), permitiendo que cada regla salarial lea datos consistentes directamente desde el contrato. `l10n_cl_hr/model/hr_employee.py:9`, `l10n_cl_hr/model/hr_contract.py:45`
- ✅ Los indicadores previsionales se modelan como registros versionados (`hr.indicadores`) con tasas UF/UTM, topes imponibles y porcentajes por AFP/SIS, lo que habilita cálculos parametrizables y trazables por mes/año. `l10n_cl_hr/model/hr_indicadores_previsionales.py:51`
- ✅ El proceso de liquidaciones se apoya en extensiones de `hr.payslip` y `hr.payslip.run` para capturar códigos Previred, movimientos de personal y vincular cada corrida con un set específico de indicadores, además de wizards para generar archivos planos Previred. `l10n_cl_hr/model/hr_payslip.py:47`, `l10n_cl_hr/model/hr_payslip_run.py:24`, `l10n_cl_hr/wizard/wizard_export_csv_previred.py:27`

## Análisis Detallado

### 1. Identidad del Trabajador y Contratos

| Modelo | Propósito | Campos/Relaciones destacados | Referencia |
|--------|-----------|------------------------------|------------|
| `hr.employee` (extensión) | Estructura nombres compuestos, clasifica tipo de trabajador y valida formato único del RUT al estilo chileno. | Campos `firstname`, `last_name`, `type_id`, `formated_vat`; métodos `_get_computed_name`, `onchange_document` y constraint `_rut_unique`. | `l10n_cl_hr/model/hr_employee.py:9`
| `hr.type.employee` | Maestro de códigos de tipo de trabajador (activo, pensionado, >65) usado en reglas y reportes Previred. | Campos `id_type`, `name`. | `l10n_cl_hr/model/hr_type_employee.py:30`
| `hr.contract` (extensión) | Centraliza parámetros de cálculo: AFP/ISAPRE/APV, moneda de cotización, asignaciones (colación, movilización, viáticos), indicadores de pensionado y banderas para saltar cálculos. | Campos `afp_id`, `isapre_id`, `carga_familiar*`, `sin_afp`, `isapre_moneda`, `aporte_voluntario`, `centro_costo_id`. | `l10n_cl_hr/model/hr_contract.py:45`
| `hr.centroscostos` | Maestro de centros de costo para imputar gastos previsionales y alimentar reportes. | Campos `name` (código) y `desc`. | `l10n_cl_hr/model/hr_centro_costos.py:5`

### 2. Datos Maestros Previsionales y de Salud

| Modelo | Rol funcional | Detalle | Referencia |
|--------|---------------|---------|------------|
| `hr.afp` | Tabla de AFP con códigos, RUT y tasas (trabajador, SIS, independientes) para alimentar reglas y archivos Previred. | Campos `codigo`, `rate`, `sis`, `independiente`. | `l10n_cl_hr/model/hr_afp.py:35`
| `hr.isapre` | Catálogo de aseguradoras de salud con código y RUT para contratos y reportes. | Campos `codigo`, `name`, `rut`. | `l10n_cl_hr/model/hr_isapre.py:31`
| `hr.apv`, `hr.mutualidad`, `hr.ccaf`, `hr.seguro.complementario` | Complementan datos de ahorro voluntario, seguros y cajas de compensación requeridos por la normativa (archivos en `data/` crean registros base). | Campos de nombre/código y tasas según cada entidad. | `l10n_cl_hr/data/l10n_cl_hr_apv.xml:7` *(datos referenciados durante carga)*
| `hr.indicadores` | Registro mensual con UF/UTM, topes imponibles, tramos de asignación familiar, tasas AFP/SIS y parámetros de mutuales; sirve como snapshot que se vincula a payruns/liquidaciones. | Campos `asignacion_familiar_*`, `tasa_afp_*`, `tope_imponible_*`, `uf`, `utm`, `ipc`, `month`, `year`. | `l10n_cl_hr/model/hr_indicadores_previsionales.py:51`

### 3. Procesamiento de Liquidaciones

| Modelo | Función | Elementos Clave | Referencia |
|--------|---------|-----------------|------------|
| `hr.payslip` (extensión) | Cada liquidación guarda el set de indicadores vigente y el código de movimiento de personal reportable a Previred. Incluye override de cálculo de días trabajados para semana corrida. | Campos `indicadores_id`, `movimientos_personal`, `date_start_mp`, `date_end_mp`; método `get_worked_day_lines` ajusta días pagados vs. efectivos. | `l10n_cl_hr/model/hr_payslip.py:47`
| `hr.payslip.run` | Agrupa nóminas por periodo y obliga a seleccionar indicadores/movimiento global para la exportación. | Campos `indicadores_id`, `movimientos_personal`. | `l10n_cl_hr/model/hr_payslip_run.py:24`
| `hr.salary.rule` (extensión) | Añade vigencia `date_start/date_end` a las reglas salariales, permitiendo tener fórmulas históricas según cambios regulatorios. | Campos `date_start`, `date_end`. | `l10n_cl_hr/model/hr_salary_rule.py:34`
| `wizard.export.csv.previred` | Genera el archivo plano Previred, calculando datos como días trabajados, tramo de asignación familiar, imponibles topeados y tipos de trabajador. | Campos `date_from`, `date_to`, `file_data`; métodos `get_regimen_provisional`, `get_dias_trabajados`, `get_imponible_afp`. | `l10n_cl_hr/wizard/wizard_export_csv_previred.py:27`

### 4. Reportes y Registros Complementarios

| Modelo | Objetivo | Referencia |
|--------|----------|------------|
| `hr.form.employee.book` (wizard) | Construye el libro de empleados exigido por la Dirección del Trabajo (campos personales, fechas de ingreso/salida). | `l10n_cl_hr/wizard/hr_form_employee_book.py:1`
| `report.hr.salary.book` (vistas XML) | Reporte PDF de sueldos por mes usando datos de `hr.payslip`. | `l10n_cl_hr/views/hr_salary_books.xml:1`
| `hr.payslip` inputs y worked days | Codificaciones como `WORK100`, `EFF100`, `HEX50`, `HEXDE` se generan en `get_worked_day_lines` para alimentar reglas de horas extra y descuentos. | `l10n_cl_hr/model/hr_payslip.py:80`

## Conclusiones
- El modelo de nómina captura todas las variables legales directamente en contratos e indicadores; mantener estas tablas al migrar es esencial para reproducir cálculos de AFP, salud y asignaciones sin reescribir reglas.
- La separación entre indicadores mensuales y reglas con vigencia facilita aplicar reformas futuras; se recomienda preservar tanto los registros históricos como la lógica que vincula cada payrun a su set de indicadores.
- Los wizards y extensiones de `hr.payslip` orientados a Previred constituyen el puente con los entes reguladores; cualquier reemplazo en Odoo 19 debe cubrir exportes planos, códigos de movimiento y control de topes imponibles.
