# Auditoría Fase 4 - Vistas y Flujos de Usuario (Nómina)

## Resumen Ejecutivo
- ✅ Las vistas de empleados y contratos se redefinen para capturar información chilena obligatoria (nombres separados, RUT formateado, tipo de trabajador, salud/APV, asignaciones), proporcionando pestañas específicas y campos requeridos. `l10n_cl_hr/views/hr_employee.xml:4`, `l10n_cl_hr/views/hr_contract_view.xml:4`
- ✅ Las liquidaciones incorporan selección de indicadores previsionales y códigos de movimiento Previred directamente en el formulario, asegurando que cada payslip quede asociado a su set regulatorio antes de calcular o exportar. `l10n_cl_hr/views/hr_payslip_view.xml:4`
- ✅ El wizard de exportación Previred ofrece un flujo de dos fechas + descarga de archivo, accesible desde el menú de reportes de nómina chilena, lo que simplifica la generación mensual exigida por la Superintendencia. `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:4`

## Análisis Detallado

### 1. Empleados

| Vista | Experiencia | Referencia |
|-------|-------------|------------|
| `view_employee_form` (herencia) | Reemplaza el nombre libre por campos `firstname`, `middle_name`, `last_name`, `mothers_name`, exige identificación y país, e inserta `type_id` antes del departamento para categorizar al trabajador. | `l10n_cl_hr/views/hr_employee.xml:4`
| Reglas de visualización | La etiqueta `name` se oculta para evitar duplicidad y el calendario laboral se fija al recurso mensual chileno. | `l10n_cl_hr/views/hr_employee.xml:21`

### 2. Contratos

| Vista | Funcionalidad | Referencia |
|-------|---------------|------------|
| `hr_contract_chile_view` | Inserta campos de asignaciones (colación, movilización, viáticos), anticipos y gratificación manual al lado de `wage`. | `l10n_cl_hr/views/hr_contract_view.xml:9`
| Pestañas nuevas | Añade pestaña “Carga Familiar” con campos para tramos y una pestaña “Salud” donde se configuran ISAPRE, moneda, FUN, APV y parámetros de aporte/forma de pago. | `l10n_cl_hr/views/hr_contract_view.xml:57`, `l10n_cl_hr/views/hr_contract_view.xml:65`
| Validaciones | Hace obligatorios campos como `isapre_id` y reemplaza `resource_calendar_id` por el calendario mensual chileno para coherencia con semana corrida. | `l10n_cl_hr/views/hr_contract_view.xml:54`

### 3. Liquidaciones

| Vista | Elementos Clave | Referencia |
|-------|-----------------|------------|
| `view_hr_payslip_inherit_form4` | Añade `indicadores_id` (obligatorio) después del campo “Pagado” para forzar la selección del snapshot mensual, y expone `movimientos_personal` con fechas inicio/fin requeridas cuando aplica, cumpliendo el registro Previred. | `l10n_cl_hr/views/hr_payslip_view.xml:4`
| Líneas de nómina | Oculta la columna `rate` en el árbol de líneas para simplificar la visualización, ya que las reglas chilenas suelen usar porcentajes codificados. | `l10n_cl_hr/views/hr_payslip_view.xml:23`

### 4. Reportes / Wizards

| Vista | Uso | Referencia |
|-------|-----|------------|
| `wizard_export_csv_previred_form_view` | Formulario modal con fechas “Desde/Hasta”, campos de archivo binario y botones “Generar reporte” / “Cerrar”; se lanza desde el menú `Previred` dentro de Reportes de Nómina CL. | `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:4`
| Acción y menú | `action_wizard_export_csv_previred_tree_view` abre el wizard en modo modal (`target='new'`), y el menú `wizard_export_csv_menu` lo expone dentro de `menu_cl_hr_payroll_reports`. | `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:27`

## Conclusiones
- Las vistas adaptadas aseguran que la captura de datos (empleado/contrato) cumpla requisitos locales antes de procesar nóminas, minimizando errores en cálculos posteriores.
- Integrar la selección de indicadores y movimientos en el payslip evita omisiones al generar reportes Previred; esta interacción debe preservarse en Odoo 19 para mantener la trazabilidad.
- El wizard Previred constituye el punto final del flujo operativo; mantener su menú dedicado y experiencia modal permitirá a RRHH seguir exportando archivos oficiales sin recurrir a herramientas externas.
