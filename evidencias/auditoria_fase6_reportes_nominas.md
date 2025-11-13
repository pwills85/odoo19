# Auditoría Fase 6 - Reportes y Exportaciones (Nómina)

## Resumen Ejecutivo
- ✅ El módulo provee wizards específicos para las salidas exigidas por entes reguladores: archivo Previred (texto plano), Libro de Remuneraciones (PDF A4 apaisado) y Centralización Contable (Excel), todos accesibles desde el menú de reportes. `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:4`, `l10n_cl_hr/views/hr_salary_books.xml:4`, `l10n_cl_hr/views/account_centralized_export.xml:47`
- ✅ Cada wizard controla la captura mínima necesaria (fechas, formato de salida) y expone botones de acción claros (“Generar reporte”, “Print”), lo que estandariza la generación mensual de evidencias. `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:17`, `l10n_cl_hr/views/hr_salary_books.xml:28`

## Análisis Detallado

| Reporte / Exportación | Flujo de Usuario | Salida | Referencia |
|-----------------------|------------------|--------|------------|
| **Previred CSV** | Menú `Reports → Previred` abre el wizard modal con rangos de fechas; botón `Generar reporte` ejecuta el método `action_generate_csv` y llena campos `file_data`/`file_name` para descarga inmediata. | Archivo `.csv` compatible con plataforma Previred (campos calculados por el wizard `wizard.export.csv.previred`). | `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:4`
| **Libro de Remuneraciones** | Wizard “Libro de Remuneraciones” solicita solo la fecha de corte y ofrece botón `Print` para disparar el reporte QWeb `report_hrsalarybymonth`; menú se ubica en `Reports`. | PDF formato A4 horizontal definido en `report_paper_format_nuevo`, firmado como evidencia de haberes. | `l10n_cl_hr/views/hr_salary_books.xml:4`, `l10n_cl_hr/views/hr_salary_books.xml:38`
| **Centralización Contable** | Wizard “Centralización Contable” recolecta rango de fechas y cuentas contables, luego genera un Excel (`excel_file`) listo para importar en contabilidad. | Archivo `.xlsx` con asientos agregados por centro de costo. | `l10n_cl_hr/views/account_centralized_export.xml:47`
| **Libro Empleados (hr.salary.employee.month)** | Desde el mismo wizard se puede imprimir registro de haberes mensual, cumpliendo con el Libro de Remuneraciones exigido por la Dirección del Trabajo. | PDF con layout personalizado (misma ruta que reporte principal). | `l10n_cl_hr/views/hr_salary_books.xml:21`

## Conclusiones
- Los wizards encapsulan toda la lógica de exportación (fechas, formato, descarga) y sus menús dedicados permiten que RRHH ejecute reportes sin soporte técnico; deben preservarse o portar la misma UX a Odoo 19.
- El formato PDF personalizado y el CSV Previred aseguran compatibilidad legal; cualquier cambio de plataforma debe validar que los archivos mantengan estructura y campos calculados.
