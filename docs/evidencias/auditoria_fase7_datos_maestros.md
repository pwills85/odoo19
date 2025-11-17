# Auditoría Fase 7 - Datos Maestros y Configuración

## Resumen Ejecutivo
- ✅ Los módulos de facturación cargan catálogos completos del SII (clases de documento, letras, responsabilidades, oficinas regionales, actividades económicas), asegurando que las listas desplegables siempre usen códigos oficiales desde el primer arranque. `l10n_cl_fe/data/sii.document_class.csv:1`, `l10n_cl_fe/data/sii.document_letter.csv:1`, `l10n_cl_fe/data/responsability.xml:4`, `l10n_cl_fe/data/sii.regional.offices.csv:1`
- ✅ La nómina chilena inicializa tablas previsionales (AFP, ISAPRE, CCAF, APV, mutuales) y los indicadores mensuales que alimentan topes, tasas y montos, además de calendarios y tipos de contrato/empleado. `l10n_cl_hr/data/l10n_cl_hr_afp.xml:8`, `l10n_cl_hr/data/l10n_cl_hr_isapre.xml:8`, `l10n_cl_hr/data/l10n_cl_hr_ccaf.xml:6`, `l10n_cl_hr/data/l10n_cl_hr_indicadores.xml:6`

## Análisis Detallado

### Facturación Electrónica (DTE)

| Dataset | Contenido | Uso | Referencia |
|---------|-----------|-----|------------|
| `sii.document_class.csv` | Define todas las clases de documentos (29, 33, 34, 43, 46, etc.) con banderas `dte`, prefijos y tipo de documento. | Se usa para poblar `sii.document_class` y relacionar secuencias, diarios y wizards. | `l10n_cl_fe/data/sii.document_class.csv:1`
| `sii.document_letter.csv` | Letras tributarias (A, C, M, etc.) con relaciones a responsabilidades emisoras/receptoras. | Determina si la factura discrimina IVA y qué responsables pueden usarla. | `l10n_cl_fe/data/sii.document_letter.csv:1`
| `responsability.xml` | Responsabilidades tributarias (Consumidor Final, IVA Afecto, Extranjero). | Se enlazan con compañías/partners y controlan restricciones de documentos. | `l10n_cl_fe/data/responsability.xml:4`
| `partner.activities.csv` | Tabla ACTECO con códigos y descripciones traducibles. | Alimenta los campos `activity_description` de partners y diarios. | `l10n_cl_fe/data/partner.activities.csv:1`
| `sii.regional.offices.csv` | Oficinas regionales y comunas asociadas para parametrizar formulario 4415. | Se seleccionan en `res.company` para definir la oficina SII correspondiente. | `l10n_cl_fe/data/sii.regional.offices.csv:1`
| `counties_data.xml` / `country.xml` | Comunas y países con códigos SII necesarios para direcciones y sucursales. | Permiten validar combinaciones ciudad/comuna exigidas en el XML DTE. | `l10n_cl_fe/data/counties_data.xml:3`
| `decimal_precision.xml`, `res.currency.csv` | Define precisión decimal y monedas especiales (UF, UTM) usadas por libros e indicadores. | Asegura consistencia en cálculos de totales y conversiones. | `l10n_cl_fe/data/res.currency.csv:1`

### Nómina Chilena

| Dataset | Contenido | Uso | Referencia |
|---------|-----------|-----|------------|
| `l10n_cl_hr_indicadores.xml` | Registros periódicos con UF, UTM, IPC, tramos de asignación familiar y tasas AFP/SIS/mutuales. | Se vinculan a `hr.indicadores` y son seleccionados en payslip/payslip run para calcular topes y tasas del periodo. | `l10n_cl_hr/data/l10n_cl_hr_indicadores.xml:6`
| `l10n_cl_hr_afp.xml` | Lista de AFP con código, tasa trabajadora, SIS y tasa para independientes. | Alimenta el maestro `hr.afp` usado en contratos y reglas `hr_rule_20+`. | `l10n_cl_hr/data/l10n_cl_hr_afp.xml:8`
| `l10n_cl_hr_isapre.xml` | Catálogo de ISAPRE (incluye FONASA) con códigos y RUT institucional. | Se selecciona en contratos para determinar cálculos de salud e integrarse con Previred. | `l10n_cl_hr/data/l10n_cl_hr_isapre.xml:8`
| `l10n_cl_hr_ccaf.xml`, `l10n_cl_hr_mutual.xml`, `l10n_cl_hr_apv.xml` | Cajas de compensación, mutuales y entidades APV autorizadas. | Permiten parametrizar contratos y alimentar exportes contables y Previred sin cargar manualmente. | `l10n_cl_hr/data/l10n_cl_hr_ccaf.xml:6`, `l10n_cl_hr/data/l10n_cl_hr_mutual.xml:6`, `l10n_cl_hr/data/l10n_cl_hr_apv.xml:7`
| `hr_type_employee.xml`, `hr_contract_type.xml`, `hr_type_employee` data | Tipos de empleado y contrato predefinidos (Sueldo Empresarial, Plazo Fijo, etc.). | Referenciados por reglas salariales para determinar tasas y exenciones. | `l10n_cl_hr/data/hr_contract_type.xml:4`
| `hr_centros_costos.xml`, `resource_calendar_attendance.xml` | Catálogo de centros de costo y calendario mensual chileno. | Se enlazan en contratos para controlar imputación y cálculo de días trabajados. | `l10n_cl_hr/data/hr_centros_costos.xml:4`

## Conclusiones
- Los datos maestros cargados por defecto son fundamentales para operar inmediatamente en producción (no depende de carga manual). Al migrar, se debe garantizar que estas tablas se mantengan sincronizadas con sus equivalentes en Odoo 19 o se replique el script de carga.
- La actualización periódica (ej. indicadores, tasas AFP) requiere procesos claros; documentar las fuentes y formatos facilitará mantener la solución vigente frente a cambios regulatorios.
