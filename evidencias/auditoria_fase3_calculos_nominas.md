# Auditoría Fase 3 - Cálculos y Lógica de Negocio (Nómina)

## Resumen Ejecutivo
- ✅ Las reglas salariales principales (SUELDO base, ajuste legal, bonos imponibles y horas extra) se expresan en XML con fórmulas Python que consideran días trabajados, topes UF y tipos de contrato, garantizando cumplimiento de Sueldo Mínimo y semana corrida. `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:35`, `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:73`
- ✅ Los aportes previsionales (AFP, SIS, Seguro de Cesantía, Salud) se calculan dinámicamente usando indicadores vigentes y banderas por contrato, incluyendo topes imponibles y diferencias entre plazos fijos/indefinidos. `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:317`, `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:338`, `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:379`, `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:500`
- ✅ El impuesto único se determina mediante tramos progresivos expresados en UTM, descontando cantidades fijas por tramo según tablas oficiales y registrándose en el contribuyente SII. `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:569`
- ✅ El wizard Previred replica estas reglas al exportar: calcula tramos de asignación familiar, imponibles topeados y movimiento de personal para cada línea del archivo plano. `l10n_cl_hr/wizard/wizard_export_csv_previred.py:130`, `l10n_cl_hr/wizard/wizard_export_csv_previred.py:185`

## Análisis Detallado

### 1. Ingresos Imponibles y Beneficios

| Regla | Lógica | Referencia |
|-------|--------|------------|
| `hr_rule_1` (SUELDO BASE) | Paga el mayor entre sueldo contractual y tope imponible AFP (UF) prorrateado por días trabajados, con excepciones para contratos empresariales. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:35`
| `hr_rule_2` (Ajuste Ley Sueldo Base) | Incrementa remuneración cuando el sueldo contractual es inferior al mínimo mensual, ajustando por días trabajados. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:59`
| `hr_rule_4` (Horas extra art. 32) | Multiplica horas registradas (`inputs.HEX50`) por factor 0.00777777 del sueldo base para obtener el recargo 50 %. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:83`
| `hr_rule_6` (Gratificación Legal) | Calcula 25 % del imponible con tope 4,75 sueldos mínimos/12, omitiendo contratos empresariales; utiliza indicadores cargados del mes. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:101`
| `hr_rule_12` (Asignación familiar) | Determina tramo A/B/C según renta imponible vs. indicadores y multiplica montos por número de cargas, prorrateado por días trabajados. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:177`

### 2. Aportes Previsionales y Salud

| Regla | Descripción funcional | Referencia |
|-------|----------------------|------------|
| `hr_rule_20` (APV) | Convierte montos pactados en UF/CLP a pesos y aplica tope mensual APV antes de descontar. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:317`
| `hr_rule_21` (Seguro Cesantía Empleador) | Usa tipo de contrato para aplicar tasa distinta (plazo fijo vs. indefinido) sobre `TOTIM`, limitado por tope imponible de seguro cesantía. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:338`
| `hr_rule_22` (SIS) | Selecciona tasa SIS según AFP del contrato y descuenta sólo hasta el tope imponible AFP, respetando banderas `sin_afp_sis`. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:379`
| `hr_rule_27` (Adicional Isapre) | Calcula diferencia entre plan pactado en UF y el 7 % legal (regla `SALUD`), prorrateando por días trabajados. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:500`
| `hr_rule_33` / `hr_rule_34` (Caja Compensación / FONASA) | Para afiliados a FONASA, aplica tasas oficiales sobre imponible hasta tope de salud definido en indicadores; registra contribución en Previred. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:533`, `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:550`

### 3. Impuesto Único y Deducciones

| Elemento | Lógica | Referencia |
|----------|--------|------------|
| `hr_rule_35` (Tributable) | Ajusta la base tributaria restando salud, previsión y seguro cesantía; limita descuentos a tope UF cuando corresponde. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:569`
| `hr_rule_36` (Impuesto Único) | Evalúa ocho tramos expresados en múltiplos de UTM y aplica tasa marginal con rebaja fija para cada rango (4 % a 40 %). | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:590`
| `hr_rule_37` (Total descuentos legales) | Suma categorías PREV, SALUD y DED para mostrar un total consolidado en la liquidación. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:617`
| `hr_rule_38/38_1/38_2` (Anticipos y préstamos) | Descuentan anticipos pactados y préstamos ingresados vía inputs para reflejar descuentos no legales pero recurrentes. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:629`

### 4. Exportación Previred

| Función | Uso | Referencia |
|---------|-----|------------|
| `get_tramo_asignacion_familiar` | Determina tramo (A–D) para cada trabajador según renta y cargas antes de conformar la línea CSV. | `l10n_cl_hr/wizard/wizard_export_csv_previred.py:154`
| `get_imponible_afp` / `_2` | Calcula imponible AFP según topes y reemplaza por licencias (LIC) cuando corresponde; reutilizado para completar columnas del archivo. | `l10n_cl_hr/wizard/wizard_export_csv_previred.py:185`
| `get_tipo_trabajador`, `get_regimen_provisional`, `get_dias_trabajados` | Traducen atributos del contrato a códigos Previred (pensionado, AFP vs. SIP, días cotizados). | `l10n_cl_hr/wizard/wizard_export_csv_previred.py:117`
| Ensamblaje CSV (`show_view` → generación) | Recorre nóminas, obtiene valores por código (`get_payslip_lines_value_2`) y arma filas que incluyen imponibles, cargas y aportes calculados. | `l10n_cl_hr/wizard/wizard_export_csv_previred.py:333`

## Conclusiones
- Las fórmulas codificadas en XML dependen directamente de campos `contract` e `indicadores`; cualquier refactor debe migrar ambos para no perder la lógica de topes, tramos y condiciones por tipo de contrato.
- El Impuesto Único se implementa como tabla explícita dentro de `hr_rule_36`; actualizarla es tan simple como modificar la fórmula, por lo que conviene trasladar este patrón a Odoo 19.
- El wizard Previred no sólo exporta datos: recalcula imponibles y tramos para cumplir el estándar del archivo, por lo que debe mantenerse o replicarse en la nueva versión para evitar reprocesos manuales.
