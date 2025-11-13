# Auditoría Fase 8 - Gaps Regulatorios 2025

## Resumen Ejecutivo
- ❌ La reforma previsional Ley 21.735 (aporte patronal 6 % y redistribución 0,9 % + 0,1 %) no está implementada: el modelo de indicadores y los contratos carecen de campos y reglas para estos nuevos conceptos, y las pruebas automatizadas dedicadas a la ley fallan por funciones no disponibles. `l10n_cl_hr/model/hr_indicadores_previsionales.py:56`, `l10n_cl_hr/model/hr_contract.py:45`, `evidencias/sprint1_tests_analysis.log:73`
- ⚠️ El wizard Previred y las exportaciones continúan usando el layout tradicional (campos TRIBU, TOTIM, imponibles AFP) sin columnas para el nuevo aporte solidario ni validaciones de fecha de entrada en vigencia, lo que impedirá cumplir con el formato que la plataforma exigirá desde agosto 2025. `l10n_cl_hr/wizard/wizard_export_csv_previred.py:130`
- ⚠️ El módulo de indicadores financieros sigue integrándose con la API SBIF, organismo que ya no opera de forma independiente; desde 2025 la CMF administra dichos datos y requiere API keys y endpoints distintos. `l10n_cl_financial_indicators/README.md:17`

## Análisis Detallado de Brechas

| Cambio Regulatorio 2025 | Requisito | Situación Actual | Evidencia |
|-------------------------|-----------|------------------|-----------|
| **Ley 21.735 – Aporte Patronal 6 %** | Registrar y calcular 0,1 % a cuentas individuales y 5,9 % a seguro social desde agosto 2025, parametrizable por indicadores. | `hr.indicadores` solo define tasas tradicionales (AFP, SIS, contrato plazo fijo/indefinido) y no posee campos para aportes solidarios; `hr.contract` no tiene flags ni montos para el nuevo aporte patronal. | `l10n_cl_hr/model/hr_indicadores_previsionales.py:56`, `l10n_cl_hr/model/hr_contract.py:45`
| **Ley 21.735 – Reglas de Cálculo** | Nuevas reglas salariales deben distribuir el 6 % en códigos separados y validar tramos PGU. | El archivo `l10n_cl_hr_payroll_data.xml` contiene reglas hasta `hr_rule_38_2` (anticipo/prestamos) sin referencias a cuentas solidarias; ninguno de los códigos calcula porcentajes adicionales. | `l10n_cl_hr/data/l10n_cl_hr_payroll_data.xml:338`
| **Ley 21.735 – Conformidad de Pruebas** | Los tests deberían verificar transición antes/después de agosto 2025. | El log `sprint1_tests_analysis.log` muestra fallas en todos los casos de `test_ley21735_reforma_pensiones`, indicando ausencia de implementación. | `evidencias/sprint1_tests_analysis.log:73`
| **Previred 2025** | Nuevo archivo debe incluir columnas para aporte solidario y seguro social, además de validaciones de movimientos. | El wizard `wizard.export.csv.previred` solo llena imponibles (`TOTIM`, `LIC`) y tramos familiares; no genera líneas adicionales ni valida fechas de vigencia. | `l10n_cl_hr/wizard/wizard_export_csv_previred.py:130`
| **Indicadores Financieros CMF** | Desde 2020 la CMF reemplazó a SBIF; las APIs antiguas se desactivarán definitivamente en 2025. | README indica integración exclusiva con “SBIF webservices” y direcciona a `api.sbif.cl`, sin soporte para CMF ni actualización automática de UF/UTM cuando cambie el endpoint. | `l10n_cl_financial_indicators/README.md:17`

## Recomendaciones
- Incorporar campos y reglas para la Ley 21.735 dentro de `hr.indicadores`, `hr.contract` y `l10n_cl_hr_payroll_data.xml`, junto con pruebas que cubran la entrada en vigencia (agosto 2025) y cálculos diferenciados (0,1 % cuenta individual, 0,9 % seguro social, 5 % seguro social colectivo). 
- Actualizar el wizard Previred para generar el layout 2025 (nuevas columnas, validaciones de fechas, códigos de movimiento) y permitir archivos híbridos durante el periodo de transición.
- Migrar el módulo de indicadores financieros a la API pública de la CMF o al servicio del Banco Central, incluyendo parámetros para la nueva clave y tratadores de error cuando el endpoint SBIF deje de responder.
