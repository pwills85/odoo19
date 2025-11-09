# PROMPT: Finalización y Cierre de Brechas P0 - Módulo de Nómina

## 1. Contexto

Hemos perdido comunicación y, tras un análisis del código, se ha determinado el siguiente estado para el módulo `l10n_cl_hr_payroll`:

1.  **Indicadores Económicos**: La lógica para la obtención automática de indicadores (`hr_economic_indicators.py`) está muy avanzada e incluye un cron y la integración con el AI-Service. Sin embargo, **este trabajo no fue confirmado (commit)** en el repositorio.
2.  **Cálculo de APV**: La funcionalidad de Ahorro Previsional Voluntario no ha sido implementada. El archivo `hr_apv.py` solo contiene un modelo de datos básico sin la lógica de cálculo correspondiente.

## 2. Objetivo Principal

**Finalizar por completo la Fase P0.** Esto implica asegurar que todo el trabajo realizado sea confirmado en el repositorio y completar la funcionalidad de APV pendiente.

## 3. Tareas Detalladas

### Tarea 1: Finalizar y Confirmar la Automatización de Indicadores Económicos

1.  **Revisa y Valida el Código Existente**:
    *   Localiza el archivo `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py`.
    *   Asegúrate de que la integración con el AI-Service y el cron (`_run_fetch_indicators_cron`) son robustos y manejan correctamente los casos de éxito y error.
2.  **Crea Tests Unitarios Exhaustivos**:
    *   Añade tests que validen el `_run_fetch_indicators_cron`, simulando tanto respuestas exitosas como fallidas del servicio de IA.
    *   Asegura una cobertura de pruebas superior al 95% para este archivo.
3.  **Confirma tu Trabajo**:
    *   Crea **un único commit** que contenga toda la funcionalidad de indicadores económicos.
    *   **Mensaje de Commit Sugerido**: `feat(payroll): Implementar carga automática de indicadores económicos vía cron y AI-Service.`

### Tarea 2: Implementar y Confirmar el Cálculo de APV

1.  **Desarrolla la Lógica de Cálculo de APV**:
    *   Modifica el modelo `hr.contract.cl` para permitir a un empleado configurar su APV (institución y monto/porcentaje).
    *   Integra el cálculo del APV dentro del proceso de cálculo de la nómina (`hr.payslip`).
    *   El cálculo debe manejar los distintos regímenes de APV (A y B) y sus topes impositivos correspondientes.
2.  **Crea Tests Unitarios**:
    *   Desarrolla pruebas que cubran diferentes escenarios: empleados con y sin APV, distintos montos, y validación de los topes.
3.  **Confirma tu Trabajo**:
    *   Crea **un único commit** para toda la funcionalidad de APV.
    *   **Mensaje de Commit Sugerido**: `feat(payroll): Implementar cálculo de APV en nómina con configuración en contrato.`

## 4. Criterios de Aceptación (Definition of Done)

*   ✅ **Dos commits en total**, uno para Indicadores y otro para APV, presentes en la rama principal.
*   ✅ Los tests unitarios para ambas funcionalidades existen, pasan exitosamente y tienen alta cobertura.
*   ✅ El cálculo de la nómina refleja correctamente los descuentos de APV según la configuración del contrato.
*   ✅ El cron de indicadores económicos es funcional y está cubierto por pruebas.
*   ✅ No queda trabajo sin confirmar en tu entorno local relacionado con estas tareas.
