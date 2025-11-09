# Prompt de Desarrollo: Cierre de Brechas P0 de Nómina Chilena

**ROL:** Agente Desarrollador Experto en Nómina Chilena para Odoo.

**OBJETIVO:** Completar el 100% de las tareas críticas de la fase P0 del módulo `l10n_cl_hr_payroll`, cerrando las brechas pendientes de APV (Ahorro Previsional Voluntario) e Indicadores Económicos para alcanzar la estabilidad base requerida antes de iniciar el sprint P1 (Finiquito y Previred).

**CONTEXTO GENERAL:**
Este prompt es la continuación directa de la sesión del 2025-11-07, donde se completaron con éxito las tareas P0-1, P0-3 y P0-5. El objetivo es aplicar los mismos patrones de alta calidad (modelos parametrizados, versionamiento, SRP, tests robustos y CI gates) para finalizar las tareas restantes de la fase P0. Todas las "Máximas de Desarrollo y Contexto Operativo" previamente definidas siguen vigentes.

**ENTREGABLE FINAL:**
- Commits separados y claros para cada tarea (P0-2 y P0-4).
- Cobertura de tests unitarios para toda la nueva funcionalidad.
- Todos los tests existentes y nuevos, incluyendo los CI gates (`ci_gate_p0.sh`), deben pasar con éxito.
- Documentación técnica actualizada si se introducen nuevos modelos o configuraciones complejas.

---

### **TAREAS DE DESARROLLO (CIERRE FASE P0)**

#### **1. Tarea P0-2: Implementación de APV (Ahorro Previsional Voluntario) - PRIORIDAD CRÍTICA**

- **Problema:** El sistema no calcula el APV, resultando en liquidaciones de sueldo incorrectas para empleados con este beneficio.
- **Instrucciones Técnicas:**
    1.  **Extensión del Modelo de Contrato:** Añade campos al modelo `hr.contract` para gestionar el APV de un empleado:
        - `l10n_cl_apv_institution_id`: `Many2one` a un nuevo modelo `l10n_cl.apv.institution` (para almacenar AFPs, Bancos, etc.).
        - `l10n_cl_apv_regime`: `Selection` con opciones `[('A', 'Régimen A'), ('B', 'Régimen B')]`.
        - `l10n_cl_apv_amount`: `Monetary` para el monto de la cotización.
        - `l10n_cl_apv_amount_type`: `Selection` con `[('fixed', 'Monto Fijo CLP'), ('percent', 'Porcentaje RLI'), ('uf', 'Monto en UF')]`.
    2.  **Nueva Regla Salarial (Salary Rule):**
        - Crea una nueva regla salarial `APV_CONTRIBUTION` que se ejecute después del cálculo de la Renta Líquida Imponible (RLI).
        - La lógica de la regla (en Python) debe calcular el monto en CLP, convirtiendo desde UF si es necesario, usando el valor del indicador económico del mes.
    3.  **Ajuste del Cálculo de Impuestos:**
        - **Régimen A:** El resultado de la regla `APV_CONTRIBUTION` debe ser una entrada que se reste de la base imponible del Impuesto Único. Modifica la categoría de la regla para que se aplique antes del cálculo del impuesto (`TAX_CALC`).
        - **Régimen B:** La contribución no afecta la base imponible. Debe aparecer como un descuento en la liquidación, pero no alterar el cálculo de impuestos.
    4.  **Implementación de Topes Legales:**
        - Crea un modelo parametrizado (similar a `hr.tax.bracket`) para los topes mensuales y anuales del APV (ej: `l10n_cl.legal.caps` con `code='APV_CAP_MONTHLY'`).
        - La lógica de la regla salarial debe consultar este modelo y limitar la contribución deducible de impuestos al tope correspondiente.
- **Criterios de Aceptación (Tests):**
    - Crea un nuevo archivo de test `tests/test_apv_calculation.py`.
    - Añade un mínimo de **8 tests** (`TransactionCase`) que cubran:
        1.  Cálculo correcto para un empleado con APV Régimen A.
        2.  Cálculo correcto para un empleado con APV Régimen B.
        3.  Un empleado con aporte en UF, verificando la conversión a CLP.
        4.  Un empleado cuyo aporte supera el tope mensual (el beneficio tributario debe limitarse al tope).
        5.  Un empleado cuyo aporte acumulado en el año supera el tope anual.
        6.  Un empleado sin APV (no debe haber ningún cálculo relacionado).
        7.  La correcta asignación de la rebaja tributaria solo para el Régimen A.
        8.  La correcta visualización del descuento en la liquidación para ambos regímenes.

---

#### **2. Tarea P0-4: Automatización Robusta de Indicadores Económicos**

- **Problema:** La actualización de indicadores económicos (UF, UTM, etc.) es manual, creando un riesgo de cálculos con datos desactualizados.
- **Instrucciones Técnicas:**
    1.  **Creación de Cron Job:**
        - En un archivo XML de datos (ej: `data/ir_cron_data.xml`), define un `ir.cron` para la actualización automática.
        - **Planificación:** `0 5 1 * *` (a las 05:00 AM del primer día de cada mes).
        - **Acción a ejecutar:** Una nueva función en el modelo `hr.economic.indicators`, por ejemplo, `_run_fetch_indicators_cron()`.
    2.  **Lógica de Fetching con Reintentos:**
        - El método `_run_fetch_indicators_cron()` debe contener la lógica para conectarse a una API externa (ej: `mindicador.cl`).
        - Implementa un bucle de reintentos (máximo 3) con un `backoff` exponencial (ej: `time.sleep(5 * retry_count)`) si la API falla (errores de red, HTTP 5xx).
        - El método debe ser **idempotente**: si se ejecuta varias veces para el mismo mes, no debe crear registros duplicados. Usa `search` o `search_count` para verificar si el indicador para ese día/mes ya existe.
    3.  **Wizard de Carga Manual (Fallback):**
        - Crea un nuevo `TransientModel` (wizard) para la carga manual de indicadores desde un archivo CSV.
        - El wizard debe tener un campo `Binary` para subir el archivo y un botón "Importar".
        - La lógica de importación debe parsear el CSV (con columnas `fecha`, `codigo_indicador`, `valor`) y crear los registros en `hr.economic.indicators`.
        - Añade un `ir.actions.act_window` y un `menuitem` para que este wizard sea accesible desde el menú de Configuración de Nómina.
- **Criterios de Aceptación (Tests):**
    - Crea un nuevo archivo de test `tests/test_indicator_automation.py`.
    - Añade un mínimo de **5 tests** que cubran:
        1.  Que el cron job se crea correctamente en la base de datos al instalar/actualizar el módulo.
        2.  La lógica de fetch maneja una respuesta exitosa de la API (usando `unittest.mock.patch` para simular la API).
        3.  La lógica de fetch maneja un fallo de la API y ejecuta los reintentos.
        4.  El wizard de importación crea correctamente los indicadores a partir de un archivo CSV de ejemplo.
        5.  La idempotencia del método del cron (al llamarlo dos veces, solo se crean registros una vez).
