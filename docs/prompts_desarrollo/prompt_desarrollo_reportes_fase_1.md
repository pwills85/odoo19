# Prompt de Desarrollo: Reportes Financieros - FASE 1

**ROL:** Agente Desarrollador Experto en Reportes Financieros para Odoo.

**OBJETIVO:** Ejecutar y completar la **FASE 1: Completitud Tributaria y KPIs** del módulo `l10n_cl_financial_reports`. El objetivo es construir sobre la base técnica de la Fase 0 para entregar valor funcional a través de la expansión de los formularios F22/F29 y la creación de un nuevo Dashboard de KPIs financieros.

**CONTEXTO GENERAL:**
Este prompt inicia la Fase 1, tras el éxito de la Fase 0 ("Wiring y Sanidad"). Se deben aplicar los mismos principios de calidad, testing y arquitectura. Todas las "Máximas de Desarrollo y Contexto Operativo" (Estándares Odoo 19 CE, Integración, Pruebas en Docker, etc.) siguen plenamente vigentes.

**ENTREGABLE FINAL:**
- Commits separados para cada una de las 5 tareas principales de la fase.
- Cobertura de tests unitarios y de integración para toda la nueva funcionalidad.
- Un nuevo script de validación `scripts/validate_phase1.py` que ejecute todos los tests relevantes para esta fase.
- Documentación técnica actualizada (`FASE1_COMPLETADA.md`).

---

### **TAREAS DE DESARROLLO (FASE 1)**

#### **1. Tarea: F29 - Ampliar Modelo y Validaciones**

- **Problema:** El modelo actual del Formulario 29 es básico y carece de campos y validaciones necesarias para una declaración completa.
- **Instrucciones Técnicas:**
    1.  **Análisis de Campos:** Revisa la especificación oficial del Formulario 29 del SII e identifica al menos 10 campos críticos faltantes (ej: créditos especiales, retenciones de segunda categoría, etc.).
    2.  **Extensión del Modelo:** Agrega los campos identificados al modelo de datos del F29.
    3.  **Validaciones de Coherencia:** Implementa 3 nuevas `constraints` (Python o SQL) que aseguren la integridad entre los campos. Por ejemplo, una validación que impida ingresar un crédito si no existe un débito asociado.
    4.  **Actualización de Vistas:** Modifica la vista de formulario del F29 para incluir los nuevos campos, agrupándolos de manera lógica y usable.
- **Criterios de Aceptación (Tests):**
    - Añade tests que verifiquen que los nuevos campos se guardan y leen correctamente.
    - Añade tests específicos que provoquen la falla de cada una de las 3 nuevas `constraints` para asegurar que funcionan como se espera.

---

#### **2. Tarea: F22 - Robustecer con Wizard y Utils**

- **Problema:** La configuración del Formulario 22 es manual y propensa a errores; no hay utilidades de RUT centralizadas.
- **Instrucciones Técnicas:**
    1.  **Wizard de Configuración:**
        - Crea un `TransientModel` (wizard) para la configuración inicial del F22.
        - El wizard debe permitir al usuario mapear cuentas contables a las líneas principales del F22 y establecer el año fiscal de trabajo.
        - Añade un `menuitem` para acceder a este wizard desde el menú de configuración de Contabilidad.
    2.  **Utilidades de RUT:**
        - Crea un nuevo archivo `utils/rut.py` dentro del módulo.
        - Implementa dos funciones: `validate_rut(rut_string)` y `format_rut(rut_string)`, que deben reusar la librería `stdnum` y manejar RUTs con o sin formato.
- **Criterios de Aceptación (Tests):**
    - Añade tests para el wizard que simulen el proceso de configuración y verifiquen que los parámetros se guardan correctamente.
    - Añade tests unitarios para las funciones `validate_rut` y `format_rut` con varios casos de prueba (RUTs válidos, inválidos, con y sin formato).

---

#### **3. Tarea: KPIs Dashboard - Lógica de Cálculo con Cache**

- **Problema:** No existe una forma centralizada y performante de consultar KPIs financieros clave.
- **Instrucciones Técnicas:**
    1.  **Definición de KPIs:** Implementa la lógica de cálculo para los siguientes 5 KPIs:
        - IVA Débito Fiscal Mensual
        - IVA Crédito Fiscal Mensual
        - Total Ventas Netas del Mes
        - Total Compras Netas del Mes
        - PPM Pagado del Mes
    2.  **Lógica de Cálculo y Cache:**
        - Cada cálculo de KPI debe ser un método separado que ejecute consultas SQL eficientes.
        - **Crucial:** Antes de ejecutar la consulta, el método debe intentar obtener el resultado desde el `cache_service` implementado en Fase 0. La clave de cache debe ser `f"finrep:<company_id>:<kpi_code>:<period>"`.
        - Si no hay un valor en cache (cache miss), se ejecuta la consulta y el resultado se guarda en la cache con un TTL de 900 segundos antes de retornarlo.
- **Criterios de Aceptación (Tests):**
    - Añade tests para cada uno de los 5 KPIs, verificando la exactitud del cálculo contra datos de prueba.
    - Añade tests específicos para la lógica de cache, simulando un `cache hit` y un `cache miss` para asegurar que el servicio se utiliza correctamente.

---

#### **4. Tarea: Dashboard - Implementación de Vistas**

- **Problema:** Los KPIs calculados no son visibles para el usuario.
- **Instrucciones Técnicas:**
    1.  **Modelo de Vista:** Crea un modelo no persistente (`models.Model` con `_auto = False`) que sirva como fuente de datos para el dashboard.
    2.  **Acción y Menú:** Crea un `ir.actions.act_window` para el dashboard y un `menuitem` llamado "Dashboard Financiero" en el menú principal de Contabilidad.
    3.  **Vistas Soportadas:** En la acción de ventana, define las siguientes vistas para el modelo no persistente:
        - `kanban`: Para mostrar los KPIs principales como tarjetas de valor.
        - `graph`: Un gráfico de barras que compare Ventas, Compras e IVA del mes.
        - `pivot`: Una tabla pivote para análisis multidimensional.
        - `tree`: Una vista de lista simple de los KPIs y sus valores.
- **Criterios de Aceptación (Tests):**
    - Añade tests "smoke" que intenten cargar cada una de las 4 vistas para asegurar que no hay errores de XML o de definición de campos.

---

#### **5. Tarea: Métricas de Rendimiento Avanzadas**

- **Problema:** No hay una forma estandarizada de medir el rendimiento de los cálculos más costosos.
- **Instrucciones Técnicas:**
    1.  **Decorador de Rendimiento:**
        - Crea un decorador Python `@measure_sql_performance` en un archivo de utilidades.
        - El decorador debe usar el `QueryCounter` de Odoo para contar el número de consultas SQL y el tiempo total de ejecución del método decorado.
    2.  **Aplicación del Decorador:** Aplica el nuevo decorador a todos los métodos de cálculo de KPIs definidos en la Tarea 3.
    3.  **Exportación de Métricas:** Los resultados del decorador (nombre de la función, número de queries, duración en ms) deben ser registrados usando el logger JSON estructurado (implementado en Fase 0) con una clave específica como `"metric_type": "performance"`.
- **Criterios de Aceptación (Tests):**
    - Añade un test que decore una función de prueba, la ejecute y verifique (usando `unittest.mock.patch` en el logger) que se ha registrado un mensaje de log con los datos de rendimiento correctos.
