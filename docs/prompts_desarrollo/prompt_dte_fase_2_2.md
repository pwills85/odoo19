# PROMPT: Módulo DTE - Ejecución de Fase 2.2 (Emisión de BHE)

## 1. Contexto

Excelente trabajo. La implementación del Dashboard de Monitoreo SII (Fase 2.1) es completa, robusta y sigue todas las mejores prácticas. El commit `e82a57d` es perfecto y la funcionalidad está muy bien documentada en tu reporte.

Ahora, procedemos con la siguiente etapa del plan.

## 2. Objetivo Principal

El objetivo de este prompt es autorizar y guiar la ejecución de la **Fase 2.2**: implementar el flujo de **emisión** de Boletas de Honorarios Electrónicas (BHE), añadiendo esta capacidad crítica al módulo DTE.

## 3. Plan de Ejecución Confirmado

Tu análisis de los requisitos es correcto. Procede con la implementación de la Fase 2.2 (Emisión de BHE), siguiendo la checklist de tareas que tú mismo has delineado.

- **Acción:** Implementar el flujo completo de emisión de BHE.

- **Checklist de Tareas:**
    1.  [ ] **Extender `account.move`:** Añade el soporte para un nuevo tipo de documento que represente una "BHE Emitida".
    2.  [ ] **Añadir Campos Específicos:** Incorpora los campos necesarios como `Retención Tercero` (booleano) y una tasa de retención configurable (con `default` de 13.75%).
    3.  [ ] **Generar XML:** Implementa la lógica para construir el archivo XML de la BHE, asegurando que cumpla estrictamente con el schema oficial del SII.
    4.  [ ] **Integrar Envío:** Conecta la generación del XML con el flujo de envío SOAP existente para la comunicación con el SII.
    5.  [ ] **Añadir Validaciones:** Implementa las validaciones clave (ej. que el receptor sea persona natural con RUT válido).
    6.  [ ] **Crear Pruebas Unitarias:** Desarrolla tests que cubran el cálculo de la retención, la correcta estructura del XML y el flujo de cambio de estados.
    7.  [ ] **Crear Commit:** Al finalizar, agrupa todo el trabajo en un único commit atómico con el mensaje: `feat(dte): add electronic fee receipt (BHE) emission`.

## 4. Entregables Esperados

1.  **Un commit único** con la funcionalidad completa de emisión de BHE.
2.  **Pruebas unitarias** que aseguren la calidad y robustez de la nueva funcionalidad.
3.  Un **informe de progreso** al finalizar esta fase, similar al que has entregado para la Fase 2.1.
