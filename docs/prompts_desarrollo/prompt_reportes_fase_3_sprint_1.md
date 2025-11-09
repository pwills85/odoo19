# PROMPT: Módulo Reportes - Aprobación de Fase 3 y Ejecución de Sprint 1

## 1. Contexto

Tu trabajo ha sido excepcional. No solo has completado la Fase 2 de manera impecable, sino que has creado proactivamente un "Plan Maestro" detallado y profesional para la Fase 3. Este es exactamente el nivel de iniciativa y planificación que buscamos. El desglose en sprints y la arquitectura técnica propuesta son excelentes.

## 2. Decisión y Objetivo Principal

**Aprobamos tu "Plan Maestro para la Fase 3" sin modificaciones.**

El objetivo de este prompt es dar la orden de ejecución, combinando tus opciones 3 y 1: primero, formalizar la planificación que has creado en el repositorio y, segundo, lanzar inmediatamente el **Sprint 1** de la Fase 3.

## 3. Plan de Ejecución Inmediato

Por favor, ejecuta las siguientes tareas en orden.

### Tarea 1: Formalizar y Commitear la Planificación (Opción 3)

**Descripción:** Antes de escribir nuevo código de funcionalidades, es crucial que tu excelente trabajo de planificación quede registrado en el historial del proyecto.

- **Acción:** Crea un único commit que guarde los documentos de planificación que has generado.
- **Archivos a incluir:**
    - `docs/sprints_log/l10n_cl_financial_reports/FASE2_COMPLETADA.md`
    - `docs/sprints_log/l10n_cl_financial_reports/FASE3_PLAN_MAESTRO.md`
- **Mensaje de Commit (Obligatorio):**
  ```
  docs(reports): add phase 2 completion report and phase 3 master plan

  - Documents the successful completion of all Phase 2 tasks, including metrics and lessons learned.
  - Adds the detailed master plan for Phase 3, outlining the 4-sprint strategy, architecture, and deliverables for implementing core Chilean financial reports.
  ```

### Tarea 2: Ejecutar Sprint 1 del Plan Maestro (Opción 1)

**Descripción:** Inmediatamente después del commit anterior, comienza el desarrollo del Sprint 1, tal como lo definiste en tu plan. El objetivo es implementar los dos reportes financieros más fundamentales.

- **User Stories a Implementar:**
    1.  **US 3.1: Balance General Clasificado**
    2.  **US 3.2: Estado de Resultados**

- **Recordatorio de Requisitos Clave (de tu Plan Maestro):**
    - **Framework:** Utiliza el framework `account.report` de Odoo 19 para construir ambos reportes.
    - **Interactividad:** La capacidad de **drill-down** desde cualquier línea del reporte hasta los asientos contables es un requisito no negociable.
    - **Funcionalidad:** Implementa filtros por fecha y la capacidad de comparar periodos.
    - **Exportación:** Ambos reportes deben poder exportarse a PDF y XLSX.
    - **Calidad:** La lógica de negocio debe tener una cobertura de tests superior al 90%.

- **Commits:** Realiza commits atómicos y descriptivos para el desarrollo de estas funcionalidades. Por ejemplo: `feat(reports): implement balance sheet report` y `feat(reports): implement income statement report`.

## 4. Entregables Esperados para este Prompt

1.  **Un commit de documentación** con los archivos de planificación.
2.  **Uno o más commits de funcionalidad** implementando completamente el Balance General y el Estado de Resultados.
3.  **Pruebas unitarias** exhaustivas que validen los cálculos y la estructura de ambos reportes.
4.  Al finalizar, un **informe de cierre de Sprint 1** que detalle los logros y confirme que los entregables están completos.
