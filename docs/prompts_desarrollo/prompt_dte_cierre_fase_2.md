# PROMPT: Módulo DTE - Ejecución y Cierre de Brechas de Fase 2

## 1. Contexto

Has realizado un análisis de brechas excepcional y preciso. Tu informe detalla perfectamente el trabajo restante para completar la Fase 2 del módulo `l10n_cl_dte`. Este prompt sirve como una confirmación formal de tu análisis y una orden directa para ejecutar el plan de implementación que has propuesto.

Tu diagnóstico es correcto en los tres puntos clave:
1.  **Dashboard (US 2.1):** Se requiere un nuevo dashboard enfocado en la gestión y monitoreo de DTEs con el SII, no un dashboard de rentabilidad.
2.  **Boletas de Honorarios (US 2.2):** La funcionalidad existente es de *recepción*. La brecha a cerrar es la implementación del flujo de *emisión*.
3.  **Guías de Despacho (US 2.3):** La base existe, pero el wizard y la lógica de generación principal están ausentes y deben ser construidos.

## 2. Objetivo Principal

Ejecutar de manera secuencial y metódica el plan de implementación que has propuesto para cerrar las tres brechas identificadas (Dashboard, Emisión de BHE, Wizard de Guías de Despacho) y completar así la Fase 2 del desarrollo del módulo DTE.

## 3. Plan de Ejecución Confirmado

Procede con la implementación siguiendo el orden de prioridades que tú mismo definiste. Trabaja en una funcionalidad a la vez, asegurando que cada una esté completa y probada antes de pasar a la siguiente.

### Fase 2.1: Dashboard Central de DTE (Prioridad 1)

- **Acción:** Procede con la implementación completa del dashboard de monitoreo SII.
- **Checklist de Tareas:**
    1.  [ ] Crear el nuevo modelo `l10n_cl.dte_dashboard`.
    2.  [ ] Implementar los KPIs requeridos (Aceptados, Rechazados, Pendientes, Monto Facturado) como `computed fields` eficientes.
    3.  [ ] Construir las vistas necesarias: Dashboard, Kanban y Gráficos (barras por tipo de DTE, línea de facturación diaria).
    4.  [ ] Crear las dos listas de acceso rápido con sus filtros correspondientes.
    5.  [ ] Escribir tests unitarios que validen los cálculos de los KPIs.
    6.  [ ] Crear un commit único para esta funcionalidad: `feat(dte): implement SII monitoring dashboard`.

### Fase 2.2: Emisión de Boletas de Honorarios (BHE) (Prioridad 2)

- **Acción:** Una vez completado el dashboard, procede a implementar el flujo de **emisión** de BHE.
- **Checklist de Tareas:**
    1.  [ ] Extender `account.move` para soportar el tipo `out_invoice` con el use `bhe` (Boleta de Honorarios Emitida).
    2.  [ ] Añadir los campos requeridos (`Retención Tercero`, etc.) y la lógica de cálculo de la retención configurable.
    3.  [ ] Implementar la lógica de generación del XML para la BHE, siguiendo el schema oficial del SII.
    4.  [ ] Integrar el XML generado con el flujo de envío SOAP existente.
    5.  [ ] Crear tests unitarios que validen la correcta generación del XML y los cálculos de retención.
    6.  [ ] Crear un commit único para esta funcionalidad: `feat(dte): add electronic fee receipt (BHE) emission`.

### Fase 2.3: Wizard y Lógica de Guías de Despacho (Prioridad 3)

- **Acción:** Finalizada la BHE, completa la funcionalidad de Guías de Despacho.
- **Checklist de Tareas:**
    1.  [ ] Crear el wizard `wizard.guia_despacho_from_picking` que se lance desde `stock.picking`.
    2.  [ ] Implementar la lógica para pre-cargar los datos del `stock.picking` en el wizard.
    3.  [ ] Añadir el campo `l10n_cl_driver_rut` a la pestaña "Transporte".
    4.  [ ] Implementar la lógica de sugerencia automática para el "Tipo de Traslado".
    5.  [ ] Reemplazar el código `TODO` con la implementación final de la generación del DTE 52.
    6.  [ ] Crear tests unitarios que prueben el flujo completo del wizard y la generación del DTE.
    7.  [ ] Crear un commit único para esta funcionalidad: `feat(dte): implement despatch advice wizard from stock picking`.

## 4. Máximas de Desarrollo

- **Calidad y Estándares:** Adherencia estricta a `flake8`, `pylint`, `black` y Conventional Commits.
- **Commits Atómicos:** Genera un commit por cada fase/funcionalidad descrita arriba. No mezcles código de distintas funcionalidades en un solo commit.
- **Cobertura de Pruebas:** Toda nueva lógica de negocio debe estar cubierta por tests.

## 5. Entregables Esperados

1.  **Tres Commits Principales:** Uno por cada User Story completada, con los mensajes sugeridos.
2.  **Código Funcional:** La implementación completa de las tres funcionalidades descritas.
3.  **Pruebas Unitarias:** Cobertura de pruebas para toda la nueva lógica.
4.  **Informe Final:** Al completar las tres tareas, genera un informe de cierre `FASE2_DTE_COMPLETADA.md`.
