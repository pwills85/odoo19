# PROMPT: Fase 2 - Inteligencia de Negocios y Alertas Proactivas

## 1. Contexto

Felicitaciones por la excepcional ejecución de la Fase 1. Has entregado una base técnica robusta, superando todas las métricas de calidad y rendimiento. Ahora, sobre esa base, construiremos funcionalidades de alto valor que transformarán el módulo de un simple sistema de reportes a una herramienta proactiva de inteligencia de negocios.

## 2. Objetivo Principal

Evolucionar el módulo `l10n_cl_financial_reports` para proporcionar **análisis comparativos, alertas automáticas y capacidades de exportación profesional**, entregando insights accionables directamente al usuario.

## 3. Tareas Detalladas

### Tarea 1: Reporte Comparativo Anual (F22 vs. F29)

El objetivo es detectar discrepancias entre la declaración anual (F22) y la suma de las declaraciones mensuales (F29).

1.  **Crea un Wizard (TransientModel)**:
    *   Nombre del modelo: `l10n_cl.report.comparison.wizard`.
    *   Campos: `year` (año fiscal a comparar), `company_id`.
2.  **Implementa la Lógica de Comparación**:
    *   Al ejecutar el wizard, el sistema debe:
        *   Calcular la suma de los campos clave de todos los F29 del año seleccionado.
        *   Obtener los valores del F22 configurado para ese mismo año.
        *   Presentar una vista de resultados con tres columnas: `Concepto`, `Total F29`, `Total F22`, y `Diferencia`.
        *   Resaltar en rojo las diferencias que superen una tolerancia de $100.
3.  **Crea Tests Unitarios**:
    *   Prueba la lógica de agregación de F29 y la correcta detección de discrepancias.
4.  **Commit Sugerido**: `feat(financial_reports): add F22 vs F29 annual comparison report`

### Tarea 2: Sistema de Alertas de Umbrales de KPI

El objetivo es notificar proactivamente a los usuarios sobre eventos financieros importantes.

1.  **Crea un Modelo de Configuración de Alertas**:
    *   Nombre: `l10n_cl.kpi.alert`.
    *   Campos: `kpi_key` (selección del KPI, ej: `iva_debito`), `condition` (mayor que, menor que), `threshold_value` (valor umbral), `users_to_notify` (Many2many a `res.users`).
2.  **Crea un Cron Job Diario**:
    *   Nombre: `_cron_check_kpi_alerts`.
    *   Lógica: Diariamente, debe iterar sobre todas las alertas activas, obtener el valor actual del KPI usando el `KPIService` y, si la condición se cumple, generar una notificación en Odoo (usando `mail.activity`) para los usuarios suscritos.
3.  **Crea Tests Unitarios**:
    *   Valida que el cron evalúe correctamente las condiciones y que las actividades se creen para los usuarios correctos.
4.  **Commit Sugerido**: `feat(financial_reports): implement KPI threshold alert system with daily cron`

### Tarea 3: Exportación a PDF (F29 y Dashboard de KPIs)

El objetivo es permitir a los usuarios compartir los reportes con stakeholders externos.

1.  **Crea Reportes QWeb PDF**:
    *   **Reporte F29**: Diseña una plantilla QWeb que emule la estructura visual del formulario F29 oficial del SII. Añade un botón "Imprimir PDF" en la vista de formulario del F29.
    *   **Reporte de Dashboard**: Diseña una plantilla limpia que presente los valores actuales de los KPIs y una versión simplificada del gráfico de barras. Añade un botón "Exportar a PDF" en el wizard del dashboard.
2.  **Crea Tests**:
    *   Añade smoke tests que confirmen que la generación de ambos PDFs se completa sin errores.
3.  **Commit Sugerido**: `feat(financial_reports): add PDF export for F29 form and KPI Dashboard`

### Tarea 4: Organización y Limpieza de Artefactos de Desarrollo

El objetivo es mantener el módulo limpio de archivos que no son parte del código productivo.

1.  **Mueve los Archivos de Validación y Documentación**:
    *   Mueve `FASE1_COMPLETADA.md` al directorio `docs/sprints_log/l10n_cl_financial_reports/`.
    *   Mueve el script `validate_phase1.py` a un nuevo directorio raíz llamado `validation_scripts/`.
2.  **Commit Sugerido**: `refactor(financial_reports): move development artifacts to out-of-module locations`

## 4. Criterios de Aceptación (Definition of Done)

*   ✅ Las 4 tareas están completadas y confirmadas en commits separados y descriptivos.
*   ✅ Todos los nuevos modelos y wizards están cubiertos por tests unitarios.
*   ✅ Los reportes PDF se generan correctamente y son visualmente profesionales.
*   ✅ El cron de alertas es funcional y está probado.
*   ✅ El módulo `l10n_cl_financial_reports` no contiene scripts de validación ni archivos de documentación de la fase anterior.
