# PROMPT: Cierre Final de Auditoría - Módulo DTE (`l10n_cl_dte`)

## 1. Contexto y Onboarding

Bienvenido al equipo. Estás asumiendo la etapa final de un importante trabajo de mejora en el módulo de Facturación Electrónica de Chile (`l10n_cl_dte`).

Un agente anterior ya ha realizado un excelente progreso, cerrando **7 de las 11 brechas** identificadas en una auditoría técnica. Su trabajo ha sido de alta calidad, con commits descriptivos y tests unitarios.

**Trabajo ya completado:**
*   **P1 - Críticos (4/4)**: Corregidos problemas de firma, validaciones de DTE 52, métricas de rendimiento y estandarización de parámetros.
*   **P2 - Importantes (3/4)**: Se implementó un fallback de algoritmos de firma, se eliminó código obsoleto de RabbitMQ y se añadió el DTE 52 a la verificación en CI.

Tu misión es tomar el relevo y completar las 4 brechas restantes para alcanzar el 100% de conformidad.

## 2. Objetivo Principal

**Completar las 4 brechas de auditoría restantes (1 de P2, 3 de P3)**, asegurando que cada una se implemente con la misma alta calidad, incluyendo tests cuando sea aplicable y commits descriptivos.

## 3. Tareas Pendientes Detalladas

A continuación se detallan las 4 tareas finales. Debes crear un commit separado para cada una.

### Tarea 1 (Gap P2.4): Exponer Parámetros Críticos en la Configuración

*   **Por qué**: Para permitir a los administradores del sistema ajustar configuraciones clave (como la URL de Redis o la activación de métricas) desde la interfaz de Odoo, sin necesidad de modificar archivos de configuración o variables de entorno.
*   **Qué hacer**:
    1.  Extiende la vista de `res.config.settings` (Ajustes Generales).
    2.  Añade los siguientes campos para que sean configurables:
        *   `l10n_cl_dte.redis_url` (la URL para las métricas de rendimiento).
        *   `l10n_cl_dte.metrics_enabled` (un booleano para activar/desactivar las métricas).
        *   `l10n_cl_dte.webhook_key` (la clave para el webhook de callbacks).
    3.  Asegúrate de que los valores se guarden correctamente como `ir.config_parameter`.
*   **Commit Sugerido**: `feat(l10n_cl_dte): expose critical DTE parameters in settings`

### Tarea 2 (Gap P3.1): Logging Estructurado Condicional

*   **Por qué**: Para tener logs detallados en formato JSON durante el desarrollo o staging (útil para análisis con herramientas externas) pero mantener logs más simples y legibles en producción.
*   **Qué hacer**:
    1.  Implementa una utilidad que determine el entorno actual (ej: a través de una variable de entorno `DTE_LOG_LEVEL=json`).
    2.  Si el logging estructurado está activado, todos los logs del módulo DTE deben emitirse en formato JSON. De lo contrario, deben usar el formato estándar de Odoo.
    3.  Aplica este logging condicional a los puntos clave del proceso DTE (generación, firma, envío, consulta).
*   **Commit Sugerido**: `feat(l10n_cl_dte): implement conditional structured JSON logging`

### Tarea 3 (Gap P3.2): Simplificar Validación de RUT con `stdnum`

*   **Por qué**: Para reemplazar la lógica de validación de RUT custom por una librería estándar y bien probada como `stdnum`, reduciendo la mantenibilidad y posibles bugs.
*   **Qué hacer**:
    1.  Asegúrate de que la librería `stdnum` esté en los `requirements.txt`.
    2.  Busca todas las ocurrencias de validación de RUT en el módulo `l10n_cl_dte`.
    3.  Reemplázalas por una función centralizada que utilice `stdnum.cl.rut.validate()`.
*   **Commit Sugerido**: `refactor(l10n_cl_dte): simplify RUT validation using stdnum library`

### Tarea 4 (Gap P3.3): Actualizar Documentación del Pull Request Template

*   **Por qué**: Para asegurar que la documentación para desarrolladores refleje la realidad de las validaciones actuales en la Integración Continua (CI).
*   **Qué hacer**:
    1.  Localiza el template de Pull Request del proyecto (probablemente en `.github/PULL_REQUEST_TEMPLATE.md`).
    2.  Encuentra la sección que describe las validaciones de esquemas XSD para los DTE.
    3.  Actualízala para confirmar que ahora se validan **5 de 5** documentos clave, incluyendo explícitamente la Guía de Despacho (DTE 52), que fue añadida en la tarea P2.3.
*   **Commit Sugerido**: `docs(dev): update PR template to reflect 5/5 XSD coverage`

## 4. Criterios de Aceptación (Definition of Done)

*   ✅ Las 4 tareas están completadas y confirmadas en **4 commits separados**.
*   ✅ La configuración en `res.config.settings` es funcional y está probada.
*   ✅ La validación de RUT utiliza exclusivamente la librería `stdnum`.
*   ✅ El template de Pull Request está actualizado.
*   ✅ Con tu trabajo, el módulo `l10n_cl_dte` alcanza el **100% de conformidad con la auditoría (11/11 gaps cerrados)**.
