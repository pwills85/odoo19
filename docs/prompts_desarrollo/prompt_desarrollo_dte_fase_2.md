# PROMPT: Módulo DTE - Fase 2: Evolución Funcional y UX

## 1. Contexto

La Fase 1 de estabilización y cierre de brechas técnicas del módulo `l10n_cl_dte` ha concluido con éxito. Las 11 brechas de la auditoría técnica han sido cerradas, y el módulo se encuentra en un estado `enterprise-ready`.

Ahora que la base es robusta, iniciamos la **Fase 2**, centrada en expandir las capacidades funcionales del módulo y mejorar significativamente la experiencia de usuario (UX) para el operador de facturación.

## 2. Objetivo Principal (Fase 2)

Transformar el módulo `l10n_cl_dte` de una herramienta puramente técnica a una solución integral y amigable, implementando un **Dashboard Central de DTEs** y añadiendo soporte para **nuevos tipos de Documentos Tributarios Electrónicos** críticos para la operación en Chile.

## 3. Requisitos Detallados

### US 2.1: Dashboard Central de DTE

**Descripción:** Crear una nueva vista de tipo "Dashboard" en el menú de Facturación que sirva como el centro de comando para toda la gestión de DTEs.

- **Componentes del Dashboard:**
    - **KPIs Principales:**
        - DTEs Aceptados por el SII (últimos 30 días).
        - DTEs Rechazados por el SII (últimos 30 días).
        - DTEs Pendientes de envío.
        - Monto total facturado (CLP) con DTEs aceptados (mes actual).
    - **Gráficos:**
        - Un gráfico de barras mostrando DTEs emitidos por tipo de documento (Factura, Nota de Crédito, Guía de Despacho, etc.) en el mes actual.
        - Un gráfico de línea mostrando la evolución de la facturación diaria en el mes actual.
    - **Listas de Acceso Rápido:**
        - "Mis DTEs con reparos": Una lista filtrada de documentos que requieren acción del usuario.
        - "Últimos DTEs enviados": Un listado de los 10 DTEs más recientes con su estado (Enviado, Aceptado, Rechazado).

**Requisitos Técnicos:**
- La vista debe ser construida usando las herramientas nativas de Odoo 19 (vistas `dashboard`).
- Los cálculos de KPIs deben ser eficientes para no impactar el rendimiento. Considera usar campos `compute` almacenados o consultas SQL materializadas si es necesario.

### US 2.2: Soporte para Boleta de Honorarios Electrónica (BHE)

**Descripción:** Implementar el flujo completo para la emisión de Boletas de Honorarios Electrónicas (BHE), un documento esencial para profesionales independientes.

- **Modelo de Datos:**
    - Extender el modelo `account.move` para soportar el tipo de documento "Boleta de Honorarios".
    - Añadir los campos específicos requeridos por el SII para BHE, como "Retención Tercero" (booleano) y el cálculo de la retención de impuestos.
- **Flujo de Emisión:**
    - El usuario debe poder crear una BHE desde el menú de facturación.
    - El sistema debe calcular automáticamente la retención del impuesto correspondiente (actualmente 13.75%, pero debe ser configurable).
    - La generación del XML y el envío al SII deben seguir el mismo flujo que los otros DTEs, pero usando el schema y especificaciones de la BHE.
- **Validaciones:**
    - El receptor de una BHE debe ser una persona natural con RUT válido.
    - El sistema debe validar que los servicios listados en la boleta son coherentes con la actividad económica del emisor.

### US 2.3 (Revisado): Optimización del Flujo de Guías de Despacho

**Descripción:** Dado que las Guías de Despacho (DTE 52) son críticas para mover equipos y materiales a las obras de EERGYGROUP, vamos a optimizar y automatizar su creación, integrándolas directamente con el módulo de Inventario de Odoo.

- **Wizard de Creación desde Transferencia de Inventario:**
    - Desde una transferencia de inventario (`stock.picking`) validada, el usuario debe poder hacer clic en un botón: "Generar Guía de Despacho".
    - Un asistente (wizard) se abrirá, pre-cargando la información del `stock.picking`:
        - **Destinatario:** El contacto de la dirección de destino.
        - **Productos:** Las líneas de productos de la transferencia.
        - **Origen y Destino:** Las direcciones de las ubicaciones de inventario.
- **Campos Adicionales para Logística:**
    - En el modelo de la Guía de Despacho (`account.move`), añadir una pestaña "Transporte" con campos para:
        - Patente del Vehículo (`l10n_cl_vehicle_plate`).
        - RUT del Conductor (`l10n_cl_driver_rut`).
    - Estos campos deben ser opcionales pero visibles en el formulario y deben incluirse en el XML del DTE si se rellenan.
- **Tipos de Traslado:**
    - El usuario debe poder seleccionar fácilmente el "Tipo de Traslado" (ej: Venta, Traslado Interno, etc.), que es un campo obligatorio para este DTE. El sistema debe sugerir "Traslado Interno" si el origen y destino son bodegas de la misma compañía.

**Requisitos Técnicos:**
- La lógica debe residir en un nuevo módulo `l10n_cl_dte_stock` para mantener la separación de responsabilidades entre facturación e inventario. Este módulo dependerá de `l10n_cl_dte` y `stock`.

## 4. Máximas de Desarrollo

- **Estándares Odoo 19:** Utiliza exclusivamente APIs y librerías de Odoo 19 Community.
- **No Dependencias Externas:** No añadas nuevas dependencias de Python a menos que sea estrictamente necesario y previamente aprobado.
- **Calidad del Código:** Aplica los estándares de `flake8`, `pylint` y `black`.
- **Pruebas Unitarias:** Cada nueva funcionalidad (ej. la lógica del wizard) debe estar cubierta por pruebas unitarias.
- **Commits Atómicos:** Realiza commits pequeños y bien descritos siguiendo el estándar de Conventional Commits.

## 5. Entregables Esperados

1.  **Commits en el Repositorio:** Múltiples commits que implementen las funcionalidades descritas.
2.  **Nuevos Módulos, Vistas y Modelos:** Los archivos correspondientes al Dashboard, la BHE y el nuevo flujo de Guías de Despacho (incluyendo el nuevo módulo `l10n_cl_dte_stock`).
3.  **Pruebas Unitarias:** Archivos de pruebas que validen la nueva lógica de negocio.
4.  **Actualización de README:** Si se introduce una nueva configuración, debe ser documentada en el `README.md` del módulo.
5.  **Informe de Cierre de Fase 2:** Un resumen final similar al de la Fase 1, detallando los logros, commits y próximos pasos recomendados.
