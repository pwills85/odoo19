# Auditoría Fase 4 - Vistas y Flujos de Usuario (Facturación)

## Resumen Ejecutivo
- ✅ Las vistas heredadas de facturas amplían filtros, árbol y formulario para exponer campos SII (clase de documento, folio, giros) y botones específicos (`Enviar XML`, `Consultar DTE`, `Imprimir Cedible`), guiando al usuario durante todo el ciclo DTE. `l10n_cl_fe/views/account_invoice.xml:4`, `l10n_cl_fe/views/account_invoice.xml:37`, `l10n_cl_fe/views/account_invoice.xml:170`
- ✅ La administración de CAF, consumo de folios y cola de envíos cuenta con menús y formularios dedicados que exponen estados, totales y acciones de validación/envío, facilitando el control operativo exigido por el SII. `l10n_cl_fe/views/caf.xml:6`, `l10n_cl_fe/views/consumo_folios.xml:44`, `l10n_cl_fe/views/sii_cola_envio.xml:3`
- ⚠️ Los menús nativos agregados bajo Contabilidad (Recepción XML, Configuración SII) no existen en Odoo estándar; deben replicarse para mantener la navegabilidad del usuario chileno. `l10n_cl_fe/views/sii_menuitem.xml:4`

## Análisis Detallado

### 1. Facturas de Cliente/Proveedor

| Vista | Experiencia de usuario | Referencia |
|-------|-----------------------|------------|
| Búsqueda (`view_account_invoice_filter`) | Amplía el filtro “Número” para buscar por folio SII, número interno, origen y referencia; añade campo de actividad económica y tipo de documento, además de filtro “Document Type” que agrupa por `document_class_id`. | `l10n_cl_fe/views/account_invoice.xml:4`
| Árbol (`invoice_tree`) | Muestra columna `reference` junto a `origin`, permitiendo visualizar correlaciones con guías o pedidos al listar DTE. | `l10n_cl_fe/views/account_invoice.xml:23`
| Formulario (`view_invoice_form`) | Inserta campos invisibles para controlar secuencias, reemplaza el encabezado para mostrar campo `document_class_id` y número, añade botones `Imprimir Cedible`/`Enviar XML`/`Ask for DTE`, status bar `sii_result`, pestañas para reclamos y respuestas de clientes, y renderiza el código de barras SII. | `l10n_cl_fe/views/account_invoice.xml:37`, `l10n_cl_fe/views/account_invoice.xml:50`, `l10n_cl_fe/views/account_invoice.xml:170`
| Acciones en encabezado | Botón `do_dte_send_invoice` sólo visible cuando el documento está listo y no enviado; `ask_for_dte_status` se habilita tras envío. Ambos conviven con el statusbar para dar feedback inmediato. | `l10n_cl_fe/views/account_invoice.xml:170`

### 2. Gestión de CAF y Secuencias

| Vista | Funcionalidad | Referencia |
|-------|---------------|------------|
| Secuencia (`view_sequence_dte_caf_form`) | Dentro de `ir.sequence` se agrega pestaña “CAF Files” con campos `sii_document_class_id`, `is_dte`, nivel mínimo, autoreposición y listado de CAF asociados, incluyendo botón “Obtener Folios desde el SII”. | `l10n_cl_fe/views/caf.xml:6`
| CAF (`view_dte_caf_form` / `tree`) | Permite cargar archivo CAF, ver rango inicial/final, fecha de emisión/vencimiento, validar y seguir el progreso de uso con barra y estados (`draft`, `in_use`, `spent`). | `l10n_cl_fe/views/caf.xml:55`

### 3. Consumo de Folios y Libros

| Vista | Funcionalidad | Referencia |
|-------|---------------|------------|
| Lista (`electronic_consumo_folios_tree`) | Muestra cada declaración con rangos de fecha, totales de boletas, neto, IVA y estado; colores indican borradores o cancelados. | `l10n_cl_fe/views/consumo_folios.xml:4`
| Formulario (`view_electroinic_consumo_folios_form`) | Header con botones `Validate`, `Download XML`, `Send XML`, `Ask for DTE`; grupos para totales, detalles de impuestos y rangos, notebook con movimientos base, anulaciones manuales y XML enviado. | `l10n_cl_fe/views/consumo_folios.xml:44`
| Búsqueda | Incluye filtros rápidos para estados Proceso/Rechazado/Anulado y agrupación por mes validado para auditorías mensuales. | `l10n_cl_fe/views/consumo_folios.xml:26`

### 4. Monitoreo de Cola de Envío

| Vista | Descripción | Referencia |
|-------|-------------|------------|
| Formulario/Árbol `sii.cola_envio` | Exponen compañía, modelo, documentos asociados, usuario, tipo de trabajo (envío, consulta, persistencia), fecha programada y flags `send_email`/`set_pruebas`, permitiendo reprogramar o activar registros manualmente. | `l10n_cl_fe/views/sii_cola_envio.xml:3`
| Menú | Entrada “Cola de envío” bajo Configuración SII para que los responsables revisen pendientes cuando el cron detecta errores. | `l10n_cl_fe/views/sii_cola_envio.xml:47`

### 5. Menús de Acceso Rápido

| Menú | Ubicación | Referencia |
|------|-----------|------------|
| “Recepcionar XML Intercambio” | En Contabilidad → Finanzas para abrir wizards de recepción de XML proveedores. | `l10n_cl_fe/views/sii_menuitem.xml:4`
| “SII Configuration” | En Contabilidad → Configuración para agrupar menús de CAF, cola, firma, actividades, etc. | `l10n_cl_fe/views/sii_menuitem.xml:5`

## Conclusiones
- Las vistas integran el flujo completo desde la creación de facturas hasta el seguimiento de respuestas SII; replicarlas garantizará que los usuarios mantengan los mismos puntos de control visuales al migrar.
- La administración de CAF y consumo de folios depende de formularios especializados con acciones directas (obtener folios, validar, enviar). Sin ellos, el equipo tendría que recurrir a scripts externos.
- La cola de envío y los menús dedicados funcionan como centro de monitoreo; mantener su organización asegura que operaciones y soporte sigan el mismo proceso de supervisión.
