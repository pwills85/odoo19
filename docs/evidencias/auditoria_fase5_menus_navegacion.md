# Auditoría Fase 5 - Menús y Estructura de Navegación

## Resumen Ejecutivo
- ✅ La localización DTE organiza sus menús bajo Contabilidad → Finanzas con dos nodos principales: “Recepcionar XML Intercambio” para flujos de compra y “SII Configuration” para toda la administración electrónica (CAF, documentos, cola, libros), facilitando que el usuario funcional trabaje sin entrar a Configuración Técnica. `l10n_cl_fe/views/sii_menuitem.xml:4`
- ✅ La localización de nómina chilena añade un árbol dentro de **Nómina** con tres secciones: Indicadores, Reports y Chilean Configuration, donde se alojan tanto los catálogos previsionales (AFP, Isapres, CCAF, APV) como los reportes (Previred, Libro de Remuneraciones, Centralización Contable). `l10n_cl_hr/views/hr_indicadores_previsionales_view.xml:132`

## Análisis Detallado

### Menú Facturación Electrónica (Odoo 11 Producción)

| Ruta | Elementos | Propósito | Referencia |
|------|-----------|-----------|------------|
| Contabilidad → Finanzas → **Recepcionar XML Intercambio** | Abre wizards para cargar XML de proveedores y responder al intercambio SII. | Permite aceptar/rechazar recepción comercial desde un punto único. | `l10n_cl_fe/views/sii_menuitem.xml:4`
| Contabilidad → Configuración → **SII Configuration** | Nodo padre de todos los catálogos y herramientas DTE. | Centraliza administración sin navegar múltiples menús estándar. | `l10n_cl_fe/views/sii_menuitem.xml:5`
| SII Configuration → **Document Classes / Types / Responsibilities / Activities** | Acciones `act_sii_document_class`, `act_sii_document_type`, `act_sii_responsability`, `act_partner_activities`. | Mantener tablas oficiales (códigos, letras, giros). | `l10n_cl_fe/views/sii_document_class_view.xml:52`, `l10n_cl_fe/views/sii_document_type_view.xml:41`, `l10n_cl_fe/views/sii_responsability_view.xml:43`, `l10n_cl_fe/views/partner_activities.xml:55`
| SII Configuration → **CAF Files / Sequences** | Acción `action_caf_files` accesible desde menú CAF y desde secuencias con pestaña “CAF Files”. | Gestionar folios, descargar nuevos y vigilar uso mínimo. | `l10n_cl_fe/views/caf.xml:6`
| SII Configuration → **Cola de envío** | Lista/formulario `sii.cola_envio` para monitorear trabajos (envío, consulta, persistencia). | Operaciones revisa pendientes y errores de envío. | `l10n_cl_fe/views/sii_cola_envio.xml:3`
| Informes → **Consumo de Folios / Libros** | Menú `menu_action_move_consumo_folios_form` bajo Reportes contables. | Generar y enviar libros mensuales/boletas. | `l10n_cl_fe/views/consumo_folios.xml:147`
| Reportes Especiales → **Honorarios / Libro Compra-Venta / Mail DTE** | Menús específicos para reportes/registros especiales exigidos por SII. | Abarcar procesos complementarios (libro honorarios, notificaciones email). | `l10n_cl_fe/views/honorarios.xml:253`, `l10n_cl_fe/views/libro_compra_venta.xml:136`, `l10n_cl_fe/views/mail_dte.xml:213`

### Menú Nómina Chilena (Odoo 11 Producción)

| Nodo | Submenús | Función | Referencia |
|------|----------|---------|------------|
| **Payroll Indicators** | `hr_indicadores_previsionales_menu` | CRUD de indicadores mensuales (UF, UTM, tasas). | `l10n_cl_hr/views/hr_indicadores_previsionales_view.xml:147`
| **Reports** | `menu_salary_books` (Libro de Remuneraciones), `wizard_account_centralized_menu` (Centralización Contable), `wizard_export_csv_menu` (Previred). | Ejecutar wizards/reportes PDF/CSV con botones de descarga. | `l10n_cl_hr/views/hr_salary_books.xml:13`, `l10n_cl_hr/views/account_centralized_export.xml:58`, `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:37`
| **Chilean Configuration** | `hr_isapres_menu`, `hr_ccaf_menu`, `hr_mutual_menu`, `hr_apv_menu`, `hr_afp_menu`. | Administrar catálogos previsionales utilizados por contratos y reglas de cálculo. | `l10n_cl_hr/views/hr_indicadores_previsionales_view.xml:161`, `l10n_cl_hr/views/hr_indicadores_previsionales_view.xml:175`, `l10n_cl_hr/views/hr_indicadores_previsionales_view.xml:190`, `l10n_cl_hr/views/hr_indicadores_previsionales_view.xml:203`, `l10n_cl_hr/views/hr_afp_view.xml:38`
| **Nómina** → Formularios estándar | Contratos, empleados y liquidaciones con vistas heredadas se acceden desde los menús nativos de Odoo, pero muestran campos chilenos gracias a las herencias descritas en la fase 4. | Mantienen navegación conocida para RRHH mientras exponen datos locales. | `l10n_cl_hr/views/hr_contract_view.xml:4`, `l10n_cl_hr/views/hr_payslip_view.xml:4`

## Conclusiones
- La navegación está alineada con el flujo funcional: emisión/recepción DTE y control de folios se agrupan bajo un solo menú, mientras que en nómina los usuarios distinguen claramente entre configuración, indicadores y reportes.
- Replicar esta estructura en Odoo 19 evitará pérdida de productividad, ya que los equipos conocen exactamente dónde gestionar cada catálogo o ejecutar reportes críticos (Previred, libros, centralización).
- Los menús dedicados a catálogos regulados (AFP, Isapre, Document Classes) son esenciales para mantener actualizada la base frente a cambios normativos sin intervención técnica.
