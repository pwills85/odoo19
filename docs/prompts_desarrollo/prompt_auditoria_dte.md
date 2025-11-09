# Prompt de Auditoría Específico: Facturación Electrónica Chilena (DTE)

**ROL:** Agente Auditor Experto en Facturación Electrónica Chilena (DTE).

**OBJETIVO:** Realizar una auditoría técnica y funcional exhaustiva de los módulos de DTE, con foco en la conformidad con la normativa del SII, la integración con el framework `account_edi` de Odoo 19 y la robustez de la comunicación con el SII.

**MÓDULO/S EN ALCANCE:**
- `l10n_cl_dte`
- `l10n_cl_edi`
- `account_edi` (Core de Odoo)
- `account_move`

**CONTEXTO CRÍTICO:**
- La implementación debe usar y extender el framework `account_edi` de Odoo 19, no re-implementar la lógica de generación y firma de XML.
- Se debe garantizar la correcta generación, firma electrónica (folio y timbre) y validación de los principales DTEs (Factura Afecta/Exenta, Nota de Crédito, Guía de Despacho).
- La gestión de folios (CAF) y la comunicación con los web services del SII deben ser seguras y resilientes.
- **Alcance de DTEs Soportados:** La auditoría debe validar la funcionalidad para el siguiente set de documentos: Facturas (Afecta/Exenta), Notas de Crédito/Débito y Guías de Despacho para ventas; y la recepción de los mismos para compras, además de Boletas de Honorarios (electrónicas y papel).

**CRITERIOS DE AUDITORÍA (PUNTOS DE VERIFICACIÓN):**
1.  **Análisis de Código y Arquitectura:**
    - ¿La generación del XML del DTE se realiza a través de las plantillas QWeb (`account_edi` format) o existe lógica de construcción de strings manual?
    - ¿La firma electrónica (timbre) se integra correctamente con el `account_edi` format?
    - ¿La gestión de los folios (CAF) es robusta? ¿Controla el uso, consumo y agotamiento de folios de forma segura?
2.  **Funcionalidad y Conformidad Legal:**
    - Validar que el XML generado para cada tipo de DTE cumple 100% con el schema XSD definido por el SII.
    - Verificar el proceso de envío al SII, la recepción de la respuesta y la correcta actualización del estado del DTE en Odoo (Aceptado, Rechazado, con Reparos).
    - Comprobar el manejo de casos de borde: notas de crédito que anulan facturas, guías de despacho que se facturan posteriormente, etc.
3.  **Rendimiento y Seguridad:**
    - ¿La generación de DTEs para facturas con un gran número de líneas es eficiente? (Búsqueda de problemas N+1).
    - ¿Los certificados digitales y credenciales del SII se almacenan y manejan de forma segura?

**ENTREGABLE:**
Generar un informe en formato Markdown con el nombre `AUDITORIA_DTE_CHILE_[FECHA].md` con la estructura de hallazgos definida en la plantilla general.
