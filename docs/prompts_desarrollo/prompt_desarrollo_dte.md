# Prompt de Cierre de Brecha Específico: Facturación Electrónica (DTE)

**ROL:** Agente Desarrollador Experto en Facturación Electrónica para Odoo.

**OBJETIVO:** Corregir una brecha de tipo "Rendimiento" que afecta la generación de DTEs para facturas con muchas líneas.

### MÁXIMAS DE DESARROLLO Y CONTEXTO OPERATIVO

Adicional a las instrucciones específicas, todo desarrollo debe adherirse a las siguientes directrices generales:

1.  **Alcance Funcional de DTEs:** El desarrollo y las pruebas deben cubrir el siguiente set de documentos:
    *   **Venta:** Factura Afecta a IVA, Factura Exenta de IVA, Nota de Crédito, Nota de Débito, Guía de Despacho.
    *   **Compra:** Factura Afecta a IVA, Factura Exenta de IVA, Nota de Crédito, Nota de Débito, Guía de Despacho, Boleta de Honorarios Electrónica y de papel (antiguas).

2.  **Estándares de Odoo 19 CE:** Utilizar exclusivamente técnicas, librerías y APIs correspondientes a Odoo 19 Community Edition. Queda explícitamente prohibido el uso de métodos o arquitecturas obsoletas de versiones anteriores.

3.  **Integración con Odoo Base y Módulos Propios:** Asegurar la completa y correcta integración de los cambios tanto con la suite base de Odoo 19 CE como con los otros módulos de nuestro stack (Nómina, Reportes, DTE).

4.  **Integración con Microservicio de IA:** El desarrollo debe contemplar y asegurar la integración con el microservicio de IA del stack, según la arquitectura definida.

5.  **Entorno de Pruebas Dockerizado:** Todas las pruebas y validaciones deben ejecutarse considerando que la aplicación corre en Docker. Para interactuar con la instancia, se deben usar comandos `docker exec` que invoquen los scripts de Odoo, utilizando las credenciales y configuraciones definidas en los archivos `.env` y `odoo.conf`.


**REFERENCIA DE AUDITORÍA:**
- **Informe:** `AUDITORIA_DTE_CHILE_2025-11-07.md`
- **Hallazgo ID:** `DTE-PERF-003`

**DESCRIPCIÓN DEL PROBLEMA (Extraído de la auditoría):**
"En el método `_get_dte_lines` del modelo `account.move` (archivo `l10n_cl_dte/models/account_move.py`, línea 258), se itera sobre las líneas de la factura y se realiza una búsqueda (`search`) a la base de datos por cada línea para obtener información del producto. Esto genera un problema de rendimiento N+1 al validar facturas con muchas líneas."

**INSTRUCCIONES TÉCNICAS DETALLADAS:**
1.  **Localiza** el método `_get_dte_lines` en el archivo `l10n_cl_dte/models/account_move.py`.
2.  **Refactoriza** la lógica para eliminar el bucle con búsquedas. Antes del bucle, recolecta todos los IDs de los productos (`product_id`) de las líneas de la factura (`invoice_line_ids`) en una lista.
3.  **Realiza una única operación** `read` o `browse` con la lista de IDs para traer todos los datos de los productos necesarios a memoria en una sola consulta.
4.  **Modifica** el bucle para que itere sobre las líneas de la factura y obtenga los datos del producto desde la estructura de datos precargada en memoria, sin realizar más consultas a la base de datos.

**CRITERIOS DE ACEPTACIÓN (VERIFICACIÓN):**
1.  El problema de rendimiento N+1 debe estar completamente resuelto.
2.  Todos los tests funcionales existentes que generan DTEs deben seguir pasando sin errores.
3.  **Crea un nuevo test de rendimiento** en `l10n_cl_dte/tests/test_dte_performance.py` que haga lo siguiente:
    a. Cree una factura con al menos 200 líneas.
    b. Utilice el `QueryCounter` de Odoo (`odoo.tests.common.QueryCounter`) para contar el número de consultas SQL ejecutadas durante la llamada al método que genera el XML del DTE.
    c. Verifique que el número de consultas sea bajo y constante, independientemente del número de líneas.

**ENTREGABLE:**
- Código refactorizado en `l10n_cl_dte/models/account_move.py`.
- Nuevo test de rendimiento que demuestre la solución.
- Un commit con el mensaje: `refactor(l10n_cl_dte): Optimize DTE line processing to fix N+1 issue`.
