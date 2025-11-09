# Prompt de Cierre de Brecha Específico: Reportes Financieros Chile

**ROL:** Agente Desarrollador Experto en Reportes Financieros para Odoo.

**OBJETIVO:** Corregir una brecha de tipo "Funcional / Arquitectura" donde una línea del Estado de Resultados utiliza cuentas contables fijas.

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
- **Informe:** `AUDITORIA_REPORTES_FINANCIEROS_2025-11-07.md`
- **Hallazgo ID:** `REP-ARQ-001`

**DESCRIPCIÓN DEL PROBLEMA (Extraído de la auditoría):**
"La línea 'Costo por Ventas' en el Estado de Resultados está calculada sumando los balances de las cuentas `601001` y `601002` de forma fija en el código Python. Esto impide que los usuarios puedan asignar otras cuentas de costo y rompe la flexibilidad del sistema."

**INSTRUCCIONES TÉCNICAS DETALLADAS:**
1.  **Localiza** la definición del reporte del Estado de Resultados en `l10n_cl_reports/data/account_financial_report_data.xml`.
2.  **Identifica** la línea (`account.report.line`) correspondiente a "Costo por Ventas".
3.  **Modifica** la definición de la línea para que su dominio (`domain`) no se base en códigos de cuenta fijos. En su lugar, haz que agrupe las cuentas que tengan asignada la etiqueta (tag) `l10n_cl.costo_venta_tag`.
4.  **Crea** un archivo de datos (`data/account_account_tag_data.xml`) para definir esta etiqueta (`account.account.tag`) si no existe, asegurando que sea parte del módulo.
5.  **Verifica** que las cuentas de costo por defecto tengan esta etiqueta asignada en el plan contable.

**CRITERIOS DE ACEPTACIÓN (VERIFICACIÓN):**
1.  El cálculo de "Costo por Ventas" ya no debe contener referencias a códigos de cuenta específicos en el código XML o Python.
2.  Crea un test unitario que realice lo siguiente:
    a. Cree una nueva cuenta contable de tipo "Costo de los bienes vendidos".
    b. Le asigne la etiqueta `l10n_cl.costo_venta_tag`.
    c. Genere un asiento contable utilizando esta nueva cuenta.
    d. Verifique que el monto de este asiento se refleja correctamente en la línea "Costo por Ventas" del Estado de Resultados.

**ENTREGABLE:**
- Código modificado y nuevos archivos de datos.
- Nuevo test unitario que valide la flexibilidad del cálculo.
- Un commit con el mensaje: `feat(l10n_cl_reports): Use account tags for Cost of Sales calculation`.
