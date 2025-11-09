# Prompt de Cierre de Brecha Específico: Nómina Chilena

**ROL:** Agente Desarrollador Experto en Nómina para Odoo.

**OBJETIVO:** Corregir una brecha de tipo "Conformidad Legal / Arquitectura" donde un parámetro legal clave está fijo en el código.

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
- **Informe:** `AUDITORIA_NOMINA_CHILENA_2025-11-07.md`
- **Hallazgo ID:** `NOM-ARQ-002`

**DESCRIPCIÓN DEL PROBLEMA (Extraído de la auditoría):**
"El tope imponible para las cotizaciones de AFP (actualmente ~84.3 UF) está definido como un valor constante y fijo dentro de una regla salarial (`hr.salary.rule`). Cada vez que este valor cambia, se requiere una intervención de código, lo cual es ineficiente y propenso a errores."

**INSTRUCCIONES TÉCNICAS DETALLADAS:**
1.  **Crea un nuevo modelo** llamado `l10n_cl.previsional.indicator` para almacenar indicadores previsionales que cambian en el tiempo. Este modelo debe tener campos como `name`, `code`, `date_from`, `date_to`, y `value`.
2.  **Crea un registro** en este nuevo modelo para el tope imponible de AFP (ej: código `TOPE_IMP_AFP`). Pobla los datos para el año actual.
3.  **Modifica la regla salarial** (`hr.salary.rule`) que calcula la base imponible de AFP. Elimina el valor fijo.
4.  **En el código Python de la regla**, implementa una lógica que busque el valor del indicador `TOPE_IMP_AFP` en el nuevo modelo, seleccionando el registro vigente para la fecha de la liquidación (`payslip.date_to`).
5.  **Utiliza este valor dinámico** para aplicar el tope al cálculo de la base imponible.

**CRITERIOS de ACEPTACIÓN (VERIFICACIÓN):**
1.  El valor del tope imponible ya no debe existir como una constante en el código de las reglas salariales.
2.  Crea un test unitario que verifique lo siguiente:
    a. Configura un valor para el tope imponible en el nuevo modelo.
    b. Procesa una liquidación para un empleado cuyo sueldo base está por sobre el tope. Verifica que la base imponible para AFP sea exactamente igual al tope configurado.
    c. Procesa una liquidación para un empleado cuyo sueldo está por debajo del tope. Verifica que la base imponible sea igual a su sueldo.

**ENTREGABLE:**
- Nuevos archivos de modelo y vistas para el indicador previsional.
- Código modificado en la regla salarial.
- Nuevo test unitario que valide el cálculo dinámico del tope.
- Un commit con el mensaje: `feat(l10n_cl_hr_payroll): Add dynamic model for previsional indicators`.
