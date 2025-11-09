# Prompt de Desarrollo Consolidado: Cierre de Brechas Auditoría DTE

**ROL:** Agente Desarrollador Experto en Odoo, Python y Localización Chilena.

**OBJETIVO:** Corregir de manera integral todas las brechas críticas (P1), importantes (P2) y menores (P3) identificadas en la auditoría de conformidad técnica del módulo DTE. El objetivo final es alcanzar un estado "enterprise-ready" sin observaciones pendientes, asegurando que el código sea robusto, mantenible y cumpla con todos los requisitos funcionales y de rendimiento.

**CONTEXTO GENERAL:**
Este prompt es una orden de trabajo completa basada en el informe de auditoría `AUDITORIA_ENTERPRISE_L10N_CL_DTE_2025-11-07.md`. Debes abordar cada punto en el orden de prioridad especificado (P1 → P2 → P3). Cada corrección debe ir acompañada de tests unitarios o de integración que validen la solución y prevengan regresiones. El código debe seguir estrictamente las convenciones del proyecto y de Odoo.

### MÁXIMAS DE DESARROLLO Y CONTEXTO OPERATIVO

Adicional a las instrucciones específicas, todo desarrollo debe adherirse a las siguientes directrices generales:

1.  **Alcance Funcional de DTEs:** El desarrollo y las pruebas deben cubrir el siguiente set de documentos:
    *   **Venta:** Factura Afecta a IVA, Factura Exenta de IVA, Nota de Crédito, Nota de Débito, Guía de Despacho.
    *   **Compra:** Factura Afecta a IVA, Factura Exenta de IVA, Nota de Crédito, Nota de Débito, Guía de Despacho, Boleta de Honorarios Electrónica y de papel (antiguas).

2.  **Estándares de Odoo 19 CE:** Utilizar exclusivamente técnicas, librerías y APIs correspondientes a Odoo 19 Community Edition. Queda explícitamente prohibido el uso de métodos o arquitecturas obsoletas de versiones anteriores.

3.  **Integración con Odoo Base y Módulos Propios:** Asegurar la completa y correcta integración de los cambios tanto con la suite base de Odoo 19 CE como con los otros módulos de nuestro stack (Nómina, Reportes, DTE).

4.  **Integración con Microservicio de IA:** El desarrollo debe contemplar y asegurar la integración con el microservicio de IA del stack, según la arquitectura definida.

5.  **Entorno de Pruebas Dockerizado:** Todas las pruebas y validaciones deben ejecutarse considerando que la aplicación corre en Docker. Para interactuar con la instancia, se deben usar comandos `docker exec` que invoquen los scripts de Odoo, utilizando las credenciales y configuraciones definidas en los archivos `.env` y `odoo.conf`.


**ENTREGABLE FINAL:**
- Una serie de commits, uno por cada punto principal resuelto, con mensajes claros y descriptivos (ej: `fix(dte): Corregir namespace en firma de nodo Documento`).
- Todos los tests existentes y nuevos deben pasar con éxito.
- El pipeline de CI/CD debe ejecutarse y pasar sin errores.

---

### **P1 – BRECHAS CRÍTICAS (CORRECCIÓN INMEDIATA)**

**1.1. Firma de Nodo `Documento` con Namespace Incorrecto**
- **Problema:** La firma del DTE no se aplica correctamente por no usar el namespace del SII en el XPath.
- **Instrucciones Técnicas:**
    1.  En el archivo `xml_signer.py`, localiza la función `sign_dte_documento()`.
    2.  Modifica la llamada a `_sign_xml_node_with_uri()`, cambiando el argumento `node_xpath` de `'.//Documento'` a `'.//{http://www.sii.cl/SiiDte}Documento'`.
    3.  **Añade un test unitario** que cargue un XML de DTE, ejecute `sign_dte_documento()` y verifique explícitamente que el nodo `ds:Signature` se ha insertado como hijo directo del nodo `sii:Documento` (usando el namespace map correcto).

**1.2. Validaciones de DTE 52 con Tipos de Datos Incorrectos**
- **Problema:** Se comparan campos `Char` (`'1'`) con `Integer` (`1`), causando que validaciones fallen incorrectamente.
- **Instrucciones Técnicas:**
    1.  En `account_move_dte.py`, localiza el método `_validate_dte_52()`.
    2.  Modifica las condiciones `if self.l10n_cl_dte_tipo_traslado not in (...)` y `if self.l10n_cl_dte_tipo_despacho not in (...)`.
    3.  Convierte los valores de los campos a `int()` antes de la comparación. Ejemplo: `int(self.l10n_cl_dte_tipo_traslado) not in (1, 2, ...)`. Asegúrate de manejar el caso en que el campo esté vacío o no sea un número.
    4.  **Añade tests unitarios** para `_validate_dte_52()` que prueben todos los valores válidos para `tipo_traslado` (1 al 8) y `tipo_despacho` (1 al 3), asegurando que no se levante ninguna excepción de validación.

**1.3. Métricas de Performance No Instrumentadas en Runtime**
- **Problema:** Las métricas no se recolectan en producción por falta de decoradores y configuración de Redis hardcodeada.
- **Instrucciones Técnicas:**
    1.  Aplica el decorador `@measure_performance` a los siguientes métodos clave en el código:
        - Generación de XML (ej: `generate_dte_xml`).
        - Firma de `Documento` y `SetDTE`.
        - Envío SOAP y consulta de estado al SII.
        - Procesamiento de webhooks entrantes.
    2.  En `performance_metrics.py`, elimina la conexión de Redis hardcodeada. La lógica debe ser: 1) Leer `os.environ.get('REDIS_URL')`. 2) Si no existe, leer el parámetro de sistema `l10n_cl_dte.redis_url` a través del ORM. 3) Usar esa URL para la conexión.
    3.  Toda la lógica de medición y envío a Redis debe estar condicionada por el parámetro de sistema `l10n_cl_dte.metrics_enabled`.

**1.4. Inconsistencia en Parámetro de Secreto de Webhook**
- **Problema:** Se usan dos nombres de parámetro (`webhook_key` y `webhook_secret`), causando confusión y riesgo operativo.
- **Instrucciones Técnicas:**
    1.  Estandariza el uso a `l10n_cl_dte.webhook_key`.
    2.  En `config_parameters.xml`, renombra el parámetro `l10n_cl_dte.webhook_secret` a `l10n_cl_dte.webhook_key`.
    3.  Verifica que el controlador `dte_webhook.py` y el `post_init_hook` ya usan `webhook_key`. No deberían necesitar cambios.
    4.  Elimina cualquier referencia a `webhook_secret` del código.

---

### **P2 – BRECHAS IMPORTANTES (CORTO PLAZO)**

**2.1. Algoritmo de Firma SHA256 sin Fallback a SHA1**
- **Instrucción:** Implementa una política de reintento. En la lógica de firma, si el envío al SII falla con un código de error específico de algoritmo de firma, reintenta la firma y el envío usando `sha1`. Esta funcionalidad debe ser activable mediante un nuevo parámetro de sistema `l10n_cl_dte.enable_sha1_fallback` (booleano, por defecto `False`).

**2.2. Incongruencia Arquitectónica con RabbitMQ**
- **Instrucción:** Se ha decidido estandarizar en `ir.cron`. Elimina todo el código relacionado con RabbitMQ para reducir la complejidad. Esto incluye:
    - Métodos `_publish_dte_to_rabbitmq` y `action_send_dte_async`.
    - El modelo `rabbitmq_helper.py`.
    - Vistas, menús o acciones relacionadas con la cola asíncrona de RabbitMQ.

**2.3. Verificación XMLDSig en CI no incluye DTE 52**
- **Instrucción:** En el script `verify_xmlsec_signatures.py`, añade al menos un fixture de Guía de Despacho (`dte52_*.xml`) al conjunto de archivos que se verifican para asegurar su correcta firma.

**2.4. Parámetros Críticos No Expuestos en la Interfaz de Ajustes**
- **Instrucción:** En `res_config_settings.py`, expón los siguientes parámetros de sistema para que sean configurables desde el menú de Ajustes de Contabilidad:
    - `l10n_cl_dte.redis_url`
    - `l10n_cl_dte.webhook_ip_whitelist`
    - `l10n_cl_dte.ratelimit_requests`
    - `l10n_cl_dte.ratelimit_period_seconds`
    - `l10n_cl_dte.metrics_enabled`

---

### **P3 – BRECHAS MENORES (MEDIO PLAZO)**

**3.1. Logging Estructurado Condicional**
- **Instrucción:** Modifica la configuración del logger para que el formato de salida sea JSON estructurado solo si el parámetro de sistema `l10n_cl_dte.log_structured` está activado.

**3.2. Simplificación de Validación de RUT**
- **Instrucción:** Dado que el módulo `l10n_cl` ya asegura la dependencia de `stdnum`, refactoriza la validación de RUT en el contexto del DTE 52 para usar siempre `stdnum`, eliminando el fallback a regex y mejorando la limpieza de formatos con puntos y guiones.

**3.3. Documentación de PR Template**
- **Instrucción:** Actualiza la documentación y plantillas de Pull Request para reflejar la cobertura real de verificación de firmas XML (si se corrigió a 5/5 en el punto 2.3, indica eso; si no, indica 4/5).
