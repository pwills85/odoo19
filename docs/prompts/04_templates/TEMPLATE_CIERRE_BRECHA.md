# Plantilla de Prompt para Agentes Desarrolladores (Cierre de Brechas)

**ROL:** Agente Desarrollador Experto en [NOMBRE DEL MÓDULO, ej: Facturación Electrónica Chilena].

**OBJETIVO:** Corregir una brecha de tipo [TIPO DE BRECHA, ej: "Rendimiento", "Conformidad Legal"] identificada durante la auditoría, siguiendo las mejores prácticas de Odoo 19.

### MÁXIMAS DE DESARROLLO Y CONTEXTO OPERATIVO

Adicional a las instrucciones específicas, todo desarrollo debe adherirse a las siguientes directrices generales:

0.  **✅ Compliance Odoo 19 CE (CRÍTICO - Validar SIEMPRE):**
    - **Checklist completo:** `docs/prompts_desarrollo/CHECKLIST_ODOO19_VALIDACIONES.md`
    - **Guía deprecaciones:** `.claude/project/ODOO19_DEPRECATIONS_CRITICAL.md`
    
    **Validaciones P0 Obligatorias (Deadline: 2025-03-01):**
    - ✅ NO usar `t-esc` en templates XML → Usar `t-out`
    - ✅ NO usar `type='json'` en routes → Usar `type='jsonrpc'` + `csrf=False`
    - ⚠️ NO usar `attrs=` en XML views → Usar expresiones Python directas
    - ⚠️ NO usar `_sql_constraints` → Usar `models.Constraint`
    - ⚠️ NO usar `<dashboard>` tags → Convertir a `<kanban class="o_kanban_dashboard">`
    
    **Validaciones P1 (Deadline: 2025-06-01):**
    - ✅ NO usar `self._cr` → Usar `self.env.cr`
    - ⚠️ NO usar `fields_view_get()` → Usar `get_view()`
    - 📋 Revisar `@api.depends` en herencias (comportamiento acumulativo)
    
    **Comando pre-commit (EJECUTAR ANTES DE COMMITEAR):**
    ```bash
    # Detectar deprecaciones en cambios
    git diff --cached | grep -E "t-esc|type='json'|attrs=|self\._cr|fields_view_get"
    
    # Esperado: 0 matches (excepto en comentarios/docs)
    ```

1.  **Alcance Funcional de DTEs:** El desarrollo y las pruebas deben cubrir el siguiente set de documentos:
    *   **Venta:** Factura Afecta a IVA, Factura Exenta de IVA, Nota de Crédito, Nota de Débito, Guía de Despacho.
    *   **Compra:** Factura Afecta a IVA, Factura Exenta de IVA, Nota de Crédito, Nota de Débito, Guía de Despacho, Boleta de Honorarios Electrónica y de papel (antiguas).

2.  **Estándares de Odoo 19 CE:** Utilizar exclusivamente técnicas, librerías y APIs correspondientes a Odoo 19 Community Edition. Queda explícitamente prohibido el uso de métodos o arquitecturas obsoletas de versiones anteriores.

3.  **Integración con Odoo Base y Módulos Propios:** Asegurar la completa y correcta integración de los cambios tanto con la suite base de Odoo 19 CE como con los otros módulos de nuestro stack (Nómina, Reportes, DTE).

4.  **Integración con Microservicio de IA:** El desarrollo debe contemplar y asegurar la integración con el microservicio de IA del stack, según la arquitectura definida.

5.  **Entorno de Pruebas Dockerizado:** Todas las pruebas y validaciones deben ejecutarse considerando que la aplicación corre en Docker. Para interactuar con la instancia, se deben usar comandos `docker exec` que invoquen los scripts de Odoo, utilizando las credenciales y configuraciones definidas en los archivos `.env` y `odoo.conf`.


**REFERENCIA DE AUDITORÍA:**
- **Informe:** `AUDITORIA_L10N_CL_DTE_2025-11-07.md`
- **Hallazgo ID:** `DTE-PERF-003`

**DESCRIPCIÓN DEL PROBLEMA (Extraído de la auditoría):**
"En el método `_get_dte_lines` del modelo `account.move` (archivo `l10n_cl_dte/models/account_move.py`, línea 258), se itera sobre las líneas de la factura y se realiza una búsqueda (`search`) a la base de datos por cada línea para obtener información del producto. Esto genera un problema de rendimiento N+1 al validar facturas con muchas líneas."

**INSTRUCCIONES TÉCNICAS DETALLADAS:**
1.  **Localiza** el método `_get_dte_lines` en el archivo `l10n_cl_dte/models/account_move.py`.
2.  **Refactoriza** la lógica para eliminar el bucle con búsquedas. Antes del bucle, recolecta todos los IDs de los productos de las líneas de la factura en una lista.
3.  **Realiza una única búsqueda** (`browse` o `search`) con la lista de IDs para traer todos los productos necesarios a memoria en una sola operación.
4.  **Modifica** el bucle para que utilice los datos de los productos ya precargados en memoria en lugar de realizar nuevas búsquedas.
5.  **Asegúrate** de que el código refactorizado sigue las guías de estilo de Odoo y PEP8. No dejes código comentado.

**CRITERIOS DE ACEPTACIÓN (VERIFICACIÓN):**

0.  **✅ Compliance Odoo 19 CE (VALIDAR PRIMERO):**
    ```bash
    # Validar código modificado NO contiene deprecaciones
    grep -rn "t-esc\|type='json'\|attrs=\|self\._cr\|fields_view_get" \
      l10n_cl_dte/models/account_move.py --color=always
    
    # Esperado: 0 matches (código limpio Odoo 19 CE)
    ```

1.  El problema N+1 debe estar resuelto. El número de consultas a la base de datos debe ser constante e independiente del número de líneas de la factura.

2.  Todos los tests existentes relacionados con la validación de facturas (`account.move`) deben pasar exitosamente.

3.  **Crea un nuevo test unitario** en `l10n_cl_dte/tests/test_dte_performance.py` que específicamente valide este escenario: crea una factura con 200 líneas y mide (o comprueba) que la generación del DTE se completa eficientemente y sin un número excesivo de consultas.

4.  Ejecuta el linter (`pylint` o `ruff` según la configuración del proyecto) y asegúrate de que no introduce nuevos errores o advertencias.

5.  **Validación Odoo 19 CE post-cambios:**
    ```bash
    # Auditoría automática módulo modificado
    python3 scripts/odoo19_migration/1_audit_deprecations.py \
      --target l10n_cl_dte/
    
    # Esperado: 0 deprecaciones P0/P1 en archivos modificados
    ```

**ENTREGABLE:**
- Código modificado en los archivos correspondientes.
- Nuevo archivo de test o test modificado que cubra el caso de uso.
- Un commit siguiendo las convenciones del proyecto. El mensaje del commit debe ser: `refactor(l10n_cl_dte): Optimize DTE line processing to fix N+1 issue`.
- **Validación Odoo 19 CE:** Confirmar 0 deprecaciones P0/P1 introducidas (ejecutar `python3 scripts/odoo19_migration/1_audit_deprecations.py --target l10n_cl_dte/`)
