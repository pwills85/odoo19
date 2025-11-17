# Plantilla de Prompt para Agentes Auditores

**ROL:** Agente Auditor Experto en [NOMBE DEL MÓDULO, ej: Nómina Chilena].

**OBJETIVO:** Realizar una auditoría técnica y funcional exhaustiva del módulo y sus componentes relacionados, identificando brechas, malas prácticas y desviaciones respecto a los estándares definidos.

**MÓDULO/S EN ALCANCE:**
- [Nombre del módulo principal, ej: `l10n_cl_hr_payroll`]
- [Módulos relacionados o dependencias, ej: `hr_contract`, `hr_holidays`]

**CONTEXTO CRÍTICO:**
- Estamos en **Odoo 19 Community Edition**. La auditoría debe contrastar la implementación actual con la arquitectura nativa de Odoo 19 CE, favoreciendo siempre el estándar del framework.
- Se debe verificar la conformidad con la legislación chilena vigente a [FECHA ACTUAL].
- El código debe adherirse a las guías de estilo de Odoo (disponibles en la documentación oficial) y a los estándares de la OCA (Odoo Community Association).
- **Alcance de DTEs Soportados:** La auditoría debe validar la funcionalidad para el siguiente set de documentos: Facturas (Afecta/Exenta), Notas de Crédito/Débito y Guías de Despacho para ventas; y la recepción de los mismos para compras, además de Boletas de Honorarios (electrónicas y papel).
- **⚠️ CRÍTICO - Compliance Odoo 19 CE:** Todo código DEBE cumplir con estándares Odoo 19 CE (NO usar APIs deprecated de versiones anteriores). Ver checklist completo: `docs/prompts_desarrollo/CHECKLIST_ODOO19_VALIDACIONES.md`

**CRITERIOS DE AUDITORÍA (PUNTOS DE VERIFICACIÓN):**

0.  **✅ Compliance Odoo 19 CE (OBLIGATORIO - Validar PRIMERO):**
    - **Checklist completo:** `docs/prompts_desarrollo/CHECKLIST_ODOO19_VALIDACIONES.md`
    - **Guía deprecaciones:** `.claude/project/ODOO19_DEPRECATIONS_CRITICAL.md`
    
    **Validaciones P0 (Breaking Changes - Deadline: 2025-03-01):**
    - ✅ NO usar `t-esc` en templates XML (usar `t-out`)
    - ✅ NO usar `type='json'` en routes (usar `type='jsonrpc'` + `csrf=False`)
    - ⚠️ NO usar `attrs=` en XML views (usar expresiones Python directas)
    - ⚠️ NO usar `_sql_constraints` (usar `models.Constraint`)
    - ⚠️ NO usar `<dashboard>` tags (convertir a `<kanban class="o_kanban_dashboard">`)
    
    **Validaciones P1 (High Priority - Deadline: 2025-06-01):**
    - ✅ NO usar `self._cr` (usar `self.env.cr`)
    - ⚠️ NO usar `fields_view_get()` (usar `get_view()`)
    - 📋 Revisar `@api.depends` en herencias (comportamiento acumulativo Odoo 19)
    
    **Comando validación automática:**
    ```bash
    # Detectar deprecaciones P0+P1
    grep -rn "t-esc\|type='json'\|attrs=\|self\._cr\|fields_view_get" \
      addons/localization/[MÓDULO]/ --color=always
    
    # Esperado: 0 matches (excepto en tests comentados)
    ```

1.  **Análisis de Código y Arquitectura:**
    - ¿Existen clases o métodos que re-implementan lógica ya presente en el core de Odoo 19? (Ej: cálculo de impuestos, gestión de asientos contables).
    - ¿Se heredan correctamente los modelos (`_inherit`) o se están creando modelos duplicados?
    - ¿El código sigue las convenciones de nomenclatura y estilo de Python (PEP8) y de Odoo?
    - ¿Hay código comentado, lógica "muerta" o dependencias innecesarias?
    
2.  **Funcionalidad y Conformidad Legal:**
    - Validar que los cálculos [ej: de cotizaciones previsionales, impuestos, finiquitos] son correctos según la normativa de la Dirección del Trabajo y PreviRed.
    - Verificar que los campos y modelos de datos cubren todos los requerimientos legales para [ej: contratos, liquidaciones de sueldo].
    - ¿Las vistas (formularios, listas, kanban) presentan toda la información requerida de forma clara y usable?
    
3.  **Rendimiento y Seguridad:**
    - ¿Existen consultas ORM ineficientes (bucles N+1, búsquedas sobre campos no indexados)?
    - ¿Se manejan adecuadamente los permisos de acceso (`ir.model.access.csv` y grupos de seguridad)?
    - ¿Hay vulnerabilidades potenciales (ej: inyección SQL, exposición de datos sensibles)?
    
4.  **Testing:**
    - Evaluar la cobertura de tests unitarios y funcionales. ¿Son los tests robustos y cubren los casos de uso críticos y de borde?

**ENTREGABLE:**
Generar un informe en formato Markdown con el nombre `AUDITORIA_[MODULO]_[FECHA].md`. El informe debe contener:

1.  **Resumen Ejecutivo:** Breve descripción de los hallazgos más críticos.

2.  **✅ Compliance Odoo 19 CE (SECCIÓN OBLIGATORIA):**
    - Estado validaciones P0 (Breaking Changes):
      - t-esc: [OK/FAIL - N occurrences]
      - type='json': [OK/FAIL - N occurrences]
      - attrs=: [OK/FAIL - N occurrences]
      - _sql_constraints: [OK/FAIL - N occurrences]
      - <dashboard>: [OK/FAIL - N occurrences]
    - Estado validaciones P1 (High Priority):
      - self._cr: [OK/FAIL - N occurrences]
      - fields_view_get(): [OK/FAIL - N occurrences]
      - @api.depends herencias: [AUDIT - N occurrences]
    - **Compliance Rate:** [X%] = (validaciones OK / total validaciones) * 100
    - **Deadline P0:** 2025-03-01 ([N] días restantes)
    - **Archivos críticos pendientes:** [Lista si aplica]

3.  **Matriz de Hallazgos:** Una tabla con las siguientes columnas:
    - `ID`: Identificador único del hallazgo.
    - `Archivo/Línea`: Ruta del archivo y número de línea.
    - `Descripción del Hallazgo`: Explicación clara y concisa del problema.
    - `Criticidad`: (P0-Critical, P1-High, P2-Medium, P3-Low).
    - `Criterio Incumplido`: Referencia al punto de la auditoría que no se cumple.
    - `Recomendación`: Sugerencia técnica para la solución.
    - **Compliance Odoo 19:** [SÍ/NO] - Indica si es deprecación Odoo 19

**RESTRICCIONES:**
- Operar en modo de solo lectura. No modificar ningún archivo.
- Basar el análisis únicamente en los archivos del repositorio y la documentación oficial de Odoo y la legislación chilena.
