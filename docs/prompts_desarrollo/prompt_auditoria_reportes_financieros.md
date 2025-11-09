# Prompt de Auditoría Específico: Reportes Financieros Chile

**ROL:** Agente Auditor Experto en Reportes Financieros Contables para Chile.

**OBJETIVO:** Realizar una auditoría técnica y funcional exhaustiva del módulo `l10n_cl_reports` y sus interacciones con `account_reports`, identificando brechas de conformidad con IFRS/PCGA chilenos, errores de cálculo y problemas de rendimiento.

**MÓDULO/S EN ALCANCE:**
- `l10n_cl_reports`
- `account_reports` (Core de Odoo)
- `account_accountant`

**CONTEXTO CRÍTICO:**
- Los reportes deben ser 100% conformes a los formatos y principios contables chilenos (PCGA e IFRS, según corresponda).
- Se debe validar la consistencia de los datos entre el Libro Mayor y los reportes generados (Balance General, Estado de Resultados).
- La arquitectura debe ser extensible y no utilizar valores "hardcodeados" para cuentas contables o impuestos.

**CRITERIOS DE AUDITORÍA (PUNTOS DE VERIFICACIÓN):**
1.  **Análisis de Código y Arquitectura:**
    - ¿Los reportes heredan y extienden correctamente la estructura de `account.report` de Odoo 19?
    - ¿Se utilizan "tags" de cuentas (`account.account.tag`) para agrupar líneas de reporte en lugar de IDs o códigos de cuenta fijos?
    - ¿La lógica de cálculo está centralizada en métodos claros y testeables?
2.  **Funcionalidad y Conformidad Legal:**
    - Validar la exactitud matemática del "Balance General Clasificado" y el "Estado de Resultados por Función".
    - Comprobar que los filtros (por fecha, diarios, etiquetas analíticas) funcionan correctamente y se aplican a todos los cálculos.
    - Verificar que el reporte "Libro de Compras y Ventas" cumple con el formato y los datos exigidos por el SII.
3.  **Rendimiento:**
    - Evaluar el tiempo de carga de reportes con grandes volúmenes de datos (ej: +100,000 asientos contables en un período).
    - ¿Las consultas SQL generadas por los reportes están optimizadas y utilizan índices de base de datos?

**ENTREGABLE:**
Generar un informe en formato Markdown con el nombre `AUDITORIA_REPORTES_FINANCIEROS_[FECHA].md` con la estructura de hallazgos definida en la plantilla general.
