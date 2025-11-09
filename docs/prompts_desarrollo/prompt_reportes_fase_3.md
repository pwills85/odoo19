# PROMPT: Módulo Reportes - Fase 3: Reportes Financieros Contables Fundamentales

## 1. Contexto

Con la conclusión exitosa de la Fase 1 (Estabilización Técnica) y la Fase 2 (Inteligencia de Negocios), el módulo `l10n_cl_financial_reports` posee una base sólida y funcionalidades de BI proactivas. La Fase 3 es la culminación de este proyecto: la implementación del conjunto de reportes financieros y contables que forman el núcleo de la gestión financiera de cualquier empresa en Chile.

## 2. Objetivo Principal (Fase 3)

Implementar de forma **magistral** el set completo de reportes financieros chilenos, asegurando una integración profunda y nativa con el motor contable de Odoo 19 Community Edition. El resultado debe ser una herramienta de reportería financiera de nivel enterprise, que sea precisa, performante y ofrezca una experiencia de usuario superior para análisis y auditoría.

La "implementación magistral" implica:
- **Uso del Framework Nativo:** Utilizar el framework `account.report` de Odoo siempre que sea posible para una integración perfecta.
- **Rendimiento:** Las consultas deben estar optimizadas para manejar grandes volúmenes de datos sin degradar la experiencia.
- **UX de Auditoría:** Todos los reportes deben tener capacidad de **"drill-down"**, permitiendo al usuario navegar desde un monto consolidado hasta los asientos contables individuales que lo componen.
- **Precisión Contable:** La lógica debe adherirse estrictamente a los Principios de Contabilidad Generalmente Aceptados (PCGA) en Chile.

## 3. Requisitos Detallados por Reporte

### US 3.1: Balance General Clasificado / Estado de Situación Financiera

- **Objetivo:** Presentar la situación financiera de la empresa en un punto específico en el tiempo.
- **Implementación:** 
    - Utilizar el framework `account.report` para definir la estructura jerárquica.
    - **Estructura:** Activo (Corriente, No Corriente), Pasivo (Corriente, No Corriente) y Patrimonio.
    - **Funcionalidades Clave:**
        - Filtros por fecha y comparación entre periodos.
        - Capacidad de drill-down en todas las líneas del reporte.
        - Exportación a PDF y XLSX.

### US 3.2: Estado de Resultados

- **Objetivo:** Reportar el rendimiento financiero de la empresa durante un período de tiempo.
- **Implementación:**
    - Utilizar el framework `account.report`.
    - **Estructura:** Ingresos Operacionales, Costo de Venta, Margen Bruto, Gastos de Administración y Venta (GAV), Resultados Operacionales, etc.
    - **Funcionalidades Clave:**
        - Filtros por rango de fechas, análisis comparativo (ej. mes actual vs. mes anterior).
        - Drill-down en todas las líneas.
        - Exportación a PDF y XLSX.

### US 3.3: Balance Tributario de Ocho Columnas

- **Objetivo:** Un reporte tributario fundamental en Chile que muestra un resumen completo de los movimientos y saldos de todas las cuentas.
- **Implementación:**
    - Este es un reporte complejo que probablemente requiera una implementación customizada (no se ajusta 100% al `account.report` estándar).
    - **Estructura (8 Columnas Dobles):**
        1.  **Saldos Iniciales:** (Debe / Haber)
        2.  **Movimientos del Período:** (Debe / Haber)
        3.  **Saldos Finales:** (Deudor / Acreedor)
        4.  **Balance:** (Activo / Pasivo y Patrimonio)
        5.  **Resultados:** (Pérdida / Ganancia)
    - **Funcionalidades Clave:**
        - El reporte debe ser una tabla que liste **todas** las cuentas contables con movimiento.
        - Los cálculos deben ser exactos para que las columnas cuadren perfectamente.
        - Exportación a XLSX es **crítica** para este reporte. El PDF es secundario.

### US 3.4: Estado de Flujo de Efectivo (Método Indirecto)

- **Objetivo:** Mostrar cómo la empresa genera y utiliza el efectivo.
- **Implementación:**
    - Implementar usando el método indirecto, que parte de la utilidad neta y la ajusta por partidas no monetarias.
    - **Estructura:** Flujos de Actividades de Operación, Inversión y Financiación.
    - **Funcionalidades Clave:**
        - Wizard para configurar las cuentas de efectivo y equivalentes.
        - Lógica para clasificar los movimientos contables en las tres actividades.
        - Drill-down y exportación a PDF/XLSX.

### US 3.5: Libros Contables Fundamentales (Diario y Mayor)

- **Objetivo:** Generar los libros oficiales requeridos por el SII.
- **Implementación:**
    - **Libro Diario:** Un listado cronológico de todos los asientos contables (`account.move`) en un período.
    - **Libro Mayor:** Un resumen de los movimientos (débitos y créditos) para cada cuenta contable, mostrando el saldo inicial y final.
    - **Funcionalidades Clave:**
        - Formato y columnas deben seguir la normativa chilena.
        - La exportación a XLSX es prioritaria.

## 4. Máximas de Desarrollo

- **Calidad del Código:** Adherencia estricta a `flake8`, `pylint` y `black`.
- **Pruebas Unitarias:** Se requiere una cobertura de tests superior al 90% para la lógica de negocio de cada reporte.
- **Commits Atómicos:** Commits pequeños y bien descritos siguiendo el estándar de Conventional Commits.

## 5. Entregables Esperados

1.  **Commits en el Repositorio:** Implementando cada reporte y sus tests.
2.  **Definiciones de `account.report`:** Nuevos registros y vistas para los reportes.
3.  **Plantillas QWeb:** Para las exportaciones a PDF y vistas en la UI.
4.  **Tests Unitarios:** Validando la lógica de cálculo y la estructura de cada reporte.
5.  **Informe de Cierre de Fase 3:** Un documento `FASE3_COMPLETADA.md` resumiendo los logros.
