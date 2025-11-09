# PROMPT: Módulo Nómina - Fase P1: Motor de Cálculo y Libro de Remuneraciones Electrónico (LRE)

## 1. Contexto

El informe de verificación ha confirmado de manera concluyente que la **Fase P0 (Indicadores y APV) está 100% completa y segura en el repositorio**. Con esta base fundamental establecida, podemos ahora construir la funcionalidad principal del módulo de nómina: el motor de cálculo de la liquidación de sueldo y la generación de su reporte legal más crítico.

## 2. Objetivo Principal (Fase P1)

Implementar el motor de cálculo de la liquidación de sueldo chilena de punta a punta y desarrollar la capacidad de generar el **Libro de Remuneraciones Electrónico (LRE)** en el formato exigido por la Dirección del Trabajo (DT). Al finalizar esta fase, el módulo será capaz de procesar un ciclo de nómina básico y cumplir con sus obligaciones de reporte legal.

## 3. Requisitos Detallados

### US 1.1: Motor de Cálculo de la Liquidación de Sueldo

**Descripción:** Evolucionar el modelo `hr.payslip` para que ejecute la secuencia completa de cálculos de una liquidación de sueldo chilena, utilizando las estructuras de Odoo (reglas salariales) y los datos de la Fase P0.

- **Acción:** Implementa la siguiente cadena de cálculo a través de reglas salariales (`hr.salary.rule`):

    1.  **Cálculo de Haberes:**
        -   `HABERES_IMPONIBLES`: Suma de todos los ingresos sujetos a cotización (Sueldo Base, Bonos, etc.).
        -   `HABERES_NO_IMPONIBLES`: Suma de ingresos no sujetos a cotización (ej. Asignación de Colación).

    2.  **Cálculo del Total Imponible con Topes:**
        -   `TOTAL_IMPONIBLE`: El valor de `HABERES_IMPONIBLES`.
        -   `TOPE_IMPONIBLE_UF`: Obtener el tope imponible legal en UF desde el modelo `l10n_cl.legal_caps` (creado en P0) y convertirlo a CLP usando el valor de la UF del último día del mes (desde `hr.economic_indicators`).
        -   `BASE_TRIBUTABLE`: Será el `min(TOTAL_IMPONIBLE, TOPE_IMPONIBLE_UF)`.

    3.  **Cálculo de Descuentos Previsionales:**
        -   **AFP (Pensión):** Calcular la cotización obligatoria (10%) más la comisión de la AFP del empleado sobre la `BASE_TRIBUTABLE`.
        -   **Salud (FONASA/ISAPRE):** Calcular la cotización de salud legal (7%) sobre la `BASE_TRIBUTABLE`.
        -   **Seguro de Cesantía (AFC):** Calcular el aporte del trabajador sobre la `BASE_TRIBUTABLE`.

    4.  **Cálculo del Impuesto Único de Segunda Categoría:**
        -   `BASE_IMPUESTO_UNICO`: `BASE_TRIBUTABLE` menos los descuentos previsionales.
        -   `IMPUESTO_UNICO`: Aplicar la tabla de `hr.tax.bracket` (creada en P0) sobre la `BASE_IMPUESTO_UNICO` para obtener el monto del impuesto a retener.

    5.  **Cálculo del Alcance Líquido:**
        -   `TOTAL_HABERES`: `HABERES_IMPONIBLES` + `HABERES_NO_IMPONIBLES`.
        -   `TOTAL_DESCUENTOS`: Suma de todos los descuentos (Previsionales, Impuesto Único, APV de P0, etc.).
        -   `SUELDO_LIQUIDO`: `TOTAL_HABERES` - `TOTAL_DESCUENTOS`.

### US 1.2: Generación del Libro de Remuneraciones Electrónico (LRE)

**Descripción:** Crear la funcionalidad para generar el archivo LRE que se declara mensualmente en el portal de la Dirección del Trabajo.

- **Investigación:** Antes de desarrollar, busca la documentación oficial y actualizada del layout del LRE en el sitio web de la Dirección del Trabajo de Chile. El formato es un CSV con una estructura y orden de columnas muy específico.
- **Implementación:**
    1.  **Crea un Wizard (`hr.lre.wizard`):** Debe permitir al usuario seleccionar el mes y año para el cual desea generar el reporte.
    2.  **Lógica de Generación:** Al ejecutar el wizard, el sistema debe:
        -   Recopilar todas las liquidaciones de sueldo (`hr.payslip`) del período seleccionado.
        -   Mapear los resultados de las reglas salariales de cada liquidación a las columnas correspondientes del formato LRE.
        -   Generar un archivo CSV con el contenido.
    3.  **Descarga:** El wizard debe ofrecer al usuario un link para descargar el archivo CSV generado.

### US 1.3: Pruebas de Integración y Casos de Borde

**Descripción:** Asegurar la robustez y precisión del motor de cálculo.

- **Acción:** Crea tests unitarios que validen:
    -   El cálculo completo de una liquidación para un empleado con sueldo bajo el mínimo imponible.
    -   El cálculo para un empleado con sueldo sobre el tope imponible, verificando la correcta aplicación de los topes.
    -   El cálculo para un empleado que además tiene un descuento de APV (integración con P0).
    -   La correcta generación de la estructura del LRE y que los totales del archivo coincidan con la suma de las liquidaciones de prueba.

## 4. Máximas de Desarrollo

- **Framework Odoo:** Utiliza el sistema de reglas salariales de Odoo de forma extensiva. Evita cálculos hardcodeados en métodos de Python.
- **Calidad y Estándares:** Adherencia estricta a `flake8`, `pylint`, `black` y Conventional Commits.
- **Cobertura de Pruebas:** Se exige una cobertura de tests superior al 90% para toda la nueva lógica de cálculo.

## 5. Entregables Esperados

1.  **Commits en el Repositorio:** Implementando las reglas salariales, el wizard LRE y los tests.
2.  **Reglas Salariales:** Nuevos registros de `hr.salary.rule` y sus correspondientes categorías.
3.  **Wizard LRE:** El modelo, la vista y la lógica del wizard para generar el LRE.
4.  **Tests Unitarios:** Pruebas exhaustivas para los casos de borde y la integración de cálculos.
5.  **Informe de Cierre de Fase 1:** Un documento `FASE_P1_COMPLETADA.md` resumiendo los logros.
