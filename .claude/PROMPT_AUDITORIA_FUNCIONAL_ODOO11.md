# 🔍 PROMPT MASTER - AUDITORÍA FUNCIONAL PROFUNDA ODOO 11 PRODUCCIÓN
## Análisis Know-How | Identificación de Features | Comparación con Desarrollo Actual

**Versión:** 1.0 (Auditoría Funcional Profunda)  
**Fecha:** 2025-11-09  
**Tipo:** Auditoría Funcional (NO Técnica/Migración)  
**Objetivo Principal:** Identificar know-how funcional existente para preservar en Odoo 19  
**Ruta Producción:** `/Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons`  
**Ruta Desarrollo:** `/Users/pedro/Documents/odoo19/addons/localization`

---

## 🎯 OBJETIVO PRINCIPAL

### Misión del Agente Auditor

**OBJETIVO CRÍTICO:** Realizar una auditoría funcional profunda de los módulos de facturación y gestión de nóminas en producción (Odoo 11) para:

1. **Identificar Know-How Funcional:**
   - Todas las features que funcionan actualmente
   - Lógica de negocio implementada
   - Cálculos y fórmulas utilizadas
   - Reglas de negocio aplicadas

2. **Documentar Arquitectura Funcional:**
   - Modelos de datos y sus relaciones
   - Vistas y flujos de usuario
   - Menús y estructura de navegación
   - Reportes y exportaciones

3. **Preservar Conocimiento:**
   - Documentar funcionalidad existente
   - Identificar gaps regulatorios 2025
   - Comparar con desarrollo actual Odoo 19

**⚠️ IMPORTANTE:** Esta auditoría es FUNCIONAL, NO TÉCNICA. No nos interesa cómo está implementado técnicamente en Odoo 11, sino QUÉ hace y CÓMO funciona desde la perspectiva del negocio.

---

## 📋 ALCANCE DE LA AUDITORÍA

### Módulos a Auditar

**Módulos Principales Identificados en Producción:**

1. **Facturación Electrónica (DTE/Chile):**
   - `l10n_cl_fe` - Facturación Electrónica (módulo principal DTE)
   - `l10n_cl_dte_factoring` - Factoring de DTE
   - `l10n_cl_balance` - Balance contable Chile
   - `l10n_cl_financial_indicators` - Indicadores financieros Chile
   - `l10n_cl_chart_of_account` - Plan de cuentas Chile
   - `l10n_cl_banks_sbif` - Bancos SBIF Chile

2. **Gestión de Nóminas (Payroll/Chile):**
   - `l10n_cl_hr` - Nóminas chilenas (módulo principal)
   - Módulos relacionados con cálculo de nóminas, AFP, Salud, Impuesto Único

**Ruta de Producción:**
```
/Users/pedro/Documents/contabo/produccion/odoo/11/prod_odoo-11_eergygroup/addons
```

**Módulos Específicos a Auditar:**
- `l10n_cl_fe/` - Facturación electrónica completa
- `l10n_cl_hr/` - Nóminas chilenas completas
- `l10n_cl_dte_factoring/` - Factoring de DTE
- `l10n_cl_balance/` - Balance contable
- `l10n_cl_financial_indicators/` - Indicadores financieros
- `l10n_cl_chart_of_account/` - Plan de cuentas
- `l10n_cl_banks_sbif/` - Bancos SBIF

**Ruta de Desarrollo (Referencia):**
```
/Users/pedro/Documents/odoo19/addons/localization
```

### Excluido del Alcance

**NO Auditar:**
- ❌ Código técnico específico de Odoo 11 (decoradores, API, etc.)
- ❌ Migración técnica de Odoo 11 a Odoo 19
- ❌ Problemas técnicos o bugs técnicos
- ❌ Optimizaciones de rendimiento
- ❌ Arquitectura técnica interna

**SÍ Auditar:**
- ✅ Funcionalidad de negocio
- ✅ Lógica de cálculos
- ✅ Reglas de negocio
- ✅ Flujos de usuario
- ✅ Modelos de datos (estructura, no implementación)
- ✅ Features y capacidades

---

## 🔍 METODOLOGÍA DE AUDITORÍA

### Fase 1: Identificación de Módulos (30min)

**Objetivo:** Identificar todos los módulos relevantes en producción.

**Tareas:**
1. Listar directorios en ruta de producción
2. Identificar módulos de facturación (l10n_cl_dte*, account*, invoice*)
3. Identificar módulos de nóminas (l10n_cl_hr_payroll*, hr_payroll*, payroll*)
4. Leer `__manifest__.py` de cada módulo para entender dependencias y propósito
5. Crear inventario de módulos con descripción funcional

**Entregable:**
- Archivo: `evidencias/auditoria_fase1_inventario_modulos.md`
- Contenido: Lista de módulos con descripción funcional, dependencias, propósito

---

### Fase 2: Análisis de Modelos de Datos (2-3h)

**Objetivo:** Documentar estructura de datos y relaciones funcionales.

**Tareas:**

#### 2.1 Modelos de Facturación (1-1.5h)

**Para cada modelo relacionado con facturación:**

1. **Identificar Modelo:**
   ```bash
   # Buscar definiciones de modelos
   grep -r "class.*models.Model\|_name.*=" addons/[modulo_facturacion]/models/
   ```

2. **Documentar Campos:**
   - Nombre del campo
   - Tipo de campo (funcional, no técnico)
   - Propósito funcional
   - Relaciones con otros modelos

3. **Documentar Relaciones:**
   - Many2one, One2many, Many2many
   - Propósito funcional de cada relación
   - Flujo de datos

4. **Documentar Métodos de Negocio:**
   - Métodos que implementan lógica de negocio
   - Cálculos realizados
   - Validaciones funcionales

**Entregable:**
- Archivo: `evidencias/auditoria_fase2_modelos_facturacion.md`
- Contenido: Documentación completa de modelos con campos, relaciones, métodos de negocio

#### 2.2 Modelos de Nóminas (1-1.5h)

**Para cada modelo relacionado con nóminas:**

1. **Identificar Modelo:**
   ```bash
   # Buscar definiciones de modelos
   grep -r "class.*models.Model\|_name.*=" addons/[modulo_nominas]/models/
   ```

2. **Documentar Campos:**
   - Nombre del campo
   - Tipo de campo (funcional)
   - Propósito funcional
   - Relaciones con otros modelos

3. **Documentar Relaciones:**
   - Many2one, One2many, Many2many
   - Propósito funcional de cada relación
   - Flujo de datos

4. **Documentar Métodos de Negocio:**
   - Métodos que implementan lógica de negocio
   - Cálculos realizados (AFP, Salud, AFC, Impuesto Único, Gratificación)
   - Validaciones funcionales

**Entregable:**
- Archivo: `evidencias/auditoria_fase2_modelos_nominas.md`
- Contenido: Documentación completa de modelos con campos, relaciones, métodos de negocio

---

### Fase 3: Análisis de Cálculos y Lógica de Negocio (3-4h)

**Objetivo:** Documentar todos los cálculos y fórmulas utilizadas.

#### 3.1 Cálculos de Facturación (1.5-2h)

**Tareas:**

1. **Cálculos de Impuestos:**
   - Identificar cómo se calculan impuestos (IVA, exentos, etc.)
   - Documentar fórmulas utilizadas
   - Documentar reglas de aplicación

2. **Cálculos de Totales:**
   - Cómo se calculan subtotales, totales, descuentos
   - Documentar fórmulas utilizadas

3. **Cálculos de DTE:**
   - Cómo se generan folios
   - Cómo se calculan totales para DTE
   - Validaciones funcionales

4. **Cálculos de Libros:**
   - Cómo se generan libros de compras y ventas
   - Qué datos se incluyen
   - Cómo se agrupan y totalizan

**Entregable:**
- Archivo: `evidencias/auditoria_fase3_calculos_facturacion.md`
- Contenido: Documentación completa de cálculos con fórmulas, ejemplos, casos de uso

#### 3.2 Cálculos de Nóminas (1.5-2h)

**Tareas:**

1. **Cálculos Previsionales:**
   - AFP: Tasa, tope, cálculo
   - Salud (FONASA/ISAPRE): Tasa, cálculo
   - AFC: Tasa, tope, cálculo
   - Documentar fórmulas utilizadas

2. **Cálculo de Impuesto Único:**
   - Tramo exento
   - Tramo 1 (4%)
   - Tramo 2 (8%)
   - Tramo 3 (13%)
   - Tramo 4 (23%)
   - Tramo 5 (30%)
   - Tramo 6 (35%)
   - Tramo 7 (40%)
   - Documentar fórmulas utilizadas

3. **Cálculo de Gratificación Legal:**
   - Base de cálculo
   - Porcentaje aplicado
   - Tope legal
   - Mensualización
   - Documentar fórmulas utilizadas

4. **Cálculos Adicionales:**
   - Horas extras
   - Bonos y asignaciones
   - Descuentos legales
   - Documentar fórmulas utilizadas

**Entregable:**
- Archivo: `evidencias/auditoria_fase3_calculos_nominas.md`
- Contenido: Documentación completa de cálculos con fórmulas, ejemplos, casos de uso

---

### Fase 4: Análisis de Vistas y Flujos de Usuario (2h)

**Objetivo:** Documentar interfaz de usuario y flujos funcionales.

#### 4.1 Vistas de Facturación (1h)

**Tareas:**

1. **Vistas de Formulario:**
   - Campos visibles
   - Campos requeridos
   - Campos calculados
   - Botones y acciones disponibles

2. **Vistas de Lista:**
   - Columnas visibles
   - Filtros disponibles
   - Agrupaciones disponibles
   - Acciones masivas

3. **Vistas de Búsqueda:**
   - Campos buscables
   - Filtros predefinidos
   - Agrupaciones predefinidas

4. **Flujos de Usuario:**
   - Crear factura
   - Validar factura
   - Enviar a SII
   - Generar DTE
   - Exportar libros

**Entregable:**
- Archivo: `evidencias/auditoria_fase4_vistas_facturacion.md`
- Contenido: Documentación completa de vistas y flujos de usuario

#### 4.2 Vistas de Nóminas (1h)

**Tareas:**

1. **Vistas de Formulario:**
   - Campos visibles
   - Campos requeridos
   - Campos calculados
   - Botones y acciones disponibles

2. **Vistas de Lista:**
   - Columnas visibles
   - Filtros disponibles
   - Agrupaciones disponibles
   - Acciones masivas

3. **Vistas de Búsqueda:**
   - Campos buscables
   - Filtros predefinidos
   - Agrupaciones predefinidas

4. **Flujos de Usuario:**
   - Crear nómina
   - Calcular nómina
   - Validar nómina
   - Confirmar nómina
   - Exportar a Previred
   - Generar reportes

**Entregable:**
- Archivo: `evidencias/auditoria_fase4_vistas_nominas.md`
- Contenido: Documentación completa de vistas y flujos de usuario

---

### Fase 5: Análisis de Menús y Estructura de Navegación (1h)

**Objetivo:** Documentar estructura de menús y navegación.

**Tareas:**

1. **Menús Principales:**
   - Identificar menús principales
   - Documentar estructura jerárquica
   - Documentar accesos y permisos

2. **Submenús:**
   - Identificar submenús
   - Documentar agrupación funcional
   - Documentar accesos y permisos

3. **Acciones:**
   - Identificar acciones disponibles
   - Documentar propósito funcional
   - Documentar accesos y permisos

**Entregable:**
- Archivo: `evidencias/auditoria_fase5_menus_navegacion.md`
- Contenido: Documentación completa de menús y estructura de navegación

---

### Fase 6: Análisis de Reportes y Exportaciones (1.5h)

**Objetivo:** Documentar reportes y exportaciones disponibles.

#### 6.1 Reportes de Facturación (45min)

**Tareas:**

1. **Reportes Disponibles:**
   - Identificar reportes disponibles
   - Documentar propósito funcional
   - Documentar datos incluidos

2. **Exportaciones:**
   - Identificar exportaciones disponibles (Excel, CSV, PDF, XML)
   - Documentar formato de exportación
   - Documentar datos incluidos

**Entregable:**
- Archivo: `evidencias/auditoria_fase6_reportes_facturacion.md`
- Contenido: Documentación completa de reportes y exportaciones

#### 6.2 Reportes de Nóminas (45min)

**Tareas:**

1. **Reportes Disponibles:**
   - Identificar reportes disponibles
   - Documentar propósito funcional
   - Documentar datos incluidos

2. **Exportaciones:**
   - Identificar exportaciones disponibles (Excel, CSV, PDF, XML, Previred)
   - Documentar formato de exportación
   - Documentar datos incluidos

**Entregable:**
- Archivo: `evidencias/auditoria_fase6_reportes_nominas.md`
- Contenido: Documentación completa de reportes y exportaciones

---

### Fase 7: Análisis de Datos Maestros y Configuración (1h)

**Objetivo:** Documentar datos maestros y configuración necesaria.

**Tareas:**

1. **Datos Maestros:**
   - Identificar datos maestros necesarios (AFPs, ISAPREs, tramos de impuesto, etc.)
   - Documentar estructura de datos
   - Documentar valores por defecto

2. **Configuración:**
   - Identificar configuraciones necesarias
   - Documentar parámetros configurables
   - Documentar valores por defecto

**Entregable:**
- Archivo: `evidencias/auditoria_fase7_datos_maestros.md`
- Contenido: Documentación completa de datos maestros y configuración

---

### Fase 8: Identificación de Gaps Regulatorios 2025 (1h)

**Objetivo:** Identificar qué falta para cumplir con regulaciones 2025.

**Tareas:**

1. **Reforma Previsional 2025:**
   - Identificar si existe implementación de reforma 2025
   - Documentar qué falta implementar
   - Documentar cambios regulatorios necesarios

2. **Ley 21.735 (Reforma Pensiones):**
   - Identificar si existe implementación de Ley 21.735
   - Documentar qué falta implementar
   - Documentar cambios regulatorios necesarios

3. **Otros Cambios Regulatorios:**
   - Identificar otros cambios regulatorios 2025
   - Documentar qué falta implementar

**Entregable:**
- Archivo: `evidencias/auditoria_fase8_gaps_regulatorios_2025.md`
- Contenido: Documentación completa de gaps regulatorios identificados

---

### Fase 9: Comparación con Desarrollo Actual Odoo 19 (2h)

**Objetivo:** Comparar funcionalidad de producción con desarrollo actual.

**Tareas:**

1. **Comparación de Features:**
   - Identificar features en producción que NO están en desarrollo
   - Identificar features en desarrollo que NO están en producción
   - Identificar features con diferencias funcionales

2. **Comparación de Cálculos:**
   - Comparar fórmulas de cálculo
   - Identificar diferencias
   - Documentar qué está correcto en cada versión

3. **Comparación de Modelos:**
   - Comparar estructura de modelos
   - Identificar campos faltantes
   - Identificar campos adicionales

4. **Análisis de Riesgos:**
   - Identificar riesgos de pérdida de funcionalidad
   - Identificar riesgos de cambios funcionales incorrectos
   - Documentar recomendaciones

**Entregable:**
- Archivo: `evidencias/auditoria_fase9_comparacion_odoo19.md`
- Contenido: Documentación completa de comparación con análisis de riesgos y recomendaciones

---

### Fase 10: Generación de Reporte Ejecutivo (1h)

**Objetivo:** Generar reporte ejecutivo consolidado.

**Tareas:**

1. **Resumen Ejecutivo:**
   - Resumen de funcionalidad identificada
   - Resumen de gaps identificados
   - Resumen de comparación con desarrollo actual

2. **Recomendaciones:**
   - Recomendaciones para preservar know-how
   - Recomendaciones para cerrar gaps
   - Recomendaciones para mejorar desarrollo actual

3. **Plan de Acción:**
   - Priorización de features a preservar
   - Priorización de gaps a cerrar
   - Plan de implementación sugerido

**Entregable:**
- Archivo: `evidencias/auditoria_fase10_reporte_ejecutivo.md`
- Contenido: Reporte ejecutivo completo con resumen, recomendaciones y plan de acción

---

## 📊 ESTRUCTURA DE ENTREGABLES

### Archivos de Evidencia

Todos los entregables deben guardarse en la carpeta `evidencias/` con el siguiente formato:

```
evidencias/
├── auditoria_fase1_inventario_modulos.md
├── auditoria_fase2_modelos_facturacion.md
├── auditoria_fase2_modelos_nominas.md
├── auditoria_fase3_calculos_facturacion.md
├── auditoria_fase3_calculos_nominas.md
├── auditoria_fase4_vistas_facturacion.md
├── auditoria_fase4_vistas_nominas.md
├── auditoria_fase5_menus_navegacion.md
├── auditoria_fase6_reportes_facturacion.md
├── auditoria_fase6_reportes_nominas.md
├── auditoria_fase7_datos_maestros.md
├── auditoria_fase8_gaps_regulatorios_2025.md
├── auditoria_fase9_comparacion_odoo19.md
└── auditoria_fase10_reporte_ejecutivo.md
```

### Formato de Documentación

**Estructura Estándar para Cada Entregable:**

```markdown
# [Título del Entregable]

## Resumen Ejecutivo
- Objetivo del análisis
- Alcance cubierto
- Hallazgos principales

## Análisis Detallado
- [Contenido específico según fase]

## Conclusiones
- Conclusiones principales
- Recomendaciones
- Próximos pasos
```

---

## 🎯 CRITERIOS DE CALIDAD

### Documentación

- ✅ **Completa:** Cubre todos los aspectos funcionales identificados
- ✅ **Clara:** Lenguaje claro y comprensible
- ✅ **Estructurada:** Organizada de manera lógica
- ✅ **Ejemplos:** Incluye ejemplos prácticos cuando sea posible
- ✅ **Referencias:** Incluye referencias a código fuente cuando sea relevante

### Análisis

- ✅ **Profundo:** Análisis detallado de cada aspecto funcional
- ✅ **Preciso:** Información precisa y verificable
- ✅ **Relevante:** Enfocado en funcionalidad, no en detalles técnicos
- ✅ **Comparativo:** Compara con desarrollo actual cuando sea relevante

### Entregables

- ✅ **Puntuales:** Entregados según cronograma establecido
- ✅ **Completos:** Todos los entregables completados
- ✅ **Consistentes:** Formato consistente entre entregables
- ✅ **Accionables:** Incluyen recomendaciones y plan de acción

---

## ⚠️ PRINCIPIOS FUNDAMENTALES

### 🚫 NO Hacer

- ❌ **NO analizar código técnico:** No nos interesa cómo está implementado técnicamente
- ❌ **NO proponer migraciones técnicas:** No proponer cambios técnicos de Odoo 11 a 19
- ❌ **NO juzgar calidad técnica:** No evaluar calidad del código técnico
- ❌ **NO optimizar código:** No proponer optimizaciones técnicas

### ✅ SÍ Hacer

- ✅ **SÍ analizar funcionalidad:** Analizar QUÉ hace y CÓMO funciona desde perspectiva de negocio
- ✅ **SÍ documentar know-how:** Documentar conocimiento funcional existente
- ✅ **SÍ identificar gaps:** Identificar qué falta para cumplir con regulaciones 2025
- ✅ **SÍ comparar funcionalidad:** Comparar funcionalidad de producción con desarrollo actual

---

## 📋 CHECKLIST DE VALIDACIÓN

### Antes de Finalizar Cada Fase

- [ ] ¿Se identificaron todos los aspectos funcionales relevantes?
- [ ] ¿Se documentó de manera clara y estructurada?
- [ ] ¿Se incluyeron ejemplos cuando fue posible?
- [ ] ¿Se verificó la precisión de la información?
- [ ] ¿Se generó el entregable correspondiente?

### Antes de Finalizar Auditoría

- [ ] ¿Se completaron todas las fases?
- [ ] ¿Se generaron todos los entregables?
- [ ] ¿Se comparó con desarrollo actual?
- [ ] ¿Se identificaron todos los gaps?
- [ ] ¿Se generó el reporte ejecutivo?

---

## 🎯 OBJETIVO FINAL

Al finalizar esta auditoría, debemos tener:

1. **Conocimiento Completo:**
   - Documentación completa de funcionalidad existente en producción
   - Entendimiento profundo de lógica de negocio implementada
   - Identificación de know-how funcional a preservar

2. **Comparación Clara:**
   - Comparación detallada entre producción y desarrollo actual
   - Identificación de diferencias funcionales
   - Análisis de riesgos de pérdida de funcionalidad

3. **Plan de Acción:**
   - Priorización de features a preservar
   - Priorización de gaps a cerrar
   - Plan de implementación sugerido

**Objetivo:** Preservar todo el know-how funcional existente y asegurar que el desarrollo en Odoo 19 incluya todas las funcionalidades que actualmente funcionan en producción.

---

**FIN DEL PROMPT MASTER - AUDITORÍA FUNCIONAL PROFUNDA**

