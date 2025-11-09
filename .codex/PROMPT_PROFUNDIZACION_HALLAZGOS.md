# Prompt para Profundización y Ratificación de Hallazgos

## 🎯 Prompt para `codex-odoo-dev`

```bash
codex-odoo-dev "
Profundiza y ratifica los hallazgos de la auditoría técnica realizada previamente sobre los MÓDULOS CUSTOM/ADDONS que desarrollamos para Odoo 19 CE en el proyecto EERGYGROUP.

## CONTEXTO CRÍTICO - ARQUITECTURA DEL PROYECTO

⚠️ IMPORTANTE: Estamos desarrollando MÓDULOS CUSTOM (ADDONS) que se INTEGRAN con Odoo 19 CE, NO estamos modificando el código base de Odoo 19 CE.

Nuestros módulos custom:
- l10n_cl_dte: Módulo custom de facturación electrónica chilena
- l10n_cl_hr_payroll: Módulo custom de nómina chilena
- l10n_cl_financial_reports: Módulo custom de reportes financieros chilenos

Estos módulos custom:
- ✅ Heredan de modelos base de Odoo 19 CE usando _inherit
- ✅ Extienden funcionalidad de módulos base (account, purchase, hr, etc.)
- ✅ Se instalan como addons adicionales sobre Odoo 19 CE
- ❌ NO modifican el código core de Odoo 19 CE

Módulos BASE de Odoo 19 CE que nuestros módulos custom utilizan:
- account: Incluye account.report, account.analytic.account, account.move, etc.
- purchase: Incluye purchase.order (SIN project_id a menos que se instale módulo project)
- project: Módulo base Odoo 19 CE que añade project_id a purchase.order
- account.analytic.account: Existe en módulo account base (NO requiere project)

## MÁXIMAS DE AUDITORÍA Y DESARROLLO (NO NEGOCIABLES)

Este análisis debe adherirse estrictamente a las máximas establecidas en `docs/prompts_desarrollo/`:

### Máximas de Auditoría (MAXIMAS_AUDITORIA.md):
1. **Alcance y Trazabilidad**: Cada hallazgo debe referenciar archivo/línea exacta y cómo reproducirlo
2. **Evidencia y Reproducibilidad**: Evidencia mínima con pasos, dataset, capturas/logs, resultado esperado vs obtenido
3. **Cobertura y Profundidad**: Incluir happy path, bordes, multi-compañía, i18n, performance y seguridad
4. **Performance y Escalabilidad**: Definir umbrales y medir con QueryCounter o registros temporizados
5. **Seguridad y Privacidad**: Revisar ACL por rol, validar wizards y endpoints, probar acceso indebido entre compañías
6. **Correctitud Legal**: Verificar cálculos con vigencias (valid_from/valid_until), sin campos obsoletos
7. **Priorización de Gaps**: P0 (bloquea producción/incumple ley), P1 (alto impacto/riesgo), P2 (mejora), P3 (cosmético)

### Máximas de Desarrollo (MAXIMAS_DESARROLLO.md):
1. **Plataforma y Versionado**: Usar exclusivamente APIs y patrones de Odoo 19 CE. Prohibido código legacy sin refactor
2. **Integración y Cohesión**: Respetar integraciones nativas (account.report, account_edi, hr_payroll). Evitar duplicar lógica del core
3. **Datos Paramétricos y Legalidad**: Ningún valor legal hardcodeado. Centralizar en modelos con vigencias
4. **Rendimiento y Escalabilidad**: Evitar N+1 queries. Tests de rendimiento para escenarios ≥10k registros
5. **Seguridad y Acceso**: Definir ir.model.access.csv mínimo. Revisar ir.rule en multi-compañía
6. **Calidad de Código**: Estándares black, flake8/ruff, pylint. Tests ≥ 90% cobertura para lógica crítica
7. **Pruebas y Fiabilidad**: Cada corrección incluye test que fallaría antes del cambio. Tests deterministas

### Contexto Global de Módulos (CONTEXTO_GLOBAL_MODULOS.md):
- **Dependencias y Contratos**: Reportes consumen asientos/etiquetas estandarizados. Nómina publica totales contables. DTE integra con contabilidad
- **Datos Paramétricos**: Indicadores legales (UF, UTM, topes, tasas) en modelos centralizados con valid_from/valid_until
- **Multi-Compañía y Seguridad**: Toda consulta filtrada por company_id y reglas record
- **Reportería**: Estándar account.report. PDF QWeb con datos dinámicos
- **Rendimiento**: Metas guía: reportes <3s en 10k-50k líneas, nómina <5m/1k empleados

## HALLAZGOS A PROFUNDIZAR Y RATIFICAR

### HALLAZGO 1: Alcance DTE Incorrecto
Archivos: libs/dte_structure_validator.py:46, models/dte_inbox.py:62-72, __manifest__.py:22

Tareas:
1. Verifica que DTE_TYPES_VALID incluye 39, 41, 70 fuera del alcance B2B autorizado
2. Confirma que el manifest promete BHE fuera de scope
3. Valida que esto contradice el alcance EERGYGROUP (solo 33,34,52,56,61)
4. Ratifica si es un problema REAL o si hay justificación técnica

### HALLAZGO 2: Validación RUT sin Prefijo CL
Archivo: libs/dte_structure_validator.py:95-137

Tareas:
1. Analiza la función validate_rut() completa
2. Verifica si elimina prefijo CL antes de validar
3. Compara con otros lugares del código que SÍ eliminan CL (report_helper.py:408)
4. Ratifica si es un bug REAL o comportamiento intencional
5. Evalúa impacto: ¿Rechaza RUTs válidos en XML SII?

### HALLAZGO 3: libs/ con Dependencias ORM
Archivos: libs/sii_authenticator.py:27-28, libs/envio_dte_generator.py:36-37, libs/performance_metrics.py:62

Tareas:
1. Rastrea TODOS los lugares donde se importan estas librerías
2. Verifica si se usan SOLO desde modelos Odoo o también desde fuera
3. Analiza si los imports de Odoo (_ , UserError, request) son necesarios
4. Verifica si performance_metrics se usa desde cron/background (request puede ser None)
5. Ratifica si viola arquitectura Pure Python o es aceptable
6. Evalúa impacto real vs teórico

### HALLAZGO 4: Financial Reports Orientado a Odoo 18
Archivos: models/l10n_cl_f29_report.py:12, models/financial_report_service_model.py:14, models/date_helper.py:3, tests/test_odoo18_compatibility.py

Tareas CRÍTICAS:
1. Verifica si account.report existe en Odoo 19 CE base (módulo account)
2. Analiza si el código hereda correctamente: _inherit = 'account.report'
3. Verifica si el código FUNCIONA en Odoo 19 CE o está roto
4. Distingue entre:
   - Código roto (no funciona en Odoo 19)
   - Documentación desactualizada (funciona pero menciona Odoo 18)
   - Tests incorrectos (validan Odoo 18 en lugar de Odoo 19)
5. Ratifica si es problema REAL de código o solo documentación
6. Evalúa impacto: ¿Bloquea producción o solo confunde?

### HALLAZGO 5: Error Domain project_id Inexistente
Archivo: models/analytic_dashboard.py:489

Tareas:
1. Verifica dependencias de l10n_cl_dte: ¿Incluye módulo 'project'?
2. Analiza purchase.order base: ¿Tiene campo project_id?
3. Verifica si purchase.order base tiene analytic_account_id
4. Compara con purchase_order_dte.py:26 que define analytic_account_id
5. Compara con analytic_dashboard.py:281 que usa correctamente analytic_account_id
6. Ratifica si project_id existe cuando se instala módulo project
7. Evalúa: ¿Es error REAL o funcionalidad condicional?

### HALLAZGO 6: DTE 34 Incompleto
Archivo: models/purchase_order_dte.py:247-269

Tareas:
1. Analiza la función action_generar_liquidacion_dte34() completa
2. Verifica qué funcionalidad está implementada vs qué falta
3. Ratifica si es funcionalidad parcial o completamente ausente
4. Evalúa impacto: ¿Bloquea uso o solo muestra mensaje informativo?

### HALLAZGO 7: _sql_constraints en Payroll
Archivo: models/hr_economic_indicators.py:88-90

Tareas:
1. Verifica si _sql_constraints está deprecated en Odoo 19
2. Compara con @api.constrains usado en el mismo archivo (línea 101)
3. Ratifica si es problema REAL o patrón aceptable
4. Evalúa impacto: ¿Causa problemas en migraciones o solo no sigue estándares?

### HALLAZGO 8: Sin CI/CD ni Coverage Útil
Archivos: METRICAS_DETALLADAS_TESTING.csv:24, coverage.xml

Tareas:
1. Verifica si existe pipeline CI/CD (GitHub Actions, GitLab CI, etc.)
2. Analiza coverage.xml: ¿Reporta 0 líneas o tiene datos reales?
3. Verifica qué módulos están incluidos en coverage
4. Ratifica si es problema REAL o configuración pendiente
5. Evalúa impacto: ¿Bloquea desarrollo o solo falta observabilidad?

## FORMATO DEL ANÁLISIS

Para cada hallazgo, proporciona:

### 1. Análisis Técnico Profundo
- Revisión completa del código relacionado en NUESTROS MÓDULOS CUSTOM
- Verificación de dependencias y módulos BASE de Odoo 19 CE
- Comparación con estándares Odoo 19 CE (APIs, patrones, convenciones)
- Análisis de impacto real vs teórico según máximas de auditoría
- Verificación de cumplimiento con máximas de desarrollo (performance, seguridad, calidad)

### 2. Ratificación
- ✅ CONFIRMADO: Si el hallazgo es válido y requiere corrección
- ⚠️ MATIZADO: Si el hallazgo es parcialmente válido o necesita contexto
- ❌ REFUTADO: Si el hallazgo es incorrecto o hay justificación técnica

### 3. Contexto de Módulos Base
- Verifica qué funcionalidades están en módulos BASE de Odoo 19 CE (no en nuestros módulos custom)
- Identifica dependencias implícitas vs explícitas entre nuestros módulos custom y módulos base
- Evalúa si el hallazgo asume funcionalidad que debe estar en módulos base de Odoo 19 CE
- Distingue entre código de nuestros módulos custom vs código de módulos base de Odoo 19 CE

### 4. Impacto Real (Según Máximas de Auditoría)
- **P0**: ¿Bloquea producción o incumple ley?
- **P1**: ¿Alto impacto o riesgo?
- **P2**: ¿Es mejora/optimización?
- **P3**: ¿Es cosmético?
- Orden de trabajo: P0 → P1 → preflight rendimiento/seguridad → P2/P3

### 5. Evidencia Concreta (Según Máximas de Auditoría)
- Referencias exactas a código de NUESTROS MÓDULOS CUSTOM (archivo:línea)
- Comparaciones con módulos BASE de Odoo 19 CE (account, purchase, hr, etc.)
- Ejemplos de código que demuestran el hallazgo en nuestros módulos custom
- Distinción clara: código custom vs código base de Odoo 19 CE
- Pasos para reproducir el hallazgo (si aplica)
- Dataset usado o escenario de prueba (si aplica)

## RESTRICCIONES CRÍTICAS

❌ NO HAGAS CAMBIOS EN EL CÓDIGO
❌ NO MODIFIQUES ARCHIVOS
❌ NO IMPLEMENTES CORRECCIONES

✅ SOLO ANALIZA Y RATIFICA
✅ SOLO PROPORCIONA EVIDENCIA
✅ SOLO EVALÚA IMPACTO REAL

## OUTPUT ESPERADO

Genera un reporte estructurado con:

1. **Resumen Ejecutivo**
   - Total hallazgos ratificados vs matizados vs refutados
   - Hallazgos críticos confirmados
   - Hallazgos que requieren revisión adicional

2. **Análisis Detallado por Hallazgo**
   - Evidencia técnica completa
   - Ratificación (✅/⚠️/❌)
   - Contexto de módulos base
   - Impacto real evaluado

3. **Tabla Comparativa**
   - Hallazgo original vs Ratificación
   - Prioridad original vs Prioridad revisada
   - Razón del cambio (si aplica)

4. **Conclusiones**
   - Precisión del reporte original
   - Hallazgos confirmados críticos
   - Recomendaciones de acción priorizadas

Comienza el análisis ahora, profundizando en cada hallazgo y ratificándolo con evidencia técnica completa.
"
```

## 🎯 Prompt Alternativo (Más Conciso)

```bash
codex-odoo-dev "
Profundiza y ratifica los 8 hallazgos de la auditoría técnica de MÓDULOS CUSTOM/ADDONS desarrollados para Odoo 19 CE en el proyecto EERGYGROUP.

CONTEXTO CRÍTICO: Estamos desarrollando MÓDULOS CUSTOM (ADDONS) que se INTEGRAN con Odoo 19 CE base. Nuestros módulos custom (l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports) heredan de modelos base usando _inherit y extienden funcionalidad. Muchas funcionalidades están en módulos base de Odoo 19 CE (account, purchase, project). NO asumas que todo debe estar en nuestros módulos custom.

HALLAZGOS A RATIFICAR:
1. Alcance DTE (39/41/70 fuera de scope) - libs/dte_structure_validator.py:46
2. RUT sin prefijo CL - libs/dte_structure_validator.py:95-137
3. libs/ con ORM - sii_authenticator.py, envio_dte_generator.py, performance_metrics.py
4. Financial Reports Odoo 18 - Verificar si account.report existe en base Odoo 19
5. Error project_id - analytic_dashboard.py:489 (verificar si purchase.order base tiene project_id)
6. DTE 34 incompleto - purchase_order_dte.py:247-269
7. _sql_constraints Payroll - hr_economic_indicators.py:88-90
8. Sin CI/CD - METRICAS_DETALLADAS_TESTING.csv:24

PARA CADA HALLAZGO:
- Analiza código completo relacionado
- Verifica dependencias y módulos base Odoo 19 CE
- Ratifica: ✅ CONFIRMADO / ⚠️ MATIZADO / ❌ REFUTADO
- Evalúa impacto real: ¿Bloquea producción? ¿Afecta calidad? ¿Es mejora?
- Proporciona evidencia concreta (archivo:línea)

RESTRICCIÓN: ❌ NO HAGAS CAMBIOS, SOLO ANALIZA Y RATIFICA

OUTPUT: Reporte estructurado con resumen ejecutivo, análisis detallado por hallazgo, tabla comparativa y conclusiones.

Comienza ahora.
"
```

## 📋 Instrucciones de Uso

### Opción 1: Prompt Completo (Recomendado)
```bash
codex-odoo-dev "Profundiza y ratifica los hallazgos de la auditoría técnica realizada previamente sobre los módulos Odoo 19 CE del proyecto EERGYGROUP. [usar prompt completo arriba]"
```

### Opción 2: Prompt Conciso (Rápido)
```bash
codex-odoo-dev "Profundiza y ratifica los 8 hallazgos de la auditoría técnica. [usar prompt conciso arriba]"
```

## 🎯 Características del Prompt

1. **Contexto Crítico**: Enfatiza integración con módulos base Odoo 19 CE
2. **Tareas Específicas**: Para cada hallazgo con archivos y líneas exactas
3. **Restricciones Claras**: NO hacer cambios, solo analizar y ratificar
4. **Formato Estructurado**: Output esperado claramente definido
5. **Ratificación Explícita**: ✅/⚠️/❌ para cada hallazgo

## 📊 Output Esperado

El agente generará:
1. ✅ Resumen ejecutivo con totales ratificados/matizados/refutados
2. 📋 Análisis detallado por hallazgo con evidencia técnica
3. 📊 Tabla comparativa: original vs ratificado
4. 🎯 Conclusiones con recomendaciones priorizadas

---

**Nota**: El prompt está diseñado para que el agente profundice en cada hallazgo considerando que estamos desarrollando MÓDULOS CUSTOM/ADDONS que se integran con Odoo 19 CE base, sin hacer cambios en el código. El agente debe distinguir claramente entre código de nuestros módulos custom y código de módulos base de Odoo 19 CE. Todas las ratificaciones deben adherirse estrictamente a las máximas establecidas en `docs/prompts_desarrollo/MAXIMAS_AUDITORIA.md` y `docs/prompts_desarrollo/MAXIMAS_DESARROLLO.md`.

