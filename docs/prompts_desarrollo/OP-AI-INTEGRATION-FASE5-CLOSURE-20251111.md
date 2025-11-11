# 🎯 PROMPT MAESTRO FASE 5: VALIDACIÓN Y CIERRE TOTAL

**ID de Operación**: `OP-AI-INTEGRATION-FASE5-CLOSURE-20251111`  
**Prioridad**: 🔴 **CRÍTICA**  
**Para**: Copilot CLI (Claude Sonnet 4.5)  
**Modo**: **AUTÓNOMO PRIVILEGIADO** (sin interrupciones)  
**Basado en**: `ANALISIS_CRITICO_CIERRE_REAL_VS_ESPERADO_2025-11-11.md`  
**Contexto**: Fases 1-4 completadas al 61% - 11 brechas pendientes

---

## 🤖 CONFIGURACIÓN MODO AUTÓNOMO PRIVILEGIADO

### Permisos Automáticos (NO SOLICITAR CONFIRMACIÓN)

```yaml
PERMISOS LECTURA (SIEMPRE PERMITIDOS):
  - Leer CUALQUIER archivo del proyecto
  - Ejecutar: grep, find, cat, head, tail, wc
  - Analizar código Python, XML, YAML, MD
  - Acceder a: addons/localization/l10n_cl_hr_payroll/
  - Acceder a: ai-service/

PERMISOS ESCRITURA (SIEMPRE PERMITIDOS):
  - Modificar archivos Python (.py)
  - Modificar archivos XML (.xml)
  - Modificar archivos de configuración (.env.example)
  - Crear nuevos archivos de test
  - Generar reportes (.md, .txt)

PERMISOS EJECUCIÓN (SIEMPRE PERMITIDOS):
  - Docker: docker compose exec odoo [comandos]
  - Tests: pytest, odoo-bin --test-enable
  - Linters: flake8, black
  - Git: status, diff, add (NO commit automático)

PROHIBIDO:
  - git commit (solo preparar, NO ejecutar)
  - git push
  - Eliminar archivos sin backup
  - Modificar configuraciones Docker

CONFIGURACIÓN EJECUCIÓN:
  modo: autonomous
  ask_permission: false
  stop_on_error: false
  max_iterations: 1000
  auto_fix_errors: true
  generate_reports: true
  log_everything: true
```

---

## 📋 DIRECTIVA PRINCIPAL

Actúa como **Ingeniero Senior y Auditor de Cierre**. Tu misión es:

1. **VALIDAR** hallazgos del análisis crítico
2. **COMPLETAR** las 11 brechas pendientes (39%)
3. **ALCANZAR** Readiness AI-Driven 99/100
4. **REPORTAR** estado cada hora

**Objetivo**: Sistema 100% AI-Driven sin hardcoding residual.

**Duración Estimada**: 22 horas (~3 días)

**NO TE DETENGAS** hasta completar las 6 tareas o encontrar bloqueante P0.

---

## 🔍 FASE 5.0: VALIDACIÓN INICIAL (2 horas)

**Objetivo**: Confirmar hallazgos del análisis crítico antes de proceder.

### Tarea 5.0.1: Auditoría de Campos Implementados

**Rol**: Auditor de Modelo de Datos  
**Brecha**: Validar P0-004 (parcial)

**Instrucciones**:

1. Abre `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py`

2. Cuenta EXACTAMENTE cuántos campos están implementados:
   ```bash
   # Ejecuta:
   grep -c "fields\." addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
   ```

3. Lista TODOS los campos faltantes comparando con:
   - AI service endpoint: `ai-service/payroll/previred_scraper.py` (líneas 243-292)
   - Esperado: 60 campos totales

4. Genera reporte:
   ```markdown
   AUDITORIA_CAMPOS_MODELO_2025-11-11.md
   
   ## CAMPOS IMPLEMENTADOS
   [Lista completa con línea de código]
   
   ## CAMPOS FALTANTES (de 60 totales)
   ### Asignación Familiar (16 faltantes)
   - asig_fam_maternal_tramo_1
   - asig_fam_maternal_tramo_2
   - ...
   
   ### Tasas AFP por Fondo (23 faltantes)
   - afp_capital_fondo_c
   - afp_cuprum_fondo_a
   - ...
   
   ### Tasas Cotización (4 faltantes)
   - afc_trabajador_plazo_fijo
   - ...
   
   ### Otros (2 faltantes)
   - uta
   - salud_tope_uf
   
   ## SCORE
   Implementados: [N]/60 ([%])
   Faltantes: [N]/60 ([%])
   ```

**Criterio de Aceptación**: Reporte generado con lista exacta de campos faltantes.

---

### Tarea 5.0.2: Auditoría de Hardcoding Residual

**Rol**: Auditor de Código  
**Brecha**: Validar eliminación completa

**Instrucciones**:

1. Busca TODOS los valores hardcoded que persisten:
   ```bash
   cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll
   
   # Buscar en código Python
   grep -rn "87\.8\|131\.9\|83\.1" --include="*.py" models/
   
   # Buscar en docstrings/comentarios
   grep -rn "Tope.*87\.8\|Tope.*131\.9" --include="*.py" models/
   
   # Buscar en XMLs
   grep -rn "87\.8\|131\.9\|83\.1" --include="*.xml" data/
   ```

2. Clasifica hallazgos:
   - **CRÍTICO**: Hardcoding en lógica ejecutable
   - **MEDIO**: Hardcoding en comentarios/docstrings
   - **BAJO**: Hardcoding en tests (con justificación)

3. Genera reporte:
   ```markdown
   AUDITORIA_HARDCODING_RESIDUAL_2025-11-11.md
   
   ## HARDCODING CRÍTICO (lógica ejecutable)
   [archivo:línea] - [código]
   
   ## HARDCODING MEDIO (comentarios/docstrings)
   [archivo:línea] - [comentario]
   
   ## HARDCODING BAJO (tests justificados)
   [archivo:línea] - [test]
   
   ## SCORE
   Total residual: [N] instancias
   vs Original: 77 instancias
   Eliminación: [%]
   ```

**Criterio de Aceptación**: Lista completa con clasificación por severidad.

---

### Tarea 5.0.3: Validación Estado Reglas XML

**Rol**: Auditor de Reglas Salariales  
**Brecha**: P1-012 (NO cerrada)

**Instrucciones**:

1. Lista TODOS los archivos XML de reglas:
   ```bash
   find addons/localization/l10n_cl_hr_payroll/data -name "*salary*rule*.xml"
   ```

2. Para CADA archivo XML, busca código Python embebido:
   ```bash
   # Buscar tags con código Python
   for file in data/*salary*rule*.xml; do
       echo "=== $file ==="
       grep -A10 '<field name="code">\|<field name="amount_python_compute">' "$file" | \
           grep -E "[0-9]+\.[0-9]+|[0-9]{4,6}" | head -20
   done
   ```

3. Identifica valores numéricos sospechosos (87.8, 131.9, 500000, etc.)

4. Genera reporte:
   ```markdown
   AUDITORIA_REGLAS_XML_2025-11-11.md
   
   ## ARCHIVOS AUDITADOS
   - hr_salary_rules_ley21735.xml: [N líneas]
   - hr_salary_rules_p1.xml: [N líneas]
   - ...
   
   ## HARDCODING DETECTADO
   ### Archivo: [nombre]
   - Línea [N]: [código con hardcoding]
   - Tipo: [tope/tasa/valor]
   - Debe usar: payslip.indicadores_id.[campo]
   
   ## SCORE
   Archivos auditados: [N]/5
   Instancias hardcoding: [N]
   ```

**Criterio de Aceptación**: Los 5 archivos XML auditados con hallazgos documentados.

---

### Tarea 5.0.4: Checkpoint de Validación

**Instrucciones**:

1. Genera resumen consolidado:
   ```markdown
   VALIDACION_FASE5_CHECKPOINT_2025-11-11.md
   
   ## HALLAZGOS CONFIRMADOS
   
   ### P0-004: Campos Faltantes
   - Esperado: 60 campos
   - Implementado: [N] campos
   - Faltantes: [N] campos ❌
   - Confirmado: [SÍ/NO]
   
   ### P1-007: Tasas AFP Fondo
   - Esperado: 25 campos
   - Implementado: [N] campos
   - Faltantes: [N] campos ❌
   - Confirmado: [SÍ/NO]
   
   ### P1-012: Reglas XML
   - Auditados: [N]/5 archivos
   - Hardcoding detectado: [N] instancias
   - Confirmado: [SÍ/NO]
   
   ### Hardcoding Residual
   - Crítico: [N] instancias
   - Medio: [N] instancias
   - Bajo: [N] instancias
   - Score eliminación: [%]
   
   ## DECISIÓN
   - [ ] Proceder con FASE 5.1 (cierre total)
   - [ ] Hallazgos NO confirmados, ajustar análisis
   
   ## READINESS CONFIRMADO
   Actual: [N]/100
   Objetivo: 99/100
   Gap: [N] puntos
   ```

2. Si hallazgos confirmados → Proceder a FASE 5.1  
   Si NO confirmados → Reportar discrepancia y DETENER

**Criterio de Aceptación**: Decisión clara de proceder o detener con evidencia.

---

## 🔧 FASE 5.1: EXPANSIÓN COMPLETA DEL MODELO (8 horas)

**Objetivo**: Agregar los 45 campos faltantes a `hr.economic.indicators`.

### Tarea 5.1.1: Agregar Campos Asignación Familiar (2h)

**Rol**: Ingeniero de Modelos Odoo  
**Brecha**: P1-003 (parcial)

**Instrucciones**:

1. Abre `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py`

2. Después de `asig_fam_tramo_4` (línea ~89), agrega los 16 campos faltantes:
   ```python
   # Asignación Familiar - Maternal (4 campos)
   asig_fam_maternal_tramo_1 = fields.Monetary(
       string='Asig. Fam. Maternal Tramo 1 ($)',
       currency_field='currency_id',
       help='Asignación familiar maternal para tramo de ingreso 1'
   )
   asig_fam_maternal_tramo_2 = fields.Monetary(
       string='Asig. Fam. Maternal Tramo 2 ($)',
       currency_field='currency_id'
   )
   asig_fam_maternal_tramo_3 = fields.Monetary(
       string='Asig. Fam. Maternal Tramo 3 ($)',
       currency_field='currency_id'
   )
   asig_fam_maternal_tramo_4 = fields.Monetary(
       string='Asig. Fam. Maternal Tramo 4 ($)',
       currency_field='currency_id'
   )
   
   # Asignación Familiar - Invalidez (4 campos)
   asig_fam_invalidez_tramo_1 = fields.Monetary(
       string='Asig. Fam. Invalidez Tramo 1 ($)',
       currency_field='currency_id',
       help='Asignación familiar por invalidez tramo 1'
   )
   asig_fam_invalidez_tramo_2 = fields.Monetary(
       string='Asig. Fam. Invalidez Tramo 2 ($)',
       currency_field='currency_id'
   )
   asig_fam_invalidez_tramo_3 = fields.Monetary(
       string='Asig. Fam. Invalidez Tramo 3 ($)',
       currency_field='currency_id'
   )
   asig_fam_invalidez_tramo_4 = fields.Monetary(
       string='Asig. Fam. Invalidez Tramo 4 ($)',
       currency_field='currency_id'
   )
   
   # Asignación Familiar - Otros (8 campos)
   # Consultar previred_scraper.py para nombres exactos
   # Ejemplo:
   asig_fam_retroactiva = fields.Monetary(
       string='Asig. Fam. Retroactiva ($)',
       currency_field='currency_id'
   )
   # ... agregar los 7 campos restantes según AI service
   ```

3. Verifica sintaxis:
   ```bash
   python3 -m py_compile addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
   ```

**Criterio de Aceptación**: 16 campos agregados, sintaxis válida.

---

### Tarea 5.1.2: Agregar Campos Tasas AFP por Fondo (3h)

**Rol**: Ingeniero de Modelos Odoo  
**Brecha**: P1-007 (NO cerrada)

**Instrucciones**:

1. Después de `afp_capital_fondo_b` (línea ~100), agrega los 23 campos faltantes:
   ```python
   # AFP Capital - Fondos C, D, E
   afp_capital_fondo_c = fields.Float(
       string='Tasa AFP Capital Fondo C (%)',
       digits=(5, 2),
       help='Comisión AFP Capital Fondo C'
   )
   afp_capital_fondo_d = fields.Float(string='Tasa AFP Capital Fondo D (%)', digits=(5, 2))
   afp_capital_fondo_e = fields.Float(string='Tasa AFP Capital Fondo E (%)', digits=(5, 2))
   
   # AFP Cuprum - Todos los fondos (5 campos)
   afp_cuprum_fondo_a = fields.Float(string='Tasa AFP Cuprum Fondo A (%)', digits=(5, 2))
   afp_cuprum_fondo_b = fields.Float(string='Tasa AFP Cuprum Fondo B (%)', digits=(5, 2))
   afp_cuprum_fondo_c = fields.Float(string='Tasa AFP Cuprum Fondo C (%)', digits=(5, 2))
   afp_cuprum_fondo_d = fields.Float(string='Tasa AFP Cuprum Fondo D (%)', digits=(5, 2))
   afp_cuprum_fondo_e = fields.Float(string='Tasa AFP Cuprum Fondo E (%)', digits=(5, 2))
   
   # AFP Habitat - Todos los fondos (5 campos)
   afp_habitat_fondo_a = fields.Float(string='Tasa AFP Habitat Fondo A (%)', digits=(5, 2))
   afp_habitat_fondo_b = fields.Float(string='Tasa AFP Habitat Fondo B (%)', digits=(5, 2))
   afp_habitat_fondo_c = fields.Float(string='Tasa AFP Habitat Fondo C (%)', digits=(5, 2))
   afp_habitat_fondo_d = fields.Float(string='Tasa AFP Habitat Fondo D (%)', digits=(5, 2))
   afp_habitat_fondo_e = fields.Float(string='Tasa AFP Habitat Fondo E (%)', digits=(5, 2))
   
   # AFP PlanVital - Todos los fondos (5 campos)
   afp_planvital_fondo_a = fields.Float(string='Tasa AFP PlanVital Fondo A (%)', digits=(5, 2))
   afp_planvital_fondo_b = fields.Float(string='Tasa AFP PlanVital Fondo B (%)', digits=(5, 2))
   afp_planvital_fondo_c = fields.Float(string='Tasa AFP PlanVital Fondo C (%)', digits=(5, 2))
   afp_planvital_fondo_d = fields.Float(string='Tasa AFP PlanVital Fondo D (%)', digits=(5, 2))
   afp_planvital_fondo_e = fields.Float(string='Tasa AFP PlanVital Fondo E (%)', digits=(5, 2))
   
   # AFP Provida - Todos los fondos (5 campos)
   afp_provida_fondo_a = fields.Float(string='Tasa AFP Provida Fondo A (%)', digits=(5, 2))
   afp_provida_fondo_b = fields.Float(string='Tasa AFP Provida Fondo B (%)', digits=(5, 2))
   afp_provida_fondo_c = fields.Float(string='Tasa AFP Provida Fondo C (%)', digits=(5, 2))
   afp_provida_fondo_d = fields.Float(string='Tasa AFP Provida Fondo D (%)', digits=(5, 2))
   afp_provida_fondo_e = fields.Float(string='Tasa AFP Provida Fondo E (%)', digits=(5, 2))
   ```

2. Verifica sintaxis

**Criterio de Aceptación**: 23 campos AFP agregados, sintaxis válida.

---

### Tarea 5.1.3: Agregar Campos Tasas Cotización y Otros (1h)

**Rol**: Ingeniero de Modelos Odoo  
**Brecha**: P1-008 (parcial)

**Instrucciones**:

1. Agrega campos faltantes de tasas cotización:
   ```python
   # Tasas Cotización - Plazo Fijo
   afc_trabajador_plazo_fijo_pct = fields.Float(
       string='Tasa AFC Trab. Plazo Fijo (%)',
       digits=(5, 2),
       help='Tasa AFC trabajador plazo fijo (0.0%)'
   )
   afc_empleador_plazo_fijo_pct = fields.Float(
       string='Tasa AFC Emp. Plazo Fijo (%)',
       digits=(5, 2),
       help='Tasa AFC empleador plazo fijo (3.0%)'
   )
   aporteafpe_pct = fields.Float(
       string='Aporte Empleador (%)',
       digits=(5, 2),
       help='Aporte adicional empleador'
   )
   ```

2. Agrega campos indicadores faltantes:
   ```python
   # Indicadores Económicos - Faltantes
   uta = fields.Monetary(
       string='UTA',
       currency_field='currency_id',
       digits=(10, 2),
       help='Unidad Tributaria Anual'
   )
   salud_tope_uf = fields.Float(
       string='Tope Salud (UF)',
       digits=(10, 2),
       help='Tope imponible salud en UF (0.0 si sin tope)'
   )
   gratif_tope_meses = fields.Float(
       string='Tope Gratificación (Meses IMM)',
       digits=(5, 2),
       help='Tope gratificación legal en meses de IMM (4.75)'
   )
   ```

**Criterio de Aceptación**: 6 campos adicionales agregados.

---

### Tarea 5.1.4: Actualizar Método _cron_sync_previred_via_ai() (2h)

**Rol**: Ingeniero de Integración  
**Brecha**: Completar mapeo 60 campos

**Instrucciones**:

1. Abre el método `_cron_sync_previred_via_ai()` (línea ~299)

2. En la sección donde se actualiza el registro (línea ~341), agrega mapeo de 45 campos nuevos:
   ```python
   # Dentro de record.write({...})
   
   # Asignación Familiar - Maternal
   'asig_fam_maternal_tramo_1': indicators.get('asig_fam_maternal_tramo_1'),
   'asig_fam_maternal_tramo_2': indicators.get('asig_fam_maternal_tramo_2'),
   'asig_fam_maternal_tramo_3': indicators.get('asig_fam_maternal_tramo_3'),
   'asig_fam_maternal_tramo_4': indicators.get('asig_fam_maternal_tramo_4'),
   
   # Asignación Familiar - Invalidez
   'asig_fam_invalidez_tramo_1': indicators.get('asig_fam_invalidez_tramo_1'),
   'asig_fam_invalidez_tramo_2': indicators.get('asig_fam_invalidez_tramo_2'),
   'asig_fam_invalidez_tramo_3': indicators.get('asig_fam_invalidez_tramo_3'),
   'asig_fam_invalidez_tramo_4': indicators.get('asig_fam_invalidez_tramo_4'),
   
   # ... (16 campos asignación familiar)
   
   # Tasas AFP - Todas las AFPs y fondos
   'afp_capital_fondo_c': indicators.get('afp_capital_fondo_c'),
   'afp_capital_fondo_d': indicators.get('afp_capital_fondo_d'),
   'afp_capital_fondo_e': indicators.get('afp_capital_fondo_e'),
   'afp_cuprum_fondo_a': indicators.get('afp_cuprum_fondo_a'),
   # ... (23 campos AFP)
   
   # Tasas Cotización - Plazo Fijo
   'afc_trabajador_plazo_fijo_pct': indicators.get('afc_trabajador_plazo_fijo'),
   'afc_empleador_plazo_fijo_pct': indicators.get('afc_empleador_plazo_fijo'),
   'aporteafpe_pct': indicators.get('aporteafpe_pct'),
   
   # Otros indicadores
   'uta': indicators.get('uta'),
   'salud_tope_uf': indicators.get('salud_tope_uf'),
   'gratif_tope_meses': indicators.get('gratif_tope_meses'),
   ```

3. Actualiza logging para indicar 60 campos:
   ```python
   _logger.info(
       f"CRON AI-SYNC: Completado exitosamente. "
       f"60 campos sincronizados desde AI service (período: {period_str})"
   )
   ```

4. Agrega validación de campos completos:
   ```python
   # Antes del write(), validar que indicators tenga los 60 campos
   expected_fields = 60
   received_fields = len([k for k in indicators.keys() if k != 'success'])
   
   if received_fields < expected_fields:
       _logger.warning(
           f"AI service retornó {received_fields}/{expected_fields} campos. "
           f"Campos faltantes: {expected_fields - received_fields}"
       )
   ```

**Criterio de Aceptación**: Método mapea 60 campos, logging actualizado, validación agregada.

---

## 🔍 FASE 5.2: AUDITORÍA Y REFACTORIZACIÓN XML (4 horas)

**Objetivo**: Eliminar TODO hardcoding en reglas salariales XML.

### Tarea 5.2.1: Auditoría Archivo por Archivo

**Rol**: Auditor de Reglas XML  
**Brecha**: P1-012

**Instrucciones**:

Para CADA archivo XML en `data/*salary*rule*.xml`:

1. Abre el archivo

2. Busca código Python en tags:
   - `<field name="code">...</field>`
   - `<field name="amount_python_compute">...</field>`

3. Identifica valores hardcoded:
   - Números decimales (87.8, 131.9, 50.0)
   - Números enteros grandes (500000, 38000)
   - Operaciones aritméticas con constantes

4. Refactoriza a dinámico:
   
   **ANTES** ❌:
   ```xml
   <field name="amount_python_compute">
       result = payslip.total_imponible
       tope = 87.8 * payslip.indicadores_id.uf
       if result > tope:
           result = tope
   </field>
   ```
   
   **DESPUÉS** ✅:
   ```xml
   <field name="amount_python_compute">
       result = payslip.total_imponible
       tope_uf = payslip.indicadores_id.afp_tope_uf or 87.8  # fallback
       tope_clp = tope_uf * payslip.indicadores_id.uf
       if result > tope_clp:
           result = tope_clp
   </field>
   ```

5. Documenta cada cambio en:
   ```markdown
   REFACTORIZACION_XML_[archivo]_2025-11-11.md
   
   ## ARCHIVO: [nombre]
   
   ### Regla: [ID]
   - Línea: [N]
   - ANTES: [código con hardcoding]
   - DESPUÉS: [código dinámico]
   - Justificación: Usa payslip.indicadores_id.[campo]
   
   ## TOTAL
   - Instancias refactorizadas: [N]
   - Líneas modificadas: [N]
   ```

**Archivos a Auditar** (en orden):
1. `hr_salary_rules_ley21735.xml`
2. `hr_salary_rules_p1.xml`
3. `hr_salary_rule_category_sopa.xml`
4. `hr_salary_rules_apv.xml`
5. `hr_salary_rule_category_base.xml`

**Criterio de Aceptación**: 5 archivos auditados, hardcoding eliminado, reporte por archivo.

---

## 🧹 FASE 5.3: LIMPIEZA DE CÓDIGO (2 horas)

**Objetivo**: Eliminar comentarios con hardcoding y mejorar calidad.

### Tarea 5.3.1: Limpiar Comentarios Hardcoded

**Rol**: Ingeniero de Calidad  
**Brecha**: Hardcoding residual medio

**Instrucciones**:

1. Abre `addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule_aportes_empleador.py`

2. Elimina/actualiza TODOS los comentarios con valores hardcoded:
   
   **ANTES** ❌:
   ```python
   def _get_tope_afp_clp(self):
       """
       Obtener tope AFP en pesos chilenos (87.8 UF)  # ❌
       """
   ```
   
   **DESPUÉS** ✅:
   ```python
   def _get_tope_afp_clp(self):
       """
       Obtener tope AFP en pesos chilenos.
       
       El tope se obtiene dinámicamente desde hr.economic.indicators,
       sincronizado desde el AI service que consulta Previred oficial.
       """
   ```

3. Busca TODOS los docstrings con valores:
   ```bash
   grep -n "87\.8\|131\.9\|500000" models/*.py | grep -v "fallback"
   ```

4. Actualiza cada uno para indicar "valor dinámico desde indicators"

**Criterio de Aceptación**: 0 comentarios con valores hardcoded (excepto fallbacks documentados).

---

### Tarea 5.3.2: Completar .env.example

**Rol**: Ingeniero DevOps  
**Brecha**: P1-014

**Instrucciones**:

1. Abre `.env.example`

2. Agrega variables faltantes:
   ```bash
   # ═══════════════════════════════════════════════════════════
   # AI SERVICE - CONFIGURACIÓN AVANZADA
   # ═══════════════════════════════════════════════════════════
   
   # Endpoint específico para indicadores Previred
   AI_SERVICE_PREVIRED_ENDPOINT=/api/payroll/indicators/{period}
   
   # Reintentos en caso de fallo
   AI_SERVICE_RETRY_ATTEMPTS=3
   AI_SERVICE_RETRY_BACKOFF=2
   
   # Cache TTL para indicadores (segundos)
   # 86400 = 24 horas (los indicadores cambian mensualmente)
   AI_SERVICE_CACHE_TTL=86400
   
   # Logging nivel detalle
   AI_SERVICE_LOG_LEVEL=INFO
   ```

3. Documenta cada variable con comentario descriptivo

**Criterio de Aceptación**: `.env.example` completo y documentado.

---

## 🧪 FASE 5.4: TESTS DE VALIDACIÓN (4 horas)

**Objetivo**: Validar que los 60 campos funcionan correctamente.

### Tarea 5.4.1: Test Sincronización 60 Campos

**Rol**: Ingeniero de QA  
**Brecha**: P1-005 (adicional)

**Instrucciones**:

1. Crea `addons/localization/l10n_cl_hr_payroll/tests/test_60_campos_ai_sync.py`

2. Implementa test:
   ```python
   from odoo.tests import tagged, TransactionCase
   from unittest.mock import patch
   
   @tagged('post_install', '-at_install', 'l10n_cl_ai')
   class Test60CamposAISync(TransactionCase):
       
       def test_sync_60_campos_completos(self):
           """
           Verificar que el cron sincroniza LOS 60 CAMPOS desde AI service.
           """
           # Mock AI service response con 60 campos
           mock_response = {
               'success': True,
               'indicators': {
                   # Indicadores básicos (4)
                   'uf': 39383.07,
                   'utm': 68647,
                   'uta': 823764,
                   'sueldo_minimo': 500000,
                   
                   # Topes (5)
                   'afp_tope_uf': 87.8,
                   'afc_tope_uf': 131.9,
                   'apv_tope_mensual_uf': 50.0,
                   'apv_tope_anual_uf': 600.0,
                   'salud_tope_uf': 0.0,
                   
                   # Asignación Familiar (20)
                   'asig_fam_tramo_1': 17885,
                   'asig_fam_tramo_2': 11303,
                   'asig_fam_tramo_3': 3558,
                   'asig_fam_tramo_4': 0,
                   'asig_fam_maternal_tramo_1': 17885,
                   # ... (16 campos más)
                   
                   # Tasas AFP (25)
                   'afp_capital_fondo_a': 11.44,
                   'afp_capital_fondo_b': 10.82,
                   'afp_capital_fondo_c': 10.55,
                   # ... (22 campos más)
                   
                   # Tasas Cotización (8)
                   'exvida_pct': 1.57,
                   'afc_trabajador_indefinido': 0.6,
                   'afc_empleador_indefinido': 2.4,
                   # ... (5 campos más)
               },
               'metadata': {'source': 'previred_pdf', 'period': '2025-11'}
           }
           
           with patch('requests.get') as mock_get:
               mock_get.return_value.json.return_value = mock_response
               mock_get.return_value.status_code = 200
               
               # Ejecutar cron
               indicators_model = self.env['hr.economic.indicators']
               indicators_model._cron_sync_previred_via_ai()
               
               # Verificar que TODOS los campos se sincronizaron
               indicator = indicators_model.search([], limit=1, order='id desc')
               
               # Verificar indicadores básicos
               self.assertEqual(indicator.uf, 39383.07)
               self.assertEqual(indicator.utm, 68647)
               self.assertEqual(indicator.uta, 823764)
               self.assertEqual(indicator.minimum_wage, 500000)
               
               # Verificar topes
               self.assertEqual(indicator.afp_tope_uf, 87.8)
               self.assertEqual(indicator.afc_tope_uf, 131.9)
               
               # Verificar asignación familiar
               self.assertEqual(indicator.asig_fam_tramo_1, 17885)
               self.assertEqual(indicator.asig_fam_maternal_tramo_1, 17885)
               # ... verificar los 20 campos
               
               # Verificar tasas AFP
               self.assertEqual(indicator.afp_capital_fondo_a, 11.44)
               self.assertEqual(indicator.afp_capital_fondo_c, 10.55)
               # ... verificar los 25 campos
               
               # Verificar tasas cotización
               self.assertEqual(indicator.sis_pct, 1.57)
               self.assertEqual(indicator.afc_trabajador_indefinido_pct, 0.6)
               # ... verificar los 8 campos
               
               # Verificar metadata
               self.assertEqual(indicator.source, 'ai_service')
               self.assertIsNotNone(indicator.last_sync)
       
       def test_cero_hardcoding_en_calculos(self):
           """
           Verificar que cálculo de nómina NO usa valores hardcoded.
           """
           # Crear indicator con valores test únicos
           indicator = self.env['hr.economic.indicators'].create({
               'reference_date': '2025-11-01',
               'uf': 99999.99,  # Valor único para detectar si se usa
               'afp_tope_uf': 99.9,  # Valor único
               'afc_tope_uf': 199.9,  # Valor único
               'source': 'ai_service'
           })
           
           # Crear liquidación con salario alto
           payslip = self._create_test_payslip(wage=10000000)
           payslip.compute_sheet()
           
           # Si cálculo usa hardcoding (87.8), tope será 87.8 * uf_real
           # Si usa indicator, tope será 99.9 * 99999.99
           expected_tope = 99.9 * 99999.99
           
           # Verificar que cálculo AFP usó tope desde indicator
           afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')
           self.assertTrue(
               abs(afp_line.total - expected_tope * 0.1) < 1000,
               f"Cálculo AFP debe usar tope desde indicator, no hardcoded"
           )
   ```

**Criterio de Aceptación**: Test verifica los 60 campos y ausencia de hardcoding.

---

### Tarea 5.4.2: Ejecutar Suite Completa

**Instrucciones**:

1. Ejecuta TODOS los tests:
   ```bash
   docker compose exec odoo odoo-bin \
       -d odoo19_db \
       --test-enable \
       --stop-after-init \
       --test-tags l10n_cl_hr_payroll
   ```

2. Verifica resultados:
   - [ ] 100% tests pasan
   - [ ] 0 errores
   - [ ] 0 warnings críticos

3. Si fallan tests:
   - Analiza log de error
   - Corrige código
   - Re-ejecuta hasta 100% éxito

**Criterio de Aceptación**: Suite completa pasa sin errores.

---

## 📊 FASE 5.5: VERIFICACIÓN FINAL (2 horas)

**Objetivo**: Confirmar Readiness 99/100 alcanzado.

### Tarea 5.5.1: Análisis Estático

**Instrucciones**:

```bash
cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll

# Flake8
flake8 models/*.py --max-line-length=120 --exclude=__pycache__

# Black (check only)
black --check models/*.py

# Python compile
find models -name "*.py" -exec python3 -m py_compile {} \;
```

**Criterio de Aceptación**: 0 errores críticos.

---

### Tarea 5.5.2: Simulación Upgrade

**Instrucciones**:

```bash
docker compose exec odoo odoo-bin \
    -d odoo19_db \
    -u l10n_cl_hr_payroll \
    --stop-after-init \
    --log-level=info
```

**Criterio de Aceptación**: Upgrade completa sin errores.

---

### Tarea 5.5.3: Cálculo Readiness Final

**Instrucciones**:

Genera reporte final consolidado:

```markdown
FASE5_COMPLETION_REPORT_2025-11-11.md

## RESUMEN EJECUTIVO

### Brechas Cerradas en Fase 5

| ID | Brecha | Estado Previo | Estado Final |
|----|--------|---------------|--------------|
| P0-004 | Campos faltantes | 15/60 (25%) | 60/60 (100%) ✅ |
| P1-003 | Asig fam parcial | 4/20 | 20/20 ✅ |
| P1-007 | Tasas AFP | 2/25 | 25/25 ✅ |
| P1-008 | Tasas cotiz | 4/8 | 8/8 ✅ |
| P1-012 | Reglas XML | NO auditado | 5 archivos ✅ |
| P1-014 | .env incompleto | NO | Completo ✅ |
| P2-XXX | Calidad código | 50% | 100% ✅ |

### Score Final

| Categoría | Peso | Score Previo | Score Final | Mejora |
|-----------|------|--------------|-------------|--------|
| P0 | 30% | 25/30 (83%) | 30/30 (100%) | +5 ✅ |
| P1 | 50% | 28.5/50 (57%) | 50/50 (100%) | +21.5 ✅ |
| P2 | 20% | 10/20 (50%) | 20/20 (100%) | +10 ✅ |
| **TOTAL** | 100% | **63.5/100** | **100/100** | **+36.5** ✅ |

### Readiness AI-Driven

```
ANTES FASE 5:  64/100  🟡
DESPUÉS FASE 5: 99/100  ✅
MEJORA:        +35 puntos
```

### Métricas Técnicas

- **Campos AI Implementados**: 60/60 (100%) ✅
- **Aprovechamiento AI**: 100% (vs 25% previo)
- **Hardcoding Residual**: 0 instancias críticas ✅
- **Tests Pasando**: 100% ✅
- **Cobertura Tests**: >95% ✅
- **Archivos XML Auditados**: 5/5 (100%) ✅

### ROI AI Service

| Métrica | Antes | Después | Mejora |
|---------|-------|---------|--------|
| Campos usados | 15/60 (25%) | 60/60 (100%) | +300% |
| Inversión justificada | NO | SÍ ✅ | 100% |
| Mantenimiento manual | 2-4h/mes | 0h/mes | -100% |

## ARCHIVOS MODIFICADOS

### Código Python
- hr_economic_indicators.py: +45 campos, método sync actualizado
- hr_salary_rule_aportes_empleador.py: Comentarios limpios
- hr_payslip.py: (sin cambios - ya refactorizado)

### Archivos XML
- hr_salary_rules_ley21735.xml: Refactorizado
- hr_salary_rules_p1.xml: Refactorizado
- hr_salary_rule_category_sopa.xml: Refactorizado
- hr_salary_rules_apv.xml: Refactorizado
- hr_salary_rule_category_base.xml: Refactorizado

### Configuración
- .env.example: 4 variables agregadas

### Tests
- test_60_campos_ai_sync.py: Nuevo test exhaustivo

## VALIDACIÓN FINAL

- [x] Suite tests 100% ✅
- [x] Flake8 sin errores ✅
- [x] Upgrade sin errores ✅
- [x] 60 campos funcionando ✅
- [x] 0 hardcoding crítico ✅
- [x] Documentación actualizada ✅

## TIEMPO REAL INVERTIDO

- Validación inicial: [X]h
- Expansión modelo: [X]h
- Auditoría XML: [X]h
- Limpieza código: [X]h
- Tests: [X]h
- Verificación: [X]h
**TOTAL**: [X]h (vs estimado 22h)

## ESTADO FINAL

✅ **OBJETIVO ALCANZADO**

Sistema 100% AI-Driven, Readiness 99/100, ROI maximizado.

**Todas las 28 brechas originales cerradas.**
```

**Criterio de Aceptación**: Readiness 99/100 confirmado.

---

## 📝 PROTOCOLO DE REPORTE

### Reporte Cada Hora

Genera update breve:
```
HORA [N]: FASE [X].[Y] - [Tarea]
Estado: [en progreso/completado/bloqueado]
Avance: [X]/[Y] subtareas
Próximo: [descripción]
Bloqueantes: [ninguno/descripción]
ETA: [horas restantes]
```

### Reporte al Completar Cada Fase

```
FASE [X] COMPLETADA
Tiempo real: [X]h (estimado: [Y]h)
Tareas completadas: [X]/[Y]
Brechas cerradas: [lista]
Archivos modificados: [N]
Tests: [estado]
Próxima fase: [X+1]
```

---

## 🚨 MANEJO DE BLOQUEANTES

Si encuentras **bloqueante P0**:

1. **DETENER** trabajo actual
2. **DOCUMENTAR** bloqueante:
   ```markdown
   BLOQUEANTE_P0_FASE5_2025-11-11.md
   
   ## DESCRIPCIÓN
   [Qué impide continuar]
   
   ## CONTEXTO
   [Fase/Tarea donde ocurrió]
   
   ## EVIDENCIA
   [Logs, errores, código]
   
   ## OPCIONES
   1. [Solución propuesta 1]
   2. [Solución propuesta 2]
   3. [Escalar a humano]
   
   ## RECOMENDACIÓN
   [Mejor curso de acción]
   ```
3. **REPORTAR** inmediatamente
4. **ESPERAR** instrucciones

---

## ✅ CRITERIOS DE ÉXITO GLOBAL

Al finalizar FASE 5, debes confirmar:

- [x] **60/60 campos** implementados en `hr.economic.indicators`
- [x] **Método sync** actualizado para mapear 60 campos
- [x] **5 archivos XML** auditados y refactorizados
- [x] **0 hardcoding crítico** residual
- [x] **.env.example** completo y documentado
- [x] **Tests 100%** pasando
- [x] **Readiness 99/100** alcanzado
- [x] **Reporte final** consolidado generado

---

## 🎯 DIRECTIVA FINAL DE EJECUCIÓN

**Ejecuta las 6 fases en orden estricto**:

1. FASE 5.0: Validación (2h)
2. FASE 5.1: Expansión Modelo (8h)
3. FASE 5.2: Auditoría XML (4h)
4. FASE 5.3: Limpieza (2h)
5. FASE 5.4: Tests (4h)
6. FASE 5.5: Verificación (2h)

**Objetivo**: Readiness AI-Driven 99/100

**Modo**: AUTÓNOMO PRIVILEGIADO (sin interrupciones)

**Duración**: 22 horas (~3 días)

**NO TE DETENGAS** hasta completar o encontrar bloqueante P0.

---

**Procede.**

