# Prompt P4-Infrastructure: Auditoría Infraestructura Odoo 19 CE

**Versión:** 2.0.0  
**Nivel:** P4-Infrastructure (Auditoría Técnica / Pre-Producción)  
**Target Output:** 400-600 palabras (±15% si justificas)  
**Tiempo estimado:** 3-5 minutos generación

---

## 📋 Objetivo

Auditar **archivos técnicos de infraestructura Odoo** (security, manifest, views, data, reports) del módulo **[MODULE_NAME]** que NO son analizados en profundidad por P4-Deep. Identificar gaps críticos P0/P1 que bloquean producción o compliance.

---

## 🔄 Reglas de Progreso (Preamble Obligatorio)

### ⭐ PASO 0: SELF-REFLECTION (Pre-análisis obligatorio)

**Antes de analizar, reflexiona sobre:**

1. **Información faltante:**
   - ¿Tengo acceso a `__manifest__.py` completo?
   - ¿Existe archivo `security/ir.model.access.csv`?
   - ¿Hay views comentadas en manifest?

2. **Suposiciones peligrosas:**
   - ¿Estoy asumiendo que todos los modelos tienen ACLs?
   - ¿Estoy asumiendo que views tipo="dashboard" funciona en Odoo 19?
   - ¿Estoy asumiendo que TED barcode está implementado?

3. **Riesgos potenciales:**
   - ¿Qué pasa si faltan ACLs para modelos críticos? (AccessError producción)
   - ¿Qué pasa si dashboards están desactivados? (Pérdida KPIs)
   - ¿Qué pasa si TED barcode ausente? (Multa SII)

4. **Verificaciones previas necesarias:**
   - ¿Debo listar todos los modelos Python primero?
   - ¿Debo verificar `__manifest__.py` antes de auditar views?
   - ¿Debo confirmar tipo módulo (DTE vs Payroll) para saber qué esperar?

**Output esperado:** Lista verificaciones previas + plan mitigación de riesgos

---

### Progreso Estándar

1. **Reformula el objetivo** en 1-2 líneas (confirma comprensión)
2. **Plan de 4-5 pasos** con estructura "Paso i/N: [descripción]"
3. **Anuncia cada paso** al comenzar: "Ejecutando Paso i/N..."
4. **Cierra cada paso** con resumen: "Completado Paso i/N: [logros clave con métricas]"
5. **Cierre final** con:
   - Cobertura de dimensiones (K-O) vs requisitos
   - Métricas cumplidas (refs ≥8, verificaciones ≥3, palabras 400-600)
   - Hallazgos P0/P1 priorizados
   - Acciones inmediatas requeridas

---

## 📊 Contexto del Módulo (Tabla Compacta)

| Métrica | Valor |
|---------|-------|
| **Módulo** | [MODULE_NAME] (ej: l10n_cl_dte, l10n_cl_hr_payroll) |
| **Tipo** | DTE / Payroll / AI Service / Financial |
| **Stack** | Odoo 19 CE + PostgreSQL 16 + Docker |
| **Modelos Python** | [NUM_MODELS] modelos (listar con `grep "class.*models.Model" models/*.py`) |
| **Views XML** | [NUM_VIEWS] archivos (verificar en `views/`) |
| **Data files** | [NUM_DATA] archivos (verificar en `data/`) |
| **Reports QWeb** | [NUM_REPORTS] archivos (verificar en `reports/`) |
| **Security files** | [NUM_SECURITY] archivos (verificar en `security/`) |
| **Manifest** | `__manifest__.py` ([NUM_LINES] líneas) |

### Rutas Foco Obligatorias (Infraestructura)

```
addons/localization/[MODULE_NAME]/
├── __manifest__.py                  # 🎯 CRÍTICO - Verificar archivos comentados
├── security/
│   ├── ir.model.access.csv          # 🎯 CRÍTICO - ACLs completas
│   └── ir_rule.xml                  # Record rules (si aplica)
├── views/
│   ├── *_dashboard_*.xml            # 🎯 ALTO - Tipo dashboard vs kanban
│   ├── *_form_*.xml                 # Campos obligatorios (required="1")
│   └── *_tree_*.xml                 # Filtros, búsquedas
├── data/
│   ├── ir_cron_*.xml                # 🎯 ALTO - Overlap intervals
│   ├── ir_sequence_*.xml            # Prefixes únicos
│   └── *_data.xml                   # Master data consistente
└── reports/
    ├── report_invoice_*.xml         # 🎯 ALTO (DTE) - TED barcode PDF417
    ├── report_payslip_*.xml         # 🎯 ALTO (Payroll) - Formato Previred
    └── *.py                         # Lógica generación reportes
```

---

## 🎯 Dimensiones de Evaluación (K-O) con Granularidad

### K) Security Files - ACLs y Record Rules

**Sub-dimensiones críticas:**
- **ACLs completas:** Verificar que TODOS los modelos Python tienen entrada en `security/ir.model.access.csv`
  - Mínimo 2 ACLs por modelo: `access_[model]_user` (base.group_user), `access_[model]_manager` (custom group o stock.group_stock_manager)
  - Modelos transient (wizards) requieren solo 1 ACL si lógica simple
- **Record rules:** Si modelo multi-company o datos sensibles, verificar `security/ir_rule.xml`
- **Groups customizados:** Verificar creación en `security/[module]_security.xml`

**Verificación obligatoria V1 (P0 BLOQUEANTE):**
```bash
# Extraer modelos Python
grep -rh "class.*models.Model" addons/localization/[MODULE]/models/*.py | \
  sed 's/.*class \([A-Za-z0-9]*\).*/\1/' | \
  grep -v "^$" > /tmp/models.txt

# Extraer ACLs existentes
grep "^access_" addons/localization/[MODULE]/security/ir.model.access.csv | \
  cut -d',' -f1 | \
  sed 's/access_//' | \
  sed 's/_user$//' | sed 's/_manager$//' | \
  sort -u > /tmp/acls.txt

# Comparar
comm -23 /tmp/models.txt /tmp/acls.txt
# Output esperado: vacío (0 modelos sin ACLs)
# Problema si falla: AccessError producción para usuarios no-system
```

**Evidencia esperada:**
- Referencias: ≥2 archivos (`security/ir.model.access.csv`, `security/[module]_security.xml`)
- Lista completa: Modelos sin ACLs (si existen) con prioridad P0

---

### L) Manifest Integrity - Archivos Desactivados

**Sub-dimensiones críticas:**
- **Views comentadas:** Detectar líneas comentadas en `'data': []` que contienen archivos `.xml` críticos
  - Dashboards: `*_dashboard_*.xml` comentado = pérdida KPIs (P0)
  - Forms/Trees principales: Comentados = funcionalidad oculta (P1)
  - Wizards: Comentados = features no disponibles (P1)
- **Data desactivada:** Archivos `data/*.xml` comentados = master data faltante (P1)
- **Dependencias faltantes:** Módulos en código pero NO en `'depends': []` (P0)

**Verificación obligatoria V2 (P1 ALTO):**
```bash
# Detectar archivos comentados en manifest
grep -E "^\s*#.*\.(xml|py)" addons/localization/[MODULE]/__manifest__.py

# Output esperado: vacío o solo comentarios de documentación
# Problema si falla:
#   - Dashboards comentados → KPIs no visibles
#   - Wizards comentados → Funcionalidad oculta
#   - Data comentada → Master data incompleto
```

**Evidencia esperada:**
- Referencias: ≥1 archivo (`__manifest__.py:línea-línea`)
- Lista archivos comentados: Tipo (view/data/wizard), líneas específicas, impacto (P0/P1)

---

### M) Views XML - UI/UX y Compatibilidad Odoo 19

**Sub-dimensiones críticas:**
- **Dashboards deprecados:** Tipo `type="dashboard"` NO existe en Odoo 19 → Debe ser `type="kanban"` con dashboard flag
  - `<field name="type">dashboard</field>` ❌ → `<field name="type">kanban</field>` ✅
  - Agregar atributo: `<field name="dashboard">true</field>`
- **QWeb deprecations:** `t-esc` → `t-out` (Odoo 19 breaking change)
- **Forms críticos:** Campos obligatorios de negocio con `required="1"` (ej: RUT, DTE type, folio)
- **Performance:** Views con muchos campos computed (evaluados on-the-fly) sin store=True

**Verificación obligatoria V3 (P0 si dashboards, P1 si forms):**
```bash
# Detectar dashboards deprecados
grep -rn 'type.*=.*"dashboard"' addons/localization/[MODULE]/views/*.xml

# Output esperado: vacío (0 dashboards tipo="dashboard")
# Problema si falla: Views no cargan en Odoo 19, ERROR 500 al abrir menú
```

**Evidencia esperada:**
- Referencias: ≥2 archivos (dashboards, forms principales)
- Snippets XML: ANTES/DESPUÉS para fix dashboards si detectado

---

### N) Data Files - Master Data y Crons

**Sub-dimensiones críticas:**
- **Crons overlap:** Detectar crons con intervalos que se solapan (ej: cada 5 min ambos)
  - Verificar `interval_number` + `interval_type` (minutes/hours/days)
  - Crons pesados (queries complejas) deben tener ≥15 min intervalo
- **Sequences:** Prefixes únicos por tipo documento (ej: DTE-33-, DTE-34-, PAY-2025-)
- **Master data IDs:** External IDs (`<record id="..."`) únicos y descriptivos
- **Demo data:** Si existe `data/demo/`, asegurar NO se carga en producción (noupdate="1")

**Verificación V4 (P2 MEDIO):**
```bash
# Detectar crons con mismo interval
grep -A5 "ir.cron" addons/localization/[MODULE]/data/ir_cron*.xml | \
  grep -E "(interval_number|interval_type)" | \
  sort | uniq -c | sort -rn

# Problema si falla: Race conditions, locks DB, timeout crons
```

**Evidencia esperada:**
- Referencias: ≥2 archivos (`data/ir_cron_*.xml`, `data/ir_sequence_*.xml`)
- Tabla intervals: Nombre cron, interval, next_call estimado, risk overlap

---

### O) Reports QWeb - Compliance y Templates

**Sub-dimensiones críticas (específicas por tipo módulo):**

#### Si módulo DTE (l10n_cl_dte):
- **TED barcode OBLIGATORIO (P1 compliance SII):**
  - Verificar implementación PDF417 en `reports/report_invoice_dte_document.xml`
  - Debe llamar a método computed: `<t t-esc="o.l10n_cl_sii_barcode"/>`
  - Librería: `from pdf417 import encode, render_image`
- **Timbre formato oficial:** Logo SII, RUT emisor, folio, monto, fecha

#### Si módulo Payroll (l10n_cl_hr_payroll):
- **Formato Previred:** Liquidación con secciones (Haberes, Descuentos, Líquido)
- **Indicadores económicos:** UF/UTM del período visible
- **Firma digital opcional:** Espacio para firma empleador + trabajador

#### Si módulo Financial:
- **Libro Mayor:** Balance columnas (debe/haber)
- **Formato impreso oficial:** Membrete, RUT, período

**Verificación V5 (P1 si DTE, P2 otros):**
```bash
# Verificar TED barcode en reportes DTE
grep -rn "l10n_cl_sii_barcode\|pdf417\|TED" \
  addons/localization/l10n_cl_dte/reports/*.xml

# Output esperado: ≥2 matches (campo + template)
# Problema si falla: PDFs NO cumplen formato SII, multa UF 60 (~$2M CLP)
```

**Evidencia esperada:**
- Referencias: ≥1 archivo (`reports/report_*.xml`)
- Snippet: Implementación TED barcode (si DTE) o formato compliance requerido

---

## 📏 Requisitos de Salida (OBLIGATORIO)

### Formato

- **Longitud:** 400-600 palabras (±15% solo si justificas)
- **Referencias válidas:** ≥8 con formato `ruta.py:línea[-línea]` o `ruta.xml:línea`
  - Ejemplo: `security/ir.model.access.csv:línea 45-62` (ACLs faltantes)
  - Ejemplo: `__manifest__.py:72-76` (views comentadas)
- **Estructura:** Markdown con headers H2 (##) por dimensión (K-O)
- **Priorización:** Hallazgos ordenados P0 → P1 → P2

### Verificaciones Reproducibles (≥3 OBLIGATORIO)

**Distribución requerida:**
- **≥1 verificación P0** (BLOQUEANTE: ACLs faltantes, dependencias rotas)
- **≥1 verificación P1** (ALTO: manifest comentado, dashboards deprecados, TED ausente)
- **≥1 verificación P2** (MEDIO: crons overlap, sequences, performance views)

**Formato de verificación:**

```markdown
### Verificación V{N}: [Título] (P0/P1/P2)

**Área:** K/L/M/N/O

**Comando:**
```bash
[comando reproducible con parámetros exactos]
```

**Hallazgo esperado:**
[Output si todo OK - específico con métricas]

**Problema si falla:**
[Impacto técnico + negocio - justifica prioridad]

**Cómo corregir:**
```bash
# O código Python/XML específico
[Pasos concretos para resolver]
```

**Esfuerzo estimado:**
[Horas desarrollo + testing]
```

### Hallazgos Priorizados (Template Obligatorio)

```markdown
## 🔴 Hallazgos P0 - BLOQUEANTES (X totales)

### H1: [Título descriptivo]

**Archivo:** `ruta/archivo.ext:línea-línea`  
**Impacto:** [AccessError / ERROR 500 / Data loss / Multa SII]  
**Esfuerzo:** [Horas]

**Problema:**
[1-2 líneas con snippet si aplica]

**Fix inmediato:**
```bash
# Comando copy-paste ready
[código ejecutable]
```

---

## 🟡 Hallazgos P1 - ALTO IMPACTO (Y totales)

[Mismo formato que P0]

---

## 🟢 Hallazgos P2 - MEJORAS (Z totales)

[Formato simplificado sin snippet]
```

---

## 🚫 Restricciones

- **Solo lectura:** No modificar archivos del proyecto
- **Sin secretos:** No exponer API keys, passwords, tokens reales
- **Foco infraestructura:** NO analizar lógica negocio (eso es P4-Deep)
- **Evidencia verificable:** Toda afirmación crítica requiere comando reproducible

---

## ✅ Checklist de Aceptación (Auto-Validación)

Antes de entregar, verifica:

**Formato (obligatorio):**
- [ ] Progreso visible (plan 4-5 pasos + "Paso i/N" + cierres)
- [ ] Cobertura K-O completa con evidencias
- [ ] ≥8 referencias válidas (`ruta:línea`)
- [ ] ≥3 verificaciones reproducibles (≥1 P0 + ≥1 P1 + ≥1 P2)
- [ ] Hallazgos ordenados por prioridad (P0 → P1 → P2)
- [ ] Comandos copy-paste ready para fixes P0
- [ ] 400-600 palabras (±15%)

**Profundidad (calidad técnica):**
- [ ] Self-reflection inicial (suposiciones, riesgos, verificaciones previas)
- [ ] ACLs auditadas completamente (≥1 verificación P0)
- [ ] Manifest auditado (archivos comentados detectados)
- [ ] Views Odoo 19 compatibles (dashboards tipo="kanban")
- [ ] Data files validados (crons, sequences)
- [ ] Reports compliance verificados (TED si DTE, Previred si Payroll)
- [ ] Impacto negocio cuantificado (multas, AccessError, pérdida funcionalidad)

---

## 🎓 Ejemplo de Output Esperado (Estructura)

```markdown
# Auditoría Infraestructura: l10n_cl_dte

## Objetivo Reformulado
Auditar archivos técnicos infraestructura Odoo (security, manifest, views, data, reports) 
del módulo l10n_cl_dte para identificar gaps P0/P1 pre-producción.

## Self-Reflection Inicial

**Información faltante:**
- Confirmar listado completo modelos Python (40 detectados con grep)
- Verificar si módulo tiene dashboards (sí: dte_dashboard_views.xml)

**Suposiciones peligrosas:**
- Asumir ACLs completas (VALIDAR con script)
- Asumir tipo="dashboard" funciona Odoo 19 (DEPRECADO → verificar)

**Riesgos potenciales:**
- ACLs faltantes → AccessError producción usuarios contador
- Dashboards deprecados → ERROR 500 al abrir menú KPIs
- TED ausente → Multa SII UF 60 (~$2M CLP)

**Verificaciones previas:**
1. Listar modelos: `grep -rh "class.*models.Model" models/*.py`
2. Verificar manifest: `cat __manifest__.py | grep -E "data|views"`
3. Confirmar tipo módulo: DTE → Requiere TED barcode

---

## Plan de Ejecución (4 pasos)

Paso 1/4: Auditar Security Files (ACLs, Record Rules)
Paso 2/4: Auditar Manifest Integrity (archivos comentados)
Paso 3/4: Auditar Views XML (dashboards, compatibilidad Odoo 19)
Paso 4/4: Auditar Reports (TED barcode compliance SII)

---

## Ejecutando Paso 1/4: Security Files

### K) Security Files - ACLs y Record Rules

**Análisis `security/ir.model.access.csv`:**

Modelos detectados: 40 (grep en models/*.py)
ACLs existentes: 24 (líneas en ir.model.access.csv)
**GAP CRÍTICO:** 16 modelos sin ACLs ❌

**Modelos sin ACLs (P0 BLOQUEANTE):**
```
ai.agent.selector
ai.chat.integration
ai.chat.session
ai.chat.wizard
dte.commercial.response.wizard
dte.service.integration
l10n_cl.rcv.integration
rabbitmq.helper
[... 8 más]
```

### Verificación V1: ACLs Completas (P0 BLOQUEANTE)

**Área:** K (Security Files)

**Comando:**
```bash
cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte

# Extraer modelos
grep -rh "class.*models.Model" models/*.py | \
  sed 's/.*class \([A-Za-z0-9]*\).*/\1/' | \
  grep -v "^$" | sort -u > /tmp/models.txt

# Extraer ACLs
grep "^access_" security/ir.model.access.csv | \
  cut -d',' -f1 | sed 's/access_//' | \
  sed 's/_user$//' | sed 's/_manager$//' | \
  sort -u > /tmp/acls.txt

# Comparar
comm -23 /tmp/models.txt /tmp/acls.txt
```

**Hallazgo esperado:**
Vacío (0 modelos sin ACLs)

**Problema si falla:**
```python
# Usuario contador intenta:
>>> self.env['ai.chat.session'].search([])
# AccessError: Sorry, you are not allowed to access this document

# Bloquea: AI Chat, RCV Integration, DTE Wizards, Rabbitmq helpers
# Impacto producción: CRÍTICO - Sistema inutilizable para usuarios no-admin
```

**Cómo corregir:**
```bash
# Agregar ACLs desde archivo preparado
cat security/MISSING_ACLS_TO_ADD.csv
# Copiar líneas 15-88 (73 líneas de ACLs)
# Pegar al final de security/ir.model.access.csv

# Verificar sintaxis CSV
grep -E "^access_.*,.*,.*,.*,.*,.*,.*$" security/ir.model.access.csv | wc -l
# Debe retornar: 97 líneas (24 existentes + 73 nuevas)

# Restart Odoo
docker compose restart odoo
```

**Esfuerzo estimado:** 30 minutos (copy-paste + restart + validación)

**Completado Paso 1/4:** Identificado 1 hallazgo P0 CRÍTICO (16 ACLs faltantes). 
Comando reproducible generado. Fix copy-paste ready disponible.

---

## Ejecutando Paso 2/4: Manifest Integrity

### L) Manifest Integrity - Archivos Desactivados

**Análisis `__manifest__.py`:**

Total archivos declarados: 85 (data + views + security + reports)
Archivos comentados: 7 ❌

**Archivos comentados críticos (P0/P1):**

```python
# __manifest__.py:72-76 (views comentadas)
# 'views/dte_dashboard_views.xml',              # 449 líneas COMENTADO ❌
# 'views/dte_dashboard_views_enhanced.xml',     # 291 líneas COMENTADO ❌

# __manifest__.py:156-159 (wizards comentados)
# 'wizards/upload_certificate_views.xml',        # P1 - Funcionalidad oculta
# 'wizards/send_dte_batch_views.xml',            # P1 - Envío masivo NO disponible
```

### Verificación V2: Manifest Sin Comentarios Críticos (P1 ALTO)

**Área:** L (Manifest Integrity)

**Comando:**
```bash
grep -En "^\s*#.*\.(xml|py)" \
  addons/localization/l10n_cl_dte/__manifest__.py | \
  grep -E "(dashboard|wizard|cron)"
```

**Hallazgo esperado:**
Vacío (0 archivos críticos comentados)

**Problema si falla:**
- Dashboards comentados → KPIs DTE NO visibles (monitoreo ciego)
- Wizards comentados → Features NO disponibles (upload cert, envío batch)
- Pérdida funcionalidad: 740 líneas código (449+291) inaccesibles

**Cómo corregir:**
```python
# __manifest__.py:72-76 - Descomentar dashboards
'views/dte_dashboard_views.xml',              # ✅ ACTIVAR
'views/dte_dashboard_views_enhanced.xml',     # ✅ ACTIVAR

# Pero ANTES: Convertir tipo="dashboard" → tipo="kanban" (ver Paso 3)
```

**Esfuerzo estimado:** 10-12 horas (convertir dashboards + reactivar + testing)

**Completado Paso 2/4:** Identificados 2 hallazgos P1 (dashboards + wizards desactivados). 
Dependencia: Paso 3 (fix dashboards) debe completarse primero.

---

## 🔴 Hallazgos P0 - BLOQUEANTES (1 total)

### H1: 16 Modelos Sin ACLs en ir.model.access.csv

**Archivo:** `security/ir.model.access.csv` (líneas faltantes)  
**Impacto:** AccessError producción para usuarios contador/vendedor  
**Esfuerzo:** 30 minutos

**Problema:**
16 modelos Python sin entradas ACL causan AccessError al intentar acceso.

**Fix inmediato:**
```bash
cat security/MISSING_ACLS_TO_ADD.csv >> security/ir.model.access.csv
docker compose restart odoo
```

---

## 🟡 Hallazgos P1 - ALTO IMPACTO (2 totales)

### H2: Dashboards Desactivados (740 líneas código)

**Archivo:** `__manifest__.py:72-76`  
**Impacto:** KPIs NO visibles, monitoreo ciego  
**Esfuerzo:** 10-12 horas

**Problema:**
Views comentadas + tipo="dashboard" deprecado Odoo 19

**Fix requerido:**
1. Convertir tipo="dashboard" → "kanban" (ver V3)
2. Descomentar líneas manifest
3. Testing KPIs

### H3: 4 Wizards Desactivados

**Archivo:** `__manifest__.py:156-159`  
**Impacto:** Features NO disponibles (upload cert, envío batch)  
**Esfuerzo:** 4-6 horas

---

## Resumen Ejecutivo

**Hallazgos:** 1 P0 + 2 P1 = 3 críticos  
**Esfuerzo total:** 15-19 horas  
**Prioridad:** P0 (ACLs) bloquea desarrollo → Fix inmediato

**Cobertura:**
- K) Security: ✅ Auditada (1 P0)
- L) Manifest: ✅ Auditada (2 P1)
- M) Views: ✅ Auditada (ver H2)
- N) Data: ✅ OK (no gaps)
- O) Reports: ⚠️ TED barcode pendiente validación

**Métricas:**
- Referencias: 9 válidas ✅
- Verificaciones: 3 (1 P0, 2 P1) ✅
- Palabras: 520 ✅
```

---

## 🚀 Cómo Usar este Prompt

### Personalizar Contexto

```bash
# 1. Identificar tipo módulo y métricas
MODULE=l10n_cl_dte
NUM_MODELS=$(grep -rh "class.*models.Model" addons/localization/$MODULE/models/*.py | wc -l)
NUM_VIEWS=$(ls addons/localization/$MODULE/views/*.xml 2>/dev/null | wc -l)

# 2. Reemplazar placeholders
sed -i '' "s/\[MODULE_NAME\]/$MODULE/g" prompt_p4_infrastructure_template.md
sed -i '' "s/\[NUM_MODELS\]/$NUM_MODELS/g" prompt_p4_infrastructure_template.md
sed -i '' "s/\[NUM_VIEWS\]/$NUM_VIEWS/g" prompt_p4_infrastructure_template.md
```

### Ejecutar con Copilot CLI

```bash
copilot -p "$(cat docs/prompts_desarrollo/templates/prompt_p4_infrastructure_template.md)" \
  --allow-all-tools \
  --model claude-sonnet-4.5 \
  > experimentos/outputs/audit_${MODULE}_infrastructure_$(date +%Y%m%d_%H%M%S).md
```

---

## 📖 Referencias

- **Estrategia completa:** `docs/prompts_desarrollo/ESTRATEGIA_PROMPTING_ALTA_PRECISION.md`
- **P4-Deep (lógica negocio):** `docs/prompts_desarrollo/templates/prompt_p4_deep_template.md`
- **P4-Deep Extended (360°):** `docs/prompts_desarrollo/templates/prompt_p4_deep_extended_template.md`
- **Guía selección:** `docs/prompts_desarrollo/GUIA_SELECCION_TEMPLATE_P4.md`

---

**Versión:** 2.0.0  
**Última actualización:** 2025-11-12  
**Mantenedor:** Pedro Troncoso (@pwills85)  
**Compatibilidad:** Odoo 19 CE, Claude Sonnet 4.5, Copilot CLI
