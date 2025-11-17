# 🔬 TEMPLATE P4 DEEP ANALYSIS - Auditoría Profunda Arquitectónica

**Versión:** 1.0.0
**Nivel:** P4 (Máxima Precisión)
**Tipo:** Análisis Profundo Multi-Capa
**Tiempo Estimado:** 3-6 horas ejecución
**Tokens Estimados:** 80K-150K

---

## 📋 Metadata Prompt

```yaml
prompt_id: TPL-P4-DEEP-001
version: 1.0.0
created: 2025-11-12
module: {MODULE_NAME}
priority: {P0|P1|P2}
compliance_level: Odoo_19_CE
scope: [architecture, code_quality, security, performance, compliance]
outputs: [findings, metrics, recommendations, action_plan]
```

---

## 🎯 Objetivo del Análisis

Realizar auditoría arquitectónica exhaustiva de **{MODULE_NAME}** evaluando:
1. Compliance Odoo 19 CE (8 patrones deprecación P0/P1/P2)
2. Arquitectura y patrones de diseño
3. Calidad código (complejidad, mantenibilidad, testabilidad)
4. Seguridad (OWASP Top 10, inyecciones, validaciones)
5. Performance (queries N+1, caching, lazy loading)
6. Testing (cobertura, calidad tests, edge cases)

**Output esperado:** Reporte detallado con hallazgos cuantificables, severidades (P0/P1/P2), y plan acción priorizado.

---

## 📐 Contexto del Proyecto

### Stack Tecnológico

```yaml
Framework: Odoo 19 Community Edition
Platform: Docker Compose (macOS M3 ARM64)
Database: PostgreSQL 15-alpine
Cache: Redis 7-alpine
Python: 3.12 (dentro container odoo)
Testing: pytest + Odoo test framework

Services:
  - odoo: eergygroup/odoo19:chile-1.0.5
  - db: postgres:15-alpine
  - redis: redis:7-alpine
  - ai_service: FastAPI + Claude API
```

### Comandos Validación

```bash
# Actualizar módulo
docker compose exec odoo odoo-bin -u {MODULE_NAME} -d odoo19_db --stop-after-init

# Ejecutar tests
docker compose exec odoo pytest /mnt/extra-addons/{MODULE_PATH}/tests/ -v --cov={MODULE_NAME}

# Shell Odoo (debug)
docker compose exec odoo odoo-bin shell -d odoo19_db --debug
```

---

## 🚨 COMPLIANCE ODOO 19 CE (BLOQUEANTE)

### Checklist Deprecaciones (VALIDAR 100%)

**Ubicación checklist completo:** `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`

#### P0 Breaking Changes (Deadline: 2025-03-01)

**1. QWeb Templates (t-esc → t-out)**

```bash
# Validar
docker compose exec odoo grep -r "t-esc" /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto
<span t-esc="invoice.partner_id.name" />

# ✅ Correcto
<span t-out="invoice.partner_id.name" />
```

**Acción:** Reportar TODAS las ocurrencias con línea exacta y contexto.

---

**2. HTTP Controllers (type='json' → type='jsonrpc' + csrf=False)**

```bash
# Validar
docker compose exec odoo grep -r "type='json'" /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto
@http.route('/api/endpoint', type='json', auth='user')

# ✅ Correcto
@http.route('/api/endpoint', type='jsonrpc', auth='user', csrf=False)
```

**Acción:** Reportar endpoints afectados + impacto integraciones.

---

**3. XML Views (attrs → Python expressions)**

```bash
# Validar
docker compose exec odoo grep -r 'attrs=' /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto
<field name="state" attrs="{'invisible': [('type', '=', 'manual')]}" />

# ✅ Correcto
<field name="state" invisible="type == 'manual'" />
```

**Acción:** Reportar fields con attrs={}, mapear complejidad conversión.

---

**4. ORM Constraints (_sql_constraints → models.Constraint)**

```bash
# Validar
docker compose exec odoo grep -r "_sql_constraints" /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto
_sql_constraints = [
    ('unique_folio', 'unique(folio)', 'El folio debe ser único')
]

# ✅ Correcto
from odoo import models
_sql_constraints = [
    models.Constraint('unique(folio)', 'El folio debe ser único')
]
```

**Acción:** Reportar constraints legacy + plan migración.

---

#### P1 High Priority (Deadline: 2025-06-01)

**5. Database Access (self._cr → self.env.cr)**

```bash
# Validar
docker compose exec odoo grep -r "self\._cr" /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto
self._cr.execute("SELECT id FROM table WHERE field = %s", (value,))

# ✅ Correcto
self.env.cr.execute("SELECT id FROM table WHERE field = %s", (value,))
```

**Acción:** Reportar accesos directos _cr con contexto (método, línea).

---

**6. View Methods (fields_view_get → get_view)**

```bash
# Validar
docker compose exec odoo grep -r "fields_view_get" /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto
view = self.fields_view_get(view_id, view_type='form')

# ✅ Correcto
view = self.get_view(view_id, view_type='form')
```

**Acción:** Reportar llamadas obsoletas + alternativas.

---

#### P2 Recommended (Deadline: 2025-12-01)

**7. Decorators (@api.one → @api.depends)**

```bash
# Validar
docker compose exec odoo grep -r "@api\.one" /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto (Odoo ≤16)
@api.one
def _compute_total(self):
    self.total = sum(self.line_ids.mapped('amount'))

# ✅ Correcto (Odoo 19)
@api.depends('line_ids.amount')
def _compute_total(self):
    for record in self:
        record.total = sum(record.line_ids.mapped('amount'))
```

**Acción:** Reportar decorators obsoletos (@api.one, @api.multi, @api.returns).

---

**8. Deprecated Modules (Identificar imports obsoletos)**

```bash
# Validar
docker compose exec odoo grep -r "from odoo.exceptions import Warning" /mnt/extra-addons/{MODULE_PATH}/

# ❌ Incorrecto
from odoo.exceptions import Warning

# ✅ Correcto
from odoo.exceptions import UserError
```

**Acción:** Reportar imports deprecated + alternativas Odoo 19.

---

### Resumen Compliance Esperado

**Tabla de hallazgos:**

| Patrón | Ocurrencias | Severidad | Esfuerzo Cierre | Deadline |
|--------|-------------|-----------|-----------------|----------|
| P0-1: t-esc | {N} | P0 | {horas} | 2025-03-01 |
| P0-2: type='json' | {N} | P0 | {horas} | 2025-03-01 |
| P0-3: attrs={} | {N} | P0 | {horas} | 2025-03-01 |
| P0-4: _sql_constraints | {N} | P0 | {horas} | 2025-03-01 |
| P1-5: self._cr | {N} | P1 | {horas} | 2025-06-01 |
| P1-6: fields_view_get | {N} | P1 | {horas} | 2025-06-01 |
| P2-7: @api.one | {N} | P2 | {horas} | 2025-12-01 |
| P2-8: imports obsoletos | {N} | P2 | {horas} | 2025-12-01 |

**TOTAL:** {N} deprecaciones | Esfuerzo: {X} horas | Riesgo: {ALTO|MEDIO|BAJO}

---

## 🏗️ ARQUITECTURA Y PATRONES

### 1. Estructura de Archivos

**Validar estructura estándar Odoo:**

```
{MODULE_NAME}/
├── __init__.py
├── __manifest__.py
├── models/
│   ├── __init__.py
│   └── {model}.py
├── views/
│   ├── {model}_views.xml
│   └── menu.xml
├── security/
│   ├── ir.model.access.csv
│   └── {model}_security.xml
├── data/
│   └── {data}.xml
├── wizard/
│   ├── __init__.py
│   └── {wizard}.py
├── report/
│   ├── {report}.xml
│   └── {report}.py
├── static/
│   └── src/
│       ├── js/
│       ├── css/
│       └── xml/
└── tests/
    ├── __init__.py
    ├── test_{feature}.py
    └── common.py
```

**Validar:**
- [ ] Separación models/views/controllers/data/security
- [ ] Nomenclatura consistente (snake_case files, PascalCase clases)
- [ ] __init__.py en cada paquete Python
- [ ] __manifest__.py completo (dependencies, data, assets)

**Reportar:** Desviaciones estructura + impacto mantenibilidad.

---

### 2. Patrones de Diseño

**2.1 Models (ORM)**

```python
# Validar patrones correctos Odoo 19
class SampleModel(models.Model):
    _name = 'sample.model'
    _description = 'Descripción clara'
    _inherit = ['mail.thread', 'mail.activity.mixin']  # Si aplica
    _order = 'create_date desc'

    # Fields con compute, inverse, search
    name = fields.Char(string='Nombre', required=True, tracking=True)
    amount = fields.Float(
        string='Monto',
        compute='_compute_amount',
        store=True,
        digits='Product Price'
    )

    # Constraints correctos (Odoo 19)
    _sql_constraints = [
        models.Constraint('unique(name)', 'El nombre debe ser único')
    ]

    @api.depends('line_ids.amount')
    def _compute_amount(self):
        for record in self:
            record.amount = sum(record.line_ids.mapped('amount'))

    @api.constrains('amount')
    def _check_amount(self):
        for record in self:
            if record.amount < 0:
                raise ValidationError("El monto no puede ser negativo")
```

**Validar:**
- [ ] _name, _description siempre presentes
- [ ] compute con @api.depends correcto
- [ ] Constraints con models.Constraint (no tuplas)
- [ ] Uso correcto self.env.cr (no self._cr)
- [ ] Tracking en fields auditables

**Reportar:** Anti-patterns + complejidad ciclomática métodos.

---

**2.2 Views (XML)**

```xml
<!-- Validar estructura correcta views -->
<odoo>
    <record id="view_{model}_form" model="ir.ui.view">
        <field name="name">{model}.form</field>
        <field name="model">{model}</field>
        <field name="arch" type="xml">
            <form>
                <header>
                    <button name="action_confirm"
                            string="Confirmar"
                            type="object"
                            invisible="state != 'draft'"
                            class="btn-primary"/>
                    <field name="state" widget="statusbar"/>
                </header>
                <sheet>
                    <group>
                        <field name="name"/>
                        <field name="date" invisible="type == 'manual'"/>
                    </group>
                </sheet>
                <div class="oe_chatter">
                    <field name="message_follower_ids"/>
                    <field name="activity_ids"/>
                    <field name="message_ids"/>
                </div>
            </form>
        </field>
    </record>
</odoo>
```

**Validar:**
- [ ] Sin attrs={} (usar invisible= directamente)
- [ ] Sin t-esc (usar t-out)
- [ ] Grupos lógicos (<group>, <page>)
- [ ] Chatter si tiene mail.thread

**Reportar:** Views mal estructuradas + UX issues.

---

**2.3 Controllers (HTTP)**

```python
# Validar endpoints correctos Odoo 19
from odoo import http
from odoo.http import request

class SampleController(http.Controller):

    @http.route('/api/sample/data', type='jsonrpc', auth='user', csrf=False, methods=['POST'])
    def get_sample_data(self, **kwargs):
        """Endpoint JSONRPC Odoo 19 compliant"""
        try:
            data = request.env['sample.model'].search_read(
                domain=[('active', '=', True)],
                fields=['id', 'name', 'amount']
            )
            return {'status': 'success', 'data': data}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
```

**Validar:**
- [ ] type='jsonrpc' (no type='json')
- [ ] csrf=False en endpoints API
- [ ] Manejo errores correcto
- [ ] Validación inputs (evitar inyecciones)

**Reportar:** Endpoints inseguros + missing validations.

---

### 3. Dependencias y Acoplamiento

**Analizar __manifest__.py:**

```python
{
    'name': '{MODULE_NAME}',
    'version': '19.0.1.0.0',
    'depends': [
        'base',
        'account',  # Dependencias claras
        'l10n_cl_dte',  # Localización Chile
    ],
    'external_dependencies': {
        'python': ['zeep', 'cryptography'],  # Especificar librerías externas
    },
}
```

**Validar:**
- [ ] Dependencias mínimas necesarias (evitar bloat)
- [ ] Versiones compatibles Odoo 19
- [ ] external_dependencies documentado
- [ ] Circular dependencies (detectar)

**Reportar:** Dependencias innecesarias + riesgos circular deps.

---

## 🔒 SEGURIDAD (OWASP Top 10)

### 1. SQL Injection

```bash
# Buscar concatenación SQL peligrosa
docker compose exec odoo grep -r "execute.*%s" /mnt/extra-addons/{MODULE_PATH}/ | grep -v "(%s,"
```

**❌ Inseguro:**
```python
query = "SELECT * FROM table WHERE name = '%s'" % user_input
self.env.cr.execute(query)
```

**✅ Seguro:**
```python
query = "SELECT * FROM table WHERE name = %s"
self.env.cr.execute(query, (user_input,))
```

**Reportar:** Queries con concatenación directa.

---

### 2. XSS (Cross-Site Scripting)

**Validar sanitización outputs:**

```xml
<!-- ❌ Inseguro -->
<span t-raw="user_input"/>

<!-- ✅ Seguro -->
<span t-out="user_input"/>  <!-- Auto-escaping -->
```

**Reportar:** t-raw sin sanitización + inputs no validados.

---

### 3. Access Control

**Validar ir.model.access.csv:**

```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_sample_user,sample.model.user,model_sample_model,base.group_user,1,1,1,0
access_sample_manager,sample.model.manager,model_sample_model,base.group_system,1,1,1,1
```

**Validar:**
- [ ] Permisos mínimo privilegio
- [ ] Record rules para multi-company
- [ ] Field-level security si aplica

**Reportar:** Permisos excesivos + missing record rules.

---

### 4. Input Validation

```python
@api.constrains('rut')
def _check_rut(self):
    """Validar RUT chileno correctamente"""
    for record in self:
        if record.rut and not self._validate_rut_format(record.rut):
            raise ValidationError("RUT inválido: formato incorrecto")

def _validate_rut_format(self, rut):
    """Validación RUT con regex + dígito verificador"""
    import re
    pattern = r'^\d{7,8}-[0-9K]$'
    if not re.match(pattern, rut):
        return False
    # Validar dígito verificador (algoritmo módulo 11)
    # ...
    return True
```

**Validar:**
- [ ] Validación RUT/email/phone con regex
- [ ] Rangos numéricos (montos, cantidades)
- [ ] Tipos de datos (fechas, booleanos)

**Reportar:** Inputs sin validación + edge cases no manejados.

---

## ⚡ PERFORMANCE

### 1. N+1 Queries

```bash
# Ejecutar con profiling
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import registry
env = registry('odoo19_db')['ir.ui.view']
import logging
logging.getLogger('odoo.sql_db').setLevel(logging.DEBUG)
# Ejecutar código sospechoso
"
```

**❌ Problema N+1:**
```python
for invoice in invoices:
    partner_name = invoice.partner_id.name  # Query por iteración!
```

**✅ Solución:**
```python
invoices = self.env['account.move'].search([...])
invoices.mapped('partner_id.name')  # Prefetch automático
```

**Reportar:** Loops con accesos relacionales + queries duplicadas.

---

### 2. Indexación Database

```python
# Validar indexes en campos búsqueda frecuente
_sql_indexes = [
    ('name_index', 'btree', 'name'),  # Odoo 19
    ('partner_date_index', 'btree', 'partner_id, invoice_date'),
]
```

**Validar:**
- [ ] Indexes en fields de búsqueda frecuente
- [ ] Indexes compuestos para queries complejas
- [ ] Sin over-indexing (degradación inserts)

**Reportar:** Missing indexes + oportunidades optimización.

---

### 3. Caching

```python
from odoo import tools

@tools.ormcache('partner_id')
def _get_partner_data(self, partner_id):
    """Cache results para lookups repetitivos"""
    return self.env['res.partner'].browse(partner_id).read(['name', 'vat'])
```

**Validar:**
- [ ] @tools.ormcache en métodos costosos
- [ ] Redis cache para datos externos (SII, Previred)
- [ ] Clear cache strategy (invalidaciones)

**Reportar:** Oportunidades caching + cache hits esperados.

---

## 🧪 TESTING

### 1. Cobertura

```bash
# Ejecutar tests con coverage
docker compose exec odoo pytest /mnt/extra-addons/{MODULE_PATH}/tests/ \
    --cov={MODULE_NAME} \
    --cov-report=term-missing \
    --cov-report=html
```

**Objetivos:**
- Coverage líneas: >80%
- Coverage branches: >70%
- Critical paths: 100%

**Reportar:** Coverage actual + gaps críticos.

---

### 2. Calidad Tests

```python
# Ejemplo test bien estructurado
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError

class TestSampleModel(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.sample = cls.env['sample.model'].create({
            'name': 'Test Sample',
            'amount': 1000,
        })

    def test_compute_amount_positive(self):
        """Test: monto se calcula correctamente con valores positivos"""
        self.assertEqual(self.sample.amount, 1000)

    def test_amount_negative_raises_error(self):
        """Test: monto negativo lanza ValidationError"""
        with self.assertRaises(ValidationError):
            self.sample.amount = -100

    def test_unique_name_constraint(self):
        """Test: constraint unique name funciona"""
        with self.assertRaises(Exception):
            self.env['sample.model'].create({'name': 'Test Sample'})
```

**Validar:**
- [ ] Tests unitarios (lógica aislada)
- [ ] Tests integración (workflows completos)
- [ ] Tests edge cases (valores límite)
- [ ] Tests regresión (bugs conocidos)

**Reportar:** Missing tests + scenarios no cubiertos.

---

## 📊 MÉTRICAS CUANTITATIVAS ESPERADAS

### Tabla Resumen

| Métrica | Valor | Target | Status |
|---------|-------|--------|--------|
| **Compliance Odoo 19** | | | |
| Deprecaciones P0 | {N} | 0 | 🔴/🟡/🟢 |
| Deprecaciones P1 | {N} | 0 | 🔴/🟡/🟢 |
| Deprecaciones P2 | {N} | <5 | 🔴/🟡/🟢 |
| **Calidad Código** | | | |
| Complejidad ciclomática media | {N} | <10 | 🔴/🟡/🟢 |
| Funciones >50 líneas | {N} | <5% | 🔴/🟡/🟢 |
| Duplicación código | {%} | <3% | 🔴/🟡/🟢 |
| **Seguridad** | | | |
| SQL injections potenciales | {N} | 0 | 🔴/🟡/🟢 |
| XSS vulnerabilities | {N} | 0 | 🔴/🟡/🟢 |
| Missing input validations | {N} | <3 | 🔴/🟡/🟢 |
| **Performance** | | | |
| N+1 queries detectadas | {N} | 0 | 🔴/🟡/🟢 |
| Queries sin index | {N} | <5 | 🔴/🟡/🟢 |
| Cache hit ratio | {%} | >85% | 🔴/🟡/🟢 |
| **Testing** | | | |
| Coverage líneas | {%} | >80% | 🔴/🟡/🟢 |
| Coverage branches | {%} | >70% | 🔴/🟡/🟢 |
| Tests fallando | {N} | 0 | 🔴/🟡/🟢 |
| Edge cases cubiertos | {%} | >90% | 🔴/🟡/🟢 |

**Leyenda:**
- 🔴 Crítico (requiere acción inmediata)
- 🟡 Atención (plan mejora corto plazo)
- 🟢 Aceptable (monitorear)

---

## 📋 DELIVERABLES

### 1. Reporte Ejecutivo (1-2 páginas)

```markdown
# Auditoría {MODULE_NAME} - Resumen Ejecutivo

**Fecha:** {FECHA}
**Auditor:** {AGENTE}
**Versión módulo:** {VERSION}

## Score Global: {X}/100

### Hallazgos Críticos (P0)
1. [H-P0-01] Descripción breve
2. [H-P0-02] Descripción breve

### Hallazgos Alta Prioridad (P1)
1. [H-P1-01] Descripción breve
2. [H-P1-02] Descripción breve

### Recomendaciones Top 5
1. Acción inmediata #1
2. Acción inmediata #2
...

### Esfuerzo Estimado Cierre
- P0: {X} horas
- P1: {Y} horas
- Total: {Z} horas
```

---

### 2. Reporte Técnico Detallado (15-30 páginas)

**Secciones:**
1. Compliance Odoo 19 (con tabla hallazgos)
2. Arquitectura (diagramas + patrones)
3. Seguridad (vulnerabilidades + mitigaciones)
4. Performance (benchmarks + optimizaciones)
5. Testing (coverage + gaps)
6. Apéndices (comandos validación, referencias)

---

### 3. Plan de Acción Priorizado

```markdown
## Plan Cierre Hallazgos {MODULE_NAME}

### Sprint 1 (1 semana) - P0 Bloqueantes
- [ ] [H-P0-01] Migrar t-esc → t-out (8h)
- [ ] [H-P0-02] Migrar type='json' → type='jsonrpc' (4h)
...

### Sprint 2 (1 semana) - P1 Altas
- [ ] [H-P1-01] Migrar self._cr → self.env.cr (6h)
...

### Sprint 3 (2 semanas) - P2 Recomendadas
- [ ] [H-P2-01] Refactoring complejidad alta (16h)
...
```

---

### 4. Métricas JSON (machine-readable)

```json
{
  "audit_metadata": {
    "prompt_id": "TPL-P4-DEEP-001",
    "module": "{MODULE_NAME}",
    "date": "2025-11-12",
    "version": "1.0.0"
  },
  "compliance": {
    "odoo_19_deprecations": {
      "p0": {"count": 12, "deadline": "2025-03-01"},
      "p1": {"count": 8, "deadline": "2025-06-01"},
      "p2": {"count": 5, "deadline": "2025-12-01"}
    }
  },
  "quality": {
    "cyclomatic_complexity": {"mean": 8.3, "max": 24},
    "code_duplication": {"percentage": 2.1}
  },
  "security": {
    "sql_injections": 0,
    "xss_vulnerabilities": 1,
    "missing_validations": 3
  },
  "performance": {
    "n_plus_one_queries": 2,
    "missing_indexes": 4,
    "cache_hit_ratio": 87.5
  },
  "testing": {
    "line_coverage": 82.3,
    "branch_coverage": 68.7,
    "failing_tests": 0
  },
  "score": 78.5
}
```

---

## 🎯 Instrucciones de Ejecución

### Paso 1: Preparación (15 min)

1. Leer este template completo
2. Leer `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
3. Leer `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md`
4. Identificar módulo target: {MODULE_NAME}

---

### Paso 2: Auditoría Compliance (1-2h)

1. Ejecutar 8 validaciones deprecaciones (comandos grep)
2. Cuantificar hallazgos (línea exacta + contexto)
3. Estimar esfuerzo cierre por patrón
4. Generar tabla resumen compliance

---

### Paso 3: Análisis Arquitectura (1-2h)

1. Revisar estructura archivos vs estándar Odoo
2. Validar patrones models/views/controllers
3. Analizar dependencias (__manifest__.py)
4. Identificar anti-patterns + complejidad

---

### Paso 4: Auditoría Seguridad (1h)

1. Buscar SQL injections (queries concatenadas)
2. Buscar XSS (t-raw sin sanitización)
3. Validar access control (ir.model.access.csv)
4. Verificar input validation

---

### Paso 5: Análisis Performance (1h)

1. Detectar N+1 queries (profiling)
2. Validar indexación database
3. Identificar oportunidades caching
4. Benchmarks queries críticas

---

### Paso 6: Evaluación Testing (30 min)

1. Ejecutar tests con coverage
2. Analizar calidad tests existentes
3. Identificar gaps coverage
4. Documentar scenarios no cubiertos

---

### Paso 7: Generación Reportes (1-2h)

1. Consolidar hallazgos en tabla resumen
2. Calcular métricas cuantitativas
3. Priorizar hallazgos (P0 > P1 > P2)
4. Generar:
   - Reporte ejecutivo
   - Reporte técnico detallado
   - Plan acción priorizado
   - Métricas JSON

---

### Paso 8: Validación y Entrega (30 min)

1. Revisar completitud reporte
2. Validar números (double-check queries)
3. Guardar outputs:
   - Prompt: `docs/prompts/05_prompts_produccion/modulos/{MODULE_NAME}/`
   - Output: `docs/prompts/06_outputs/2025-11/auditorias/{DATE}_AUDIT_{MODULE}_DEEP.md`
4. Actualizar README si necesario

---

## ✅ Checklist Pre-Entrega

- [ ] Auditoría compliance completa (8 patrones)
- [ ] Tabla hallazgos con severidades P0/P1/P2
- [ ] Métricas cuantitativas calculadas
- [ ] Hallazgos con línea exacta + contexto
- [ ] Esfuerzo estimado cierre (horas)
- [ ] Plan acción priorizado por sprints
- [ ] Reporte ejecutivo (1-2 páginas)
- [ ] Reporte técnico detallado (15-30 páginas)
- [ ] Métricas JSON generadas
- [ ] Comandos validación documentados
- [ ] Referencias cruzadas a docs proyecto

---

## 📚 Referencias

**Documentación Proyecto:**
- `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
- `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md`
- `.github/agents/knowledge/odoo19_patterns.md`
- `.github/agents/knowledge/odoo19_deprecations_reference.md`
- `.github/agents/knowledge/docker_odoo_command_reference.md`

**Estándares Externos:**
- Odoo 19 CE Documentation: https://www.odoo.com/documentation/19.0/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Python PEP 8: https://peps.python.org/pep-0008/

---

**Template Version:** 1.0.0
**Creado:** 2025-11-12
**Mantenedor:** Pedro Troncoso (@pwills85)
**Próxima revisión:** 2025-12-12
