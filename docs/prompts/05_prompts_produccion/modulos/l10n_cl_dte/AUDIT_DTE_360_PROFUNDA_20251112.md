# 🔬 AUDITORÍA 360° PROFUNDA - l10n_cl_dte (Facturación Electrónica)

**Versión:** 1.0.0  
**Fecha:** 2025-11-12  
**Tipo:** P4-Deep Extended (360° Completa)  
**Módulo:** l10n_cl_dte  
**Tiempo Estimado:** 12-15 minutos ejecución  
**Tokens Estimados:** 120K-180K

---

## 🎯 OBJETIVO

Realizar auditoría arquitectónica exhaustiva 360° del módulo `l10n_cl_dte` combinando:
1. **P4-Deep** (lógica negocio, integraciones, performance, seguridad)
2. **P4-Infrastructure** (ACLs, manifest, views, data, reports)

**Output esperado:** Reporte consolidado con hallazgos cuantificables, severidades P0/P1/P2, métricas JSON, y plan acción priorizado.

---

## 📐 CONTEXTO DEL PROYECTO

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

Módulo Target:
  - Nombre: l10n_cl_dte
  - Versión: 19.0.6.0.0
  - Ruta: addons/localization/l10n_cl_dte/
  - Tipo: Facturación Electrónica Chilena (DTE)
```

### Comandos Validación

```bash
# Actualizar módulo
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# Ejecutar tests
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --cov=l10n_cl_dte

# Shell Odoo (debug)
docker compose exec odoo odoo-bin shell -d odoo19_db --debug
```

---

## 🚨 COMPLIANCE ODOO 19 CE (BLOQUEANTE - VALIDAR PRIMERO)

### Checklist Deprecaciones (VALIDAR 100%)

**Ubicación checklist completo:** `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`

#### P0 Breaking Changes (Deadline: 2025-03-01)

**1. QWeb Templates (t-esc → t-out)**

```bash
# Validar
docker compose exec odoo grep -r "t-esc" /mnt/extra-addons/localization/l10n_cl_dte/views/ /mnt/extra-addons/localization/l10n_cl_dte/reports/ 2>/dev/null | grep -v ".backup"

# Reportar TODAS las ocurrencias con línea exacta y contexto
```

**2. HTTP Controllers (type='json' → type='jsonrpc' + csrf=False)**

```bash
# Validar
docker compose exec odoo grep -r "type='json'" /mnt/extra-addons/localization/l10n_cl_dte/controllers/ 2>/dev/null

# Reportar endpoints afectados + impacto integraciones
```

**3. XML Views (attrs → Python expressions)**

```bash
# Validar
docker compose exec odoo grep -r 'attrs=' /mnt/extra-addons/localization/l10n_cl_dte/views/ 2>/dev/null | grep -v ".backup"

# Reportar fields con attrs={}, mapear complejidad conversión
```

**4. ORM Constraints (_sql_constraints → models.Constraint)**

```bash
# Validar
docker compose exec odoo grep -r "_sql_constraints" /mnt/extra-addons/localization/l10n_cl_dte/models/ 2>/dev/null

# Reportar constraints legacy + plan migración
```

#### P1 High Priority (Deadline: 2025-06-01)

**5. Database Access (self._cr → self.env.cr)**

```bash
# Validar
docker compose exec odoo grep -r "self\._cr" /mnt/extra-addons/localization/l10n_cl_dte/models/ 2>/dev/null

# Reportar accesos directos _cr con contexto (método, línea)
```

**6. View Methods (fields_view_get → get_view)**

```bash
# Validar
docker compose exec odoo grep -r "fields_view_get" /mnt/extra-addons/localization/l10n_cl_dte/ 2>/dev/null

# Reportar llamadas obsoletas + alternativas
```

### Resumen Compliance Esperado

**Tabla de hallazgos:**

| Patrón | Ocurrencias | Severidad | Esfuerzo Cierre | Deadline | Archivos Afectados |
|--------|-------------|-----------|-----------------|----------|-------------------|
| P0-1: t-esc | {N} | P0 | {horas} | 2025-03-01 | {lista archivos} |
| P0-2: type='json' | {N} | P0 | {horas} | 2025-03-01 | {lista archivos} |
| P0-3: attrs={} | {N} | P0 | {horas} | 2025-03-01 | {lista archivos} |
| P0-4: _sql_constraints | {N} | P0 | {horas} | 2025-03-01 | {lista archivos} |
| P1-5: self._cr | {N} | P1 | {horas} | 2025-06-01 | {lista archivos} |
| P1-6: fields_view_get | {N} | P1 | {horas} | 2025-06-01 | {lista archivos} |

**TOTAL:** {N} deprecaciones | Esfuerzo: {X} horas | Riesgo: {ALTO|MEDIO|BAJO}

---

## 🏗️ DIMENSIÓN A-J: ARQUITECTURA Y LÓGICA NEGOCIO (P4-Deep)

### A) Arquitectura y Patrones de Diseño

**Validar estructura estándar Odoo:**

```
l10n_cl_dte/
├── __init__.py
├── __manifest__.py
├── models/ (40 archivos Python)
├── views/ (34 archivos XML)
├── security/ (ir.model.access.csv, multi_company_rules.xml)
├── data/ (certificates, config_parameters, cron_jobs, etc.)
├── libs/ (xml_signer, sii_soap_client, safe_xml_parser, etc.)
├── controllers/ (dte_webhook.py)
├── wizards/ (20 archivos)
├── reports/ (QWeb reports)
└── tests/ (39 archivos)
```

**Validar:**
- [ ] Separación models/views/controllers/data/security
- [ ] Nomenclatura consistente (snake_case files, PascalCase clases)
- [ ] __init__.py en cada paquete Python
- [ ] __manifest__.py completo (dependencies, data, assets)

**Reportar:** Desviaciones estructura + impacto mantenibilidad.

---

### B) Patrones de Diseño (Models, Views, Controllers)

**2.1 Models (ORM)**

**Validar patrones correctos Odoo 19:**

```python
# Ejemplo correcto
class AccountMoveDte(models.Model):
    _name = 'account.move.dte'
    _inherit = 'account.move'
    _description = 'DTE Electronic Invoice'
    
    # Fields con compute, inverse, search
    l10n_cl_dte_type_id = fields.Many2one('l10n_cl.dte.type', string='DTE Type')
    
    @api.depends('line_ids.amount')
    def _compute_total(self):
        for record in self:
            record.total = sum(record.line_ids.mapped('amount'))
    
    @api.constrains('l10n_cl_dte_type_id')
    def _check_dte_type(self):
        # Validación
        pass
```

**Validar:**
- [ ] _name, _description siempre presentes
- [ ] compute con @api.depends correcto
- [ ] Constraints con models.Constraint (no tuplas)
- [ ] Uso correcto self.env.cr (no self._cr)
- [ ] Tracking en fields auditables

**Archivos clave a revisar:**
- `models/account_move_dte.py` (modelo principal)
- `models/dte_service_integration.py` (integración SII)
- `models/stock_picking_dte.py` (guías de despacho)

**Reportar:** Anti-patterns + complejidad ciclomática métodos.

---

**2.2 Views (XML)**

**Validar estructura correcta views:**

```xml
<!-- Validar sin attrs={}, sin t-esc -->
<field name="state" invisible="type == 'manual'"/>
<span t-out="invoice.partner_id.name"/>
```

**Archivos clave a revisar:**
- `views/invoice_form.xml`
- `views/invoice_tree.xml`
- `reports/dte_receipt_report.xml`

**Validar:**
- [ ] Sin attrs={} (usar invisible= directamente)
- [ ] Sin t-esc (usar t-out)
- [ ] Grupos lógicos (<group>, <page>)
- [ ] Chatter si tiene mail.thread

**Reportar:** Views mal estructuradas + UX issues.

---

**2.3 Controllers (HTTP)**

**Validar endpoints correctos Odoo 19:**

```python
# Validar type='jsonrpc' (no type='json')
@http.route('/api/dte/validate', type='jsonrpc', auth='user', csrf=False, methods=['POST'])
def validate_dte(self, **kwargs):
    # Endpoint JSONRPC Odoo 19 compliant
    pass
```

**Archivos clave a revisar:**
- `controllers/dte_webhook.py`

**Validar:**
- [ ] type='jsonrpc' (no type='json')
- [ ] csrf=False en endpoints API
- [ ] Manejo errores correcto
- [ ] Validación inputs (evitar inyecciones)

**Reportar:** Endpoints inseguros + missing validations.

---

### C) Integraciones Externas (SII, SOAP, APIs)

**3.1 Integración SII Webservices**

**Archivos clave:**
- `libs/sii_soap_client.py` (cliente SOAP)
- `libs/sii_authenticator.py` (autenticación)
- `models/dte_service_integration.py` (integración modelo)

**Validar:**
- [ ] Manejo errores SOAP (SOAPFault, timeout)
- [ ] Reintentos con exponential backoff
- [ ] Circuit breaker si aplica
- [ ] Logging estructurado requests/responses
- [ ] Validación certificados SSL/TLS

**Comandos validación:**

```bash
# Buscar manejo errores SII
docker compose exec odoo grep -rn "SOAPFault\|zeep\|suds" /mnt/extra-addons/localization/l10n_cl_dte/libs/ 2>/dev/null

# Validar reintentos
docker compose exec odoo grep -rn "retry\|backoff\|circuit" /mnt/extra-addons/localization/l10n_cl_dte/libs/ 2>/dev/null
```

**Reportar:** Gaps integración + riesgos disponibilidad.

---

**3.2 Firma Digital XML (xmlsec)**

**Archivos clave:**
- `libs/xml_signer.py` (firma digital)
- `libs/safe_xml_parser.py` (parser seguro)

**Validar:**
- [ ] Protección XXE (XML External Entity)
- [ ] Validación esquema XSD antes firma
- [ ] Manejo certificados (CAF, certificado empresa)
- [ ] Logging firma (auditoría)

**Comandos validación:**

```bash
# Buscar vulnerabilidades XXE
docker compose exec odoo grep -rn "etree.fromstring\|etree.XML\|XMLParser" /mnt/extra-addons/localization/l10n_cl_dte/libs/ 2>/dev/null

# Validar parser seguro
docker compose exec odoo grep -rn "defusedxml\|safe_xml" /mnt/extra-addons/localization/l10n_cl_dte/libs/ 2>/dev/null
```

**Reportar:** Vulnerabilidades seguridad XML + mitigaciones.

---

### D) Seguridad (OWASP Top 10)

**4.1 SQL Injection**

```bash
# Buscar concatenación SQL peligrosa
docker compose exec odoo grep -rn "execute.*%" /mnt/extra-addons/localization/l10n_cl_dte/models/ 2>/dev/null | grep -v "(%s,"
```

**Reportar:** Queries con concatenación directa.

---

**4.2 XSS (Cross-Site Scripting)**

**Validar sanitización outputs:**

```xml
<!-- ❌ Inseguro -->
<span t-raw="user_input"/>

<!-- ✅ Seguro -->
<span t-out="user_input"/>  <!-- Auto-escaping -->
```

**Reportar:** t-raw sin sanitización + inputs no validados.

---

**4.3 Access Control**

**Validar ir.model.access.csv:**

```bash
# Revisar ACLs
docker compose exec odoo cat /mnt/extra-addons/localization/l10n_cl_dte/security/ir.model.access.csv | head -20

# Validar record rules
docker compose exec odoo cat /mnt/extra-addons/localization/l10n_cl_dte/security/multi_company_rules.xml
```

**Validar:**
- [ ] Permisos mínimo privilegio
- [ ] Record rules para multi-company
- [ ] Field-level security si aplica

**Reportar:** Permisos excesivos + missing record rules.

---

**4.4 Input Validation**

**Validar validaciones RUT, montos, fechas:**

```bash
# Buscar validaciones RUT
docker compose exec odoo grep -rn "def.*validate.*rut\|def.*check.*rut" /mnt/extra-addons/localization/l10n_cl_dte/ 2>/dev/null -i

# Validar constraints
docker compose exec odoo grep -rn "@api.constrains" /mnt/extra-addons/localization/l10n_cl_dte/models/ 2>/dev/null
```

**Reportar:** Inputs sin validación + edge cases no manejados.

---

### E) Performance

**5.1 N+1 Queries**

```bash
# Buscar loops con accesos relacionales
docker compose exec odoo grep -rn "for.*in.*:" /mnt/extra-addons/localization/l10n_cl_dte/models/account_move_dte.py 2>/dev/null | head -20

# Validar prefetch
docker compose exec odoo grep -rn "prefetch\|mapped\|read_group" /mnt/extra-addons/localization/l10n_cl_dte/models/account_move_dte.py 2>/dev/null
```

**Reportar:** Loops con accesos relacionales + queries duplicadas.

---

**5.2 Indexación Database**

**Validar indexes en campos búsqueda frecuente:**

```bash
# Buscar campos sin index
docker compose exec odoo grep -rn "name.*=.*fields\." /mnt/extra-addons/localization/l10n_cl_dte/models/account_move_dte.py 2>/dev/null | grep -E "Char|Integer|Date" | head -20
```

**Reportar:** Missing indexes + oportunidades optimización.

---

**5.3 Caching**

**Validar uso cache:**

```bash
# Buscar implementación cache
docker compose exec odoo grep -rn "redis\|cache\|@tools.ormcache" /mnt/extra-addons/localization/l10n_cl_dte/models/ 2>/dev/null
```

**Reportar:** Oportunidades caching + cache hits esperados.

---

### F) Testing

**6.1 Cobertura**

```bash
# Ejecutar tests con coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ \
    --cov=l10n_cl_dte \
    --cov-report=term-missing \
    --cov-report=html:coverage_html/
```

**Objetivos:**
- Coverage líneas: >80%
- Coverage branches: >70%
- Critical paths: 100%

**Reportar:** Coverage actual + gaps críticos.

---

**6.2 Calidad Tests**

**Validar estructura tests:**

```bash
# Contar tests
docker compose exec odoo find /mnt/extra-addons/localization/l10n_cl_dte/tests/ -name "test_*.py" -exec wc -l {} \; | awk '{sum+=$1} END {print sum}'

# Validar tests críticos
docker compose exec odoo grep -rn "def test_" /mnt/extra-addons/localization/l10n_cl_dte/tests/ 2>/dev/null | grep -E "dte|sii|sign|validate" | wc -l
```

**Validar:**
- [ ] Tests unitarios (lógica aislada)
- [ ] Tests integración (workflows completos)
- [ ] Tests edge cases (valores límite)
- [ ] Tests regresión (bugs conocidos)

**Reportar:** Missing tests + scenarios no cubiertos.

---

## 🏗️ DIMENSIÓN K-O: INFRAESTRUCTURA ODOO (P4-Infrastructure)

### K) Security Files (ACLs, Record Rules)

**7.1 ir.model.access.csv**

**Validar ACLs completos:**

```bash
# Contar modelos vs ACLs
docker compose exec odoo grep -c "^model_" /mnt/extra-addons/localization/l10n_cl_dte/security/ir.model.access.csv 2>/dev/null

# Listar modelos sin ACL
docker compose exec odoo python3 -c "
import csv
models = set()
with open('/mnt/extra-addons/localization/l10n_cl_dte/security/ir.model.access.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        models.add(row['model_id:id'].replace('model_', ''))
print(f'ACLs definidos: {len(models)}')
"
```

**Validar:**
- [ ] Todos los modelos tienen ACL mínimo
- [ ] Permisos mínimo privilegio (read-only donde aplica)
- [ ] Grupos seguridad definidos correctamente

**Reportar:** Modelos sin ACL + permisos excesivos.

---

**7.2 Record Rules (Multi-Company)**

**Validar multi_company_rules.xml:**

```bash
# Revisar record rules
docker compose exec odoo cat /mnt/extra-addons/localization/l10n_cl_dte/security/multi_company_rules.xml
```

**Validar:**
- [ ] Record rules para multi-company
- [ ] Reglas no permiten acceso cross-company
- [ ] Reglas aplicadas a modelos sensibles (DTE, CAF)

**Reportar:** Missing record rules + riesgos seguridad.

---

### L) Manifest Integrity

**8.1 __manifest__.py**

**Validar manifest completo:**

```bash
# Revisar manifest
docker compose exec odoo cat /mnt/extra-addons/localization/l10n_cl_dte/__manifest__.py | head -100
```

**Validar:**
- [ ] Dependencias mínimas necesarias
- [ ] external_dependencies documentado (xmlsec, zeep, cryptography)
- [ ] Data files listados correctamente
- [ ] Assets definidos si aplica
- [ ] Versión correcta (19.0.x.x)

**Reportar:** Dependencias innecesarias + riesgos circular deps.

---

**8.2 Archivos Comentados**

**Validar archivos no utilizados:**

```bash
# Buscar archivos comentados en manifest
docker compose exec odoo grep -rn "#.*data\|#.*views\|#.*reports" /mnt/extra-addons/localization/l10n_cl_dte/__manifest__.py 2>/dev/null

# Listar archivos en directorio vs manifest
docker compose exec odoo find /mnt/extra-addons/localization/l10n_cl_dte/views/ -name "*.xml" | wc -l
```

**Reportar:** Archivos comentados (dashboards, wizards) + impacto.

---

### M) Views XML (Dashboards, UI/UX)

**9.1 Dashboards Odoo 19**

**Validar dashboards deprecados:**

```bash
# Buscar tipo="dashboard" (deprecado Odoo 19)
docker compose exec odoo grep -rn 'type="dashboard"' /mnt/extra-addons/localization/l10n_cl_dte/views/ 2>/dev/null

# Validar conversión a kanban class="o_kanban_dashboard"
docker compose exec odoo grep -rn 'class="o_kanban_dashboard"' /mnt/extra-addons/localization/l10n_cl_dte/views/ 2>/dev/null
```

**Reportar:** Dashboards deprecados + plan migración.

---

**9.2 UI/UX Issues**

**Validar:**
- [ ] Campos obligatorios claramente marcados
- [ ] Help text en campos complejos
- [ ] Estados visuales claros (colores, iconos)
- [ ] Responsive design (móvil)

**Reportar:** UX issues + mejoras recomendadas.

---

### N) Data Files (Crons, Sequences)

**10.1 Cron Jobs**

**Validar crons:**

```bash
# Listar crons
docker compose exec odoo find /mnt/extra-addons/localization/l10n_cl_dte/data/ -name "*cron*.xml" -exec cat {} \;

# Validar overlap (mismo intervalo)
docker compose exec odoo grep -rn "interval_number\|interval_type" /mnt/extra-addons/localization/l10n_cl_dte/data/*cron*.xml 2>/dev/null
```

**Validar:**
- [ ] Crons no se solapan (mismo tiempo ejecución)
- [ ] Intervalos apropiados (no muy frecuentes)
- [ ] Active/inactive correctamente configurado

**Reportar:** Crons solapados + optimización intervalos.

---

**10.2 Sequences**

**Validar sequences:**

```bash
# Buscar sequences
docker compose exec odoo grep -rn "ir.sequence" /mnt/extra-addons/localization/l10n_cl_dte/data/ 2>/dev/null
```

**Validar:**
- [ ] Sequences únicas por compañía
- [ ] Prefix/suffix correctos
- [ ] Padding apropiado

**Reportar:** Sequences mal configuradas.

---

### O) Reports QWeb (TED Barcode, Formato)

**11.1 TED Barcode (Compliance SII)**

**Validar TED barcode en PDFs:**

```bash
# Buscar generación TED barcode
docker compose exec odoo grep -rn "ted\|barcode\|PDF417" /mnt/extra-addons/localization/l10n_cl_dte/reports/ /mnt/extra-addons/localization/l10n_cl_dte/libs/ 2>/dev/null -i

# Validar librería barcode
docker compose exec odoo grep -rn "import.*barcode\|from.*barcode" /mnt/extra-addons/localization/l10n_cl_dte/ 2>/dev/null
```

**Validar:**
- [ ] TED barcode presente en PDFs DTE
- [ ] Formato PDF417 correcto
- [ ] Posición barcode correcta (esquina superior derecha)

**Reportar:** TED barcode ausente + riesgo compliance SII.

---

**11.2 Formato Reports**

**Validar estructura QWeb:**

```bash
# Revisar reports
docker compose exec odoo find /mnt/extra-addons/localization/l10n_cl_dte/reports/ -name "*.xml" -exec head -50 {} \;
```

**Validar:**
- [ ] Sin t-esc (usar t-out)
- [ ] Estructura QWeb correcta
- [ ] Formato PDF correcto (márgenes, fuentes)

**Reportar:** Issues formato reports.

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
| Missing ACLs | {N} | 0 | 🔴/🟡/🟢 |
| **Performance** | | | |
| N+1 queries detectadas | {N} | 0 | 🔴/🟡/🟢 |
| Queries sin index | {N} | <5 | 🔴/🟡/🟢 |
| Cache hit ratio | {%} | >85% | 🔴/🟡/🟢 |
| **Testing** | | | |
| Coverage líneas | {%} | >80% | 🔴/🟡/🟢 |
| Coverage branches | {%} | >70% | 🔴/🟡/🟢 |
| Tests fallando | {N} | 0 | 🔴/🟡/🟢 |
| Edge cases cubiertos | {%} | >90% | 🔴/🟡/🟢 |
| **Infraestructura** | | | |
| ACLs faltantes | {N} | 0 | 🔴/🟡/🟢 |
| Dashboards deprecados | {N} | 0 | 🔴/🟡/🟢 |
| TED barcode ausente | {N} | 0 | 🔴/🟡/🟢 |
| Crons solapados | {N} | 0 | 🔴/🟡/🟢 |

**Leyenda:**
- 🔴 Crítico (requiere acción inmediata)
- 🟡 Atención (plan mejora corto plazo)
- 🟢 Aceptable (monitorear)

---

## 📋 DELIVERABLES

### 1. Reporte Ejecutivo (1-2 páginas)

```markdown
# Auditoría l10n_cl_dte - Resumen Ejecutivo

**Fecha:** 2025-11-12
**Auditor:** {AGENTE}
**Versión módulo:** 19.0.6.0.0

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

### 2. Matriz de Hallazgos (CSV)

**Formato:**

```csv
ID,Archivo/Línea,Descripción,Criticidad,Compliance Odoo 19,Dimensión,Estado,Esfuerzo Horas
H-P0-01,models/account_move_dte.py:125,N+1 query en _get_dte_lines(),P0,NO,Performance,Pendiente,4
H-P0-02,views/invoice_form.xml:45,Uso de t-esc en lugar de t-out,P0,SÍ,Compliance,Pendiente,2
H-P1-01,security/ir.model.access.csv:15,ACL faltante para account.move.l10n_cl_dte,P1,NO,Infraestructura,Pendiente,1
```

**Guardar en:** `docs/prompts/06_outputs/2025-11/auditorias/MATRIZ_HALLAZGOS_DTE_20251112.csv`

---

### 3. Métricas JSON (machine-readable)

```json
{
  "audit_metadata": {
    "prompt_id": "AUDIT-DTE-360-001",
    "module": "l10n_cl_dte",
    "date": "2025-11-12",
    "version": "19.0.6.0.0",
    "auditor": "{AGENTE}"
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
    "missing_validations": 3,
    "missing_acls": 16
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
  "infrastructure": {
    "missing_acls": 16,
    "deprecated_dashboards": 2,
    "ted_barcode_missing": 0,
    "crons_overlapping": 1
  },
  "score": 78.5
}
```

**Guardar en:** `docs/prompts/06_outputs/2025-11/auditorias/METRICAS_DTE_20251112.json`

---

### 4. Reporte Técnico Detallado (15-30 páginas)

**Secciones:**
1. Compliance Odoo 19 (con tabla hallazgos)
2. Arquitectura (diagramas + patrones)
3. Integraciones (SII, SOAP, APIs)
4. Seguridad (vulnerabilidades + mitigaciones)
5. Performance (benchmarks + optimizaciones)
6. Testing (coverage + gaps)
7. Infraestructura (ACLs, manifest, views, data, reports)
8. Apéndices (comandos validación, referencias)

**Guardar en:** `docs/prompts/06_outputs/2025-11/auditorias/AUDIT_DTE_360_PROFUNDA_20251112.md`

---

## ✅ CHECKLIST PRE-ENTREGA

- [ ] Auditoría compliance completa (8 patrones)
- [ ] Tabla hallazgos con severidades P0/P1/P2
- [ ] Métricas cuantitativas calculadas
- [ ] Hallazgos con línea exacta + contexto
- [ ] Esfuerzo estimado cierre (horas)
- [ ] Plan acción priorizado por sprints
- [ ] Reporte ejecutivo (1-2 páginas)
- [ ] Reporte técnico detallado (15-30 páginas)
- [ ] Matriz CSV generada
- [ ] Métricas JSON generadas
- [ ] Comandos validación documentados
- [ ] Referencias cruzadas a docs proyecto

---

## 📚 REFERENCIAS

**Documentación Proyecto:**
- `docs/prompts/02_compliance/CHECKLIST_ODOO19_VALIDACIONES.md`
- `docs/prompts/03_maximas/MAXIMAS_AUDITORIA.md`
- `docs/prompts/04_templates/TEMPLATE_P4_DEEP_ANALYSIS.md`
- `docs/prompts/04_templates/TEMPLATE_P4_INFRASTRUCTURE_AUDIT.md`
- `.github/agents/knowledge/odoo19_patterns.md`
- `.github/agents/knowledge/docker_odoo_command_reference.md`

**Estándares Externos:**
- Odoo 19 CE Documentation: https://www.odoo.com/documentation/19.0/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- SII Resolución 80/2014: https://www.sii.cl/factura_electronica/formato_dte.pdf

---

**Template Version:** 1.0.0  
**Creado:** 2025-11-12  
**Mantenedor:** Sistema de Prompts Profesional

