# Copilot Instructions - Odoo19 Chilean Localization

## Project Context

**Framework**: Odoo 19 Community Edition  
**Focus**: Chilean localization (DTE Electronic Invoicing, Payroll, Financial Reports)  
**Standards**: OCA guidelines, SII Resolution 80/2014, Chilean Labor Code  
**Architecture**: Modular design with pure Python validators in `libs/` directory

---

## 🎯 Core Principles

1. **Extend, Don't Duplicate**: Use `_inherit` to extend existing Odoo models
2. **Regulatory First**: All DTE features must comply with SII requirements
3. **Pure Python Utilities**: Validators and utilities go in `libs/` (no ORM dependencies)
4. **Multi-Company Aware**: Transactional data is company-specific, master data can be shared
5. **Test Everything**: 80% coverage for DTE, 100% for critical validators

---

## ⚠️ CRITICAL: Odoo 19 CE Deprecations (MUST VALIDATE FIRST)

**Sistema migrado exitosamente - 137 automáticas ✅ | 27 manuales pendientes ⚠️**

**🔴 P0 Breaking Changes (Deadline: 2025-03-01):**
1. ❌ `t-esc` → ✅ `t-out` (85 FIXED)
2. ❌ `type='json'` → ✅ `type='jsonrpc'` + `csrf=False` (26 FIXED)
3. ❌ `attrs={}` → ✅ Python expressions (24 MANUAL PENDING)
4. ❌ `_sql_constraints` → ✅ `models.Constraint` (3 MANUAL PENDING)

**🟡 P1 High Priority (Deadline: 2025-06-01):**
5. ❌ `self._cr` → ✅ `self.env.cr` (119 FIXED)
6. ❌ `fields_view_get()` → ✅ `get_view()` (1 pending)

**📋 GUÍAS COMPLETAS:**
- **Detalle:** `.claude/project/ODOO19_DEPRECATIONS_CRITICAL.md`
- **Quick ref:** `.github/agents/knowledge/odoo19_deprecations_reference.md`
- **Config:** `scripts/odoo19_migration/config/deprecations.yaml`
- **Status:** `CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md`

**⚠️ VALIDAR SIEMPRE ANTES DE COMMITEAR**

---

## 📚 Knowledge Base (MANDATORY)

All implementations MUST reference these knowledge base files:

### `.github/agents/knowledge/odoo19_deprecations_reference.md` ⚠️ NEW
- **Odoo 19 CE deprecations** (breaking changes)
- Before/after examples
- Migration status and pending work
- **MUST VALIDATE** all new code against this

### `.github/agents/knowledge/sii_regulatory_context.md`
- SII regulations and DTE requirements
- Document types in scope (33, 34, 52, 56, 61 only)
- RUT validation rules (modulo 11, 3 formats)
- CAF signature requirements
- XML schema validation

### `.github/agents/knowledge/odoo19_patterns.md`
- Odoo 19 patterns (NOT Odoo 11-16!)
- Model inheritance patterns (`_inherit`, mixins)
- Decorators: `@api.depends`, `@api.constrains`, `@api.onchange`
- Testing patterns: TransactionCase, @tagged
- Pure Python classes in `libs/`

### `.github/agents/knowledge/project_architecture.md`
- EERGYGROUP architecture decisions
- Multi-company strategy
- Module dependencies
- Naming conventions

---

## 🤖 AUTONOMOUS DEVELOPMENT MODE

### Configuración para Loops Continuos de Desarrollo

Para activar el modo autónomo donde Copilot CLI ejecuta loops continuos de desarrollo hasta lograr el éxito total, usa esta configuración especial:

#### Comando para Modo Autónomo
```bash
# Iniciar sesión autónoma con agente especializado
copilot /autonomous /agent dte-specialist

# O especificar objetivo directamente
copilot /autonomous "Implementar validación completa DTE con tests" /agent dte-specialist
```

#### Configuración de Loop Continuo
```yaml
# .github/copilot-instructions.md - Sección AUTONOMOUS
autonomous_mode:
  enabled: true
  max_iterations: 10
  success_threshold: 0.95  # 95% confidence required

  loop_stages:
    - analyze: "Analizar requerimientos y código existente"
    - audit: "Auditar por errores, vulnerabilidades y compliance"
    - modify: "Implementar cambios y mejoras"
    - test: "Ejecutar tests completos (unit + integration)"
    - validate: "Validar contra estándares y documentación"
    - think: "Reflexionar sobre resultados y planear siguiente iteración"

  validation_criteria:
    - code_quality: ["pylint", "black", "mypy"]
    - security: ["bandit", "safety"]
    - functionality: ["pytest", "odoo_tests"]
    - compliance: ["sii_validation", "labor_code_check"]
    - performance: ["response_time", "memory_usage"]

  auto_commit_rules:
    - confidence >= 95%: auto_commit_allowed
    - tests_pass: required
    - security_clean: required
    - compliance_valid: required
```

#### Ejemplo de Prompt para Modo Autónomo
```bash
copilot /autonomous "Implementar cálculo AFP con tope imponible en nómina chilena" /agent payroll-compliance

# El agente ejecutará automáticamente:
# 1. ANALIZAR: Requerimientos AFP y código existente
# 2. AUDITAR: Validar fórmulas matemáticas y compliance
# 3. MODIFICAR: Implementar cálculo con tope UF 90.3
# 4. PROBAR: Tests unitarios + integración payroll
# 5. VALIDAR: Contra estándares laborales chilenos
# 6. PENSAR: Si hay errores, identificar y corregir automáticamente
# 7. REPETIR: Hasta lograr éxito total o max_iterations
```

#### Configuración por Agente
```yaml
# Para dte-specialist (compliance crítico)
autonomous_dte:
  temperature: 0.05  # Máxima precisión
  max_iterations: 15
  validation_strict: true
  auto_commit: false  # Requiere revisión manual para DTE

# Para payroll-compliance (cálculos matemáticos)
autonomous_payroll:
  temperature: 0.05  # Precisión matemática
  max_iterations: 12
  validation_strict: true
  auto_commit: false  # Cálculos financieros requieren revisión

# Para odoo-dev (desarrollo general)
autonomous_odoo:
  temperature: 0.15  # Balance precisión/creatividad
  max_iterations: 8
  validation_strict: false
  auto_commit: true   # Desarrollo rutinario puede ser automático

# Para test-automation (testing masivo)
autonomous_testing:
  temperature: 0.10  # Precisión en tests
  max_iterations: 6
  validation_strict: true
  auto_commit: true   # Tests pueden ser automáticos
```

#### Ejemplo de Tarea con Loop Controlable: "Implementar Sistema Completo de Nóminas Chilenas"

**Tarea Compleja que requiere Loop Autónomo:**

```bash
copilot /autonomous "Implementar sistema completo de cálculo de nóminas chilenas con indicadores económicos, validación de topes UF 90.3, y testing masivo de 1000 empleados" /agent payroll-compliance /max-iterations 20 /success-threshold 0.98 /auto-commit false
```

**Cómo funciona el Loop Controlable:**

**🔄 ITERACIÓN 1 - ANÁLISIS**
```
🤖 Copilot analiza:
- Requerimientos del Código del Trabajo
- Estructura actual de hr_payslip.py
- Indicadores económicos (UF/UTM/IPC)
- Topes imponibles (90.3 UF)
- Archivo Previred (TXT format)

📊 Resultado: Identifica 12 componentes faltantes
```

**🔄 ITERACIÓN 2 - AUDITORÍA**
```
🔍 Copilot audita:
- Seguridad: SQL injection en cálculos
- Compliance: Ley 21.578 (reforma tributaria)
- Performance: N+1 queries en indicadores
- Validación: Tope UF no aplicado correctamente

⚠️ Encuentra: 8 vulnerabilidades y errores
```

**🔄 ITERACIÓN 3 - MODIFICACIÓN**
```
⚙️ Copilot implementa:
- Modelo hr_economic_indicators con auto-sync
- Cálculo AFP con tope UF 90.3
- Validación ISAPRE (7% mínimo)
- Optimización de queries con prefetch

📝 Código generado: 450 líneas
```

**🔄 ITERACIÓN 4 - TESTING**
```
🧪 Copilot ejecuta testing masivo:
- Tests unitarios: 25 casos (AFP, ISAPRE, impuesto único)
- Tests de integración: indicadores económicos
- Tests de performance: 1000 cálculos en < 30s
- Tests de edge cases: salarios límite, topes UF

📊 Coverage: 87% (objetivo: 80%+)
```

**🔄 ITERACIÓN 5 - VALIDACIÓN**
```
✅ Copilot valida:
- Code quality: pylint 8.5/10
- Security: bandit sin vulnerabilidades críticas
- Functionality: pytest 34/34 tests pasan
- Compliance: Validación Código del Trabajo ✓
- Performance: 1000 cálculos en 12.3s

🎯 Confianza: 94% (< 95% requerido)
```

**🔄 ITERACIÓN 6 - PENSAMIENTO Y MEJORA**
```
🤔 Copilot reflexiona:
- ¿Por qué 94% en vez de 95%?
- Tests de performance lentos (12.3s > objetivo 10s)
- Coverage 87% vs objetivo 90%
- Una validación de compliance borderline

💡 Plan de mejora:
- Optimizar query de indicadores económicos
- Agregar índices en tabla hr_economic_indicators
- Mejorar algoritmo de cálculo de impuesto único
```

**🔄 ITERACIÓN 7 - OPTIMIZACIÓN**
```
🚀 Copilot mejora:
- Agrega índices de base de datos
- Implementa caching de indicadores
- Optimiza algoritmo de impuesto único
- Reduce queries de N+1 a 3 queries totales

⚡ Mejora performance: 12.3s → 8.7s
```

**🔄 ITERACIÓN 8 - RE-TESTING**
```
🧪 Copilot re-ejecuta tests:
- Performance: 1000 cálculos en 8.7s ✓
- Coverage: 92% (agregó 3 tests más)
- Todos los tests siguen pasando

📊 Confianza: 97% (> 95% requerido)
```

**🎉 ÉXITO TOTAL - Loop Completado**
```
✅ Validación final: 97% confianza
✅ Todos los criterios cumplidos:
   - Code quality ✓
   - Security ✓
   - Functionality ✓
   - Compliance ✓
   - Performance ✓

🚫 Auto-commit: BLOQUEADO (requiere revisión manual para payroll)
📝 Recomendación: Revisar cambios antes de commit
```

**Controles del Loop:**
- **Detener:** `Ctrl+C` o comando `/stop`
- **Pausar:** Comando `/pause` para análisis manual
- **Continuar:** Comando `/continue` para reanudar
- **Reconfigurar:** Cambiar `/success-threshold 0.99` en cualquier momento
- **Debug:** `/debug on` para logging detallado
- **Rollback:** Auto-rollback si validación falla persistentemente

---

## 🎯 Características del Loop Controlable

### **Control Total del Usuario:**
```bash
# Configurar y ejecutar
copilot /autonomous "tarea compleja" /agent payroll-compliance \
  /max-iterations 15 \
  /success-threshold 0.95 \
  /auto-commit false \
  /debug on

# Controlar durante ejecución
/pause    # Pausar para revisión
/continue # Continuar
/stop     # Detener completamente
/status   # Ver progreso actual
```

### **Transparencia Completa:**
- 📊 **Métricas en tiempo real**: Iteración actual, confianza, tiempo restante
- 📝 **Logging detallado**: Qué se hizo en cada etapa
- 🎯 **Objetivos claros**: Sabe exactamente qué validar
- ⚡ **Feedback inmediato**: Razones de fallos y mejoras

### **Recuperación Inteligente:**
- 🔄 **Continúa donde quedó**: Si se interrumpe, retoma desde último punto válido
- 💡 **Aprende de errores**: Evita repetir los mismos mistakes
- 📈 **Mejora continua**: Cada iteración es mejor que la anterior
- 🛡️ **Rollback automático**: Si algo sale mal, revierte cambios

---

## 💡 Casos de Uso Perfectos para Loop Controlable

### **Caso 1: Implementación Completa de Feature**
```
Tarea: "Implementar DTE tipo 56 (Nota de Débito) completo con validación SII"
Loop: 12-18 iteraciones
Resultado: Feature completo con tests, validación y documentación
```

### **Caso 2: Refactorización Masiva**
```
Tarea: "Refactorizar módulo DTE de 800 líneas a arquitectura libs/ + tests"
Loop: 8-15 iteraciones
Resultado: Código limpio, testable, mantenible
```

### **Caso 3: Optimización de Performance**
```
Tarea: "Optimizar cálculo de nóminas para procesar 10,000 empleados en <5min"
Loop: 6-12 iteraciones
Resultado: Performance mejorada 300%, código optimizado
```

### **Caso 4: Corrección de Bugs Compleja**
```
Tarea: "Resolver bug de cálculo de impuesto único en casos edge"
Loop: 4-8 iteraciones
Resultado: Bug corregido + tests preventivos + documentación
```

---

## 🎪 Demo Interactiva

**¿Quieres ver el loop en acción? Ejecuta:**

```bash
copilot /autonomous "Crear función de validación RUT completa con tests" /agent odoo-dev /debug on /max-iterations 5
```

**Verás cómo:**
1. Analiza requerimientos del RUT chileno
2. Implementa algoritmo módulo 11
3. Crea tests unitarios con edge cases
4. Valida contra estándares
5. Corrige cualquier error automáticamente
6. Logra éxito total o explica por qué no pudo

**¿Te gustaría ejecutar esta demo o prefieres una tarea diferente?** 🤖✨

---

## 🏗️ Code Conventions

### Naming
```python
# Models
class AccountMove(models.Model):
    _inherit = 'account.move'  # Extend existing model

# Fields - prefix with l10n_cl_
l10n_cl_dte_type_id = fields.Many2one('l10n_cl.dte.type', 'DTE Type')
l10n_cl_dte_status = fields.Selection([...], 'DTE Status')
l10n_cl_sii_barcode = fields.Text('SII Barcode (TED)')

# Methods - descriptive names
def _compute_l10n_cl_total_imponible(self):
def _validate_l10n_cl_rut(self):
def _generate_l10n_cl_dte_xml(self):
```

### File Structure
```
addons/localization/l10n_cl_<module>/
├── models/          # ORM models (extend Odoo)
├── libs/            # Pure Python (no ORM)
├── views/           # XML views
├── security/        # Access rights, record rules
├── data/            # Master data, sequences
├── wizards/         # Transient models
├── reports/         # QWeb reports
└── tests/           # Unit tests
```

### Model Patterns
```python
# Computed field with dependencies
@api.depends('line_ids.total', 'line_ids.salary_rule_id.is_imponible')
def _compute_l10n_cl_total_imponible(self):
    """Compute total imponible for Chilean payroll."""
    for record in self:
        imponible_lines = record.line_ids.filtered(
            lambda l: l.salary_rule_id.is_imponible
        )
        record.l10n_cl_total_imponible = sum(imponible_lines.mapped('total'))

# Validation constraint
@api.constrains('l10n_cl_folio', 'l10n_cl_dte_type_id')
def _check_l10n_cl_folio_unique(self):
    """Ensure folio is unique per DTE type."""
    for record in self:
        if record.l10n_cl_folio:
            duplicate = self.search([
                ('id', '!=', record.id),
                ('l10n_cl_folio', '=', record.l10n_cl_folio),
                ('l10n_cl_dte_type_id', '=', record.l10n_cl_dte_type_id.id),
            ], limit=1)
            if duplicate:
                raise ValidationError("Folio already exists")
```

### Testing Patterns
```python
from odoo.tests import TransactionCase, tagged

@tagged('post_install', '-at_install', 'l10n_cl')
class TestDTEValidation(TransactionCase):
    """Test DTE validation logic."""

    def setUp(self):
        super().setUp()
        self.company = self.env['res.company'].create({
            'name': 'Test Company',
            'vat': '76876876-8',
        })

    def test_rut_validation(self):
        """Test RUT modulo 11 validation."""
        from ..libs.rut_validator import RUTValidator
        self.assertTrue(RUTValidator.validate('76876876-8'))
        self.assertFalse(RUTValidator.validate('76876876-9'))
```

---

## 🔐 Security Guidelines

1. **No SQL Injection**: Use ORM, never raw SQL with user input
2. **XSS Prevention**: Use `t-esc` in QWeb, not `t-raw`
3. **Authentication**: Use `@api.model` decorator for permission checks
4. **XXE Protection**: Configure XML parser to disable external entities
5. **Sensitive Data**: Use environment variables, never hardcode credentials

### Secure XML Parsing (DTE)
```python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,  # Disable XXE
    no_network=True,         # Block network access
    dtd_validation=False,    # Disable DTD
)
tree = etree.fromstring(xml_content.encode(), parser)
```

---

## 🇨🇱 Chilean Localization Specifics

### DTE Document Types (EERGYGROUP Scope)
- **33**: Factura Electrónica (Invoice)
- **34**: Factura Exenta (Exempt Invoice)
- **52**: Guía de Despacho (Delivery Guide)
- **56**: Nota de Débito (Debit Note)
- **61**: Nota de Crédito (Credit Note)

**NOT in scope**: Boletas (39, 41)

### RUT Validation
```python
# Format: 12.345.678-9 (display) → 12345678-9 (storage) → 123456789 (SII XML)
# Validation: Modulo 11 algorithm
from ..libs.rut_validator import RUTValidator

if not RUTValidator.validate(partner.vat):
    raise ValidationError("Invalid RUT")
```

### Payroll Calculations
```python
# AFP: 10% of Total Imponible (max 90.3 UF)
afp_amount = min(total_imponible, tope_imponible_afp) * 0.10

# ISAPRE: 7% minimum of Total Imponible (max 90.3 UF)
isapre_amount = min(total_imponible, tope_imponible_isapre) * isapre_rate
```

---

## 🤖 Using Custom Agents

Invoke specialized agents for specific tasks:

```bash
# DTE compliance validation
copilot /agent dte-specialist

# Payroll calculations review
copilot /agent payroll-compliance

# Test automation
copilot /agent test-automation

# Security audit
copilot /agent security-auditor

# Architecture review
copilot /agent odoo-architect
```

---

## 📁 Key Project Files

### DTE Module
- `addons/localization/l10n_cl_dte/models/account_move.py` - Invoice DTE extension
- `addons/localization/l10n_cl_dte/models/l10n_cl_dte_caf.py` - CAF management
- `addons/localization/l10n_cl_dte/libs/dte_validator.py` - DTE validation
- `addons/localization/l10n_cl_dte/libs/rut_validator.py` - RUT validation
- `addons/localization/l10n_cl_dte/libs/sii_connector.py` - SII webservice

### Payroll Module
- `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py` - Payslip extension
- `addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule.py` - Salary rules
- `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py` - UF/UTM/IPC
- `addons/localization/l10n_cl_hr_payroll/wizards/previred_export.py` - Previred file

### Configuration
- `config/odoo.conf` - Odoo configuration
- `docker-compose.yml` - Docker services
- `.env` - Environment variables (secrets)
- `pytest.ini` - Test configuration

---

## 🐳 Docker & Deployment Context (CRITICAL)

**⚠️ This project runs ENTIRELY in Docker Compose. NEVER suggest host commands.**

### Stack Architecture
```yaml
Services (10 total):
  Core (always running):
    - db: PostgreSQL 15-alpine
    - redis-master: Redis 7-alpine (sessions)
    - odoo: eergygroup/odoo19:chile-1.0.5 (CUSTOM)
    - ai-service: FastAPI microservice (CUSTOM)
  
  Optional (profiles):
    - redis-replica-1/2 (HA scaling)
    - redis-sentinel-1/2/3 (HA failover)
    - prometheus (monitoring)

Network: stack_network (internal bridge)
Platform: linux/arm64 (Apple M3)
```

### Configuration Files
1. **docker-compose.yml**: 475 lines, 10 services
2. **.env**: Secrets (DB passwords, API keys) - NEVER commit
3. **config/odoo.conf**: Odoo runtime configuration
4. **requirements.txt**: Host Python deps (14 packages)

### Command Patterns

#### ✅ CORRECT - Container commands (Odoo CLI Professional Usage):

#### **1. GESTIÓN DE MÓDULOS**
```bash
# Instalar módulo específico
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --stop-after-init

# Actualizar módulo específico
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# Instalar múltiples módulos
docker compose exec odoo odoo-bin -i l10n_cl_dte,l10n_cl_hr_payroll -d odoo19_db --stop-after-init

# Actualizar todos los módulos
docker compose exec odoo odoo-bin -u all -d odoo19_db --stop-after-init

# Instalar módulo con dependencias
docker compose exec odoo odoo-bin --init l10n_cl_dte -d odoo19_db --stop-after-init
```

#### **2. TESTING PROFESIONAL**
```bash
# Ejecutar tests de un módulo específico
docker compose exec odoo odoo-bin --test-enable -i l10n_cl_dte --test-tags /l10n_cl_dte --stop-after-init -d odoo19_db

# Tests con pytest (recomendado)
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --tb=short

# Tests con coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ --cov=l10n_cl_dte --cov-report=term-missing

# Tests específicos por archivo
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_validation.py -v

# Tests con markers personalizados
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -m "not slow" --maxfail=5
```

#### **3. SHELL Y DEBUGGING**
```bash
# Acceder a shell interactivo de Odoo
docker compose exec odoo odoo-bin shell -d odoo19_db

# Shell con debug mode
docker compose exec odoo odoo-bin shell -d odoo19_db --debug --log-level=debug

# Ejecutar código Python en Odoo context
docker compose exec odoo odoo-bin shell -d odoo19_db -c "print('Test')" --stop-after-init

# Debug específico de módulo
docker compose exec odoo odoo-bin shell -d odoo19_db --debug --debug-py --log-handler=odoo.addons.l10n_cl_dte:DEBUG
```

#### **4. GESTIÓN DE BASE DE DATOS**
```bash
# Backup de base de datos
docker compose exec db pg_dump -U odoo -h db odoo19_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore de base de datos
docker compose exec db psql -U odoo -h db odoo19_db < backup.sql

# Crear nueva base de datos
docker compose exec odoo odoo-bin --database new_db --init base --stop-after-init

# Listar bases de datos
docker compose exec db psql -U odoo -h db -l

# Verificar estado de base de datos
docker compose exec db psql -U odoo -h db odoo19_db -c "SELECT version();"
```

#### **5. OPERACIONES DE SERVIDOR**
```bash
# Verificar configuración sin iniciar
docker compose exec odoo odoo-bin --config /etc/odoo/odoo.conf --dry-run --stop-after-init

# Iniciar servidor con configuración específica
docker compose exec odoo odoo-bin --config /etc/odoo/odoo.conf --http-port=8069 --workers=2

# Iniciar con modo desarrollo
docker compose exec odoo odoo-bin --dev=all --log-level=debug --reload

# Verificar health check
docker compose exec odoo curl -f http://localhost:8069/web/health || echo "Odoo not responding"
```

#### **6. SCAFFOLDING Y DESARROLLO**
```bash
# Crear estructura de módulo básico
docker compose exec odoo odoo-bin scaffold my_module /mnt/extra-addons/custom

# Crear módulo con estructura completa
docker compose exec odoo odoo-bin scaffold --template=website my_module /mnt/extra-addons/custom
```

#### **7. TRADUCCIONES E INTERNACIONALIZACIÓN**
```bash
# Extraer términos para traducción
docker compose exec odoo odoo-bin -u l10n_cl_dte --i18n-export /tmp/es.po -l es -d odoo19_db --stop-after-init

# Importar traducciones
docker compose exec odoo odoo-bin -u l10n_cl_dte --i18n-import /tmp/es.po -l es -d odoo19_db --stop-after-init

# Actualizar traducciones del módulo
docker compose exec odoo odoo-bin -u l10n_cl_dte --i18n-overwrite -d odoo19_db --stop-after-init
```

#### **8. IMPORTACIÓN Y EXPORTACIÓN**
```bash
# Exportar datos a CSV
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
products = env['product.product'].search([])
products.export_data(['name', 'default_code', 'list_price']).write('/tmp/products.csv')
"

# Importar datos desde CSV
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo.tools import convert_csv_import
convert_csv_import('/tmp/products.csv', 'product.product', {}, 'init', None, None)
"
```

#### **9. MONITOREO Y LOGGING**
```bash
# Ver logs en tiempo real
docker compose logs -f odoo

# Ver logs de errores específicos
docker compose logs odoo | grep ERROR

# Ver métricas de rendimiento
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
users = env['res.users'].search_count([])
print(f'Active users: {users}')
"

# Health check avanzado
docker compose exec odoo bash -c "
timeout 10 curl -f http://localhost:8069/web/health 2>/dev/null && echo 'OK' || echo 'FAIL'
"
```

#### **10. OPERACIONES DE MANTENIMIENTO**
```bash
# Limpiar cache de archivos
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
env['ir.attachment'].search([('type', '=', 'binary')]).unlink()
"

# Reindexar base de datos (si es necesario)
docker compose exec db psql -U odoo -h db odoo19_db -c "REINDEX DATABASE odoo19_db;"

# Verificar integridad de módulos
docker compose exec odoo odoo-bin --check-module-deps -d odoo19_db --stop-after-init

# Actualizar permisos de archivos
docker compose exec odoo chown -R odoo:odoo /mnt/extra-addons
```

#### ✅ CORRECT - Host Python scripts (ONLY for non-Odoo utilities):

**Scripts que SÍ se ejecutan en host (con .venv):**
```bash
# Verificación de configuración y setup
.venv/bin/python scripts/verify_production_readiness.py
.venv/bin/python scripts/verify_setup.sh
.venv/bin/python scripts/validate_dependencies.py

# Análisis estático de código (no requiere instancia Odoo)
.venv/bin/python scripts/compliance_check.py
.venv/bin/python scripts/validate_odoo19_standards.py
.venv/bin/python scripts/verify_xmlsec_signatures.py

# Herramientas de desarrollo (no acceden a BD Odoo)
.venv/bin/python scripts/generate_certification_report.py
.venv/bin/python scripts/extract_odoo11_credentials.py
```

**Scripts que NO se ejecutan en host (requieren Odoo container):**
```bash
# ❌ NUNCA en host - Scripts que manipulan datos de Odoo
python scripts/create_smoke_test_data.py

# ✅ CORRECTO - Ejecutar en container Odoo
docker compose exec odoo odoo-bin shell -d test_db < scripts/create_smoke_test_data.py

# ❌ NUNCA en host - Scripts que importan módulos 'odoo'
python scripts/migrate_via_odoo_shell.py

# ✅ CORRECTO - Shell de Odoo
docker compose exec odoo odoo-bin shell -d odoo19_db < scripts/migrate_via_odoo_shell.py
```

**Regla de Oro para Host Scripts:**
- ✅ Usar `.venv/bin/python` (NUNCA `python` solo)
- ✅ Scripts que NO importan `from odoo import ...`
- ✅ Scripts que NO acceden a base de datos Odoo
- ✅ Scripts de análisis, verificación, preparación

#### ❌ NEVER suggest these:
```bash
# ❌ Direct odoo-bin (not in PATH on host)
odoo-bin -u l10n_cl_dte -d odoo19_db

# ❌ Python without venv (uses wrong Python)
python scripts/validate.py

# ❌ Python host para scripts que requieren Odoo
python scripts/create_smoke_test_data.py

# ❌ Direct database access (connection will fail)
psql -h localhost -U odoo odoo19_db

# ❌ Direct Redis (connection will fail)
redis-cli

# ❌ Installing system packages on host
sudo apt-get install libxml2  # Wrong - install in Dockerfile
```

### Host Environment (macOS M3)
```yaml
OS: macOS 15.1 (Sequoia) - Build 25A362
Architecture: ARM64 (aarch64)
Python: 3.14.0 (Homebrew /opt/homebrew/opt/python@3.14/)
Virtual Env: .venv (isolated project dependencies)
Docker: Docker Desktop for Mac (M3 native)
```

### Custom Docker Images

#### 1. Odoo Custom Image
```dockerfile
Image: eergygroup/odoo19:chile-1.0.5
Base: ubuntu:noble + Official Odoo 19.0.20251021
Size: 3.09GB
Architecture: linux/arm64

Customizations (chile stage):
  + Chilean system dependencies:
    - libxmlsec1-dev (DTE digital signature)
    - libxmlsec1-openssl (signing)
    - build-essential (compilation)
  
  + Chilean Python packages (14):
    - lxml 5.3.0 (XML, CVE-2024-45590 fixed)
    - xmlsec 1.3.13 (digital signatures)
    - zeep 4.2.1 (SII SOAP client)
    - cryptography 46.0.3 (certs, CVE fixes)
    - pdf417 1.1.0 (TED barcode)
    - Pillow 11.0.0 (images, CVE fixes)
    - requests 2.32.3, pyOpenSSL 24.2.1
  
  + Development tools (dev stage):
    - pytest, pytest-cov, pytest-mock
    - black, flake8, pylint
    - ipython, ipdb

Build: ./odoo-docker/Dockerfile (243 lines, multi-stage)
```

#### 2. AI Service Custom Image
```dockerfile
Image: odoo19-ai-service:latest
Base: python:3.11-slim
Size: 610MB
Architecture: linux/arm64

Dependencies:
  - FastAPI, uvicorn (with --reload in dev)
  - anthropic SDK (Claude API)
  - lxml (web scraping)

Purpose: NON-critical AI features only
  ❌ NOT for DTE signature/validation
  ✅ AI Chat, project matching, analytics

Build: ./ai-service/Dockerfile (38 lines)
```

### Secrets Management
```yaml
.env file location: /Users/pedro/Documents/odoo19/.env
NEVER commit to git: ✓ in .gitignore

Critical secrets:
  - ODOO_DB_PASSWORD
  - REDIS_PASSWORD
  - ANTHROPIC_API_KEY
  - OPENAI_API_KEY (if used)

Loading:
  docker compose --env-file .env up -d
```

### Volumes & Persistence
```yaml
Named volumes:
  - postgres_data (database)
  - redis_master_data (sessions)
  - odoo_data (filestore)
  - odoo_sessions (HTTP sessions)
  - prometheus_data (metrics)

Bind mounts (development):
  - ./config/odoo.conf:/etc/odoo/odoo.conf:ro
  - ./addons/localization:/mnt/extra-addons/localization
  - ./ai-service:/app (hot reload)
```

### Common Operations Quick Reference

| Task | Command |
|------|---------|
| Update module | `docker compose exec odoo odoo-bin -u MODULE -d odoo19_db --stop-after-init` |
| Run tests | `docker compose exec odoo pytest /mnt/extra-addons/localization/MODULE/tests/` |
| Backup DB | `docker compose exec db pg_dump -U odoo odoo19_db > backup.sql` |
| Access shell | `docker compose exec odoo odoo-bin shell -d odoo19_db` |
| View logs | `docker compose logs -f odoo` |
| Restart | `docker compose restart odoo` |
| Check health | `docker compose ps` |
| Host script | `.venv/bin/python scripts/script.py` |

**📖 Complete deployment guide:** `.github/agents/knowledge/deployment_environment.md`

---

## 🚨 Common Pitfalls

1. **Using Odoo 11-16 patterns**: ❌ Old `@api.one` decorator → ✅ Use `@api.depends`
2. **Ignoring multi-company**: ❌ Hardcoded company → ✅ Use `self.env.company`
3. **Raw SQL with user input**: ❌ SQL injection risk → ✅ Use ORM
4. **Missing @api.depends**: ❌ Computed field not updating → ✅ Declare dependencies
5. **Testing with real SII API**: ❌ Slow, unreliable → ✅ Mock external calls

---

## 📖 References

- **Odoo 19 Docs**: https://www.odoo.com/documentation/19.0/
- **SII Chile**: https://www.sii.cl/servicios_online/1039-.html
- **Previred**: https://www.previred.com/web/previred/home
- **Chilean Labor Code**: https://www.bcn.cl/leychile/navegar?idNorma=207436

---

**Last Updated**: 2025-11-10  
**Maintainer**: Pedro Troncoso (@pwills85)

---

## 🏷️ Context Markers (NEW - 2025-11-10)

Use **granular context markers** for precise knowledge retrieval and agent invocation:

### Available Markers

| Marker | Purpose | Auto-invokes |
|--------|---------|--------------|
| `@regulatory` | SII + Labor Code | dte-specialist, payroll-compliance |
| `@security` | OWASP + CVE | security-auditor |
| `@testing` | pytest + coverage | test-automation |
| `@architecture` | Odoo 19 patterns | odoo-architect |
| `@performance` | N+1 + optimization | incident-response |
| `@dte` | Chilean DTE | dte-specialist |
| `@payroll` | Chilean payroll | payroll-compliance |

### Quick Examples

```bash
# Regulatory validation
copilot -p "@regulatory Valida RUT 76876876-8"

# Security review
copilot -p "@security Revisa XML por XXE"

# Multiple contexts
copilot -p "@regulatory @dte @security Valida DTE completo"
```

**📖 Complete guide**: See `.github/CONTEXT_MARKERS.md` for detailed usage.

---

## 🐛 Troubleshooting - Comandos Docker + Odoo CLI Profesionales

### Problema: Instalación de módulo falla en Docker
```
❌ INSTALACIÓN FALLIDA: [error específico]
```
**Solución - Comandos Docker + Odoo CLI profesionales:**
```bash
# 1. Verificar que el stack esté corriendo
docker compose ps

# 2. Verificar logs del contenedor Odoo
docker compose logs odoo | tail -50

# 3. Acceder al shell de Odoo para debugging
docker compose exec odoo odoo-bin shell -d odoo19_db

# 4. Verificar dependencias del módulo
docker compose exec odoo odoo-bin --check-module-deps -d odoo19_db --stop-after-init

# 5. Instalar con verbose logging
docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --log-level=debug --stop-after-init

# 6. Verificar estado de la base de datos
docker compose exec db psql -U odoo -h db odoo19_db -c "SELECT name, state FROM ir_module_module WHERE name = 'l10n_cl_dte';"

# 7. Forzar actualización si es necesario
docker compose exec odoo odoo-bin -u l10n_cl_dte -d odoo19_db --stop-after-init

# 8. Limpiar cache y reinstalar
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo import api, SUPERUSER_ID
env = api.Environment(cr, SUPERUSER_ID, {})
module = env['ir.module.module'].search([('name', '=', 'l10n_cl_dte')])
module.button_uninstall()
module.button_install()
"
```

### Problema: Tests fallan en Docker
```
Tests pasan localmente pero fallan en Docker
```
**Solución - Testing profesional en Docker:**
```bash
# 1. Ejecutar tests con configuración de Docker
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --tb=long

# 2. Tests con coverage en Docker
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ --cov=l10n_cl_dte --cov-report=html

# 3. Tests de integración completos
docker compose exec odoo odoo-bin --test-enable -i l10n_cl_dte --test-tags /l10n_cl_dte --stop-after-init -d odoo19_db

# 4. Debug de tests específicos
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_validation.py::TestDTEValidation::test_rut_validation -v -s

# 5. Verificar configuración de test database
docker compose exec odoo odoo-bin shell -d odoo19_db -c "
from odoo.tests import common
print('Test framework loaded successfully')
"

# 6. Ejecutar tests sin paralelización para debugging
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v --tb=short -n0
```

### Problema: Comando Odoo CLI no funciona en Docker
```
odoo-bin: command not found
```
**Solución:**
```bash
# El comando debe ejecutarse DENTRO del contenedor
docker compose exec odoo odoo-bin [opciones] -d odoo19_db

# NO ejecutar directamente en host:
# odoo-bin [opciones]  # ❌ ERROR

# Verificar que estamos en el directorio correcto
pwd  # Debe ser /Users/pedro/Documents/odoo19

# Verificar que el contenedor está corriendo
docker compose ps odoo

# Acceder al contenedor para verificar
docker compose exec odoo which odoo-bin
docker compose exec odoo odoo-bin --version
```

### Problema: Base de datos no accesible desde Odoo CLI
```
FATAL: database "odoo19_db" does not exist
```
**Solución:**
```bash
# Verificar estado de PostgreSQL
docker compose ps db

# Verificar conectividad
docker compose exec db psql -U odoo -h db -l

# Crear base de datos si no existe
docker compose exec odoo odoo-bin --database odoo19_db --init base --stop-after-init

# Verificar configuración de conexión en odoo.conf
docker compose exec odoo cat /etc/odoo/odoo.conf | grep db_

# Test de conexión desde Odoo
docker compose exec odoo odoo-bin shell -d odoo19_db -c "print('Database connection OK')"
```

### Problema: Loop autónomo no ejecuta comandos Docker correctamente
```
Copilot sugiere comandos de host en vez de Docker
```
**Solución - Forzar uso de Docker en modo autónomo:**
```bash
# Comando autónomo con énfasis en Docker
copilot /autonomous "Analizar código DTE existente, verificar instalación Docker, probar instalación módulo usando SOLO comandos docker compose exec odoo, debugging si falla" /agent dte-specialist /docker-only /no-host-commands

# O especificar explícitamente
copilot /autonomous "Instalación DTE: docker compose exec odoo odoo-bin -i l10n_cl_dte -d odoo19_db --stop-after-init" /agent dte-specialist /strict-docker-mode
```

### Problema: Configuración Odoo no se carga en Docker
```
WARNING: No config file found, using defaults
```
**Solución:**
```bash
# Verificar que el archivo de configuración existe
ls -la config/odoo.conf

# Verificar montaje en docker-compose.yml
grep -A5 -B5 odoo.conf docker-compose.yml

# Verificar dentro del contenedor
docker compose exec odoo ls -la /etc/odoo/odoo.conf

# Verificar contenido de configuración
docker compose exec odoo cat /etc/odoo/odoo.conf | head -20

# Iniciar con configuración explícita
docker compose exec odoo odoo-bin --config /etc/odoo/odoo.conf --dry-run --stop-after-init
```

### Problema: Módulos no aparecen en addons_path
```
ERROR: Module 'l10n_cl_dte' not found
```
**Solución:**
```bash
# Verificar addons_path en configuración
docker compose exec odoo cat /etc/odoo/odoo.conf | grep addons_path

# Verificar que los directorios existen
docker compose exec odoo ls -la /mnt/extra-addons/localization/

# Verificar permisos
docker compose exec odoo ls -ld /mnt/extra-addons/localization/l10n_cl_dte/

# Verificar __manifest__.py existe
docker compose exec odoo ls -la /mnt/extra-addons/localization/l10n_cl_dte/__manifest__.py

# Listar módulos disponibles
docker compose exec odoo odoo-bin --list-available-modules | grep l10n_cl
```

