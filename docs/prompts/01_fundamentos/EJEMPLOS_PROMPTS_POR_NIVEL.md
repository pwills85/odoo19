# 📝 Ejemplos de Prompts por Nivel - Templates Validados

**Basado en**: Experimento de locuacidad (2025-11-11)  
**Validación**: 6 prompts ejecutados, escalamiento 13x confirmado

---

## 🎯 P1 - Nivel Simple (Consultas Factuales)

### Características
- **Target**: 70-150 palabras
- **Especificidad**: 0.50-0.60
- **Estructura**: Lista concisa, 0 análisis
- **File refs**: 0
- **Code blocks**: 0

### Template Genérico

```text
[Verbo acción] + [Objeto concreto]
```

### Ejemplos Validados

#### Ejemplo 1: Lista de Servicios
```text
Lista los servicios Docker activos en docker-compose.yml
```

**Output esperado** (76 palabras):
```
Servicios Docker activos:
- db: PostgreSQL 15-alpine
- redis-master: Redis 7-alpine
- odoo: eergygroup/odoo19:chile-1.0.5
- ai-service: FastAPI microservice

Perfiles opcionales:
- redis-replica-1/2 (HA scaling)
- redis-sentinel-1/2/3 (HA failover)
- prometheus (monitoring)

Total: 10 servicios (4 core + 6 opcional)
```

#### Ejemplo 2: Validación RUT
```text
Valida el RUT 76.876.876-8
```

**Output esperado**:
```
✅ RUT válido

Formato: 76.876.876-8
Sin puntos: 76876876-8
Sólo dígitos: 768768768
Dígito verificador: 8

Validación modulo 11: CORRECTO
```

#### Ejemplo 3: Archivos en Directorio
```text
Muestra archivos .py en addons/localization/l10n_cl_dte/models/
```

**Output esperado**:
```
Archivos Python en models/:
- account_move.py
- l10n_cl_dte_type.py
- l10n_cl_dte_caf.py
- res_partner.py
- res_company.py

Total: 5 archivos
```

### Cuándo Usar P1

✅ Consultas rápidas sin análisis  
✅ Listados simples  
✅ Validaciones de formato  
✅ Conteo de elementos  

❌ NO usar para análisis de código  
❌ NO usar para comparaciones  
❌ NO usar para evaluaciones arquitectónicas

---

## 📊 P2 - Nivel Medio (Análisis Técnico Básico)

### Características
- **Target**: 300-400 palabras
- **Especificidad**: 0.55-0.65
- **Estructura**: Headers + tabla + 1 code block
- **File refs**: 0-1
- **Code blocks**: 1-3

### Template Genérico

```text
Analiza [archivo/componente] y evalúa:
1. [Aspecto técnico 1]
2. [Aspecto técnico 2]
3. [Aspecto técnico 3]
```

### Ejemplos Validados

#### Ejemplo 1: Análisis de Modelo Odoo
```text
Analiza addons/localization/l10n_cl_dte/models/account_move.py y evalúa:
1. Patrones de herencia (uso de _inherit)
2. Campos agregados (prefijo l10n_cl_*)
3. Métodos compute y validaciones (@api decorators)
```

**Output esperado** (342 palabras, especificidad 0.56):

```markdown
## Análisis: account_move.py (DTE Extension)

**Archivo**: `addons/localization/l10n_cl_dte/models/account_move.py`

### 1. Patrón de Herencia

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
```

✅ Correcto: Usa `_inherit` (no `_name`) para extender modelo existente

### 2. Campos Agregados (Prefijo l10n_cl_*)

| Campo | Tipo | Propósito |
|-------|------|-----------|
| l10n_cl_dte_type_id | Many2one | Tipo de DTE (33, 34, 52...) |
| l10n_cl_dte_status | Selection | Estado SII (draft, sent, accepted) |
| l10n_cl_sii_barcode | Text | TED (Timbre Electrónico) |
| l10n_cl_folio | Integer | Folio único del DTE |

✅ Naming convention consistente con prefijo `l10n_cl_`

### 3. Métodos Compute y Validaciones

```python
@api.depends('line_ids.price_subtotal')
def _compute_l10n_cl_total_imponible(self):
    for move in self:
        move.l10n_cl_total_imponible = sum(...)

@api.constrains('l10n_cl_folio', 'l10n_cl_dte_type_id')
def _check_l10n_cl_folio_unique(self):
    if self.search([...]):
        raise ValidationError("Folio duplicado")
```

✅ Uso correcto de decoradores:
- `@api.depends` para campos computados
- `@api.constrains` para validaciones

### Conclusión

Código sigue best practices Odoo 19:
- ✅ Herencia correcta
- ✅ Naming conventions
- ✅ Decoradores apropiados
```

#### Ejemplo 2: Análisis de Configuración Docker
```text
Analiza docker-compose.yml y evalúa:
1. Servicios críticos (db, redis, odoo)
2. Volúmenes persistentes
3. Configuración de networking
```

**Output esperado** (350-400 palabras):

```markdown
## Análisis: docker-compose.yml

**Archivo**: `docker-compose.yml` (475 líneas)

### 1. Servicios Críticos

| Servicio | Imagen | Propósito | Status |
|----------|--------|-----------|--------|
| db | postgres:15-alpine | Base de datos principal | ✅ Persistent |
| redis-master | redis:7-alpine | Cache y sesiones | ✅ Configured |
| odoo | eergygroup/odoo19:chile-1.0.5 | Aplicación principal | ✅ Custom image |
| ai-service | odoo19-ai-service:latest | Microservicio AI | ⚠️ Optional |

**Evaluación**:
- ✅ Usa imágenes oficiales alpine (tamaño reducido)
- ✅ Versiones específicas (no latest)
- ⚠️ ai-service no crítico para DTE

### 2. Volúmenes Persistentes

```yaml
volumes:
  postgres_data:
  redis_master_data:
  odoo_data:
  odoo_sessions:
```

**Named volumes**: 4 volúmenes críticos
- ✅ postgres_data: Persistencia BD
- ✅ odoo_data: Filestore (attachments)
- ✅ redis_master_data: Cache persistente
- ✅ odoo_sessions: Sesiones HTTP

**Bind mounts** (desarrollo):
```yaml
- ./config/odoo.conf:/etc/odoo/odoo.conf:ro
- ./addons/localization:/mnt/extra-addons/localization
```

✅ Read-only config, editable addons

### 3. Networking

```yaml
networks:
  stack_network:
    driver: bridge
```

**Configuración**:
- Red interna `stack_network`
- Servicios aislados del host
- Comunicación inter-contenedores por nombre

**Puertos expuestos**:
- Odoo: 8069:8069 (HTTP)
- AI-Service: 8000:8000 (API)

⚠️ **Recomendación**: En producción usar proxy reverso (nginx)

### Conclusión

Arquitectura Docker sólida:
- ✅ Persistencia configurada
- ✅ Networking aislado
- ⚠️ Mejorar exposición de puertos en producción
```

### Cuándo Usar P2

✅ Análisis de 1 archivo específico  
✅ Evaluación de 3-5 aspectos técnicos  
✅ Comparación simple (2 opciones)  
✅ Review de configuraciones

❌ NO usar para análisis multi-módulo  
❌ NO usar para arquitectura completa  
❌ NO usar para evaluaciones críticas

---

## 🔍 P3 - Nivel Complejo (Análisis Multi-Componente)

### Características
- **Target**: 800-1,000 palabras
- **Especificidad**: 0.70-0.80
- **Estructura**: Headers multi-nivel + tablas comparativas + 10+ code blocks
- **File refs**: 2-5
- **Tech terms**: 5-10

### Template Genérico

```text
Compara arquitectura de [módulo A], [módulo B], [módulo C]:

Dimensiones de análisis:
1. [Dimensión arquitectónica 1]
2. [Dimensión técnica 2]
3. [Aspecto de diseño 3]

Identifica:
- Patrones comunes
- Inconsistencias críticas
- Mejores prácticas aplicadas
- Recomendaciones de homologación
```

### Ejemplo Validado

#### Comparación de Módulos l10n_cl_*

```text
Compara arquitectura de l10n_cl_dte, l10n_cl_hr_payroll, l10n_cl_financial_reports:

Dimensiones de análisis:
1. Patrón de herencia (_inherit vs _name)
2. Naming conventions (dte_* vs l10n_cl_* vs sin prefijo)
3. Estrategia de parsing (libs/ puro Python vs AI-Service vs mixto)

Identifica:
- Patrones comunes entre los 3 módulos
- Inconsistencias que afecten mantenibilidad
- Mejores prácticas aplicadas
- Propuestas de homologación
```

**Output esperado** (915 palabras, especificidad 0.74):

```markdown
## Comparación Arquitectónica: Módulos l10n_cl_*

**Fecha**: 2025-11-11  
**Scope**: 3 módulos chilenos, ~15K líneas totales

---

### 1. Patrón de Herencia

#### l10n_cl_dte (Facturación Electrónica)

```python
# addons/localization/l10n_cl_dte/models/account_move.py
class AccountMove(models.Model):
    _inherit = 'account.move'
```

✅ **Correcto**: Extiende modelos existentes

#### l10n_cl_hr_payroll (Nóminas)

```python
# addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
class HrPayslip(models.Model):
    _inherit = 'hr.payslip'
```

✅ **Correcto**: Misma estrategia de herencia

#### l10n_cl_financial_reports (Reportes Financieros)

```python
# addons/localization/l10n_cl_financial_reports/models/account_report.py
class AccountReport(models.Model):
    _inherit = 'account.report'
```

✅ **Correcto**: Patrón consistente

**Evaluación**: ✅ **CONSISTENTE** - Todos usan `_inherit`

---

### 2. Naming Conventions

| Módulo | Prefijo Campos | Ejemplo | Consistencia |
|--------|----------------|---------|--------------|
| l10n_cl_dte | `l10n_cl_dte_*` | `l10n_cl_dte_type_id` | ✅ Específico |
| l10n_cl_dte | `l10n_cl_sii_*` | `l10n_cl_sii_barcode` | ✅ Sistema externo |
| l10n_cl_hr_payroll | `l10n_cl_*` | `l10n_cl_total_imponible` | ⚠️ Genérico |
| l10n_cl_hr_payroll | Sin prefijo | `afp_amount`, `isapre_rate` | ❌ Inconsistente |
| l10n_cl_financial_reports | `l10n_cl_*` | `l10n_cl_tax_report_line` | ✅ Genérico aceptable |

**Inconsistencias detectadas**:

```python
# ❌ Módulo hr_payroll - Sin prefijo
class HrPayslip(models.Model):
    afp_amount = fields.Monetary()       # Sin l10n_cl_
    isapre_rate = fields.Float()         # Sin l10n_cl_
```

```python
# ✅ Debería ser
class HrPayslip(models.Model):
    l10n_cl_afp_amount = fields.Monetary()
    l10n_cl_isapre_rate = fields.Float()
```

**Evaluación**: ⚠️ **PARCIAL** - hr_payroll necesita homologación

---

### 3. Estrategia de Parsing

#### l10n_cl_dte (Parsing XML DTE)

**Arquitectura**: Pure Python en `libs/`

```python
# addons/localization/l10n_cl_dte/libs/dte_parser.py
from lxml import etree

class DTEParser:
    """Pure Python - NO dependencies on Odoo ORM"""
    
    @staticmethod
    def parse_dte_xml(xml_content: str) -> dict:
        tree = etree.fromstring(xml_content.encode())
        # 100+ líneas de parsing lógica
```

✅ **Fortalezas**:
- Testeable sin BD
- Separación de concerns
- Reutilizable fuera de Odoo

#### l10n_cl_hr_payroll (Parsing Archivo Previred)

**Arquitectura**: Mixta (libs/ + AI-Service)

```python
# addons/localization/l10n_cl_hr_payroll/libs/previred_parser.py
class PreviredParser:
    """Pure Python para formato TXT"""
    
    @staticmethod
    def parse_previred_file(content: str) -> dict:
        lines = content.split('\n')
        # Parsing línea por línea
```

**PERO también**:

```python
# addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
def _compute_total_imponible(self):
    # ❌ Llama AI-Service para validación
    response = requests.post('http://ai-service:8000/validate')
```

⚠️ **Problema**: Dependencia innecesaria de AI-Service para cálculo crítico

#### l10n_cl_financial_reports (Sin Parsing Complejo)

**Arquitectura**: ORM directo

```python
# addons/localization/l10n_cl_financial_reports/models/account_report.py
def _get_tax_report_lines(self):
    # Query directo a BD, sin parsing
    lines = self.env['account.move.line'].search([...])
```

✅ **Adecuado**: No requiere parsing externo

**Evaluación**: ⚠️ **MIXTO** - hr_payroll debe remover dependencia AI

---

### 4. Patrones Comunes Identificados

#### ✅ Fortalezas Compartidas

1. **Uso de `@api.depends`** (3/3 módulos):
```python
@api.depends('line_ids.total')
def _compute_field(self):
    ...
```

2. **Validaciones con `@api.constrains`** (3/3 módulos):
```python
@api.constrains('field_name')
def _check_validation(self):
    if not condition:
        raise ValidationError("...")
```

3. **Tests con TransactionCase** (3/3 módulos):
```python
from odoo.tests import TransactionCase, tagged

@tagged('post_install', '-at_install')
class TestModule(TransactionCase):
    ...
```

#### ❌ Inconsistencias Críticas

1. **Naming**: hr_payroll sin prefijo `l10n_cl_` en algunos campos
2. **Parsing strategy**: hr_payroll depende de AI-Service (no crítico)
3. **Estructura libs/**: DTE tiene 8 archivos, payroll 3, reports 0

---

### 5. Recomendaciones de Homologación

#### P0 (Crítico)

**Renombrar campos hr_payroll**:

```python
# De:
afp_amount → l10n_cl_afp_amount
isapre_rate → l10n_cl_isapre_rate
total_imponible → l10n_cl_total_imponible

# Con migración de datos:
ALTER TABLE hr_payslip RENAME COLUMN afp_amount TO l10n_cl_afp_amount;
```

#### P1 (Alta Prioridad)

**Eliminar dependencia AI-Service en hr_payroll**:

```python
# Antes (❌):
def _compute_total_imponible(self):
    response = requests.post('http://ai-service:8000/validate')
    self.total_imponible = response.json()['amount']

# Después (✅):
def _compute_total_imponible(self):
    from ..libs.payroll_calculator import PayrollCalculator
    self.l10n_cl_total_imponible = PayrollCalculator.compute_imponible(self)
```

#### P2 (Mejora Continua)

**Estandarizar estructura libs/**:

```
l10n_cl_dte/libs/
  - dte_parser.py
  - dte_validator.py
  - rut_validator.py
  - sii_connector.py

l10n_cl_hr_payroll/libs/
  - previred_parser.py
  - payroll_calculator.py      # ⭐ NUEVO
  - economic_indicators.py     # ⭐ NUEVO
  - rut_validator.py           # ⭐ Duplicar desde DTE

l10n_cl_financial_reports/libs/
  - (no requiere por ahora)
```

---

### 6. Conclusión

**Homogeneidad**: 75% (mejorable)

**Fortalezas**:
- ✅ Patrón de herencia consistente
- ✅ Uso correcto de decoradores Odoo 19
- ✅ Testing framework uniforme

**Debilidades**:
- ❌ Naming inconsistente (hr_payroll)
- ⚠️ Dependencia AI-Service innecesaria (hr_payroll)
- ⚠️ Estructura libs/ no estandarizada

**Impacto en mantenibilidad**: MEDIO
- Renombrado de campos requiere migración
- Eliminar AI-Service es refactor mediano

**Prioridad de homologación**: ALTA (P0+P1 en próximo sprint)
```

### Cuándo Usar P3

✅ Comparación de 3+ módulos o componentes  
✅ Identificación de inconsistencias arquitectónicas  
✅ Evaluación de patrones de diseño  
✅ Propuestas de homologación  

❌ NO usar para consultas simples  
❌ NO usar para análisis de 1 archivo  
❌ NO usar para evaluaciones críticas (usar P4)

---

## 🏗️ P4 - Nivel Crítico (Análisis Arquitectónico Profundo)

### Características
- **Target**: 1,200-1,500 palabras
- **Especificidad**: 0.90-0.95 (máxima precisión)
- **Estructura**: 50+ headers multi-nivel + 20+ tablas + 30+ code blocks
- **File refs**: 30+ explícitos (file.py:line)
- **Tech terms**: 100+ (8+ por 100 palabras)

### Template Genérico

```text
Analiza críticamente la arquitectura de [sistema completo]:

**Contexto**: [Descripción detallada: N componentes, X líneas totales, propósito]

**Evalúa**:
1. [Dimensión arquitectónica 1] (separación, flujo, patrones)
2. [Dimensión técnica 2] (herramientas, edge cases, alternativas)
3. [Aspecto de seguridad] (capas, fallos, recuperación)
4. [Validación/Testing] (suficiencia, tipos, completitud)
5. [Performance/Escalabilidad] (cuellos de botella, optimizaciones)
6. [Trade-offs] (priorización de conflictos técnicos)
7. [Mejoras críticas] (propuestas arquitectónicas con código)

**Archivos a analizar**:
- [path/file1.py (N líneas)]
- [path/file2.py (M líneas)]
- [...]

**Entregable esperado**:
Análisis profesional que evalúe decisiones de diseño, fortalezas/debilidades,
riesgos identificados, recomendaciones con ejemplos de código concretos,
evaluación de trade-offs técnicos
```

### Ejemplo Validado (Sistema de Migración Odoo 19)

```text
Analiza críticamente la arquitectura de sistema de migración Odoo 19 CE:

**Contexto**: Sistema de 3 capas (Audit → Migrate → Validate), 2,723 líneas totales,
137 migraciones automáticas aplicadas, validación triple, backups automáticos

**Evalúa**:
1. Diseño de 3 capas (separación adecuada, flujo datos, patrones detectados)
2. Estrategia parsing (AST Python vs regex vs XML ElementTree, edge cases)
3. Sistema seguridad multi-capa (Git stash + backups + commits atomícos)
4. Validación triple (sintaxis + semántica + funcional, suficiencia)
5. Escalabilidad (performance con 10K archivos, paralelización)
6. Trade-offs (automatización vs seguridad, velocidad vs exhaustividad)
7. Mejoras críticas (validación JSON schema, rollback inteligente, observabilidad)

**Archivos a analizar**:
- scripts/odoo19_migration/1_audit_deprecations.py (444 líneas)
- scripts/odoo19_migration/2_migrate_safe.py (406 líneas)
- scripts/odoo19_migration/3_validate_changes.py (455 líneas)
- scripts/odoo19_migration/MASTER_ORCHESTRATOR.sh (414 líneas)
- scripts/odoo19_migration/config/deprecations.yaml (284 líneas)

**Entregable esperado**:
Reporte de arquitectura profesional con evaluación de decisiones de diseño,
análisis de fortalezas/debilidades, identificación de riesgos,
recomendaciones con código, evaluación de trade-offs
```

**Output generado** (1,303 palabras, especificidad 0.95):

*Ver: `experimentos/outputs/current_session/p4_1_arquitectura_sistema_migracion.txt`*

**Métricas del output**:
- Palabras: 1,303
- Especificidad: 0.95/1.0 ⭐
- File references: 31 explícitos
- Technical terms: 109 (8.37 por 100 palabras)
- Code blocks: 38 (con soluciones arquitectónicas)
- Tables: 21 comparativas
- Headers: 55 multi-nivel
- Style: Professional report

### Cuándo Usar P4

✅ Evaluación de sistema completo (2,000+ líneas)  
✅ Decisiones arquitectónicas críticas  
✅ Análisis de trade-offs técnicos  
✅ Identificación de riesgos de seguridad  
✅ Propuestas de refactor mayor  
✅ Auditorías de código pre-producción  

❌ NO usar para consultas simples  
❌ NO usar para análisis de 1 archivo  
❌ NO usar para comparaciones básicas

---

## 📊 Comparación de Niveles

| Aspecto | P1 | P2 | P3 | P4 |
|---------|----|----|----|----|
| Palabras | 70-150 | 300-400 | 800-1,000 | 1,200-1,500 |
| Especificidad | 0.50-0.60 | 0.55-0.65 | 0.70-0.80 | 0.90-0.95 |
| File refs | 0 | 0-1 | 2-5 | 30+ |
| Tech terms | 0 | 0-2 | 5-10 | 100+ |
| Code blocks | 0 | 1-3 | 10-15 | 30-40 |
| Tables | 0 | 1-2 | 3-5 | 20+ |
| Headers | 0-2 | 3-5 | 10-15 | 50+ |
| Tiempo análisis | <1 min | 2-3 min | 3-5 min | 5-10 min |

---

## 🚀 Cómo Usar Este Documento

### Para Desarrolladores

1. **Identifica complejidad de tu consulta**:
   - Dato rápido → P1
   - Análisis 1 archivo → P2
   - Comparación múltiple → P3
   - Arquitectura completa → P4

2. **Usa template correspondiente**

3. **Valida output con métricas**:
   ```bash
   .venv/bin/python3 experimentos/analysis/analyze_response.py output.txt prompt_id P3
   ```

### Para Auditorías

Si necesitas análisis arquitectónico (P4), SIEMPRE incluye:
- Contexto completo (componentes, líneas, propósito)
- Lista de archivos específicos con paths
- Dimensiones de evaluación (7 mínimo)
- Entregable esperado explícito

---

**Última actualización**: 2025-11-11  
**Basado en**: Experimento de 6 prompts con escalamiento 13x validado  
**Autor**: GitHub Copilot + Claude Sonnet 4.5
