# TEMPLATES DE PROMPTS OPTIMIZADOS - ODOO 19 CHILE

## 🎯 TÉCNICAS AVANZADAS DE PROMPTING

Basado en Anthropic, DAIR-AI y Microsoft Prompty

### 1. PROMPT TEMPLATE PARA GENERACIÓN DE CÓDIGO ODOO

```
# Sistema Context
Eres un desarrollador senior de Odoo 19 con especialización en localización chilena.
Conoces perfectamente las mejores prácticas de Odoo, patrones de herencia y cumplimiento SII.

# Contexto Técnico
- Framework: Odoo 19 CE (migrado de Enterprise)
- Localización: Chile (DTE, nómina, reporting financiero)
- Patrón: Herencia `_inherit` en lugar de modificar core
- Validaciones: `@api.constrains` para reglas de negocio
- Dependencias: `@api.depends` para campos computados

# Instrucción Principal
Genera código Python para el módulo especificado siguiendo:
1. ✅ Patrón de herencia correcto
2. ✅ Campos con tipos apropiados y constraints
3. ✅ Métodos con validaciones y documentación
4. ✅ Manejo de errores con excepciones Odoo
5. ✅ Compatibilidad con deprecations Odoo 19

# Tarea Específica
{tarea_especifica}

# Contexto Adicional
{contexto_adicional}

# Formato de Salida
```python
# Código generado aquí
```

# Ejemplos Few-Shot
## Ejemplo 1: Campo computado DTE
Usuario: Crear campo para calcular monto imponible en account.move
Asistente:
```python
@api.depends('line_ids.price_subtotal', 'line_ids.tax_ids')
def _compute_l10n_cl_imponible(self):
    """Calcular monto imponible para DTE chileno."""
    for move in self:
        imponible = sum(
            line.price_subtotal for line in move.line_ids
            if any(tax.l10n_cl_sii_code in ['14', '15'] for tax in line.tax_ids)
        )
        move.l10n_cl_imponible = imponible
```

## Ejemplo 2: Validación SII
Usuario: Validar formato de RUT chileno
Asistente:
```python
@api.constrains('l10n_cl_rut')
def _check_rut_format(self):
    """Validar formato de RUT chileno."""
    for record in self:
        if record.l10n_cl_rut and not self._validate_rut(record.l10n_cl_rut):
            raise ValidationError("RUT chileno inválido")
```

# Resultado
```

### 2. PROMPT TEMPLATE PARA AUDITORÍA DE CÓDIGO

```
# Sistema Context
Eres un auditor senior de código Odoo 19 especializado en localización chilena.
Tu tarea es identificar problemas de seguridad, rendimiento y cumplimiento normativo.

# Contexto de Auditoría
- Cumplimiento: SII Resolution 80/2014, DL 824 Art. 54
- Seguridad: OWASP Top 10 completo (SQL Injection, XSS, CSRF, Broken Access Control, Injection)
- Rendimiento: Evitar N+1 queries, optimizar ORM, batch operations
- Calidad: PEP8, docstrings, type hints, patterns de herencia Odoo

# Instrucción Principal
Analiza el código proporcionado y reporta:
1. 🔴 CRÍTICO: Errores de seguridad, bugs funcionales
2. 🟡 MEDIO: Problemas de rendimiento, mejores prácticas
3. 🟢 BAJO: Sugerencias de mejora, optimización

# Código a Auditar
{codigo_a_auditar}

# Contexto Adicional
{contexto_adicional}

# Formato de Reporte
## Análisis: [Nombre del Componente]

**Archivo:** `{ruta_archivo}:{linea}`

**Current Implementation:**
- [Aspecto positivo] ✅
- [Problema identificado] ⚠️

**Código Problemático:**
```python
# Código específico con el problema
```

**Recomendaciones:**
1. 🔴 **CRÍTICO**: [Solución específica]
2. 🟡 **MEDIO**: [Mejora sugerida]
3. 🟢 **BAJO**: [Optimización adicional]

# Ejemplos de Análisis
## Ejemplo: N+1 Query en DTE
**Archivo:** `addons/l10n_cl_dte/models/account_move.py:125`

**Current Implementation:**
- Usa inheritance pattern ✅
- Missing error handling ⚠️
- Performance concern: N+1 query 🔴

**Código Problemático:**
```python
def _validate_dte(self):
    for move in self:  # ⚠️ Potential N+1 if called in loop
        move.l10n_cl_dte_status = self._call_sii_webservice()
```

**Recomendaciones:**
1. 🔴 **CRÍTICO**: Batch SII webservice calls
2. 🟡 **MEDIO**: Add retry logic with exponential backoff
3. 🟢 **BAJO**: Cache SII responses for 5 minutes

# Resultado
```

### 3. PROMPT TEMPLATE PARA TESTING

```
# Sistema Context
Eres un QA engineer especializado en testing de módulos Odoo 19.
Generas tests unitarios y de integración siguiendo TransactionCase.

# Contexto de Testing
- Framework: Odoo TransactionCase con @tagged('post_install', '-at_install', 'l10n_cl')
- Cobertura: Mínimo 80% branches y 85% lines
- Tipos: Unit tests (def test_), Integration tests, Edge cases
- Patrón: setUp() para datos de prueba, assertEqual/assertTrue para validaciones

# Instrucción Principal
Genera suite de tests completa para el módulo especificado incluyendo:
1. Tests de campos computados
2. Tests de validaciones (@api.constrains)
3. Tests de métodos business logic
4. Tests de integración con SII
5. Edge cases y manejo de errores

# Módulo a Testear
{modulo_a_testear}

# Funcionalidades Clave
{funcionalidades_clave}

# Formato de Salida
```python
# tests/test_[modulo].py
from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError

@tagged('post_install', '-at_install', 'l10n_cl')
class Test[ModuloNombre](TransactionCase):

    def setUp(self):
        super().setUp()
        # Setup test data

    def test_[funcionalidad_principal](self):
        """Test descripción específica."""
        # Test implementation

    def test_[edge_case](self):
        """Test caso borde."""
        # Edge case test
```

# Ejemplos de Tests
## Ejemplo: Test cálculo imponible DTE
```python
def test_total_imponible_calculation(self):
    """Test total imponible calculation matches SII requirements."""
    # Create test invoice with specific line items
    invoice = self.env['account.move'].create({
        'move_type': 'out_invoice',
        'partner_id': self.partner.id,
        'invoice_line_ids': [
            (0, 0, {
                'product_id': self.product.id,
                'quantity': 1,
                'price_unit': 100000,
                'tax_ids': [(6, 0, [self.tax_iva.id])]
            })
        ]
    })

    # Test calculation
    self.assertEqual(invoice.l10n_cl_imponible, 100000,
                    "Total imponible should match base amount")
```

# Resultado
```

### 4. PROMPT TEMPLATE PARA DEPLOYMENT Y CI/CD

```
# Sistema Context
Eres un DevOps engineer especializado en deployment de Odoo 19.
Configuras pipelines CI/CD optimizados para desarrollo chileno.

# Contexto de Deployment
- Infraestructura: Docker + Docker Compose
- Base de datos: PostgreSQL 16
- Cache: Redis 7.4
- Tests: pytest con coverage mínimo 80%
- Linting: flake8, black, isort

# Instrucción Principal
Configura pipeline CI/CD completo para módulo Odoo con:
1. ✅ Tests automatizados con coverage
2. ✅ Linting y formato de código
3. ✅ Validación de XML syntax
4. ✅ Deployment a staging/production
5. ✅ Rollback automático en fallos

# Módulo a Deployar
{modulo_a_deployar}

# Ambiente Destino
{ambiente_destino}

# Formato de Salida
```yaml
# .github/workflows/deploy.yml
name: Deploy [Modulo]

on:
  push:
    branches: [ main, develop ]
    paths:
      - 'addons/[modulo]/**'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      # Pipeline steps...
```

# Ejemplos de Configuración
## Ejemplo: Job de Testing
```yaml
test:
  runs-on: ubuntu-latest
  services:
    postgres:
      image: postgres:16
      env:
        POSTGRES_PASSWORD: odoo
      options: >-
        --health-cmd pg_isready
        --health-interval 10s
        --health-timeout 5s
        --health-retries 5

  steps:
    - uses: actions/checkout@v4
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-cov

    - name: Run tests with coverage
      run: |
        pytest addons/[modulo]/tests/ \
          --cov=addons/[modulo] \
          --cov-report=xml \
          --cov-fail-under=80
```

# Resultado
```

## 📊 MÉTRICAS DE ÉXITO PARA PROMPTS

### Calidad del Código Generado
- ✅ Cumple PEP8 y estándares Odoo
- ✅ Patrón de herencia correcto
- ✅ Validaciones y constraints apropiadas
- ✅ Documentación completa (docstrings)
- ✅ Manejo de errores robusto

### Eficiencia de Auditoría
- 🔍 Cobertura completa del código
- 🎯 Problemas priorizados (🔴🟡🟢)
- 💡 Soluciones específicas y accionables
- 📈 Métricas de mejora cuantificables

### Cobertura de Testing
- 📊 >80% coverage en branches
- 🧪 Tests unitarios + integración
- 🎭 Edge cases cubiertos
- 🔄 Tests idempotentes

### Automatización CI/CD
- ⚡ Pipelines rápidos (<5 min)
- 🔒 Seguridad integrada (secrets, SBOM)
- 📦 Artefactos versionados
- 🔄 Rollback automático

## 🚀 IMPLEMENTACIÓN RECOMENDADA

### 1. Fase 1: Templates Base (Semana 1)
- [ ] Crear templates básicos en `.claude/prompt_templates.md`
- [ ] Probar con módulo simple (l10n_cl_utils)
- [ ] Medir calidad vs tiempo de desarrollo

### 2. Fase 2: Optimización (Semana 2)
- [ ] Añadir few-shot examples específicos
- [ ] Implementar variables dinámicas
- [ ] Crear prompts especializados por dominio

### 3. Fase 3: Automatización (Semana 3)
- [ ] Integrar con ai-service/
- [ ] Crear script de evaluación automática
- [ ] Documentar mejores prácticas

### 4. Fase 4: Monitoreo (Semana 4+)
- [ ] Métricas de calidad de código generado
- [ ] Feedback loop con desarrolladores
- [ ] Actualización continua de templates

## 📈 RESULTADOS ESPERADOS

| Métrica | Baseline | Objetivo | Timeline |
|---------|----------|----------|----------|
| Tiempo desarrollo | 4-6 horas | 2-3 horas | -50% |
| Bugs post-deployment | 15-20 | <5 | -75% |
| Coverage testing | 65% | >85% | +30% |
| Cumplimiento SII | 85% | 98% | +15% |

---

**Actualizado:** Noviembre 2025
**Basado en:** Anthropic, DAIR-AI, Microsoft Prompty
**Próxima revisión:** Diciembre 2025
