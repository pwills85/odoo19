# 🧪 Plan de Evaluación de Inteligencia y Agudeza de Agentes

**Proyecto**: Odoo19 Chilean Localization  
**Fecha**: 2025-11-10  
**Objetivo**: Medir capacidad de respuesta, precisión técnica y cumplimiento de estándares

---

## 📊 Metodología de Evaluación

### Criterios de Medición (Score 1-10)

| Criterio | Peso | Descripción |
|----------|------|-------------|
| **Precisión Técnica** | 30% | Corrección del código/análisis |
| **Cumplimiento Regulatorio** | 25% | Adherencia a normativas (SII, Código Laboral) |
| **Referencias a Knowledge Base** | 20% | Uso correcto de documentación oficial |
| **Detección de Vulnerabilidades** | 15% | Identificación de errores/riesgos |
| **Completitud** | 10% | Cobertura de todos los aspectos solicitados |

### Escala de Evaluación
- **9-10**: Excelente - Respuesta profesional completa
- **7-8**: Bueno - Respuesta correcta con detalles menores
- **5-6**: Aceptable - Respuesta básica correcta
- **3-4**: Insuficiente - Errores importantes
- **1-2**: Deficiente - Respuesta incorrecta o peligrosa

---

## 🧾 Test Suite 1: DTE Specialist

### Test 1.1: Validación Básica RUT
**Categoría**: Precisión Técnica  
**Complejidad**: ⭐ Básica

**Prompt**:
```
Validate this RUT: 76.876.876-8
Is it valid? Show the modulo 11 calculation.
```

**Resultado Esperado**:
- ✅ Confirma validez (check digit = 8)
- ✅ Muestra cálculo paso a paso
- ✅ Referencia 3 formatos contextuales (Display, DB, SII XML)
- ✅ Menciona `sii_regulatory_context.md`

**Puntos Críticos**:
- Algoritmo modulo 11 correcto
- Manejo de dígito verificador 'K'
- Formatos según contexto

---

### Test 1.2: Detección de Vulnerabilidad XXE
**Categoría**: Seguridad + Cumplimiento  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Review this XML parsing code for security issues:

from lxml import etree
xml_content = request.params['dte_xml']
tree = etree.fromstring(xml_content.encode())
```

**Resultado Esperado**:
- ✅ Identifica vulnerabilidad XXE (XML External Entity)
- ✅ Proporciona código seguro con parser configurado
- ✅ Menciona `resolve_entities=False`, `no_network=True`
- ✅ Referencia OWASP o CWE-611

**Puntos Críticos**:
- Detección de XXE sin pistas explícitas
- Solución completa y segura
- Explicación del riesgo

---

### Test 1.3: Validación CAF Expirado
**Categoría**: Cumplimiento Regulatorio  
**Complejidad**: ⭐⭐ Intermedia

**Prompt**:
```
A DTE type 33 folio 12345 is being generated, but the CAF expired yesterday.
What should happen according to SII regulations?
```

**Resultado Esperado**:
- ✅ Rechaza emisión de DTE con CAF expirado
- ✅ Cita SII Resolution 80/2014
- ✅ Sugiere proceso de renovación CAF
- ✅ Menciona validación de fechas (FRNG, FHASTA)

**Puntos Críticos**:
- Conocimiento de normativa SII
- Proceso correcto de renovación
- Implicaciones legales

---

### Test 1.4: Scope Out-of-Scope
**Categoría**: Adherencia a Proyecto  
**Complejidad**: ⭐⭐ Intermedia

**Prompt**:
```
How do I implement Boleta Electrónica (DTE 39) in EERGYGROUP?
```

**Resultado Esperado**:
- ✅ **Rechaza implementación** - DTE 39 NO está en scope
- ✅ Referencia `project_architecture.md` (scope: 33,34,52,56,61)
- ✅ Explica por qué no está en scope EERGYGROUP
- ✅ Sugiere alternativas si aplica

**Puntos Críticos**:
- Rechaza claramente scope incorrecto
- Conocimiento de arquitectura del proyecto
- No implementa features fuera de scope

---

### Test 1.5: Integración SII Webservice
**Categoría**: Arquitectura + Seguridad  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
Design the authentication flow for SII webservice integration.
Include certificate handling and SOAP envelope structure.
```

**Resultado Esperado**:
- ✅ Menciona certificado digital (PFX/P12)
- ✅ SOAP envelope con WS-Security
- ✅ Manejo seguro de claves privadas (environment variables)
- ✅ Timeout y retry logic
- ✅ Mock strategy para testing
- ✅ Referencias a `libs/sii_connector.py`

**Puntos Críticos**:
- Arquitectura completa y segura
- Manejo de certificados correcto
- Testing strategy con mocks

---

## 💰 Test Suite 2: Payroll Compliance

### Test 2.1: Cálculo AFP Básico
**Categoría**: Precisión Técnica  
**Complejidad**: ⭐ Básica

**Prompt**:
```
Calculate AFP for an employee with:
- Monthly salary: CLP 1,500,000
- UF value: 37,000
- AFP rate: 10%
```

**Resultado Esperado**:
- ✅ Calcula Total Imponible
- ✅ Aplica tope 90.3 UF (90.3 * 37,000 = 3,341,100)
- ✅ AFP = min(1,500,000, 3,341,100) * 0.10 = 150,000
- ✅ Cita Ley AFP y topes vigentes

**Puntos Críticos**:
- Aplicación correcta de topes
- Uso de UF actual
- Fórmula correcta

---

### Test 2.2: Mes Parcial Trabajado
**Categoría**: Cumplimiento Regulatorio  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Employee worked 15 days in a 30-day month.
Base salary: CLP 1,800,000
How should AFP be calculated?
```

**Resultado Esperado**:
- ✅ Proporcionaliza salario: 1,800,000 * (15/30) = 900,000
- ✅ Aplica tope imponible proporcionalmente
- ✅ Calcula AFP sobre salario proporcional
- ✅ Cita Código del Trabajo sobre proporcionalidad

**Puntos Críticos**:
- Proporcionalidad correcta
- Aplicación de topes en mes parcial
- Normativa laboral

---

### Test 2.3: Ley 21.735 (Sala Cuna)
**Categoría**: Cumplimiento Regulatorio + Actualidad  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
How does Ley 21.735 affect payroll calculations in 2025?
What changes are needed in l10n_cl_hr_payroll?
```

**Resultado Esperado**:
- ✅ Explica extensión sala cuna a hombres
- ✅ Cambios en cálculo de beneficios
- ✅ Impacto en Total Tributable
- ✅ Modificaciones en salary rules
- ✅ Testing requirements para validar cambios

**Puntos Críticos**:
- Conocimiento de legislación 2025
- Impacto técnico en módulo
- Propuesta de implementación

---

### Test 2.4: Archivo Previred TXT
**Categoría**: Precisión Técnica + Formato  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Generate Previred TXT format for employee:
- RUT: 12345678-9
- Apellidos: GONZALEZ SILVA
- Nombres: JUAN PABLO
- AFP: 150,000
- Salud: 105,000
```

**Resultado Esperado**:
- ✅ Formato correcto (largo fijo, sin separadores)
- ✅ RUT sin puntos ni guión (123456789)
- ✅ Apellidos y nombres uppercase, padding correcto
- ✅ Montos alineados a derecha, sin decimales
- ✅ Validación de checksum final

**Puntos Críticos**:
- Formato exacto Previred
- Padding y alineación
- Validaciones de integridad

---

### Test 2.5: Multi-Company Payroll
**Categoría**: Arquitectura  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Company A uses AFP Provida (10%), Company B uses AFP Habitat (11.44%).
How should salary rules handle this in multi-company setup?
```

**Resultado Esperado**:
- ✅ Usa `self.env.company` para obtener compañía activa
- ✅ AFP rate configurable por compañía
- ✅ Salary rules con company_id
- ✅ Tests para cada compañía
- ✅ Referencia `project_architecture.md` (multi-company strategy)

**Puntos Críticos**:
- Arquitectura multi-empresa correcta
- Configuración por compañía
- Testing multi-company

---

## 🧪 Test Suite 3: Test Automation

### Test 3.1: Test Básico TransactionCase
**Categoría**: Precisión Técnica  
**Complejidad**: ⭐ Básica

**Prompt**:
```
Write a test for RUT validation function that validates: 76.876.876-8
```

**Resultado Esperado**:
- ✅ Usa `TransactionCase` (Odoo 19)
- ✅ Decorator `@tagged('post_install', '-at_install', 'l10n_cl')`
- ✅ Setup correcto
- ✅ Assertions con `assertTrue`/`assertFalse`
- ✅ Test cases: válido, inválido, edge cases

**Puntos Críticos**:
- Patrón Odoo 19 (NO Odoo 11-16)
- Tags correctos
- Casos de prueba completos

---

### Test 3.2: Mock External Service
**Categoría**: Arquitectura + Testing  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Write test for SII webservice authentication that mocks the SOAP call.
Don't call real SII API.
```

**Resultado Esperado**:
- ✅ Usa `unittest.mock.patch`
- ✅ Mock de requests o zeep library
- ✅ Simula respuesta exitosa y error
- ✅ Valida manejo de certificados sin llamar API real
- ✅ Referencia `odoo19_patterns.md` (mock patterns)

**Puntos Críticos**:
- Mock correcto de external services
- NO llamadas reales a SII
- Simula errores y timeouts

---

### Test 3.3: Coverage Gap Detection
**Categoría**: Agudeza + Análisis  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
Analyze libs/dte_validator.py and identify untested code paths.
Suggest tests to reach 100% coverage.
```

**Resultado Esperado**:
- ✅ Identifica métodos sin tests
- ✅ Detecta branches no cubiertos (if/else)
- ✅ Identifica edge cases faltantes
- ✅ Propone tests específicos para cada gap
- ✅ Prioriza tests por criticidad

**Puntos Críticos**:
- Análisis exhaustivo de cobertura
- Priorización por riesgo
- Tests concretos y accionables

---

### Test 3.4: Pytest vs Odoo Test
**Categoría**: Conocimiento Técnico  
**Complejidad**: ⭐⭐ Intermedia

**Prompt**:
```
When should I use pytest vs Odoo's TransactionCase?
Show example of testing libs/rut_validator.py (pure Python).
```

**Resultado Esperado**:
- ✅ Explica: pytest para libs/ (pure Python sin ORM)
- ✅ TransactionCase para models/ (con ORM)
- ✅ Ejemplo pytest para RUT validator
- ✅ Ventajas de cada approach
- ✅ Referencia `project_architecture.md` (libs/ pattern)

**Puntos Críticos**:
- Distinción clara pytest vs Odoo test
- Uso correcto según contexto
- Ejemplos concretos

---

### Test 3.5: CI/CD Pipeline Design
**Categoría**: Arquitectura + DevOps  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
Design a CI/CD pipeline for l10n_cl_dte module with:
- Linting, type checking, security scan
- Unit tests, integration tests
- Coverage gates (80% minimum)
- Deployment to staging
```

**Resultado Esperado**:
- ✅ GitHub Actions o GitLab CI structure
- ✅ Stages: lint → test → security → deploy
- ✅ Coverage report y quality gates
- ✅ Docker-based testing
- ✅ Artifact management
- ✅ Rollback strategy

**Puntos Críticos**:
- Pipeline completo y profesional
- Quality gates configurados
- Strategy de deployment

---

## 🔒 Test Suite 4: Security Auditor

### Test 4.1: SQL Injection Detection
**Categoría**: Detección de Vulnerabilidades  
**Complejidad**: ⭐⭐ Intermedia

**Prompt**:
```
Review this code for security issues:

def search_invoices(self, term):
    query = f"SELECT * FROM account_move WHERE name LIKE '%{term}%'"
    self.env.cr.execute(query)
    return self.env.cr.fetchall()
```

**Resultado Esperado**:
- ✅ Identifica SQL Injection (CRÍTICO)
- ✅ Menciona CWE-89
- ✅ Proporciona código seguro con ORM
- ✅ Alternativa con parameterized query
- ✅ Explica impacto del ataque

**Puntos Críticos**:
- Detección inmediata de vulnerabilidad
- Solución segura y práctica
- Educación sobre riesgos

---

### Test 4.2: XXE en DTE Parsing
**Categoría**: Seguridad Específica Dominio  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
Audit the DTE XML parsing in libs/dte_validator.py for XXE vulnerabilities.
Provide secure parser configuration.
```

**Resultado Esperado**:
- ✅ Identifica parser sin protección XXE
- ✅ Menciona CWE-611
- ✅ Configura parser seguro:
  - `resolve_entities=False`
  - `no_network=True`
  - `dtd_validation=False`
- ✅ Ejemplo de ataque XXE
- ✅ Test para validar protección

**Puntos Críticos**:
- Conocimiento específico de XXE
- Configuración completa de seguridad
- Tests de seguridad

---

### Test 4.3: CAF Private Key Exposure
**Categoría**: Seguridad + Cumplimiento  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Review how CAF private keys (RSASK) are stored and handled.
Are there security risks?
```

**Resultado Esperado**:
- ✅ Identifica riesgos de almacenamiento
- ✅ Recomienda: NO hardcode, NO commit to git
- ✅ Sugiere: environment variables, key vault
- ✅ Menciona cifrado at-rest
- ✅ Access control y audit logging

**Puntos Críticos**:
- Detección de secrets exposure
- Mejores prácticas de key management
- Cumplimiento regulatorio

---

### Test 4.4: XSS en QWeb Templates
**Categoría**: Detección de Vulnerabilidades  
**Complejidad**: ⭐⭐ Intermedia

**Prompt**:
```
Review this QWeb template for XSS:

<div>
    <t t-esc="partner.name"/>
    <p t-raw="partner.description"/>
</div>
```

**Resultado Esperado**:
- ✅ Identifica riesgo XSS en `t-raw`
- ✅ Menciona CWE-79
- ✅ Explica: `t-esc` es seguro, `t-raw` es peligroso
- ✅ Recomienda: sanitize o usar `t-esc`
- ✅ Ejemplo de payload XSS

**Puntos Críticos**:
- Detección de XSS en templates
- Diferencia t-esc vs t-raw
- Solución práctica

---

### Test 4.5: Access Control Audit
**Categoría**: Arquitectura de Seguridad  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
Audit the access control for l10n_cl_dte_caf model.
Who should access CAF records? Are record rules needed?
```

**Resultado Esperado**:
- ✅ Identifica necesidad de access rights
- ✅ Propone grupos: DTE Manager, DTE User
- ✅ Record rules para multi-company
- ✅ Validación de permisos en métodos críticos
- ✅ Audit trail de cambios a CAF

**Puntos Críticos**:
- Diseño completo de access control
- Multi-company security
- Audit logging

---

## 🏗️ Test Suite 5: Odoo Architect

### Test 5.1: Model Inheritance Pattern
**Categoría**: Precisión Técnica  
**Complejidad**: ⭐⭐ Intermedia

**Prompt**:
```
Extend account.move to add l10n_cl_dte_status field.
Show the correct Odoo 19 pattern.
```

**Resultado Esperado**:
- ✅ Usa `_inherit = 'account.move'` (NO `_name`)
- ✅ Field prefixado: `l10n_cl_dte_status`
- ✅ Selection con opciones claras
- ✅ Computed field con `@api.depends`
- ✅ Referencia `odoo19_patterns.md`

**Puntos Críticos**:
- Patrón de herencia correcto
- Naming conventions
- Odoo 19 decorators

---

### Test 5.2: Refactoring to libs/
**Categoría**: Arquitectura + Separación de Concerns  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
The DTE validation logic is in models/account_move.py but has no ORM dependencies.
How should it be refactored to libs/?
```

**Resultado Esperado**:
- ✅ Identifica lógica sin dependencias ORM
- ✅ Propone clase Pure Python en `libs/dte_validator.py`
- ✅ Model llama a lib: `from ..libs.dte_validator import DTEValidator`
- ✅ Testing strategy: pytest para libs/, TransactionCase para model
- ✅ Ventajas: reusabilidad, testing independiente

**Puntos Críticos**:
- Separación correcta ORM vs Pure Python
- Arquitectura limpia
- Testability mejorada

---

### Test 5.3: Performance Optimization
**Categoría**: Agudeza + Performance  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
This query is slow:

for payslip in payslips:
    for line in payslip.line_ids:
        if line.salary_rule_id.is_imponible:
            total += line.total

How can it be optimized?
```

**Resultado Esperado**:
- ✅ Identifica N+1 query problem
- ✅ Propone: `filtered()` + `mapped()`
- ✅ Código optimizado:
  ```python
  imponible_lines = payslips.mapped('line_ids').filtered(
      lambda l: l.salary_rule_id.is_imponible
  )
  total = sum(imponible_lines.mapped('total'))
  ```
- ✅ Explica reducción de queries
- ✅ Sugiere index en `is_imponible`

**Puntos Críticos**:
- Detección de N+1
- Optimización práctica
- Database indexing

---

### Test 5.4: Multi-Company Strategy
**Categoría**: Arquitectura  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Design multi-company strategy for:
- DTE CAF (company-specific)
- Economic indicators UF/UTM (shared)
- Payslip configuration (company-specific)
```

**Resultado Esperado**:
- ✅ CAF: `company_id` required, record rules
- ✅ UF/UTM: NO `company_id` (master data shared)
- ✅ Payslip config: `company_id` optional con defaults
- ✅ Access via `self.env.company`
- ✅ Referencia `project_architecture.md`

**Puntos Críticos**:
- Criterio correcto para company_id
- Master data vs transactional
- Access patterns seguros

---

### Test 5.5: Deprecation Detection
**Categoría**: Agudeza + Conocimiento Histórico  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Review this code and identify deprecated Odoo patterns:

@api.one
def compute_total(self):
    self.total = sum(self.line_ids.mapped('amount'))
    return True
```

**Resultado Esperado**:
- ✅ Identifica `@api.one` (deprecado desde Odoo 13)
- ✅ Identifica `return True` innecesario
- ✅ Propone código Odoo 19:
  ```python
  @api.depends('line_ids.amount')
  def _compute_total(self):
      for record in self:
          record.total = sum(record.line_ids.mapped('amount'))
  ```
- ✅ Explica diferencias y ventajas

**Puntos Críticos**:
- Detección de patrones obsoletos
- Migración a Odoo 19
- Mejores prácticas actuales

---

## 🤖 Test Suite 6: AI Service Specialist

### Test 6.1: Integration Architecture
**Categoría**: Arquitectura  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Design integration between Odoo and AI microservice for:
- DTE validation assistance
- Payroll calculation verification
```

**Resultado Esperado**:
- ✅ REST API endpoint design
- ✅ Request/response schemas
- ✅ Authentication strategy (API keys)
- ✅ Error handling y timeouts
- ✅ Async processing con Redis queue

**Puntos Críticos**:
- Arquitectura desacoplada
- Resiliencia y fault tolerance
- Performance considerations

---

### Test 6.2: AI Response Validation
**Categoría**: Seguridad + Validación  
**Complejidad**: ⭐⭐⭐⭐ Experta

**Prompt**:
```
AI service returns AFP calculation result.
How should Odoo validate this before using it?
```

**Resultado Esperado**:
- ✅ NUNCA confiar ciegamente en AI
- ✅ Validación de rangos (AFP 0-12%)
- ✅ Re-cálculo independiente para verificar
- ✅ Logging de discrepancias
- ✅ Human-in-the-loop para valores críticos

**Puntos Críticos**:
- Validación de AI outputs
- Compliance crítico
- Audit trail completo

---

### Test 6.3: Prompt Engineering for DTE
**Categoría**: AI Expertise  
**Complejidad**: ⭐⭐⭐ Avanzada

**Prompt**:
```
Design a prompt template for AI to validate DTE XML structure.
Include context and expected output format.
```

**Resultado Esperado**:
- ✅ Contexto regulatorio en prompt
- ✅ XML schema requirements
- ✅ Expected output: JSON con errores
- ✅ Few-shot examples
- ✅ Temperature y parámetros

**Puntos Críticos**:
- Prompt engineering efectivo
- Output estructurado
- Dominio-specific context

---

## 📋 Matriz de Evaluación

### Scorecard Template

```markdown
## Agente: [Nombre]
**Fecha**: [YYYY-MM-DD]
**Evaluador**: [Nombre]

| Test | Precisión | Regulatorio | KB Refs | Vulnerab. | Completitud | **Total** |
|------|-----------|-------------|---------|-----------|-------------|-----------|
| 1.1  | __/10     | __/10       | __/10   | __/10     | __/10       | __/50     |
| 1.2  | __/10     | __/10       | __/10   | __/10     | __/10       | __/50     |
| 1.3  | __/10     | __/10       | __/10   | __/10     | __/10       | __/50     |
| 1.4  | __/10     | __/10       | __/10   | __/10     | __/10       | __/50     |
| 1.5  | __/10     | __/10       | __/10   | __/10     | __/10       | __/50     |

**Score Ponderado**: __/250 → __/100

### Observaciones:
- Fortalezas: [...]
- Debilidades: [...]
- Recomendaciones: [...]
```

---

## 🎯 Procedimiento de Ejecución

### Fase 1: Preparación (15 min)
```bash
# 1. Verificar knowledge base actualizada
ls -la .github/agents/knowledge/

# 2. Limpiar contexto de sesiones previas
# (reiniciar terminal si es necesario)

# 3. Preparar scorecard vacío
cp docs/PLAN_EVALUACION_AGENTES_INTELIGENCIA.md \
   docs/evaluacion/resultados_$(date +%Y%m%d).md
```

### Fase 2: Ejecución por Agente (30-45 min cada uno)
```bash
# Iniciar sesión con agente
copilot /agent [agent-name]

# Ejecutar tests 1.1 - 1.5 en orden
# Copiar respuestas completas
# Evaluar en tiempo real con scorecard
```

### Fase 3: Análisis Comparativo (30 min)
```bash
# Comparar scores entre agentes
# Identificar patrones de fortalezas/debilidades
# Generar reporte ejecutivo
```

---

## 📊 Métricas de Éxito

### Benchmarks Esperados

| Agente | Score Mínimo | Score Objetivo | Área Crítica |
|--------|--------------|----------------|--------------|
| **dte-specialist** | 75/100 | 90/100 | Cumplimiento regulatorio |
| **payroll-compliance** | 75/100 | 90/100 | Precisión cálculos |
| **test-automation** | 70/100 | 85/100 | Coverage strategy |
| **security-auditor** | 80/100 | 95/100 | Detección vulnerabilidades |
| **odoo-architect** | 70/100 | 85/100 | Arquitectura patterns |
| **ai-service-specialist** | 65/100 | 80/100 | Integration design |

### Red Flags (Score < 60)
- ⚠️ Revisar configuración del agente
- ⚠️ Actualizar knowledge base
- ⚠️ Refinar prompts del agente

---

## 📁 Entregables

### 1. Reporte Individual por Agente
```
docs/evaluacion/
├── dte_specialist_YYYYMMDD.md
├── payroll_compliance_YYYYMMDD.md
├── test_automation_YYYYMMDD.md
├── security_auditor_YYYYMMDD.md
├── odoo_architect_YYYYMMDD.md
└── ai_service_specialist_YYYYMMDD.md
```

### 2. Reporte Ejecutivo Consolidado
```
docs/evaluacion/RESUMEN_EJECUTIVO_EVALUACION_AGENTES.md

Incluye:
- Scores comparativos
- Ranking de agentes
- Recomendaciones de mejora
- Plan de actualización knowledge base
```

### 3. Test Cases Archive
```
docs/evaluacion/test_cases/
├── test_suite_1_dte.md
├── test_suite_2_payroll.md
├── test_suite_3_testing.md
├── test_suite_4_security.md
├── test_suite_5_architecture.md
└── test_suite_6_ai.md
```

---

## 🔄 Ciclo de Mejora Continua

### Iteración Mensual
1. **Ejecutar evaluación completa**
2. **Identificar gaps en knowledge base**
3. **Actualizar documentación de agentes**
4. **Re-evaluar con mismos tests**
5. **Medir mejora vs baseline**

### Actualización Knowledge Base
```bash
# Basado en resultados de evaluación
# Actualizar archivos en .github/agents/knowledge/
git add .github/agents/knowledge/
git commit -m "docs: update knowledge base based on agent evaluation"
```

---

## 🚀 Quick Start - Primera Evaluación

```bash
# 1. Crear directorio de evaluaciones
mkdir -p docs/evaluacion/resultados_$(date +%Y%m%d)

# 2. Ejecutar test DTE Specialist (ejemplo)
copilot /agent dte-specialist

# Dentro del agente, ejecutar Test 1.1:
> Validate this RUT: 76.876.876-8. Is it valid? Show the modulo 11 calculation.

# 3. Copiar respuesta completa a scorecard
# 4. Evaluar según criterios
# 5. Continuar con tests 1.2 - 1.5

# 6. Repetir para todos los agentes
```

---

## 📞 Soporte

**Preguntas sobre evaluación**:
- Revisar: `docs/copilot-agents-guide.md`
- Contacto: Pedro Troncoso (@pwills85)

**Problemas técnicos con agentes**:
```bash
# Verificar configuración
gh copilot version
gh auth status

# Revisar knowledge base
cat .github/agents/knowledge/sii_regulatory_context.md
```

---

**¡Comienza la evaluación y mide la inteligencia real de cada agente!** 🧪🤖
