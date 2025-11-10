# 🚀 Quick Start - Evaluación de Agentes

**Duración Total**: 4-5 horas  
**Fecha**: 2025-11-10

---

## ⚡ Inicio Rápido (5 minutos)

### 1. Preparar Entorno
```bash
cd /Users/pedro/Documents/odoo19

# Verificar knowledge base
ls -la .github/agents/knowledge/
# ✅ Debe existir: sii_regulatory_context.md, odoo19_patterns.md, project_architecture.md

# Ver estructura de evaluación
ls -la docs/evaluacion/resultados_20251110/
```

### 2. Abrir Scorecard en Editor
```bash
# Abrir los 6 scorecards en tu editor
code docs/evaluacion/resultados_20251110/*.md
# o
open docs/evaluacion/resultados_20251110/
```

---

## 🎯 Evaluación Paso a Paso

### Ejemplo Completo: Agente DTE Specialist

#### Paso 1: Iniciar Agente (1 min)
```bash
copilot /agent dte-specialist
# Esperar confirmación de inicio
```

#### Paso 2: Ejecutar Test 1.1 (5 min)
**En la sesión de Copilot, escribir**:
```
Validate this RUT: 76.876.876-8
Is it valid? Show the modulo 11 calculation.
```

**Esperar respuesta del agente**, luego:

1. **Copiar respuesta COMPLETA** (Ctrl+C)
2. **Abrir**: `dte-specialist_scorecard.md`
3. **Pegar** en sección "Test 1.1 - Respuesta"
4. **Evaluar** (0-10 cada criterio):
   - ✅ **Precisión**: ¿Cálculo modulo 11 correcto? → __/10
   - ✅ **Regulatorio**: ¿Menciona 3 formatos contextuales? → __/10
   - ✅ **KB Refs**: ¿Cita `sii_regulatory_context.md`? → __/10
   - ✅ **Vulnerabilidades**: N/A para este test → 5/10
   - ✅ **Completitud**: ¿Respuesta completa y clara? → __/10

5. **Anotar** total en tabla del scorecard

#### Paso 3: Ejecutar Test 1.2 (7 min)
**En Copilot**:
```
Review this XML parsing code for security issues:

from lxml import etree
xml_content = request.params['dte_xml']
tree = etree.fromstring(xml_content.encode())
```

**Evaluar respuesta**:
- ✅ **Precisión**: ¿Identifica XXE? → __/10
- ✅ **Regulatorio**: ¿Menciona SII security? → __/10
- ✅ **KB Refs**: ¿Referencia docs? → __/10
- ✅ **Vulnerabilidades**: ¿Detecta y corrige XXE? → __/10 ⭐
- ✅ **Completitud**: ¿Código seguro + explicación? → __/10

#### Paso 4: Ejecutar Test 1.3 (5 min)
```
A DTE type 33 folio 12345 is being generated, but the CAF expired yesterday.
What should happen according to SII regulations?
```

**Evaluar**: ¿Rechaza emisión? ¿Cita Resolución 80/2014?

#### Paso 5: Ejecutar Test 1.4 (5 min)
```
How do I implement Boleta Electrónica (DTE 39) in EERGYGROUP?
```

**CRÍTICO**: Agente debe **RECHAZAR** porque DTE 39 NO está en scope.

**Evaluar**:
- ✅ **Precisión**: ¿Rechaza correctamente? → __/10 ⭐
- ✅ **Regulatorio**: ¿Explica por qué? → __/10
- ✅ **KB Refs**: ¿Cita `project_architecture.md`? → __/10 ⭐
- ✅ **Vulnerabilidades**: N/A → 5/10
- ✅ **Completitud**: ¿Alternativas si aplica? → __/10

#### Paso 6: Ejecutar Test 1.5 (10 min)
```
Design the authentication flow for SII webservice integration.
Include certificate handling and SOAP envelope structure.
```

**Evaluar**: ¿Arquitectura completa? ¿Menciona certificados, WS-Security, mocks?

#### Paso 7: Calcular Score Final (3 min)
```
# Sumar cada columna
Precisión_Total = Test1.1_Precisión + Test1.2_Precisión + ... (máx 50)
Regulatorio_Total = ... (máx 50)
KB_Total = ... (máx 50)
Vulnerab_Total = ... (máx 50)
Completitud_Total = ... (máx 50)

# Ponderar
Score_Final = 
  (Precisión_Total / 50) * 30 +
  (Regulatorio_Total / 50) * 25 +
  (KB_Total / 50) * 20 +
  (Vulnerab_Total / 50) * 15 +
  (Completitud_Total / 50) * 10
```

#### Paso 8: Escribir Observaciones (5 min)
- **Fortalezas**: ¿Qué hizo bien?
- **Debilidades**: ¿Qué falló?
- **Recomendaciones**: ¿Qué mejorar?

#### Paso 9: Salir del Agente
```
> exit
```

---

## 📊 Repetir para Todos los Agentes

### Checklist de Ejecución

- [ ] **dte-specialist** (30-40 min)
- [ ] **payroll-compliance** (30-40 min)
- [ ] **test-automation** (30-40 min)
- [ ] **security-auditor** (30-40 min)
- [ ] **odoo-architect** (30-40 min)
- [ ] **ai-service-specialist** (30-40 min)

**Total**: 3-4 horas

---

## 📋 Templates de Tests por Agente

### Payroll Compliance (Tests 2.x)

#### Test 2.1
```
Calculate AFP for an employee with:
- Monthly salary: CLP 1,500,000
- UF value: 37,000
- AFP rate: 10%
```

#### Test 2.2
```
Employee worked 15 days in a 30-day month.
Base salary: CLP 1,800,000
How should AFP be calculated?
```

#### Test 2.3
```
How does Ley 21.735 affect payroll calculations in 2025?
What changes are needed in l10n_cl_hr_payroll?
```

#### Test 2.4
```
Generate Previred TXT format for employee:
- RUT: 12345678-9
- Apellidos: GONZALEZ SILVA
- Nombres: JUAN PABLO
- AFP: 150,000
- Salud: 105,000
```

#### Test 2.5
```
Company A uses AFP Provida (10%), Company B uses AFP Habitat (11.44%).
How should salary rules handle this in multi-company setup?
```

---

### Test Automation (Tests 3.x)

#### Test 3.1
```
Write a test for RUT validation function that validates: 76.876.876-8
```

#### Test 3.2
```
Write test for SII webservice authentication that mocks the SOAP call.
Don't call real SII API.
```

#### Test 3.3
```
Analyze libs/dte_validator.py and identify untested code paths.
Suggest tests to reach 100% coverage.
```

#### Test 3.4
```
When should I use pytest vs Odoo's TransactionCase?
Show example of testing libs/rut_validator.py (pure Python).
```

#### Test 3.5
```
Design a CI/CD pipeline for l10n_cl_dte module with:
- Linting, type checking, security scan
- Unit tests, integration tests
- Coverage gates (80% minimum)
- Deployment to staging
```

---

### Security Auditor (Tests 4.x)

#### Test 4.1
```
Review this code for security issues:

def search_invoices(self, term):
    query = f"SELECT * FROM account_move WHERE name LIKE '%{term}%'"
    self.env.cr.execute(query)
    return self.env.cr.fetchall()
```

#### Test 4.2
```
Audit the DTE XML parsing in libs/dte_validator.py for XXE vulnerabilities.
Provide secure parser configuration.
```

#### Test 4.3
```
Review how CAF private keys (RSASK) are stored and handled.
Are there security risks?
```

#### Test 4.4
```
Review this QWeb template for XSS:

<div>
    <t t-esc="partner.name"/>
    <p t-raw="partner.description"/>
</div>
```

#### Test 4.5
```
Audit the access control for l10n_cl_dte_caf model.
Who should access CAF records? Are record rules needed?
```

---

### Odoo Architect (Tests 5.x)

#### Test 5.1
```
Extend account.move to add l10n_cl_dte_status field.
Show the correct Odoo 19 pattern.
```

#### Test 5.2
```
The DTE validation logic is in models/account_move.py but has no ORM dependencies.
How should it be refactored to libs/?
```

#### Test 5.3
```
This query is slow:

for payslip in payslips:
    for line in payslip.line_ids:
        if line.salary_rule_id.is_imponible:
            total += line.total

How can it be optimized?
```

#### Test 5.4
```
Design multi-company strategy for:
- DTE CAF (company-specific)
- Economic indicators UF/UTM (shared)
- Payslip configuration (company-specific)
```

#### Test 5.5
```
Review this code and identify deprecated Odoo patterns:

@api.one
def compute_total(self):
    self.total = sum(self.line_ids.mapped('amount'))
    return True
```

---

### AI Service Specialist (Tests 6.x)

#### Test 6.1
```
Design integration between Odoo and AI microservice for:
- DTE validation assistance
- Payroll calculation verification
```

#### Test 6.2
```
AI service returns AFP calculation result.
How should Odoo validate this before using it?
```

#### Test 6.3
```
Design a prompt template for AI to validate DTE XML structure.
Include context and expected output format.
```

---

## 🎯 Criterios de Evaluación Rápidos

### Excelente (9-10/10)
- ✅ Respuesta completa y precisa
- ✅ Cita knowledge base específicamente
- ✅ Proporciona código correcto
- ✅ Explica razonamiento

### Bueno (7-8/10)
- ✅ Respuesta correcta con detalles menores
- ⚠️ Algunas referencias faltantes
- ✅ Código funcional

### Aceptable (5-6/10)
- ⚠️ Respuesta básica correcta
- ⚠️ Falta profundidad
- ⚠️ Pocas referencias a docs

### Insuficiente (3-4/10)
- ❌ Errores importantes
- ❌ No cita knowledge base
- ❌ Código incompleto

### Deficiente (1-2/10)
- ❌ Respuesta incorrecta
- ❌ Peligroso/inseguro
- ❌ Fuera de scope

---

## 📊 Consolidación Final (30 min)

### Paso 1: Completar Reporte Consolidado
```bash
# Abrir template
code docs/evaluacion/resultados_20251110/REPORTE_CONSOLIDADO_TEMPLATE.md

# Completar con datos de scorecards individuales
```

### Paso 2: Ranking de Agentes
```
# Ordenar por Score Ponderado (mayor a menor)
1. [Agente] - __/100
2. [Agente] - __/100
3. [Agente] - __/100
...
```

### Paso 3: Identificar Gaps en Knowledge Base
```
# ¿Qué documentación faltó que los agentes necesitaron?
- Agregar a sii_regulatory_context.md: [...]
- Clarificar en odoo19_patterns.md: [...]
```

### Paso 4: Plan de Acción
```
# Priorizar mejoras
Alta: [...]
Media: [...]
Baja: [...]
```

---

## ✅ Checklist Final

### Archivos Completados
- [ ] dte-specialist_scorecard.md (con scores y observaciones)
- [ ] payroll-compliance_scorecard.md
- [ ] test-automation_scorecard.md
- [ ] security-auditor_scorecard.md
- [ ] odoo-architect_scorecard.md
- [ ] ai-service-specialist_scorecard.md
- [ ] REPORTE_CONSOLIDADO_TEMPLATE.md (completado)

### Entregables
- [ ] Scores calculados correctamente
- [ ] Observaciones escritas para cada agente
- [ ] Ranking de agentes generado
- [ ] Plan de acción definido
- [ ] Gaps en knowledge base identificados

---

## 📞 Soporte

**Si tienes dudas**:
1. Ver: `docs/PLAN_EVALUACION_AGENTES_INTELIGENCIA.md` (plan completo)
2. Ver: `docs/evaluacion/resultados_20251110/INSTRUCCIONES_EJECUCION.md`
3. Revisar: `docs/copilot-agents-guide.md` (guía de agentes)

**Problemas técnicos**:
```bash
# Verificar Copilot
gh copilot version
gh auth status

# Verificar knowledge base
cat .github/agents/knowledge/sii_regulatory_context.md | head -20
```

---

## 🚀 ¡Comienza Ahora!

```bash
# Paso 1: Leer este quick start ✅ (ya lo hiciste)

# Paso 2: Abrir scorecards
code docs/evaluacion/resultados_20251110/*.md

# Paso 3: Iniciar primer agente
copilot /agent dte-specialist

# Paso 4: Ejecutar Test 1.1 (copiar prompt de arriba)
```

**¡Buena suerte!** 🧪🤖
