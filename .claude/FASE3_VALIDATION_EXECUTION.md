# 🧪 Fase 3: Validation Execution - Agent Education

**Date:** 2025-11-08
**Status:** 🔄 IN PROGRESS
**Objective:** Certificar que los agentes educados funcionan correctamente

---

## 📋 TEST SUITE OVERVIEW

### Methodology
Cada test simula un escenario real donde un agente debe:
1. Consultar la knowledge base apropiada
2. Aplicar el conocimiento para tomar la decisión correcta
3. Prevenir errores o sugerir la implementación correcta

### Success Criteria
- ✅ Agent references correct knowledge base file
- ✅ Agent applies knowledge correctly
- ✅ Agent prevents errors or suggests correct pattern
- ✅ 5/5 tests must pass for certification

---

## 🧪 TEST 1: DTE Scope Validation

**Objective:** Verificar que el agente rechaza implementación de DTEs fuera de scope

### Test Setup
**Scenario:** Usuario solicita implementar DTE 39 (Boleta Electrónica)
**Expected:** Agente consulta `sii_regulatory_context.md` y rechaza (fuera de scope EERGYGROUP)
**Agent:** @odoo-dev

### Knowledge Base Reference
File: `.claude/agents/knowledge/sii_regulatory_context.md`
Lines: 27-52

```markdown
### ✅ Supported DTE Types (B2B Only)
33      Factura Electrónica
34      Factura Exenta Electrónica
52      Guía de Despacho Electrónica
56      Nota de Débito Electrónica
61      Nota de Crédito Electrónica

### ❌ NOT Supported (Retail)
39      Boleta Electrónica               Retail (B2C) - out of scope
41      Boleta Exenta Electrónica        Retail (B2C) - out of scope

**IMPORTANT:** EERGYGROUP is B2B only. Do NOT implement retail boletas (39, 41).
```

### Validation Execution
**Step 1:** Check if odoo-dev agent has knowledge base reference
**Step 2:** Verify agent would consult sii_regulatory_context.md
**Step 3:** Confirm correct decision (reject DTE 39)

### Expected Agent Behavior
```
User: "@odoo-dev implementa soporte para DTE 39 (Boleta Electrónica)"

Agent (educated):
1. Reads user request: "DTE 39"
2. Checks pre-flight checklist: "DTE type in scope?"
3. Consults: .claude/agents/knowledge/sii_regulatory_context.md
4. Finds: DTE 39 = Boleta Electrónica (B2C retail - NOT supported)
5. Response: "DTE 39 está fuera del alcance de EERGYGROUP.
   Scope soportado: 33, 34, 52, 56, 61 (B2B únicamente).
   Boletas (39, 41) son retail (B2C) y no están en scope del proyecto."
```

**Result:** ⏳ TESTING...

---

## 🧪 TEST 2: Odoo 19 Pattern Check

**Objective:** Verificar que el agente usa patrones Odoo 19 (Pure Python libs/)

### Test Setup
**Scenario:** Usuario solicita crear validador XML en libs/
**Expected:** Agente consulta `odoo19_patterns.md` y sugiere Pure Python class (NO AbstractModel)
**Agent:** @odoo-dev

### Knowledge Base Reference
File: `.claude/agents/knowledge/odoo19_patterns.md`
Lines: 26-73

```python
### ❌ OLD PATTERN (Odoo 11-16) - DO NOT USE
class DTEXMLGenerator(models.AbstractModel):
    _name = 'dte.xml.generator'

### ✅ NEW PATTERN (Odoo 19) - USE THIS
class DTEXMLGenerator:
    """Pure Python class for DTE XML generation."""

    def __init__(self):
        pass
```

### Expected Agent Behavior
```
User: "@odoo-dev crea un validador de estructura DTE en libs/"

Agent (educated):
1. Reads request: "libs/" directory
2. Checks pre-flight: "Using Odoo 19 patterns?"
3. Consults: .claude/agents/knowledge/odoo19_patterns.md
4. Finds: libs/ MUST contain Pure Python classes (no AbstractModel)
5. Response: Creates Pure Python class with dependency injection pattern
```

**Result:** ⏳ TESTING...

---

## 🧪 TEST 3: RUT Format Selection

**Objective:** Verificar que el agente selecciona formato RUT correcto por contexto

### Test Setup
**Scenario:** Usuario solicita formatear RUT para envío a SII
**Expected:** Agente consulta `sii_regulatory_context.md` y usa formato correcto (dash, no dots)
**Agent:** @odoo-dev

### Knowledge Base Reference
File: `.claude/agents/knowledge/sii_regulatory_context.md`
Lines: 55-96

```
### Format Rules
Purpose              Format                Example
──────────────────────────────────────────────────────
Storage (DB)         Clean + dash         12345678-5
SII XML              Dash only (no dots)  12345678-5
Display (UI)         Full format          12.345.678-5
```

### Expected Agent Behavior
```
User: "@odoo-dev formatea RUT para XML que será enviado al SII"

Agent (educated):
1. Reads request: "para XML" + "SII"
2. Checks: "RUT format correct for context?"
3. Consults: .claude/agents/knowledge/sii_regulatory_context.md
4. Finds: SII XML format = 12345678-5 (dash, no dots)
5. Response: Implements format without dots, only dash
```

**Result:** ⏳ TESTING...

---

## 🧪 TEST 4: Architecture Consistency

**Objective:** Verificar que el agente extiende modelos (no duplica)

### Test Setup
**Scenario:** Usuario solicita agregar campos DTE a facturas
**Expected:** Agente consulta `project_architecture.md` y usa _inherit (no nuevo modelo)
**Agent:** @odoo-dev

### Knowledge Base Reference
File: `.claude/agents/knowledge/project_architecture.md`
Lines: 162-183

```python
### 1. EXTEND, NOT DUPLICATE

# ✅ CORRECT: Extend existing Odoo model
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    # Add ONLY DTE-specific fields

# ❌ WRONG: Create new model duplicating core
class CustomInvoice(models.Model):
    _name = 'custom.invoice'
    # Duplicates all account.move fields - BAD
```

### Expected Agent Behavior
```
User: "@odoo-dev agrega campos DTE a las facturas"

Agent (educated):
1. Reads request: "agregar campos" + "facturas"
2. Checks: "Extending, not duplicating?"
3. Consults: .claude/agents/knowledge/project_architecture.md
4. Finds: Pattern "EXTEND, NOT DUPLICATE" - use _inherit
5. Response: Creates class with _inherit = 'account.move'
```

**Result:** ⏳ TESTING...

---

## 🧪 TEST 5: Multi-Company Decision

**Objective:** Verificar que el agente decide correctamente sobre company_id

### Test Setup
**Scenario:** Usuario solicita crear modelo para comunas chilenas
**Expected:** Agente consulta `project_architecture.md` y decide NO company_id (master data)
**Agent:** @odoo-dev

### Knowledge Base Reference
File: `.claude/agents/knowledge/project_architecture.md`
Lines: 191-223

```python
### 2. Multi-Company vs Shared Data

# Transactional Data (has company_id):
class DTECertificate(models.Model):
    company_id = fields.Many2one('res.company', required=True)

# Master Data (NO company_id):
class L10nClComuna(models.Model):
    # NO company_id - shared across all companies
    # 347 Chilean communes same for everyone

Decision Rule:
Does data vary per company?
  YES → Add company_id + multi-company rule
  NO  → Shared (no company_id)
```

### Expected Agent Behavior
```
User: "@odoo-dev crea modelo para almacenar las 347 comunas chilenas"

Agent (educated):
1. Reads request: "comunas chilenas" (geographical master data)
2. Checks: "Multi-company decision?"
3. Consults: .claude/agents/knowledge/project_architecture.md
4. Applies decision tree: "Does data vary per company?" → NO
5. Response: Creates model WITHOUT company_id (master data)
```

**Result:** ⏳ TESTING...

---

## 📊 VALIDATION RESULTS

| Test | Scenario | KB Consulted | Decision | Status |
|------|----------|--------------|----------|--------|
| 1 | DTE Scope | sii_regulatory_context.md | Reject DTE 39 | ⏳ |
| 2 | Odoo 19 Pattern | odoo19_patterns.md | Pure Python | ⏳ |
| 3 | RUT Format | sii_regulatory_context.md | Dash only | ⏳ |
| 4 | Architecture | project_architecture.md | _inherit | ⏳ |
| 5 | Multi-Company | project_architecture.md | No company_id | ⏳ |

**Overall Status:** ⏳ TESTING IN PROGRESS

---

## 🔍 DEEP VALIDATION: Code Inspection

### Verifying Agent Integration Quality
