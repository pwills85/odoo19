# 🎯 DESIGN MAXIMS - EERGYGROUP Odoo 19 CE

**Status**: Production Standard v1.0
**Last Updated**: 2025-11-11
**Authority**: Senior Engineering Team
**Enforcement**: ALL agents MUST validate decisions against these maxims

---

## 📜 IMMUTABLE PRINCIPLES

These are the **foundational design principles** that guide EVERY architectural decision in this project. They are NOT negotiable and MUST be verified before implementing ANY feature.

---

## 1️⃣ MÁXIMA INTEGRACIÓN CON SUITE BASE ODOO 19 CE

### Statement

> **"Our modules EXTEND Odoo CE base suite, they do NOT duplicate or replace it."**

### Rationale

**Why This Matters:**
- ✅ Reuses battle-tested Odoo workflows (invoicing, payments, HR, accounting)
- ✅ Maintains compatibility with thousands of community modules
- ✅ Facilitates future Odoo upgrades (16 → 17 → 18 → 19 → 20+)
- ✅ Reduces maintenance burden (less code = fewer bugs)
- ✅ Leverages Odoo's 20+ years of ERP expertise

**What Happens If We Violate This:**
- ❌ Break compatibility with other modules
- ❌ Lose access to Odoo updates and security patches
- ❌ Duplicate thousands of lines of well-tested code
- ❌ Create maintenance nightmare
- ❌ Prevent clients from using other Odoo modules

### The Decision Rule

```
┌─────────────────────────────────────────────────────────┐
│ BEFORE implementing ANY feature, ask:                   │
│                                                          │
│ "Does this concept already exist in Odoo base?"         │
│                                                          │
│    ┌─────────┐                                          │
│    │   YES   │ → Use _inherit and EXTEND                │
│    └─────────┘   DO NOT create new model                │
│                                                          │
│    ┌─────────┐                                          │
│    │   NO    │ → Create new model ONLY IF:              │
│    └─────────┘   1. Truly Chilean-specific concept      │
│                  2. No Odoo equivalent exists            │
│                  3. Documented justification             │
│                  4. Senior engineer approval             │
└─────────────────────────────────────────────────────────┘
```

### Implementation Patterns

#### ✅ CORRECT: Extend Existing Models

```python
# ✅ PATTERN A: Inherit and extend
class AccountMoveDTE(models.Model):
    """
    Extends account.move with Chilean DTE (Electronic Tax Documents).

    Why _inherit:
    - Reuses ALL invoice workflows
    - Maintains compatibility with:
      * account_payment
      * account_bank_statement_import
      * sale/purchase workflows
      * Multi-currency
      * Multi-company
      * Analytic accounting
      * And 100+ other modules
    """
    _inherit = 'account.move'

    # Add ONLY DTE-specific fields
    dte_status = fields.Selection([
        ('draft', 'Draft'),
        ('sent', 'Sent to SII'),
        ('accepted', 'Accepted by SII'),
        ('rejected', 'Rejected by SII'),
    ], string='DTE Status')

    dte_folio = fields.Char(string='Folio Number')
    dte_xml = fields.Binary(string='DTE XML')
    dte_track_id = fields.Char(string='SII Track ID')

    # Extend existing methods
    def action_post(self):
        """Override to generate DTE after posting"""
        res = super().action_post()
        if self.move_type in ('out_invoice', 'out_refund'):
            self._generate_dte()
        return res

    def _generate_dte(self):
        """Chilean-specific: Generate DTE XML"""
        # Pure Chilean functionality
        pass
```

```python
# ✅ PATTERN B: Add Chilean data to existing models
class ResPartner(models.Model):
    """Extends res.partner with Chilean RUT and activity codes"""
    _inherit = 'res.partner'

    # Chilean-specific fields only
    l10n_cl_activity_description = fields.Char(
        string='Activity Description (SII)',
        help='Business activity registered with Chilean IRS',
    )

    l10n_cl_dte_email = fields.Char(
        string='DTE Email',
        help='Email for receiving electronic tax documents',
    )

    @api.constrains('vat', 'country_id')
    def _check_vat_cl(self):
        """Chilean RUT validation"""
        for partner in self:
            if partner.country_id.code == 'CL' and partner.vat:
                if not self._validate_rut_cl(partner.vat):
                    raise ValidationError('Invalid Chilean RUT')
```

#### ❌ WRONG: Duplicate Existing Models

```python
# ❌ ANTI-PATTERN: Creating parallel model
class ChileanInvoice(models.Model):
    """
    ⚠️ DO NOT DO THIS!

    Problems:
    - Duplicates ALL account.move fields
    - Breaks compatibility with:
      * Payments (account.payment expects account.move)
      * Bank reconciliation
      * Sale orders
      * Purchase orders
      * Inventory
      * And 100+ other modules
    - Creates 10,000+ lines of duplicate code
    - Impossible to upgrade
    """
    _name = 'chilean.invoice'  # ❌ BAD!

    # ❌ Duplicating core Odoo fields
    partner_id = fields.Many2one('res.partner')
    invoice_date = fields.Date()
    amount_total = fields.Monetary()
    state = fields.Selection([...])

    # Even if you add Chilean fields:
    dte_folio = fields.Char()

    # You've now created a maintenance nightmare!
```

#### ❌ WRONG: Creating Custom Workflows

```python
# ❌ ANTI-PATTERN: Custom payment workflow
class ChileanPayment(models.Model):
    _name = 'chilean.payment'  # ❌ BAD!

    # Why this is wrong:
    # - account.payment already handles:
    #   * Multi-currency
    #   * Bank reconciliation
    #   * Payment methods
    #   * Batch payments
    #   * Payment follow-ups
    # - You'd have to reimplement ALL of this
    # - Incompatible with bank statement imports
    # - Can't use Odoo's payment acquirers
```

### When Creating New Models IS Allowed

**Scenario 1: Chilean-Specific Master Data**

```python
# ✅ OK: Chilean communes (don't exist in Odoo)
class L10nClComuna(models.Model):
    """
    Chilean administrative divisions (communes).

    Justification:
    - No Odoo equivalent (country.state is for regions)
    - Required by SII for address validation
    - 347 communes defined by Chilean government
    - Master data shared across companies
    """
    _name = 'l10n.cl.comuna'
    _description = 'Chilean Commune'

    code = fields.Char(required=True)
    name = fields.Char(required=True)
    state_id = fields.Many2one('res.country.state')
```

**Scenario 2: Chilean Tax Authority Objects**

```python
# ✅ OK: CAF (Código de Autorización de Folios)
class DTECAF(models.Model):
    """
    SII Certificate of Folio Authorization.

    Justification:
    - Pure Chilean concept (no international equivalent)
    - Issued by SII (Chilean IRS)
    - Contains cryptographic signatures
    - Company-specific (has company_id)
    """
    _name = 'dte.caf'
    _description = 'DTE CAF (Folio Authorization)'

    company_id = fields.Many2one('res.company', required=True)
    document_type = fields.Selection([...])
    folio_start = fields.Integer()
    folio_end = fields.Integer()
```

**Scenario 3: Chilean-Specific Transactional Objects**

```python
# ✅ OK: Libro de Ventas (SII Sales Book)
class L10nClLibroVentas(models.Model):
    """
    Chilean Monthly Sales Book (required by SII).

    Justification:
    - Chilean regulatory requirement
    - No Odoo equivalent
    - Aggregates multiple invoices
    - Must be submitted to SII monthly
    - Different from standard accounting reports
    """
    _name = 'l10n.cl.libro.ventas'
    _description = 'Chilean Sales Book (Libro de Ventas)'

    company_id = fields.Many2one('res.company', required=True)
    period_month = fields.Selection([...])
    period_year = fields.Integer()

    # Relates to invoices (doesn't replace them)
    invoice_ids = fields.Many2many('account.move')
```

### Validation Checklist

Before creating ANY new model, verify:

- [ ] **Search Odoo base**: Did you search existing models?
  ```python
  self.env['ir.model'].search([('name', 'ilike', 'concept')])
  ```

- [ ] **Check inheritance**: Can you use `_inherit` instead?

- [ ] **Document why**: Write justification in docstring

- [ ] **Get approval**: Senior engineer review required

- [ ] **Verify compatibility**: Will this break other modules?

- [ ] **Plan migration**: How will this upgrade to Odoo 20+?

---

## 2️⃣ INTEGRACIÓN APROPIADA CON MICROSERVICIO IA

### Statement

> **"Critical path uses native Python libs/, non-critical features use AI Service."**

### Rationale

**Architecture Evolution:**

We migrated from microservices to native libs/ in Phase 2 (Oct 2024) because:

```
❌ BEFORE (Phase 1: Microservices)
┌──────────────┐
│  Odoo 19 CE  │
│              │
│  l10n_cl_dte │
└──────┬───────┘
       │ HTTP (100-200ms overhead)
       │ Network latency
       │ Reliability issues
       ▼
┌──────────────┐
│ AI Service   │
│ (FastAPI)    │
└──────────────┘

Problems:
- Every DTE signature: 100-200ms HTTP overhead
- Network failures break critical workflows
- Complex deployment (2 services to manage)
- Testing requires mocks for AI service
```

```
✅ AFTER (Phase 2: Native libs/)
┌──────────────────────────────────┐
│         Odoo 19 CE               │
│                                  │
│  ┌────────────────────────────┐  │
│  │  l10n_cl_dte               │  │
│  │                            │  │
│  │  models/ ←─── libs/        │  │
│  │  (ORM)       (Pure Python) │  │
│  └────────────────────────────┘  │
│                                  │
│  AI Service (FastAPI)            │
│  └─ NON-critical only:           │
│     - Chat                       │
│     - Analytics                  │
│     - ML predictions             │
└──────────────────────────────────┘

Benefits:
- ✅ No HTTP overhead (100-200ms faster)
- ✅ No network dependencies
- ✅ Simpler deployment (single container)
- ✅ More reliable
- ✅ Easier testing
```

### The Decision Rule

```
┌─────────────────────────────────────────────────────────┐
│ BEFORE using AI Service, ask:                           │
│                                                          │
│ "Is this feature on the CRITICAL PATH?"                 │
│                                                          │
│  Critical Path = Required for core business workflow    │
│                                                          │
│    ┌──────────────┐                                     │
│    │     YES      │ → Use libs/ (Pure Python)           │
│    │  (Critical)  │   NO AI Service                     │
│    └──────────────┘                                     │
│    Examples:                                            │
│    • DTE signature                                      │
│    • DTE validation                                     │
│    • SII communication                                  │
│    • Tax calculations                                   │
│    • CAF management                                     │
│                                                          │
│    ┌──────────────┐                                     │
│    │      NO      │ → Can use AI Service                │
│    │(Non-critical)│   (Optional HTTP call)              │
│    └──────────────┘                                     │
│    Examples:                                            │
│    • AI Chat (Previred questions)                       │
│    • ML predictions (project matching)                  │
│    • Analytics dashboards                               │
│    • Cost tracking                                      │
│    • Smart suggestions                                  │
└─────────────────────────────────────────────────────────┘
```

### Implementation Patterns

#### ✅ CORRECT: Critical Path in libs/

```python
# ✅ libs/xml_signer.py - Critical path
"""
DTE XML Digital Signature.

This is CRITICAL PATH - must be fast and reliable.
Therefore: Pure Python in libs/, NO microservice.
"""

class XMLSigner:
    """
    Signs DTE XML with XMLDSig (RSA + SHA256).

    Critical because:
    - Required for EVERY invoice
    - SII rejects unsigned DTEs
    - Must be fast (<50ms)
    - Must be 100% reliable

    Architecture: Native Python libs/
    - No HTTP overhead
    - No network failures
    - Synchronous and predictable
    """

    def __init__(self, env=None):
        """Inject env for certificate DB access"""
        self.env = env

    def sign_xml_dte(self, xml_string, certificate_id):
        """
        Signs XML in <50ms using lxml + cryptography.

        This is 100-200ms faster than calling AI Service.
        """
        from lxml import etree
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        # Pure Python cryptography
        # No HTTP, no network, no failures
        signed_xml = self._apply_xmldsig(xml_string, certificate_id)
        return signed_xml
```

```python
# ✅ libs/caf_signature_validator.py - Critical path
"""
CAF Digital Signature Validation.

Critical because:
- Validates cryptographic signatures from SII
- Prevents unauthorized invoicing
- Security-critical operation
"""

class CAFSignatureValidator:
    """Pure Python signature validation"""

    def validate_caf_signature(self, caf_xml):
        """
        Validates CAF signature against SII public key.

        Must be in libs/ because:
        - Security-critical
        - Must work offline
        - No tolerance for network failures
        """
        # Use cryptography library (pure Python)
        # No AI Service involvement
```

#### ✅ CORRECT: Non-Critical in AI Service

```python
# ✅ models/hr_contract.py - AI integration for non-critical
class HrContract(models.Model):
    _inherit = 'hr.contract'

    def action_ai_chat_previred(self):
        """
        Open AI chat for Previred questions.

        Non-critical because:
        - Optional feature (nice-to-have)
        - User can still work if AI is down
        - Not required for payroll calculation
        - Just enhances UX
        """
        try:
            # Call AI Service (can fail gracefully)
            response = self._call_ai_service_chat()
            return self._display_chat_dialog(response)
        except Exception as e:
            # If AI Service is down, just notify user
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': 'AI Chat temporarily unavailable',
                    'type': 'warning',
                }
            }

    def _call_ai_service_chat(self):
        """HTTP call to AI Service - can fail"""
        import requests
        # Optional HTTP call
        # If fails: user can still use Odoo normally
```

```python
# ✅ models/project_project.py - ML prediction (non-critical)
class ProjectProject(models.Model):
    _inherit = 'project.project'

    def action_predict_cost(self):
        """
        ML prediction for project cost.

        Non-critical because:
        - Just a suggestion (not binding)
        - User can manually enter cost
        - Analytics feature (not required)
        """
        try:
            prediction = self._get_ml_prediction()
            self.predicted_cost = prediction
        except:
            # If ML service down: no problem
            # User just won't see prediction
            pass
```

#### ❌ WRONG: Critical Path via AI Service

```python
# ❌ ANTI-PATTERN: DTE signature via microservice
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    def action_generate_dte(self):
        """
        ⚠️ DO NOT DO THIS!

        Calling AI Service for DTE signature is WRONG because:
        - Adds 100-200ms HTTP overhead per invoice
        - Network failures break invoicing
        - AI Service outage = business stops
        - Makes deployment complex
        - Testing requires mocks
        """
        # ❌ BAD: HTTP call for critical operation
        try:
            response = requests.post(
                'http://ai-service:8000/sign-dte',
                json={'xml': self.dte_xml},
                timeout=10,
            )
            self.dte_xml_signed = response.json()['signed_xml']
        except requests.RequestException:
            # ❌ Critical workflow blocked by network!
            raise UserError('Cannot generate DTE: AI Service unavailable')
```

### Critical vs Non-Critical Classification

#### 🔴 CRITICAL PATH (Use libs/)

**Definition**: Feature required for core business operations.

**Characteristics**:
- ✅ Blocking workflow if fails
- ✅ Must work offline
- ✅ Must be fast (<100ms)
- ✅ Must be 100% reliable
- ✅ No tolerance for network issues

**Examples**:

```python
# DTE Module
✓ DTE XML generation          → libs/xml_generator.py
✓ DTE signature               → libs/xml_signer.py
✓ CAF validation              → libs/caf_signature_validator.py
✓ RUT validation              → libs/rut_validator.py
✓ SII SOAP client             → libs/sii_soap_client.py
✓ XML structure validation    → libs/dte_structure_validator.py

# Payroll Module
✓ Salary calculations         → libs/payroll_calculator.py
✓ Tax withholding             → libs/tax_calculator.py
✓ Social security             → libs/previred_calculator.py
✓ Legal minimum validation    → libs/minimum_wage_validator.py

# Financial Reports
✓ F29 generation             → libs/f29_generator.py
✓ F50 generation             → libs/f50_generator.py
✓ Balance sheet              → native Odoo (account.report)
```

#### 🟢 NON-CRITICAL PATH (Can Use AI Service)

**Definition**: Enhancement features that improve UX but aren't required.

**Characteristics**:
- ✅ Optional feature (nice-to-have)
- ✅ Business continues if unavailable
- ✅ Can degrade gracefully
- ✅ Acceptable latency (>200ms OK)
- ✅ Network failures tolerated

**Examples**:

```python
# AI Chat Features
✓ Previred Q&A chatbot        → AI Service (optional)
✓ Tax regulation explanations → AI Service (optional)
✓ Document search             → AI Service (optional)

# ML Predictions
✓ Project cost estimation     → AI Service (suggestions)
✓ Invoice approval prediction → AI Service (suggestions)
✓ Employee churn prediction   → AI Service (analytics)

# Analytics
✓ Cost tracking dashboard     → AI Service (visualization)
✓ Anomaly detection           → AI Service (alerts)
✓ Smart suggestions           → AI Service (recommendations)
```

### Migration Path (If Currently Using AI Service for Critical Path)

If you find critical operations using AI Service:

**Step 1: Identify Critical Operations**
```bash
# Search for critical paths calling AI Service
grep -r "requests.post.*ai-service" addons/
```

**Step 2: Migrate to libs/**
```python
# BEFORE (via AI Service)
response = requests.post('http://ai-service/sign', ...)
xml_signed = response.json()['xml']

# AFTER (via libs/)
from addons.l10n_cl_dte.libs.xml_signer import XMLSigner
signer = XMLSigner(self.env)
xml_signed = signer.sign_xml_dte(xml, cert_id)
```

**Step 3: Test Performance**
```python
import time

# Before migration
start = time.time()
# ... AI Service call
print(f"AI Service: {(time.time() - start) * 1000}ms")
# Typical: 150-250ms

# After migration
start = time.time()
# ... libs/ call
print(f"libs/: {(time.time() - start) * 1000}ms")
# Typical: 20-50ms (3-5x faster!)
```

**Step 4: Update Tests**
```python
# BEFORE: Need to mock HTTP
@patch('requests.post')
def test_dte_generation(self, mock_post):
    mock_post.return_value = Mock(json=...)
    # Complex mocking

# AFTER: Direct testing
def test_dte_generation(self):
    # No mocks needed - pure Python
    result = signer.sign_xml_dte(xml, cert_id)
    self.assertTrue(result)
```

### Validation Checklist

Before integrating with AI Service:

- [ ] **Is this critical path?** If YES → use libs/, NOT AI Service

- [ ] **Can business continue without it?** If NO → use libs/

- [ ] **Is <100ms latency required?** If YES → use libs/

- [ ] **Must work offline?** If YES → use libs/

- [ ] **Security-critical?** If YES → use libs/

- [ ] **Documented justification:** Why AI Service is appropriate

- [ ] **Graceful degradation:** What happens if AI Service is down?

- [ ] **Performance tested:** Is latency acceptable?

---

## 🔍 VALIDATION FRAMEWORK

### Pre-Implementation Checklist

For EVERY feature, before writing code:

```
□ Design Maxim #1 Validated:
  □ Searched Odoo base for existing models
  □ Using _inherit if concept exists
  □ Documented why new model if creating one
  □ Senior engineer approved new model

□ Design Maxim #2 Validated:
  □ Classified as critical or non-critical
  □ Critical path → libs/ (Pure Python)
  □ Non-critical → Can use AI Service
  □ Graceful degradation implemented

□ Architecture Review:
  □ Aligns with project_architecture.md
  □ Follows odoo19_patterns.md
  □ Compatible with existing modules
  □ Migration path documented
```

### Code Review Checklist

For code reviewers:

```
□ Maxim #1: Odoo Integration
  □ Uses _inherit where appropriate
  □ Not duplicating Odoo base
  □ Maintains compatibility
  □ Reuses existing workflows

□ Maxim #2: AI Integration
  □ Critical path in libs/
  □ AI Service only for non-critical
  □ Performance acceptable
  □ Handles failures gracefully

□ Quality Standards:
  □ Tests cover critical paths (>80%)
  □ Documentation complete
  □ Security validated
  □ Performance benchmarked
```

### Enforcement

**How These Maxims Are Enforced:**

1. **Agent Configuration**
   - All agents reference this document
   - Agents validate decisions against maxims
   - Automatic checks in hooks

2. **Code Review**
   - Senior engineer approval required
   - Checklist must be completed
   - CI/CD gates enforce compliance

3. **Testing**
   - Integration tests verify Odoo compatibility
   - Performance tests catch AI Service overuse
   - Security tests validate critical paths

4. **Documentation**
   - All modules reference design maxims
   - Architecture decisions documented
   - Migration guides maintained

---

## 📚 REFERENCES

### Internal Documentation

- **Project Architecture**: `.claude/agents/knowledge/project_architecture.md`
- **Odoo 19 Patterns**: `.claude/agents/knowledge/odoo19_patterns.md`
- **SII Compliance**: `.claude/agents/knowledge/sii_regulatory_context.md`

### External Resources

- **Odoo Development**: https://www.odoo.com/documentation/19.0/developer.html
- **Odoo Model Inheritance**: https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html#model-reference
- **Chilean SII**: https://www.sii.cl

### Agent Integration

All agents MUST load this document and validate against it:

```python
# In agent prompt
**MANDATORY: Read Design Maxims**
Before ANY architectural decision:
1. Read .claude/DESIGN_MAXIMS.md
2. Validate against Maxim #1 (Odoo Integration)
3. Validate against Maxim #2 (AI Integration)
4. Document compliance in commit message
```

---

## 🎯 SUCCESS CRITERIA

**A feature respects these maxims when:**

✅ **Maxim #1: Odoo Integration**
- Uses `_inherit` for existing concepts
- Creates new models only with justification
- Maintains compatibility with Odoo base
- Reuses existing workflows
- Senior engineer approved

✅ **Maxim #2: AI Integration**
- Critical path uses libs/ (pure Python)
- AI Service only for non-critical
- Handles AI Service failures gracefully
- Performance benchmarked and acceptable
- Architecture decision documented

---

**Version**: 1.0.0
**Status**: Production Standard
**Authority**: EERGYGROUP Senior Engineering Team
**Last Review**: 2025-11-11
**Next Review**: 2025-12-11

---

*These maxims are the foundation of our architecture. They ensure our codebase remains maintainable, upgradeable, and reliable for years to come.*
