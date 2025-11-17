# INTEGRATION MATRIX: Odoo 19 CE + AI Microservice

## 🎯 QUICK OVERVIEW

```
TOTAL ENDPOINTS DEPLOYED:  14
ENDPOINTS ACTIVE IN ODOO:   2 (out of 14)
INTEGRATION COMPLETION:    14%

MODULES EXTENDED:          6
MODULES WITH AI CALLS:     1
INTEGRATION COMPLETION:    17%
```

---

## 📊 ENDPOINT STATUS MATRIX

| # | Endpoint | Method | Purpose | Status | Called from Odoo | Notes |
|---|----------|--------|---------|--------|------------------|-------|
| 1 | /health | GET | Health check | ✅ | ⚠️ Test only | ResConfigSettings |
| 2 | /metrics | GET | Prometheus metrics | ✅ | ❌ | Internal monitoring |
| 3 | /metrics/costs | GET | Cost tracking | ✅ | ❌ | API key required |
| 4 | /api/ai/validate | POST | DTE pre-validation | ✅ | ❌ | Ready but not called |
| 5 | /api/ai/reconcile | POST | DTE-PO reconcile | ⚠️ | ❌ | DEPRECATED |
| 6 | /api/ai/reception/match_po | POST | PO matching | ⚠️ | ⚠️ | Stub (Phase 2) |
| 7 | /api/payroll/validate | POST | Payslip validation | ✅ | ❌ | Not called |
| 8 | /api/payroll/indicators/{p} | GET | Previred extraction | ✅ | ❌ | Not called |
| 9 | /api/ai/analytics/suggest_project | POST | Project suggestion | ✅ | ❌ | Not called |
| 10 | /api/chat/message | POST | Chat message | ✅ | ❌ | Not integrated |
| 11 | /api/chat/session/new | POST | New chat session | ✅ | ❌ | Not integrated |
| 12 | /api/chat/session/{id} | GET | Get conversation | ✅ | ❌ | Not integrated |
| 13 | /api/chat/session/{id} | DELETE | Clear session | ✅ | ❌ | Not integrated |
| 14 | /api/ai/sii/monitor | POST | SII monitoring | ⚠️ | ❌ | Partial implementation |

**Legend:** ✅ = Fully implemented | ⚠️ = Partial/Stub | ❌ = Not implemented

---

## 🔌 INTEGRATION POINTS

### 2.1 DTE VALIDATION FLOW

```
┌─────────────────┐
│ AccountMoveDTE  │ Create/Edit DTE
└────────┬────────┘
         │
         ├─ [LOCAL] _validate_dte_data()
         │  • RUT validation
         │  • Type validation
         │  • Required fields
         │
         ├─ [AI-SERVICE] /api/ai/validate ❌ NOT CALLED
         │  • Semantic validation
         │  • Pattern detection
         │  • SII compliance
         │
         └─ [ODOO] _compute_fields()
            • Automatic numbering
            • Tax calculation

CALL STATUS: ❌ NO
POTENTIAL BENEFIT: 8/10 (Early error detection)
IMPLEMENTATION EFFORT: 2/10 (Method exists)
```

### 2.2 INVOICE-TO-PROJECT MATCHING

```
┌──────────────────────┐
│ AccountMove (INVOICE)│ Received from supplier
└─────────┬────────────┘
          │
          ├─ [USER] Manual project selection ❌ NOT SUGGESTED
          │
          ├─ [AI-SERVICE] /api/ai/analytics/suggest_project
          │  • Partner history analysis
          │  • Line item semantics
          │  • Project characteristics
          │  Status: ❌ NOT CALLED FROM account_move
          │  Status: ⚠️ METHOD EXISTS in DTEAIClient
          │
          └─ [DB] Link to account.analytic.account

CALL STATUS: ❌ NO
POTENTIAL BENEFIT: 9/10 (Reduce manual work)
IMPLEMENTATION EFFORT: 3/10 (Router & UI)
```

### 2.3 RECEIVED DTE MATCHING (PARTIAL)

```
┌────────────────┐
│  DTEInbox      │ Received DTE from supplier
└────────┬───────┘
         │
         ├─ [PARSE] Extract metadata
         │  • Folio, emisor, amount
         │
         └─ [AI-SERVICE] /api/ai/reception/match_po ⚠️ CALLED
            • Endpoint: ✅ Exists
            • Client: ✅ Implemented
            • Response: ⚠️ Stub (confidence=0)
            • Benefit: ❌ NO (returns dummy)

CALL STATUS: ⚠️ YES but broken
POTENTIAL BENEFIT: 7/10 (Auto-matching)
IMPLEMENTATION EFFORT: 5/10 (Phase 2 work)
```

### 2.4 PAYROLL VALIDATION FLOW

```
┌──────────────────┐
│ HrPayslip        │ Calculate payroll
└────────┬─────────┘
         │
         ├─ [LOCAL] compute_line_ids()
         │  • AFP calculation
         │  • Health deduction
         │  • Tax calculation
         │  • Gratification
         │
         ├─ [AI-SERVICE] /api/payroll/validate ❌ NOT CALLED
         │  • Logical coherence
         │  • Range validation
         │  • Legal compliance
         │
         └─ [ODOO] Store in database

CALL STATUS: ❌ NO
POTENTIAL BENEFIT: 7/10 (Error detection)
IMPLEMENTATION EFFORT: 2/10 (Method ready)
```

### 2.5 INDICATORS EXTRACTION

```
┌───────────────────────┐
│ HrEconomicIndicators  │ Monthly Previred data
└───────────┬───────────┘
            │
            ├─ [USER] Manual data entry ❌ SLOW
            │  • UF, UTM, UTA
            │  • Min wage, AFP limits
            │  • Family allowances
            │
            ├─ [AI-SERVICE] /api/payroll/indicators/{period} ⚠️ METHOD EXISTS
            │  • Endpoint: ✅ Implemented (main.py:585)
            │  • Client: ⚠️ Wrong endpoint path
            │  • Button: ❌ No UI action
            │
            └─ [DB] Store for payslip calculation

CALL STATUS: ⚠️ METHOD EXISTS but not used
POTENTIAL BENEFIT: 10/10 (Eliminates manual work)
IMPLEMENTATION EFFORT: 4/10 (Needs UI button)
```

---

## 📋 CLIENT IMPLEMENTATIONS

### AIApiClient (dte_api_client.py:121-244)

```python
✅ METHODS IMPLEMENTED

1. validate_dte(dte_data)
   Endpoint: /api/ai/validate
   Status: Ready but NOT CALLED
   
2. reconcile_invoice(dte_xml, pending_pos)
   Endpoint: /api/ai/reconcile
   Status: DEPRECATED (sentence-transformers)
   
3. health_check()
   Endpoint: /health
   Status: Used by ResConfigSettings test

ISSUES:
- No timeout on health_check (requests.exceptions caught)
- Graceful fallback returns confidence=50 (should validate this)
```

### DTEAIClient (dte_ai_client.py - AbstractModel)

```python
✅ METHODS IMPLEMENTED

1. suggest_project_for_invoice(...)
   Endpoint: /api/ai/analytics/suggest_project
   Status: Ready but NOT CALLED
   Caching: @cache_method decorator applied
   
2. validate_dte_with_ai(dte_data)
   Endpoint: /api/ai/validate_dte ❌ MISMATCH
   Status: Endpoint not in main.py
   Should be: /api/ai/validate
   
ISSUES:
- Cache decorator on async method (doesn't work)
- Endpoint path mismatch (validate_dte_with_ai)
- Method never inherited/used
```

### AIChatIntegration (ai_chat_integration.py - AbstractModel)

```python
✅ METHODS IMPLEMENTED (Read file for full list)

1. check_ai_service_health()
2. send_chat_message(session_id, message, context)
3. create_new_session(context)
4. get_conversation_history(session_id)
5. clear_session(session_id)
6. search_knowledge_base(query)

Status: Ready but NOT USED
Inheritance: AbstractModel (no model inherits it)
Called from: NOWHERE
```

---

## 🔴 CRITICAL ISSUES

### Issue 1: Endpoint Path Mismatch

**File:** dte_ai_client.py:205
```python
response = requests.post(
    f'{url}/api/ai/validate_dte',  # ← This endpoint doesn't exist!
    ...
)
```

**Correct endpoint:** `/api/ai/validate` (main.py:350)

**Impact:** If validate_dte_with_ai() is called, it will FAIL

**Fix:** Change to `/api/ai/validate`

---

### Issue 2: match_po Stub Implementation

**File:** main.py:471-476
```python
return POMatchResponse(
    matched_po_id=None,
    confidence=0.0,  # ← Always zero!
    line_matches=[],
    reasoning="Matching automático de Purchase Orders en desarrollo"
)
```

**Called from:** DTEInbox.action_validate() (dte_inbox.py)

**Impact:** Matching never works, always returns confidence=0

**Fix:** Implement complete matching logic with Claude (Phase 2)

---

### Issue 3: Wrong Endpoint in HR Module

**File:** hr_economic_indicators.py:173
```python
response = requests.post(
    f"{ai_service_url}/api/ai/payroll/previred/extract",  # ← Custom
    ...
)
```

**Correct endpoint:** `/api/payroll/indicators/{period}` (main.py:585)

**Called from:** NOWHERE (method not invoked)

**Fix:** Implement UI action to call fetch_from_ai_service()

---

### Issue 4: Misleading Documentation

**File:** hr_payslip.py:13-16
```python
"""
Liquidación de Sueldo Chile

Integra con AI-Service para cálculos y validaciones.  # ← FALSE!
"""
```

**Reality:** 
- No calls to AI Service
- Only local calculations
- Indicadores are loaded from hr.economic.indicators (which could be from AI)

**Fix:** Update docstring to be accurate

---

## 🟡 PARTIAL IMPLEMENTATIONS

### DTEInbox.action_validate()

```python
# PARTIALLY INTEGRATED
def action_validate(self):
    ...
    # Call AI Service for PO matching
    response = requests.post(
        f"{ai_service_url}/api/ai/reception/match_po",
        json=payload
    )
    
    # ✅ Endpoint is called
    # ❌ But returns confidence=0
    # ⚠️ No error handling if request fails
    # ✅ Doesn't block workflow (graceful)
```

**Status:** 1.5/5 stars (Calls endpoint but gets no useful data)

---

## 📈 INTEGRATION READINESS

### By Module

```
l10n_cl_dte:
├─ Configuration: ✅ 100%
├─ HTTP Clients: ✅ 100%
├─ Call Points: ⚠️ 10%
└─ OVERALL: 40%

l10n_cl_hr_payroll:
├─ Configuration: ⚠️ 50%
├─ HTTP Clients: ⚠️ 60%
├─ Call Points: ❌ 0%
└─ OVERALL: 20%

account.analytic:
├─ Configuration: ❌ 0%
├─ HTTP Clients: ❌ 0%
├─ Call Points: ❌ 0%
└─ OVERALL: 0%

purchase:
├─ Configuration: ❌ 0%
├─ HTTP Clients: ❌ 0%
├─ Call Points: ❌ 0%
└─ OVERALL: 0%
```

---

## 🛠️ WHAT'S NEEDED TO ACTIVATE

### Low Effort (1-2 hours each)

```
1. Add validate_dte call in AccountMoveDTE.action_send_to_sii()
   - Use existing AIApiClient
   - Add UI toggle: use_ai_validation
   - Show warnings before send

2. Add validate_payslip call in HrPayslip.action_done()
   - Use PayrollValidator
   - Show errors/warnings dialog
   - Block if critical errors

3. Fix endpoint path mismatch in dte_ai_client.py
   - Change /api/ai/validate_dte → /api/ai/validate
   - Test both methods
```

### Medium Effort (3-4 hours each)

```
4. Add "Fetch indicators" button in HrEconomicIndicators
   - Call /api/payroll/indicators/{period}
   - Parse response
   - Auto-create indicators

5. Integrate ChatEngine in account_move_dte views
   - Add chat sidebar
   - Store session per record
   - Show contextual help

6. Implement Project suggestion in PurchaseOrder receive
   - Call /api/ai/analytics/suggest_project
   - Pre-populate project field
   - Show confidence score
```

### High Effort (5+ hours each)

```
7. Complete match_po implementation (Phase 2)
   - Query pending POs from API
   - Call Claude for line matching
   - Store matching results
   - Test with real DTEs

8. SII Monitoring dashboard
   - Monitor /api/ai/sii/monitor execution
   - Display results in Odoo
   - Alert on critical changes
```

---

## 📊 IMPLEMENTATION ROADMAP

```
PHASE 0: FIX ISSUES (TODAY) - 1 hour
├─ Fix endpoint paths
├─ Update misleading docs
└─ Remove debug code

PHASE 1: ACTIVATE LOW FRUIT (THIS WEEK) - 6 hours
├─ DTE validation pre-send
├─ Payslip validation post-calc
├─ Indicator fetching from AI
└─ Test all 3

PHASE 2: MEDIUM EFFORT (NEXT WEEK) - 12 hours
├─ Project suggestion in PO
├─ Chat integration in forms
├─ Proper error handling
└─ Testing

PHASE 3: COMPLETE IMPLEMENTATIONS (MONTH 2) - 20+ hours
├─ Full match_po logic
├─ SII monitoring dashboard
├─ Analytics dashboard
└─ Performance optimization
```

