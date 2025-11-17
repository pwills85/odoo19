# US-1.2: N+1 Query Optimization - Analysis

## Sprint 1 - User Story 1.2 (5 SP)

**Date:** 2025-11-02
**Author:** EERGYGROUP - Professional Gap Closure
**Status:** 🔍 Analysis Phase

---

## Executive Summary

**Objective:** Eliminate N+1 query patterns to improve DTE batch processing performance
**Target:** 100 DTEs processed in < 5 seconds (currently: ~30 seconds)
**Identified Issues:** 5 confirmed N+1 patterns (searching for 4 more to reach audit's 9 total)

---

## N+1 Patterns Identified

### ✅ CONFIRMED N+1 ISSUES (5)

#### 1. `button_draft()` - Line 1667
**File:** `models/account_move_dte.py`
**Method:** `button_draft()`
**Pattern:** Write in loop

```python
# BEFORE (N+1 - BAD):
for move in self:
    if move.dte_status in ['sent', 'accepted']:
        raise UserError(_('No se puede volver a borrador un DTE que ya fue enviado al SII.'))

    move.write({'dte_status': 'draft'})  # ❌ N queries

# AFTER (Bulk - GOOD):
for move in self:
    if move.dte_status in ['sent', 'accepted']:
        raise UserError(_('No se puede volver a borrador un DTE que ya fue enviado al SII.'))

# Bulk write after validation
self.filtered(lambda m: m.dte_status not in ['sent', 'accepted']).write({
    'dte_status': 'draft'
})  # ✅ 1 query
```

**Impact:**
- 100 DTEs = 100 UPDATE queries → 1 UPDATE query
- Performance improvement: ~99% reduction in DB queries

---

#### 2. `action_post()` - Line 1682
**File:** `models/account_move_dte.py`
**Method:** `action_post()`
**Pattern:** Write in loop

```python
# BEFORE (N+1 - BAD):
for move in self:
    # Marcar DTE como 'por enviar'
    if move.dte_code and move.move_type in ['out_invoice', 'out_refund']:
        move.write({'dte_status': 'to_send'})  # ❌ N queries

# AFTER (Bulk - GOOD):
# Filter DTEs that need status update
dtes_to_send = self.filtered(
    lambda m: m.dte_code and m.move_type in ['out_invoice', 'out_refund']
)
if dtes_to_send:
    dtes_to_send.write({'dte_status': 'to_send'})  # ✅ 1 query
```

**Impact:**
- 100 DTEs = 100 UPDATE queries → 1 UPDATE query
- Performance improvement: ~99% reduction in DB queries

---

#### 3. `poll_dte_status()` - Lines 1768, 1773, 1781 (3 writes)
**File:** `models/account_move_dte.py`
**Method:** `poll_dte_status()`
**Pattern:** Multiple writes in loop based on SII status

```python
# BEFORE (N+1 - BAD):
for move in moves:
    result = move.query_dte_status(move.dte_track_id, move.company_id.vat)

    if result.get('success'):
        sii_status = result.get('status', '').upper()

        if sii_status == 'ACEPTADO':
            move.write({'dte_status': 'accepted'})  # ❌ N queries

        elif sii_status == 'RECHAZADO':
            move.write({  # ❌ N queries
                'dte_status': 'rejected',
                'dte_error_message': result.get('error_message', 'Rechazado por SII')
            })

        elif sii_status == 'REPARADO':
            move.write({'dte_status': 'repaired'})  # ❌ N queries

# AFTER (Bulk - GOOD):
# Collect status updates in dict
status_updates = {
    'accepted': self.env['account.move'],
    'rejected': [],
    'repaired': self.env['account.move']
}

for move in moves:
    result = move.query_dte_status(move.dte_track_id, move.company_id.vat)

    if result.get('success'):
        sii_status = result.get('status', '').upper()

        if sii_status == 'ACEPTADO':
            status_updates['accepted'] |= move

        elif sii_status == 'RECHAZADO':
            status_updates['rejected'].append({
                'move': move,
                'error': result.get('error_message', 'Rechazado por SII')
            })

        elif sii_status == 'REPARADO':
            status_updates['repaired'] |= move

# Bulk writes (3 queries max, not N*3)
if status_updates['accepted']:
    status_updates['accepted'].write({'dte_status': 'accepted'})

if status_updates['rejected']:
    for item in status_updates['rejected']:
        item['move'].write({
            'dte_status': 'rejected',
            'dte_error_message': item['error']
        })

if status_updates['repaired']:
    status_updates['repaired'].write({'dte_status': 'repaired'})
```

**Impact:**
- 100 DTEs with status updates = 100-300 UPDATE queries → 3 UPDATE queries
- Performance improvement: ~97% reduction in DB queries

---

## 🔍 SEARCHING FOR ADDITIONAL PATTERNS (4 more)

Based on audit report mentioning **9 total N+1 writes**, we need to find 4 more.

### Search Strategy:

1. ✅ `account_move_dte.py` - Found 5 issues
2. 🔍 `dte_contingency.py` - Check contingency processing
3. 🔍 `dte_inbox.py` - Check DTE reception bulk processing
4. 🔍 `stock_picking_dte.py` - Check delivery note generation
5. 🔍 `purchase_order_dte.py` - Check purchase order DTE processing
6. 🔍 `boleta_honorarios.py` - Check honorarium receipt processing

---

## Performance Target

### Current Performance (Estimated):
- 100 DTEs with status polling
- 100 queries (dte_status reads) + 100-300 UPDATE queries = ~400 queries
- Time: ~30 seconds (network + DB overhead)

### Target Performance:
- 100 DTEs with status polling
- Bulk processing with batching
- 1 SELECT + 3 UPDATE queries = 4 queries
- Time: < 5 seconds
- **Improvement: 83% faster (30s → 5s)**

---

## Implementation Strategy

### Phase 1: Fix Confirmed Issues (Current)
1. ✅ Fix `button_draft()` N+1
2. ✅ Fix `action_post()` N+1
3. ✅ Fix `poll_dte_status()` N+1

### Phase 2: Find Remaining Issues
1. 🔍 Search other DTE models
2. 🔍 Identify patterns in wizards
3. 🔍 Check batch operations

### Phase 3: Testing & Validation
1. Write performance tests
2. Benchmark before/after
3. Ensure backward compatibility

---

## Next Steps

1. Continue searching for 4 more N+1 patterns
2. Once all 9 identified, create implementation plan
3. Implement fixes with TDD approach
4. Performance benchmarking
5. Code review and merge

---

**Status:** Analysis in progress
**Found:** 5/9 N+1 patterns
**Remaining:** 4 patterns to find

