# Performance & Scalability Readiness Plan
## Phoenix (UI) & Quantum (Financial Reports) - Odoo 19 CE-Pro

**Version:** 1.0
**Date:** 2025-11-08
**Status:** Pre-Implementation Planning (Phase I)
**Target Stack:** Odoo 19 CE + PostgreSQL 15 + Redis 7 + AI Microservice

---

## Executive Summary

This document defines Service Level Agreements (SLAs), optimization strategies, testing methodology, and monitoring architecture for Phoenix (UI) and Quantum (Financial Reports) projects. The goal is to ensure enterprise-grade performance and horizontal scalability for EERGYGROUP's Odoo 19 CE-Pro stack.

**Key Performance Targets:**
- UI Operations: p95 < 2s (list/form/kanban views)
- Financial Reports: < 10s for 100k account.move.line records
- XLSX Export: < 15s for large datasets
- Drilldown Navigation: < 3s per level
- Database Query Time: p95 < 500ms
- Frontend Bundle Load: < 1.5s (TTI)

**Architecture Foundation:**
- PostgreSQL 15 with optimized indexing
- Redis 7 for caching and session management
- Multi-worker Odoo deployment (4-8 workers)
- OWL-based frontend with virtual scrolling
- AI microservice with token optimization

---

## 1. Service Level Agreements (SLAs)

### 1.1 Backend Operations

| Operation | Target (p95) | Target (p99) | Max Acceptable | Priority |
|-----------|--------------|--------------|----------------|----------|
| **Quantum - Financial Reports** |
| Balance Sheet (10k lines) | < 3s | < 5s | 8s | P0 |
| Balance Sheet (100k lines) | < 10s | < 15s | 20s | P0 |
| Profit & Loss (10k lines) | < 3s | < 5s | 8s | P0 |
| Profit & Loss (100k lines) | < 10s | < 15s | 20s | P0 |
| Comparative Report (YTD/PY) | < 5s | < 8s | 12s | P1 |
| XLSX Export (10k rows) | < 5s | < 8s | 10s | P0 |
| XLSX Export (100k rows) | < 15s | < 20s | 30s | P1 |
| Drilldown to account.move.line | < 2s | < 3s | 5s | P0 |
| Cached Report Retrieval | < 500ms | < 1s | 2s | P0 |
| **Phoenix - UI Operations** |
| List View (100 records) | < 1s | < 1.5s | 3s | P0 |
| List View (1000 records) | < 2s | < 3s | 5s | P1 |
| Form View Open | < 1.5s | < 2s | 4s | P0 |
| Kanban View (50 cards) | < 1.5s | < 2s | 4s | P0 |
| Search/Filter Application | < 1s | < 1.5s | 3s | P0 |
| Dashboard Load (6 widgets) | < 2s | < 3s | 5s | P1 |
| **Database Queries** |
| Simple SELECT (indexed) | < 50ms | < 100ms | 200ms | P0 |
| Complex JOIN (3 tables) | < 200ms | < 500ms | 1s | P0 |
| Aggregation (read_group) | < 300ms | < 800ms | 1.5s | P0 |
| Full-text search | < 500ms | < 1s | 2s | P1 |

### 1.2 Frontend Operations

| Operation | Target (p95) | Target (p99) | Max Acceptable | Priority |
|-----------|--------------|--------------|----------------|----------|
| **Page Load** |
| Time to Interactive (TTI) | < 1.5s | < 2s | 3s | P0 |
| First Contentful Paint (FCP) | < 800ms | < 1.2s | 2s | P0 |
| Largest Contentful Paint (LCP) | < 1.2s | < 1.8s | 2.5s | P0 |
| **Interactions** |
| Button Click Response | < 100ms | < 200ms | 500ms | P0 |
| Filter/Search Debounced | < 300ms | < 500ms | 1s | P0 |
| Virtual Scroll (1000 rows) | < 100ms | < 200ms | 500ms | P0 |
| **Assets** |
| JS Bundle Size | < 500KB | < 750KB | 1MB | P1 |
| CSS Bundle Size | < 200KB | < 300KB | 500KB | P1 |
| Total Bundle Load Time | < 1s | < 1.5s | 2s | P0 |

### 1.3 Availability & Reliability

| Metric | Target | Measurement |
|--------|--------|-------------|
| Uptime (Monthly) | 99.5% | Prometheus + Grafana |
| Error Rate | < 0.5% | Application logs + APM |
| Database Availability | 99.9% | PostgreSQL health checks |
| Cache Hit Ratio (Redis) | > 80% | Redis INFO stats |
| Mean Time to Recovery (MTTR) | < 30 min | Incident logs |

---

## 2. Optimization Strategies

### 2.1 Backend Optimizations

#### 2.1.1 Database Indexing Strategy

**Critical Indexes for Quantum Reports:**

```sql
-- account.move.line: Core accounting data
CREATE INDEX idx_aml_account_date
ON account_move_line(account_id, date)
WHERE parent_state = 'posted';

CREATE INDEX idx_aml_company_date
ON account_move_line(company_id, date, account_id)
WHERE parent_state = 'posted';

CREATE INDEX idx_aml_analytic_date
ON account_move_line(analytic_distribution, date)
WHERE parent_state = 'posted' AND analytic_distribution IS NOT NULL;

CREATE INDEX idx_aml_journal_date
ON account_move_line(journal_id, date)
WHERE parent_state = 'posted';

-- account.account: Chart of accounts with hierarchy
CREATE INDEX idx_account_parent_path
ON account_account USING GIN(parent_path);

CREATE INDEX idx_account_company_code
ON account_account(company_id, code);

-- account.move: Invoice/payment headers
CREATE INDEX idx_move_partner_date
ON account_move(partner_id, date)
WHERE state = 'posted';

CREATE INDEX idx_move_journal_date
ON account_move(journal_id, date, move_type)
WHERE state = 'posted';
```

**Index Maintenance:**

```python
# models/account_report_engine.py (Quantum)

def _ensure_indexes_exist(self):
    """
    Verify critical indexes exist for performance.
    Run during module installation or via ir.cron weekly.
    """
    self.env.cr.execute("""
        SELECT schemaname, tablename, indexname
        FROM pg_indexes
        WHERE tablename IN ('account_move_line', 'account_account', 'account_move')
        AND indexname LIKE 'idx_%';
    """)
    existing = {row[2] for row in self.env.cr.fetchall()}

    required = {
        'idx_aml_account_date',
        'idx_aml_company_date',
        'idx_account_parent_path',
        'idx_move_partner_date'
    }

    missing = required - existing
    if missing:
        _logger.warning(f"Missing performance indexes: {missing}")
        # Log to odoo.exceptions for sysadmin alert
```

#### 2.1.2 ORM Optimization Patterns

**Pattern 1: Batch read_group vs Sequential Queries**

```python
# ❌ BAD: N+1 queries
def get_balances_slow(self, account_ids):
    balances = {}
    for account in account_ids:
        lines = self.env['account.move.line'].search([
            ('account_id', '=', account.id),
            ('date', '>=', self.date_from),
            ('date', '<=', self.date_to),
        ])
        balances[account.id] = sum(lines.mapped('balance'))
    return balances

# ✅ GOOD: Single read_group
def get_balances_fast(self, account_ids):
    domain = [
        ('account_id', 'in', account_ids.ids),
        ('date', '>=', self.date_from),
        ('date', '<=', self.date_to),
        ('parent_state', '=', 'posted'),
    ]

    result = self.env['account.move.line'].read_group(
        domain,
        ['account_id', 'debit', 'credit', 'balance'],
        ['account_id'],
        lazy=False
    )

    return {
        r['account_id'][0]: r['balance']
        for r in result
    }
```

**Pattern 2: Use search_fetch (Odoo 19 New API)**

```python
# Odoo 19 search_fetch: More efficient than search + read
def get_account_data(self, account_ids):
    """
    search_fetch combines search + read in single query.
    ~30% faster than search().read() for large datasets.
    """
    accounts = self.env['account.account'].search_fetch(
        [('id', 'in', account_ids.ids)],
        ['code', 'name', 'parent_path', 'account_type']
    )
    return accounts
```

**Pattern 3: Prefetch and Avoid Lazy Evaluation**

```python
# ✅ GOOD: Prefetch related data
def generate_report_lines(self, account_ids):
    # Prefetch all accounts and parents in one query
    accounts = account_ids.with_context(prefetch_fields=True)
    accounts.mapped('parent_id')  # Load parents

    lines = []
    for account in accounts:
        # No additional queries for parent_id
        lines.append({
            'account': account.name,
            'parent': account.parent_id.name,  # Already loaded
        })
    return lines
```

#### 2.1.3 Caching Strategy (Redis)

**Three-Layer Cache Architecture:**

```python
# models/account_report_cache.py

import hashlib
import json
from odoo import models, fields, api
from odoo.tools import ormcache

class AccountReportCache(models.Model):
    _name = 'account.report.cache'
    _description = 'Financial Report Cache'

    # Layer 1: Database cache (persistent)
    params_hash = fields.Char(index=True, required=True)
    report_type = fields.Char(index=True)
    payload = fields.Text()  # JSON
    create_date = fields.Datetime(index=True)
    ttl_hours = fields.Integer(default=24)

    @api.model
    def get_cached_report(self, report_type, params):
        """
        Check cache layers in order:
        1. ORM Cache (ormcache decorator)
        2. Redis (fast, in-memory)
        3. Database (persistent)
        """
        cache_key = self._compute_cache_key(report_type, params)

        # Layer 1: Try ORM cache (fastest)
        cached = self._get_from_orm_cache(cache_key)
        if cached:
            return cached

        # Layer 2: Try Redis (fast)
        cached = self._get_from_redis(cache_key)
        if cached:
            return cached

        # Layer 3: Try database (slower)
        cached = self._get_from_db(cache_key)
        if cached:
            # Warm up upper layers
            self._set_to_redis(cache_key, cached)
            return cached

        return None

    @ormcache('cache_key')
    def _get_from_orm_cache(self, cache_key):
        """ORM cache (memory, process-local)"""
        return None  # Populated by decorator on first miss

    def _get_from_redis(self, cache_key):
        """Redis cache (memory, shared across workers)"""
        try:
            import redis
            r = redis.Redis(host='redis', port=6379, db=1)
            cached = r.get(f'report:{cache_key}')
            if cached:
                return json.loads(cached)
        except Exception as e:
            _logger.warning(f"Redis cache miss: {e}")
        return None

    def _set_to_redis(self, cache_key, data, ttl=3600):
        """Set Redis cache with TTL"""
        try:
            import redis
            r = redis.Redis(host='redis', port=6379, db=1)
            r.setex(
                f'report:{cache_key}',
                ttl,
                json.dumps(data)
            )
        except Exception as e:
            _logger.error(f"Redis cache write failed: {e}")

    def _get_from_db(self, cache_key):
        """Database cache (persistent)"""
        cache = self.search([
            ('params_hash', '=', cache_key),
            ('create_date', '>', fields.Datetime.now() - timedelta(hours=24))
        ], limit=1)

        if cache:
            return json.loads(cache.payload)
        return None

    @staticmethod
    def _compute_cache_key(report_type, params):
        """Generate stable hash for cache key"""
        # Sort dict for stable hash
        stable = json.dumps(params, sort_keys=True)
        return hashlib.sha256(
            f"{report_type}:{stable}".encode()
        ).hexdigest()
```

**Cache Invalidation Strategy:**

```python
# models/account_move.py (DTE module)

def write(self, vals):
    """Invalidate report cache on accounting changes"""
    res = super().write(vals)

    # Invalidate if posted state changes or amounts change
    if 'state' in vals or any(k in vals for k in ['debit', 'credit', 'balance']):
        self.env['account.report.cache']._invalidate_cache(
            company_id=self.company_id.id,
            date_range=(self.date, self.date)
        )

    return res
```

#### 2.1.4 Pagination and Lazy Loading

```python
# models/account_report_engine.py

def compute_report_paginated(self, params, page=1, page_size=50):
    """
    Generate report with server-side pagination.
    Frontend loads pages on demand (infinite scroll).
    """
    offset = (page - 1) * page_size

    # Get total count (cached)
    total_lines = self._count_report_lines(params)

    # Fetch only requested page
    lines = self._fetch_report_lines(
        params,
        limit=page_size,
        offset=offset
    )

    return {
        'lines': lines,
        'total': total_lines,
        'page': page,
        'page_size': page_size,
        'has_more': (offset + page_size) < total_lines
    }
```

#### 2.1.5 Parent Path for Hierarchies

```python
# models/account_account.py (already in Odoo core)

# ✅ GOOD: Use parent_path for hierarchy queries
def get_children_fast(self, account_id):
    """
    parent_path enables O(1) hierarchy queries.
    Example parent_path: '1/5/12/' means account 12 -> 5 -> 1
    """
    account = self.env['account.account'].browse(account_id)

    # Get all descendants in single query
    children = self.env['account.account'].search([
        ('parent_path', '=like', f'{account.parent_path}%')
    ])

    return children

# ❌ BAD: Recursive queries (N queries for N levels)
def get_children_slow(self, account_id):
    account = self.env['account.account'].browse(account_id)
    children = account.child_ids
    for child in children:
        children |= self.get_children_slow(child.id)  # Recursive!
    return children
```

---

### 2.2 Frontend Optimizations

#### 2.2.1 Virtual Scrolling (OWL Component)

```javascript
// static/src/components/virtual_list/virtual_list.js

/** @odoo-module **/
import { Component, useState, onMounted, onWillUnmount } from "@odoo/owl";

export class VirtualList extends Component {
    setup() {
        this.state = useState({
            scrollTop: 0,
            visibleStart: 0,
            visibleEnd: 50,
        });

        this.itemHeight = this.props.itemHeight || 40;
        this.bufferSize = this.props.bufferSize || 10;

        onMounted(() => {
            this.scrollContainer = this.__owl__.refs.scrollContainer;
            this.scrollContainer.addEventListener('scroll', this.onScroll);
        });

        onWillUnmount(() => {
            this.scrollContainer.removeEventListener('scroll', this.onScroll);
        });
    }

    onScroll = (event) => {
        const scrollTop = event.target.scrollTop;
        const visibleStart = Math.floor(scrollTop / this.itemHeight);
        const visibleEnd = visibleStart + Math.ceil(
            event.target.clientHeight / this.itemHeight
        ) + this.bufferSize;

        this.state.scrollTop = scrollTop;
        this.state.visibleStart = Math.max(0, visibleStart - this.bufferSize);
        this.state.visibleEnd = Math.min(this.props.items.length, visibleEnd);
    }

    get visibleItems() {
        return this.props.items.slice(
            this.state.visibleStart,
            this.state.visibleEnd
        );
    }

    get totalHeight() {
        return this.props.items.length * this.itemHeight;
    }

    get offsetY() {
        return this.state.visibleStart * this.itemHeight;
    }
}

VirtualList.template = "quantum.VirtualList";
VirtualList.props = {
    items: Array,
    itemHeight: { type: Number, optional: true },
    bufferSize: { type: Number, optional: true },
};
```

```xml
<!-- static/src/components/virtual_list/virtual_list.xml -->
<templates xml:space="preserve">
    <t t-name="quantum.VirtualList">
        <div class="o_virtual_list" ref="scrollContainer" style="height: 500px; overflow-y: auto;">
            <div class="o_virtual_list_spacer" t-att-style="`height: ${totalHeight}px;`">
                <div class="o_virtual_list_content" t-att-style="`transform: translateY(${offsetY}px);`">
                    <t t-foreach="visibleItems" t-as="item" t-key="item.id">
                        <t t-slot="item" item="item"/>
                    </t>
                </div>
            </div>
        </div>
    </t>
</templates>
```

#### 2.2.2 Debounced Filters

```javascript
// static/src/components/report_filters/report_filters.js

/** @odoo-module **/
import { Component, useState } from "@odoo/owl";
import { debounce } from "@web/core/utils/timing";

export class ReportFilters extends Component {
    setup() {
        this.state = useState({
            searchTerm: "",
            dateFrom: null,
            dateTo: null,
        });

        // Debounce search by 300ms
        this.debouncedSearch = debounce(
            this.applyFilters.bind(this),
            300
        );
    }

    onSearchInput(event) {
        this.state.searchTerm = event.target.value;
        this.debouncedSearch();
    }

    async applyFilters() {
        const filters = {
            search: this.state.searchTerm,
            date_from: this.state.dateFrom,
            date_to: this.state.dateTo,
        };

        await this.props.onFiltersChange(filters);
    }
}
```

#### 2.2.3 Web Workers for Heavy Calculations

```javascript
// static/src/workers/report_calculator.js

self.addEventListener('message', (event) => {
    const { action, data } = event.data;

    if (action === 'calculate_totals') {
        const totals = calculateTotals(data.lines);
        self.postMessage({ action: 'totals_calculated', totals });
    }
});

function calculateTotals(lines) {
    // Heavy calculation (sum, aggregations, variance, etc.)
    return lines.reduce((acc, line) => {
        acc.debit += line.debit || 0;
        acc.credit += line.credit || 0;
        acc.balance += line.balance || 0;
        return acc;
    }, { debit: 0, credit: 0, balance: 0 });
}
```

```javascript
// static/src/components/report_view/report_view.js

/** @odoo-module **/
import { Component, useState, onMounted } from "@odoo/owl";

export class ReportView extends Component {
    setup() {
        this.state = useState({
            lines: [],
            totals: null,
            calculating: false,
        });

        onMounted(() => {
            this.worker = new Worker('/quantum/static/src/workers/report_calculator.js');
            this.worker.addEventListener('message', this.onWorkerMessage.bind(this));
        });
    }

    async loadReport() {
        this.state.calculating = true;
        const lines = await this.rpc('/quantum/report', { ... });
        this.state.lines = lines;

        // Offload calculation to worker
        this.worker.postMessage({
            action: 'calculate_totals',
            data: { lines }
        });
    }

    onWorkerMessage(event) {
        if (event.data.action === 'totals_calculated') {
            this.state.totals = event.data.totals;
            this.state.calculating = false;
        }
    }
}
```

#### 2.2.4 Asset Bundling Optimization

```python
# __manifest__.py (Quantum module)

{
    'name': 'Quantum Financial Reports',
    'assets': {
        'web.assets_backend': [
            # Core dependencies (load first)
            'quantum/static/src/components/virtual_list/*.js',
            'quantum/static/src/components/virtual_list/*.xml',

            # Report components (lazy load)
            ('lazy', 'quantum/static/src/components/report_view/*.js'),
            ('lazy', 'quantum/static/src/components/report_filters/*.js'),

            # SCSS (minimal, variables first)
            'quantum/static/src/scss/variables.scss',
            'quantum/static/src/scss/components.scss',
        ],

        # Separate bundle for heavy components (loaded on demand)
        'quantum.assets_report': [
            'quantum/static/src/components/drilldown/*.js',
            'quantum/static/src/components/export/*.js',
            'quantum/static/src/workers/report_calculator.js',
        ],
    },
}
```

---

## 3. Performance Testing Plan

### 3.1 Test Datasets

**Dataset Sizes (Progressive):**

```python
# scripts/create_test_datasets.py

DATASETS = {
    'xs': {
        'partners': 100,
        'invoices': 500,
        'move_lines': 1_000,
        'accounts': 50,
    },
    'small': {
        'partners': 500,
        'invoices': 2_000,
        'move_lines': 10_000,
        'accounts': 100,
    },
    'medium': {
        'partners': 2_000,
        'invoices': 10_000,
        'move_lines': 100_000,
        'accounts': 200,
    },
    'large': {
        'partners': 5_000,
        'invoices': 50_000,
        'move_lines': 500_000,
        'accounts': 500,
    },
    'xlarge': {
        'partners': 10_000,
        'invoices': 100_000,
        'move_lines': 1_000_000,
        'accounts': 1_000,
    },
}

def create_dataset(env, size_key):
    """
    Generate realistic test data matching Chilean accounting patterns.
    """
    config = DATASETS[size_key]

    # Create partners (companies, individuals)
    partners = create_partners(env, config['partners'])

    # Create invoices (70% factura, 20% credit note, 10% debit note)
    invoices = create_invoices(env, partners, config['invoices'])

    # Create account.move.line (validate totals match)
    move_lines = create_move_lines(env, invoices, config['move_lines'])

    # Create hierarchical chart of accounts
    accounts = create_accounts(env, config['accounts'])

    return {
        'partners': partners,
        'invoices': invoices,
        'move_lines': move_lines,
        'accounts': accounts,
    }
```

### 3.2 Test Scenarios

**Quantum (Financial Reports):**

```python
# addons/localization/l10n_cl_financial_reports/tests/test_performance.py

import pytest
from odoo.tests import TransactionCase
from time import time

class TestQuantumPerformance(TransactionCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Load medium dataset (100k lines)
        cls.dataset = create_dataset(cls.env, 'medium')

    def test_balance_sheet_10k_lines(self):
        """SLA: < 3s for 10k account.move.line"""
        start = time()

        report = self.env['account.balance.eight.columns'].create({
            'date_from': '2025-01-01',
            'date_to': '2025-12-31',
            'company_id': self.env.company.id,
        })
        report.compute_report()

        elapsed = time() - start
        self.assertLess(elapsed, 3.0, f"Balance Sheet took {elapsed:.2f}s (SLA: 3s)")

    def test_balance_sheet_100k_lines(self):
        """SLA: < 10s for 100k account.move.line"""
        # Use large dataset
        dataset = create_dataset(self.env, 'large')

        start = time()
        report = self.env['account.balance.eight.columns'].create({
            'date_from': '2025-01-01',
            'date_to': '2025-12-31',
            'company_id': self.env.company.id,
        })
        report.compute_report()
        elapsed = time() - start

        self.assertLess(elapsed, 10.0, f"Balance Sheet took {elapsed:.2f}s (SLA: 10s)")

    def test_drilldown_performance(self):
        """SLA: < 2s for drilldown to account.move.line"""
        report = self.env['account.balance.eight.columns'].create({
            'date_from': '2025-01-01',
            'date_to': '2025-12-31',
        })
        report.compute_report()

        # Simulate drilldown
        start = time()
        account_line = report.line_ids[0]
        domain = account_line.get_drilldown_domain()
        move_lines = self.env['account.move.line'].search(domain)
        elapsed = time() - start

        self.assertLess(elapsed, 2.0, f"Drilldown took {elapsed:.2f}s (SLA: 2s)")

    def test_xlsx_export_10k_rows(self):
        """SLA: < 5s for XLSX export (10k rows)"""
        report = self.env['account.balance.eight.columns'].create({
            'date_from': '2025-01-01',
            'date_to': '2025-12-31',
        })
        report.compute_report()

        start = time()
        xlsx_data = report.export_xlsx()
        elapsed = time() - start

        self.assertLess(elapsed, 5.0, f"XLSX export took {elapsed:.2f}s (SLA: 5s)")

    def test_cache_hit_performance(self):
        """SLA: < 500ms for cached report"""
        report = self.env['account.balance.eight.columns'].create({
            'date_from': '2025-01-01',
            'date_to': '2025-12-31',
        })

        # First call (cache miss)
        report.compute_report()

        # Second call (cache hit)
        start = time()
        report.compute_report()
        elapsed = time() - start

        self.assertLess(elapsed, 0.5, f"Cache hit took {elapsed:.2f}s (SLA: 500ms)")

    def test_comparative_report_performance(self):
        """SLA: < 5s for comparative report (YTD vs PY)"""
        report = self.env['account.balance.eight.columns'].create({
            'date_from': '2025-01-01',
            'date_to': '2025-12-31',
            'compare_periods': True,
            'comparison_type': 'prior_year',
        })

        start = time()
        report.compute_report()
        elapsed = time() - start

        self.assertLess(elapsed, 5.0, f"Comparative report took {elapsed:.2f}s (SLA: 5s)")
```

**Phoenix (UI):**

```python
# addons/custom/phoenix_web_theme/tests/test_performance.py

from odoo.tests import HttpCase
from time import time

class TestPhoenixPerformance(HttpCase):

    def test_list_view_100_records(self):
        """SLA: < 1s for list view (100 records)"""
        # Measure backend response time
        start = time()
        response = self.url_open('/web/dataset/search_read', data={
            'model': 'res.partner',
            'limit': 100,
            'fields': ['name', 'email', 'phone', 'vat'],
        })
        elapsed = time() - start

        self.assertEqual(response.status_code, 200)
        self.assertLess(elapsed, 1.0, f"List view took {elapsed:.2f}s (SLA: 1s)")

    def test_form_view_open(self):
        """SLA: < 1.5s for form view open"""
        partner = self.env['res.partner'].create({'name': 'Test Partner'})

        start = time()
        response = self.url_open(f'/web#id={partner.id}&model=res.partner&view_type=form')
        elapsed = time() - start

        self.assertEqual(response.status_code, 200)
        self.assertLess(elapsed, 1.5, f"Form view took {elapsed:.2f}s (SLA: 1.5s)")

    def test_kanban_view_50_cards(self):
        """SLA: < 1.5s for kanban view (50 cards)"""
        # Create 50 test records
        for i in range(50):
            self.env['res.partner'].create({'name': f'Partner {i}'})

        start = time()
        response = self.url_open('/web/dataset/search_read', data={
            'model': 'res.partner',
            'limit': 50,
            'view_type': 'kanban',
        })
        elapsed = time() - start

        self.assertEqual(response.status_code, 200)
        self.assertLess(elapsed, 1.5, f"Kanban view took {elapsed:.2f}s (SLA: 1.5s)")
```

### 3.3 Load Testing with Locust

```python
# tests/load/locustfile.py

from locust import HttpUser, task, between
import random

class OdooUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        """Login and get session"""
        self.client.post('/web/login', data={
            'login': 'admin',
            'password': 'admin',
            'db': 'odoo19_test',
        })

    @task(3)
    def view_partner_list(self):
        """Most common: viewing partner list"""
        self.client.post('/web/dataset/search_read', json={
            'model': 'res.partner',
            'limit': 80,
            'offset': random.randint(0, 200),
        })

    @task(2)
    def generate_balance_sheet(self):
        """Generate financial report"""
        self.client.post('/quantum/report/balance_sheet', json={
            'date_from': '2025-01-01',
            'date_to': '2025-12-31',
        })

    @task(1)
    def drilldown_report(self):
        """Drilldown to account.move.line"""
        self.client.post('/web/dataset/search_read', json={
            'model': 'account.move.line',
            'domain': [['account_id', '=', random.randint(1, 100)]],
            'limit': 100,
        })

    @task(1)
    def export_xlsx(self):
        """Export XLSX report"""
        self.client.get(f'/quantum/report/export/xlsx/{random.randint(1, 10)}')

# Run with: locust -f locustfile.py --host=http://localhost:8169 --users=50 --spawn-rate=5
```

### 3.4 Frontend Performance (Lighthouse)

```bash
#!/bin/bash
# scripts/test_lighthouse.sh

# Run Lighthouse CI for Phoenix theme
npx lighthouse-ci autorun \
    --url="http://localhost:8169/web" \
    --collect.numberOfRuns=3 \
    --assert.preset="lighthouse:recommended" \
    --upload.target=temporary-public-storage

# Custom assertions
npx lighthouse-ci assert \
    --preset lighthouse:recommended \
    --assertions.first-contentful-paint=1200 \
    --assertions.largest-contentful-paint=1800 \
    --assertions.interactive=2000 \
    --assertions.total-blocking-time=300
```

---

## 4. Scalability Architecture

### 4.1 Multi-Worker Deployment

**Odoo Worker Configuration (odoo.conf):**

```ini
[options]
# Database
db_host = db
db_port = 5432
db_user = odoo
db_password = odoo
db_name = odoo19_production

# Workers (4-8 for production, 1 CPU core per 2 workers)
# Formula: workers = (2 * num_cpu_cores) + 1
workers = 8
max_cron_threads = 2

# Limits per worker
limit_memory_hard = 2684354560   # 2.5 GB
limit_memory_soft = 2147483648   # 2 GB
limit_request = 8192
limit_time_cpu = 600             # 10 min
limit_time_real = 1200           # 20 min
limit_time_real_cron = 3600      # 1 hour for scheduled jobs

# Longpolling (separate workers)
gevent_port = 8072
longpolling_port = 8072

# Proxy mode (behind nginx)
proxy_mode = True

# Logging
log_level = info
log_handler = :INFO
logfile = /var/log/odoo/odoo.log
logrotate = True

# Performance
list_db = False
dbfilter = ^odoo19_production$

# Cache (Redis)
session_store_type = redis
session_store_dbindex = 2
session_store_host = redis
session_store_port = 6379
```

**Docker Compose (Production):**

```yaml
# docker-compose.production.yml

services:
  odoo:
    image: eergygroup/odoo19:chile-1.0.5
    deploy:
      replicas: 4  # 4 Odoo instances
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
    environment:
      - ODOO_WORKERS=8
      - ODOO_MAX_CRON_THREADS=2
    depends_on:
      - db
      - redis
      - nginx

  # Load balancer
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - odoo
```

**Nginx Load Balancer (nginx.conf):**

```nginx
upstream odoo_backend {
    least_conn;  # Load balance by least connections

    server odoo:8069 max_fails=3 fail_timeout=30s;
    server odoo:8069 max_fails=3 fail_timeout=30s;
    server odoo:8069 max_fails=3 fail_timeout=30s;
    server odoo:8069 max_fails=3 fail_timeout=30s;
}

upstream odoo_longpolling {
    server odoo:8072;
}

server {
    listen 80;
    server_name erp.eergygroup.com;

    # Timeouts
    proxy_connect_timeout 600s;
    proxy_send_timeout 600s;
    proxy_read_timeout 600s;

    # Buffer sizes
    client_max_body_size 100M;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;

    # Longpolling (WebSocket)
    location /longpolling {
        proxy_pass http://odoo_longpolling;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Static files (cache)
    location ~* /web/static/ {
        proxy_pass http://odoo_backend;
        proxy_cache_valid 200 60m;
        expires 864000;
        add_header Cache-Control "public, immutable";
    }

    # Backend
    location / {
        proxy_pass http://odoo_backend;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
    }
}
```

### 4.2 Database Read Replicas

**PostgreSQL Master-Replica Setup:**

```yaml
# docker-compose.production.yml (extended)

services:
  db_master:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: odoo
      POSTGRES_PASSWORD: odoo
      POSTGRES_DB: odoo19_production
      POSTGRES_INITDB_ARGS: "--wal-level=replica"
    volumes:
      - postgres_master_data:/var/lib/postgresql/data
    command: >
      postgres
      -c wal_level=replica
      -c max_wal_senders=3
      -c max_replication_slots=3

  db_replica1:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: odoo
      POSTGRES_PASSWORD: odoo
      PGPASSWORD: odoo
    volumes:
      - postgres_replica1_data:/var/lib/postgresql/data
    command: >
      bash -c "
      pg_basebackup -h db_master -D /var/lib/postgresql/data -U odoo -v -P --wal-method=stream &&
      postgres -c hot_standby=on
      "
```

**Odoo Read/Write Split:**

```python
# models/account_report_engine.py

def _get_read_db_cursor(self):
    """
    Use read replica for heavy report queries.
    Write operations use master DB.
    """
    if hasattr(self.env, 'read_replica_cr'):
        return self.env.read_replica_cr

    # Fallback to master if no replica configured
    return self.env.cr

def compute_report(self):
    """Use read replica for report generation"""
    cr = self._get_read_db_cursor()

    query = """
        SELECT account_id, SUM(debit) as debit, SUM(credit) as credit
        FROM account_move_line
        WHERE date >= %s AND date <= %s AND parent_state = 'posted'
        GROUP BY account_id
    """

    cr.execute(query, (self.date_from, self.date_to))
    results = cr.fetchall()

    return self._process_results(results)
```

### 4.3 CDN for Static Assets

```nginx
# nginx.conf (CDN integration)

# Serve static assets from CDN
location ~* /web/static/ {
    # Try local cache first
    try_files $uri @cdn;
}

location @cdn {
    # Redirect to CloudFlare/AWS CloudFront
    proxy_pass https://cdn.eergygroup.com$request_uri;
    proxy_cache cdn_cache;
    proxy_cache_valid 200 7d;
    add_header X-Cache-Status $upstream_cache_status;
}
```

### 4.4 Concurrency Limits

```python
# addons/localization/l10n_cl_financial_reports/models/account_report_engine.py

from threading import Semaphore

# Global semaphore to limit concurrent report generations
MAX_CONCURRENT_REPORTS = 5
report_semaphore = Semaphore(MAX_CONCURRENT_REPORTS)

class AccountReportEngine(models.AbstractModel):
    _name = 'account.report.engine'

    @api.model
    def compute_report_with_limit(self, params):
        """
        Limit concurrent report generations to prevent resource exhaustion.
        """
        if not report_semaphore.acquire(blocking=False):
            raise UserError(_(
                "Too many reports are being generated simultaneously. "
                "Please try again in a few moments."
            ))

        try:
            return self._compute_report_internal(params)
        finally:
            report_semaphore.release()
```

---

## 5. Monitoring & Observability

### 5.1 Key Performance Indicators (KPIs)

**Prometheus Metrics (Custom Exporter):**

```python
# addons/custom/odoo_prometheus_exporter/models/metrics.py

from prometheus_client import Counter, Histogram, Gauge
import time

# Request metrics
http_requests_total = Counter(
    'odoo_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration = Histogram(
    'odoo_http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
)

# Report metrics
report_generation_duration = Histogram(
    'odoo_report_generation_duration_seconds',
    'Report generation duration',
    ['report_type', 'dataset_size'],
    buckets=[1.0, 3.0, 5.0, 10.0, 15.0, 30.0, 60.0]
)

report_cache_hits = Counter(
    'odoo_report_cache_hits_total',
    'Report cache hits',
    ['report_type']
)

# Database metrics
db_query_duration = Histogram(
    'odoo_db_query_duration_seconds',
    'Database query duration',
    ['query_type'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
)

# System metrics
active_sessions = Gauge(
    'odoo_active_sessions',
    'Number of active user sessions'
)

# Usage example in model
def compute_report(self):
    start = time.time()

    try:
        result = self._compute_report_internal()

        # Record success
        duration = time.time() - start
        report_generation_duration.labels(
            report_type='balance_sheet',
            dataset_size=len(result)
        ).observe(duration)

        return result

    except Exception as e:
        # Record failure
        http_requests_total.labels(
            method='POST',
            endpoint='/quantum/report',
            status='500'
        ).inc()
        raise
```

**Grafana Dashboard (JSON Config):**

```json
{
  "dashboard": {
    "title": "Odoo Performance Dashboard",
    "panels": [
      {
        "title": "Request Rate (req/s)",
        "targets": [
          {
            "expr": "rate(odoo_http_requests_total[5m])",
            "legendFormat": "{{endpoint}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "P95 Response Time",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(odoo_http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "{{endpoint}}"
          }
        ],
        "type": "graph",
        "thresholds": [
          { "value": 2, "color": "yellow" },
          { "value": 5, "color": "red" }
        ]
      },
      {
        "title": "Report Generation Time",
        "targets": [
          {
            "expr": "odoo_report_generation_duration_seconds{report_type=\"balance_sheet\"}",
            "legendFormat": "Balance Sheet"
          }
        ],
        "type": "graph",
        "thresholds": [
          { "value": 10, "color": "yellow" },
          { "value": 20, "color": "red" }
        ]
      },
      {
        "title": "Cache Hit Ratio",
        "targets": [
          {
            "expr": "rate(odoo_report_cache_hits_total[5m]) / rate(odoo_http_requests_total{endpoint=\"/quantum/report\"}[5m])",
            "legendFormat": "Hit Ratio"
          }
        ],
        "type": "singlestat",
        "thresholds": "0.6,0.8",
        "format": "percentunit"
      },
      {
        "title": "Database Query Time (P95)",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(odoo_db_query_duration_seconds_bucket[5m]))",
            "legendFormat": "{{query_type}}"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Active Sessions",
        "targets": [
          {
            "expr": "odoo_active_sessions",
            "legendFormat": "Sessions"
          }
        ],
        "type": "graph"
      }
    ]
  }
}
```

### 5.2 Application Performance Monitoring (APM)

**New Relic Integration:**

```python
# config/newrelic.ini

[newrelic]
license_key = YOUR_LICENSE_KEY
app_name = Odoo 19 Production

# Performance settings
monitor_mode = true
developer_mode = false

# Transaction tracing
transaction_tracer.enabled = true
transaction_tracer.transaction_threshold = apdex_f
transaction_tracer.record_sql = obfuscated
transaction_tracer.stack_trace_threshold = 0.5

# Slow SQL
slow_sql.enabled = true

# Error collection
error_collector.enabled = true
error_collector.ignore_status_codes = 404,405
```

```python
# odoo-bin (startup script)

import newrelic.agent
newrelic.agent.initialize('config/newrelic.ini')

# Wrap WSGI application
from odoo.service import wsgi_server
application = newrelic.agent.wsgi_application()(wsgi_server.application)
```

### 5.3 Logging Strategy

```python
# models/account_report_engine.py

import logging
import json

_logger = logging.getLogger(__name__)

class AccountReportEngine(models.AbstractModel):

    def compute_report(self, params):
        """Generate report with structured logging"""

        # Structured log (JSON for Elasticsearch/Splunk)
        log_context = {
            'report_type': params.get('report_type'),
            'date_from': str(params.get('date_from')),
            'date_to': str(params.get('date_to')),
            'user_id': self.env.user.id,
            'company_id': self.env.company.id,
        }

        _logger.info(f"Report generation started: {json.dumps(log_context)}")

        start = time.time()

        try:
            result = self._compute_report_internal(params)

            duration = time.time() - start
            log_context.update({
                'status': 'success',
                'duration_seconds': round(duration, 2),
                'line_count': len(result),
            })

            _logger.info(f"Report generation completed: {json.dumps(log_context)}")

            return result

        except Exception as e:
            duration = time.time() - start
            log_context.update({
                'status': 'error',
                'duration_seconds': round(duration, 2),
                'error': str(e),
                'error_type': type(e).__name__,
            })

            _logger.error(f"Report generation failed: {json.dumps(log_context)}")
            raise
```

---

## 6. Pre-Go-Live Performance Checklist

### 6.1 Database Preparation

- [ ] All critical indexes created (see section 2.1.1)
- [ ] VACUUM ANALYZE executed on large tables
- [ ] PostgreSQL configuration optimized (shared_buffers, effective_cache_size)
- [ ] Connection pooling enabled (pgbouncer)
- [ ] Read replica configured (if applicable)
- [ ] Database backup and restore tested

**PostgreSQL Optimization (postgresql.conf):**

```ini
# Memory
shared_buffers = 4GB                  # 25% of RAM
effective_cache_size = 12GB           # 75% of RAM
work_mem = 64MB                       # (RAM / max_connections) / 2
maintenance_work_mem = 1GB

# Checkpoints
checkpoint_completion_target = 0.9
wal_buffers = 16MB
max_wal_size = 4GB
min_wal_size = 1GB

# Query planner
random_page_cost = 1.1                # SSD
effective_io_concurrency = 200        # SSD

# Connections
max_connections = 200

# Logging
log_min_duration_statement = 1000     # Log slow queries (>1s)
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_checkpoints = on
log_lock_waits = on
```

### 6.2 Application Layer

- [ ] Redis cache configured and tested
- [ ] Report cache invalidation logic verified
- [ ] Multi-worker deployment tested
- [ ] Session management (Redis) verified
- [ ] Longpolling working correctly
- [ ] Static assets bundled and minified
- [ ] CDN configured (if applicable)
- [ ] Concurrency limits tested

### 6.3 Performance Testing

- [ ] Load testing completed (Locust)
- [ ] 100k account.move.line dataset tested
- [ ] All SLAs validated (see section 1)
- [ ] Frontend Lighthouse score > 80
- [ ] Virtual scrolling tested with 1000+ rows
- [ ] Drilldown performance verified
- [ ] XLSX export tested (large datasets)
- [ ] Comparative reports tested (YTD/PY)

### 6.4 Monitoring & Alerting

- [ ] Prometheus exporter installed
- [ ] Grafana dashboards created
- [ ] Alerting rules configured:
  - [ ] Response time p95 > 5s (warning)
  - [ ] Response time p95 > 10s (critical)
  - [ ] Database query time > 2s (warning)
  - [ ] Cache hit ratio < 60% (warning)
  - [ ] Error rate > 1% (critical)
- [ ] APM integration tested (New Relic/Datadog)
- [ ] Log aggregation configured (ELK/Splunk)

### 6.5 Scalability Verification

- [ ] Load balancer (Nginx) tested
- [ ] Horizontal scaling tested (4+ Odoo workers)
- [ ] Database connection pool tested
- [ ] Graceful degradation verified
- [ ] Failover scenarios tested

---

## 7. Bottlenecks & Mitigation Strategies

### 7.1 Anticipated Bottlenecks

| Bottleneck | Symptoms | Impact | Mitigation |
|------------|----------|--------|------------|
| **Unindexed Queries** | Slow report generation (>30s) | P0 Critical | Create indexes (section 2.1.1), use EXPLAIN ANALYZE |
| **N+1 Queries** | Slow list views, high DB load | P0 Critical | Use read_group, prefetch, search_fetch |
| **Large Datasets** | Memory exhaustion, OOM errors | P0 Critical | Pagination, virtual scrolling, limit result sets |
| **Cache Misses** | Repeated slow queries | P1 High | Redis cache, increase TTL, warm up cache |
| **Frontend Bundle Size** | Slow page load (>5s) | P1 High | Code splitting, lazy loading, minification |
| **Synchronous Exports** | Blocked UI during XLSX export | P2 Medium | Background jobs (ir.cron), async downloads |
| **Concurrent Reports** | Resource exhaustion | P2 Medium | Semaphore limits (section 4.4), queue system |
| **Database Locks** | Deadlocks, timeouts | P1 High | Use SELECT FOR UPDATE carefully, reduce transaction scope |
| **Single Worker** | Low throughput, poor concurrency | P0 Critical | Multi-worker deployment (8+ workers) |
| **Unoptimized ORM** | Excessive queries, high memory | P1 High | Use raw SQL for heavy aggregations, batch operations |

### 7.2 Mitigation Playbook

**Scenario 1: Report Generation Taking >30s**

```bash
# 1. Check if indexes exist
docker-compose exec db psql -U odoo -d odoo19_production -c "
    SELECT schemaname, tablename, indexname
    FROM pg_indexes
    WHERE tablename = 'account_move_line'
    AND indexname LIKE 'idx_%';
"

# 2. If missing, create indexes (see section 2.1.1)

# 3. Analyze query plan
docker-compose exec db psql -U odoo -d odoo19_production -c "
    EXPLAIN ANALYZE
    SELECT account_id, SUM(debit), SUM(credit)
    FROM account_move_line
    WHERE date >= '2025-01-01' AND date <= '2025-12-31'
    GROUP BY account_id;
"

# 4. Vacuum and analyze
docker-compose exec db psql -U odoo -d odoo19_production -c "
    VACUUM ANALYZE account_move_line;
"
```

**Scenario 2: High Memory Usage**

```bash
# 1. Check Odoo worker memory
docker stats odoo19_app

# 2. Check for memory leaks (Python)
docker-compose exec odoo python3 -m memory_profiler /usr/bin/odoo-bin

# 3. Reduce worker memory limits (odoo.conf)
# limit_memory_soft = 2GB
# limit_memory_hard = 2.5GB

# 4. Restart workers periodically (ir.cron)
docker-compose restart odoo
```

**Scenario 3: Low Cache Hit Ratio (<60%)**

```bash
# 1. Check Redis stats
docker-compose exec redis redis-cli INFO stats

# 2. Increase cache TTL
# In account_report_cache.py: ttl_hours = 48 (instead of 24)

# 3. Warm up cache (preload common reports)
docker-compose exec odoo odoo-bin shell -d odoo19_production --no-http -c "
    env['account.balance.eight.columns'].search([]).compute_report()
"
```

---

## 8. Performance Roadmap

### Phase 1: Foundation (Weeks 1-2)

- [ ] Implement database indexes
- [ ] Configure Redis caching
- [ ] Set up multi-worker deployment
- [ ] Implement basic monitoring (Prometheus)

**Deliverables:**
- Indexed database
- Redis cache layer
- 4-worker Odoo deployment
- Basic Grafana dashboard

### Phase 2: Optimization (Weeks 3-4)

- [ ] Implement virtual scrolling (Phoenix)
- [ ] Add report cache (Quantum)
- [ ] Optimize ORM queries (read_group)
- [ ] Bundle optimization (lazy loading)

**Deliverables:**
- Virtual scrolling for lists >100 rows
- Cache hit ratio >70%
- Bundled assets <750KB
- p95 response time <3s

### Phase 3: Scalability (Weeks 5-6)

- [ ] Load balancer (Nginx)
- [ ] Database read replicas
- [ ] CDN for static assets
- [ ] Horizontal scaling tests

**Deliverables:**
- 8-worker deployment
- Load balancer tested
- 500+ concurrent users supported
- Failover verified

### Phase 4: Monitoring (Week 7)

- [ ] APM integration (New Relic)
- [ ] Advanced Grafana dashboards
- [ ] Alerting rules
- [ ] Performance regression tests

**Deliverables:**
- Full observability stack
- Automated alerts
- Performance test suite
- Documentation

---

## 9. Appendix: ASCII Architecture Diagrams

### 9.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         LOAD BALANCER (Nginx)                   │
│                    SSL Termination + Caching                    │
└────────────┬────────────────────────────┬───────────────────────┘
             │                            │
             ▼                            ▼
┌────────────────────────┐    ┌────────────────────────┐
│   Odoo Worker 1-4      │    │   Odoo Worker 5-8      │
│   ┌──────────────┐     │    │   ┌──────────────┐     │
│   │ Phoenix UI   │     │    │   │ Quantum      │     │
│   │ (OWL)        │     │    │   │ Reports      │     │
│   └──────────────┘     │    │   └──────────────┘     │
│   ┌──────────────┐     │    │   ┌──────────────┐     │
│   │ DTE Module   │     │    │   │ Cache Layer  │     │
│   └──────────────┘     │    │   └──────────────┘     │
└────────┬───────────────┘    └──────────┬─────────────┘
         │                               │
         ▼                               ▼
┌─────────────────────────────────────────────────────┐
│                  Redis Cache                        │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │   Sessions   │  │ Report Cache │  │  ORM Cache│ │
│  └──────────────┘  └──────────────┘  └───────────┘ │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────┐
│           PostgreSQL 15 (Master)                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ account.*   │  │  res.*      │  │   stock.*   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
└────────┬────────────────────────────────────────────┘
         │
         ├──────────┐
         ▼          ▼
┌───────────────┐  ┌───────────────┐
│ Read Replica1 │  │ Read Replica2 │
│  (Reports)    │  │  (Queries)    │
└───────────────┘  └───────────────┘
```

### 9.2 Report Generation Flow

```
┌──────────────┐
│   User       │
│   Browser    │
└──────┬───────┘
       │
       │ 1. Request Balance Sheet
       │
       ▼
┌────────────────────────────────────────┐
│     Odoo Controller                    │
│  /quantum/report/balance_sheet         │
└──────┬─────────────────────────────────┘
       │
       │ 2. Check Cache
       │
       ▼
┌────────────────────────────────────────┐
│    Cache Layer (3-tier)                │
│  ┌──────┐  ┌──────┐  ┌──────┐          │
│  │ ORM  │→ │Redis │→ │  DB  │          │
│  └──────┘  └──────┘  └──────┘          │
└──────┬─────────────────────────────────┘
       │
       │ 3a. Cache HIT → Return JSON (500ms)
       │ 3b. Cache MISS → Continue
       │
       ▼
┌────────────────────────────────────────┐
│   Report Engine                        │
│  ┌──────────────────────────────────┐  │
│  │ 1. Get account hierarchy         │  │
│  │    (parent_path)                 │  │
│  │ 2. Read_group account.move.line  │  │
│  │ 3. Calculate totals              │  │
│  │ 4. Format lines                  │  │
│  └──────────────────────────────────┘  │
└──────┬─────────────────────────────────┘
       │
       │ 4. Query DB (indexed)
       │
       ▼
┌────────────────────────────────────────┐
│   PostgreSQL (Read Replica)            │
│  ┌──────────────────────────────────┐  │
│  │ SELECT account_id,               │  │
│  │        SUM(debit),               │  │
│  │        SUM(credit)               │  │
│  │ FROM account_move_line           │  │
│  │ WHERE date BETWEEN ... (indexed) │  │
│  │ GROUP BY account_id              │  │
│  └──────────────────────────────────┘  │
└──────┬─────────────────────────────────┘
       │
       │ 5. Return rows (2-3s for 100k lines)
       │
       ▼
┌────────────────────────────────────────┐
│   Cache Write                          │
│  ┌──────┐  ┌──────┐  ┌──────┐          │
│  │ ORM  │← │Redis │← │  DB  │          │
│  └──────┘  └──────┘  └──────┘          │
└──────┬─────────────────────────────────┘
       │
       │ 6. Return JSON to client
       │
       ▼
┌────────────────────────────────────────┐
│   Frontend (OWL)                       │
│  ┌──────────────────────────────────┐  │
│  │ Virtual Scroll Component         │  │
│  │ (render 50 visible rows)         │  │
│  │ Total: 500 rows in memory        │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

### 9.3 Monitoring Stack

```
┌─────────────────────────────────────────────────────┐
│                 Odoo Application                    │
│  ┌──────────────────────────────────────────────┐   │
│  │  Prometheus Exporter (Custom Metrics)        │   │
│  │  - http_requests_total                       │   │
│  │  - http_request_duration_seconds             │   │
│  │  - report_generation_duration_seconds        │   │
│  │  - db_query_duration_seconds                 │   │
│  └──────────┬───────────────────────────────────┘   │
└─────────────┼───────────────────────────────────────┘
              │
              │ metrics
              │
              ▼
┌─────────────────────────────────────────────────────┐
│             Prometheus (TSDB)                       │
│  ┌──────────────────────────────────────────────┐   │
│  │  Scrape Interval: 15s                        │   │
│  │  Retention: 30 days                          │   │
│  │  Alerting Rules:                             │   │
│  │  - p95_response_time > 5s → Warning          │   │
│  │  - error_rate > 1% → Critical                │   │
│  └──────────┬───────────────────────────────────┘   │
└─────────────┼───────────────────────────────────────┘
              │
              │ query
              │
              ▼
┌─────────────────────────────────────────────────────┐
│                Grafana Dashboards                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │  Request     │  │  Database    │  │  Cache   │  │
│  │  Rate        │  │  Query Time  │  │  Hit %   │  │
│  └──────────────┘  └──────────────┘  └──────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │  P95 Time    │  │  Error Rate  │  │  Workers │  │
│  └──────────────┘  └──────────────┘  └──────────┘  │
└─────────────────────────────────────────────────────┘
              │
              │ alerts
              │
              ▼
┌─────────────────────────────────────────────────────┐
│              Alertmanager                           │
│  ┌──────────────────────────────────────────────┐   │
│  │  Routes:                                     │   │
│  │  - Critical → PagerDuty                      │   │
│  │  - Warning → Slack                           │   │
│  │  - Info → Email                              │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## 10. Summary & Next Steps

### 10.1 Performance Targets Summary

| Category | Metric | Target | Status |
|----------|--------|--------|--------|
| **Reports** | Balance Sheet (100k) | <10s | To validate |
| **UI** | List View (100 records) | <1s | To validate |
| **Cache** | Hit Ratio | >80% | To implement |
| **Database** | Query Time p95 | <500ms | To optimize |
| **Frontend** | TTI | <1.5s | To validate |
| **Availability** | Uptime | 99.5% | To measure |

### 10.2 Critical Success Factors

1. **Database Indexing:** Without proper indexes, reports will timeout (>30s)
2. **Caching Strategy:** 3-tier cache (ORM → Redis → DB) is essential for <10s reports
3. **Multi-Worker Deployment:** Single worker cannot handle 50+ concurrent users
4. **Virtual Scrolling:** Mandatory for lists >100 rows
5. **Monitoring:** Cannot optimize what you don't measure

### 10.3 Next Actions

**Immediate (Week 1):**
- [ ] Create database indexes (section 2.1.1)
- [ ] Configure Redis cache (section 2.1.3)
- [ ] Set up 4-worker deployment (section 4.1)
- [ ] Install Prometheus exporter (section 5.1)

**Short-term (Weeks 2-3):**
- [ ] Implement virtual scrolling (section 2.2.1)
- [ ] Add report cache layer (section 2.1.3)
- [ ] Optimize ORM queries (section 2.1.2)
- [ ] Create Grafana dashboards (section 5.1)

**Medium-term (Weeks 4-6):**
- [ ] Load testing with Locust (section 3.3)
- [ ] Horizontal scaling tests (section 4.1)
- [ ] APM integration (section 5.2)
- [ ] Performance regression suite (section 3.2)

---

**Document Version:** 1.0
**Last Updated:** 2025-11-08
**Maintained By:** EERGYGROUP Engineering Team
**Review Cycle:** Quarterly

**References:**
- Quantum Spec: `/docs/upgrade_enterprise_to_odoo19CE/utils_and_scripts/docs/quantum_financial_reports.md`
- Phoenix Spec: `/docs/upgrade_enterprise_to_odoo19CE/utils_and_scripts/docs/phoenix_web_enterprise_theme.md`
- Architecture: `.claude/project/02_architecture.md`
- Odoo Performance Guide: https://www.odoo.com/documentation/19.0/administration/performance.html

---

**END OF DOCUMENT**
