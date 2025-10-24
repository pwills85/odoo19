# Code_Patterns

## 1. Model Extension Pattern (Odoo Module)

All DTE functionality extends existing Odoo models rather than creating new ones:

```python
# addons/localization/l10n_cl_dte/models/account_move_dte.py
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'  # Extend, don't duplicate

    dte_status = fields.Selection(...)  # Add DTE-specific fields
    dte_folio = fields.Char(...)
    dte_xml = fields.Text(...)
```

**Files:** account_move_dte.py, purchase_order_dte.py, stock_picking_dte.py

## 2. Factory Pattern (DTE Service)

Runtime generator selection based on DTE type:

```python
# dte-service/main.py
def _get_generator(dte_type: str):
    generators = {
        '33': DTEGenerator33,  # Invoice
        '34': DTEGenerator34,  # Fees
        '52': DTEGenerator52,  # Shipping guide
        '56': DTEGenerator56,  # Debit note
        '61': DTEGenerator61,  # Credit note
    }
    return generators[dte_type]()
```

**Files:** dte-service/generators/dte_generator_{33,34,52,56,61}.py

## 3. Singleton Pattern (AI Service)

Expensive ML models loaded once and reused:

```python
# ai-service/reconciliation/invoice_matcher.py
class InvoiceMatcher:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.model = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
        return cls._instance
```

**Purpose:** Reduce memory footprint, faster inference

## 4. Orchestration Pattern (SII Monitor) ✨ NUEVO

Sistema de monitoreo automático del SII con análisis IA:

```python
# ai-service/sii_monitor/orchestrator.py
class SIIMonitorOrchestrator:
    async def monitor_all(self, force: bool = False):
        # 1. Scraping
        changes = await self.scraper.detect_changes()

        # 2. Extraction
        content = await self.extractor.extract(changes)

        # 3. Analysis (Claude AI)
        analysis = await self.analyzer.analyze(content)

        # 4. Classification
        classified = self.classifier.classify(analysis)

        # 5. Notification (Slack)
        await self.notifier.notify(classified)

        # 6. Storage (Redis)
        await self.storage.store(classified)
```

**Ubicación:** `ai-service/sii_monitor/`
**Componentes:** 8 módulos (~1,215 líneas)
**Endpoints:** `/api/ai/sii/monitor`, `/api/ai/sii/status`

## 5. RUT Validation (Local, No External Calls)

```python
# addons/localization/l10n_cl_dte/tools/rut_validator.py
class RUTValidator:
    @classmethod
    def validate_rut(cls, rut: str) -> Tuple[bool, Optional[str]]:
        # Módulo 11 algorithm
        # Returns (is_valid, error_message)
```

**Tests:** test_rut_validator.py (10 test cases)

## Critical Validation Flow

```
User Input → RUT Validator (local) → Odoo Validation →
DTE Service → XSD Validator → Structure Validator →
TED Generator → XMLDSig Signer → SII SOAP Client →
Response Parser → Update Odoo
```

**Retry Logic:** 3 attempts with exponential backoff (tenacity library)
**Timeout:** 60 seconds for SII SOAP calls
