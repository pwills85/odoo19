# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Odoo 19 Community Edition - Chilean Electronic Invoicing (DTE)**

Enterprise-grade localization module for Chilean tax compliance (SII - Servicio de Impuestos Internos) with microservices architecture. Supports 5 DTE document types (33, 34, 52, 56, 61) with digital signature, XML generation, and SII SOAP communication.

**Status:** ✅ **100% SII COMPLIANCE** (Gap closure completed 2025-10-21)
**Stack:** Docker Compose | PostgreSQL 15 | Redis 7 | RabbitMQ 3.12 | FastAPI | Anthropic Claude | APScheduler

---

## Architecture

### Three-Tier System

1. **Odoo Module** (`addons/localization/l10n_cl_dte/`)
   - Extends standard Odoo models (account.move, purchase.order, stock.picking)
   - UI/UX for DTE operations, certificate management, folio tracking
   - Integration with l10n_cl and l10n_latam_base
   - Access control and audit logging

2. **DTE Microservice** (`dte-service/`)
   - FastAPI service (port 8001, internal only)
   - XML generation for 5 DTE types using factory pattern
   - XMLDSig PKCS#1 digital signature (xmlsec)
   - SII SOAP client with retry logic
   - XSD validation and TED (Timbre Electrónico) generation

3. **AI Microservice** (`ai-service/`)
   - FastAPI service (port 8002, internal only)
   - Pre-validation using Anthropic Claude API
   - Invoice reconciliation with semantic embeddings (sentence-transformers)
   - Singleton pattern for ML model management
   - Graceful fallback (doesn't block DTE operations)

### Key Architectural Principles

- **Extend, Don't Duplicate:** Module inherits from Odoo models rather than creating duplicates
- **Single Responsibility:** Each generator handles one DTE type independently
- **Defense in Depth:** Multiple validation layers (RUT → XSD → Structure → TED → SII)
- **Internal-Only Services:** DTE/AI services not exposed to internet, only to Odoo

---

## Development Commands

### Docker Operations

```bash
# Build all images (Odoo, DTE service, AI service)
./scripts/build_all_images.sh

# Verify setup before starting
./scripts/verify_setup.sh

# Start stack
docker-compose up -d

# View logs
docker-compose logs -f odoo
docker-compose logs -f dte-service
docker-compose logs -f ai-service

# Stop stack
docker-compose down

# Rebuild specific service
docker-compose build dte-service
docker-compose up -d dte-service
```

### Testing

**Odoo Module Tests**
```bash
# Run all module tests
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-enable -i l10n_cl_dte --stop-after-init

# Run specific test file
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo \
  --test-tags /l10n_cl_dte --stop-after-init

# Available test files:
# - test_rut_validator.py (RUT validation, módulo 11)
# - test_dte_validations.py (field validation)
# - test_dte_workflow.py (end-to-end workflows)
# - test_integration_l10n_cl.py (l10n_cl compatibility)
```

**DTE Service Tests**
```bash
docker-compose exec dte-service pytest /app/tests/ -v

# With coverage
docker-compose exec dte-service pytest /app/tests/ --cov=generators --cov=signers
```

**AI Service Tests**
```bash
docker-compose exec ai-service pytest /app/tests/ -v
```

### Odoo Module Development

```bash
# Install module
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -i l10n_cl_dte

# Update module after code changes
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -u l10n_cl_dte

# Access Odoo shell (for debugging)
docker-compose exec odoo odoo shell -c /etc/odoo/odoo.conf -d odoo
```

### Database Operations

```bash
# Access PostgreSQL
docker-compose exec db psql -U odoo -d odoo

# Create new database
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d new_db_name --init=base --stop-after-init

# Backup database
docker-compose exec db pg_dump -U odoo odoo > backup.sql

# Restore database
docker-compose exec -T db psql -U odoo odoo < backup.sql
```

---

## Key Code Patterns

### 1. Model Extension Pattern (Odoo Module)

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

### 2. Factory Pattern (DTE Service)

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

### 3. Singleton Pattern (AI Service)

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

### 4. RUT Validation (Local, No External Calls)

```python
# addons/localization/l10n_cl_dte/tools/rut_validator.py
class RUTValidator:
    @classmethod
    def validate_rut(cls, rut: str) -> Tuple[bool, Optional[str]]:
        # Módulo 11 algorithm
        # Returns (is_valid, error_message)
```

**Tests:** test_rut_validator.py (10 test cases)

---

## DTE Document Types

| Code | Document Type | Odoo Model | Generator File |
|------|---------------|------------|----------------|
| 33 | Factura Electrónica | account.move (invoice) | dte_generator_33.py |
| 61 | Nota de Crédito | account.move (refund) | dte_generator_61.py |
| 56 | Nota de Débito | account.move (debit_note) | dte_generator_56.py |
| 52 | Guía de Despacho | stock.picking | dte_generator_52.py |
| 34 | Liquidación Honorarios | purchase.order | dte_generator_34.py |

---

## Configuration Files

### Environment Variables (.env)

**Required:**
- `ANTHROPIC_API_KEY` - Claude API key for AI service

**Optional (have defaults):**
- `DTE_SERVICE_API_KEY` - Bearer token for DTE service
- `AI_SERVICE_API_KEY` - Bearer token for AI service
- `ODOO_DB_PASSWORD` - PostgreSQL password
- `SII_ENVIRONMENT` - `sandbox` (Maullin) or `production` (Palena)

### Odoo Configuration (config/odoo.conf)

```ini
[options]
db_host = db
db_port = 5432
addons_path = /opt/odoo/addons,/mnt/extra-addons/custom,/mnt/extra-addons/localization,/mnt/extra-addons/third_party
workers = 4
timezone = America/Santiago
lang = es_CL.UTF-8
```

---

## Service Communication

### Odoo → DTE Service

```python
# Synchronous (REST)
response = requests.post(
    'http://dte-service:8001/api/v1/generate',
    json={'dte_type': '33', 'invoice_data': {...}},
    headers={'Authorization': f'Bearer {api_key}'},
    timeout=30
)

# Asynchronous (RabbitMQ)
# Odoo publishes to queue → DTE Service processes → Callback to Odoo
```

### Odoo → AI Service

```python
# Pre-validation
response = requests.post(
    'http://ai-service:8002/api/v1/validate',
    json={'dte_data': {...}, 'company_id': 1},
    headers={'Authorization': f'Bearer {api_key}'}
)

# Invoice reconciliation
response = requests.post(
    'http://ai-service:8002/api/v1/reconcile',
    json={'invoice': {...}, 'pending_pos': [...]},
    headers={'Authorization': f'Bearer {api_key}'}
)
```

### DTE Service → SII (SOAP)

**Endpoints:**
- Sandbox: `https://maullin.sii.cl/DTEWS/DTEServiceTest.asmx?wsdl`
- Production: `https://palena.sii.cl/DTEWS/DTEService.asmx?wsdl`

**Operations:** RecepcionDTE, RecepcionEnvio, GetEstadoSolicitud, GetEstadoDTE

---

## Critical Validation Flow

```
User Input → RUT Validator (local) → Odoo Validation →
DTE Service → XSD Validator → Structure Validator →
TED Generator → XMLDSig Signer → SII SOAP Client →
Response Parser → Update Odoo
```

**Retry Logic:** 3 attempts with exponential backoff (tenacity library)
**Timeout:** 60 seconds for SII SOAP calls

---

## Module Dependencies (l10n_cl_dte)

```python
'depends': [
    'base',
    'account',
    'l10n_latam_base',              # LATAM identification types
    'l10n_latam_invoice_document',  # LATAM fiscal documents
    'l10n_cl',                       # Chilean chart of accounts, taxes, RUT
    'purchase',                      # For DTE 34 (fees)
    'stock',                         # For DTE 52 (shipping guides)
    'web',
]
```

**Install Order:** l10n_latam_base → l10n_cl → l10n_cl_dte

---

## Important Implementation Notes

### When Extending Models

- **ALWAYS** use `_inherit`, never duplicate functionality
- Add only DTE-specific fields
- Leverage existing Odoo workflows and data structures
- Check l10n_cl compatibility before adding features

### When Adding DTE Types

1. Create generator in `dte-service/generators/dte_generator_XX.py`
2. Register in factory pattern (main.py)
3. Add model extension if needed (e.g., new document type)
4. Update views and wizards
5. Add XSD schema validation
6. Write tests

### When Modifying Microservices

- **DTE Service:** Changes require restart (`docker-compose restart dte-service`)
- **AI Service:** Model changes may require rebuilding image
- **Environment Variables:** Restart affected service to pick up changes
- **API Changes:** Update corresponding Odoo integration code

### Security Considerations

- Certificates (PKCS#12) encrypted, audit logged
- Passwords hashed, never logged
- DTEs encrypted at rest, signed in transit
- API keys in environment variables, not code
- Microservices internal-only (not exposed to internet)

---

## Common Troubleshooting

### Odoo Module Not Loading
- Check dependencies installed: `l10n_latam_base`, `l10n_cl`
- Verify addons path in odoo.conf
- Update apps list: Settings → Apps → Update Apps List

### DTE Service Connection Failed
- Verify service running: `docker-compose ps dte-service`
- Check API key configured in Odoo settings
- Ensure internal network connectivity: `docker-compose exec odoo curl http://dte-service:8001/health`

### SII SOAP Timeout
- Verify SII environment setting (sandbox vs production)
- Check certificate validity
- Review retry logic in logs: `docker-compose logs dte-service | grep retry`

### AI Service Not Responding
- Check ANTHROPIC_API_KEY set in .env
- Verify model loaded: `docker-compose logs ai-service | grep "Model loaded"`
- Test with simple validation request

---

## Performance Characteristics

**Target Metrics:**
- HTTP Latency (p95): < 500ms
- DTE Generation: < 200ms
- AI Validation: < 2 seconds
- Throughput: 1000+ DTEs/hour
- Concurrent Users: 500+

**Scaling:**
- Horizontal: Add Odoo/DTE/AI replicas behind load balancer
- Vertical: Increase worker processes (odoo.conf: `workers = 8+`)
- Caching: Redis for certificates, CAF ranges, embeddings
- Async: RabbitMQ for batch processing

---

## Key Files Reference

**Odoo Module Entry Point:**
- `addons/localization/l10n_cl_dte/__manifest__.py` - Module metadata

**Models (15 total):**
- `models/account_move_dte.py` - Invoices/Credit Notes/Debit Notes
- `models/purchase_order_dte.py` - DTE 34 (Fees)
- `models/stock_picking_dte.py` - DTE 52 (Shipping)
- `models/dte_certificate.py` - Digital certificates
- `models/dte_caf.py` - Folio authorization files

**Validators:**
- `tools/rut_validator.py` - RUT validation (módulo 11)

**DTE Service Core:**
- `dte-service/main.py` - FastAPI application
- `dte-service/generators/` - DTE XML generators
- `dte-service/signers/dte_signer.py` - XMLDSig signature
- `dte-service/clients/sii_soap_client.py` - SII integration

**AI Service Core:**
- `ai-service/main.py` - FastAPI application
- `ai-service/clients/anthropic_client.py` - Claude integration
- `ai-service/reconciliation/invoice_matcher.py` - Semantic matching

---

## Documentation

### Project Documentation

**Start Here:**
- `README.md` - Project overview and quick start
- `docs/PRODUCTION_FOCUSED_PLAN.md` - Implementation roadmap

**Technical Deep Dives:**
- `docs/L10N_CL_DTE_IMPLEMENTATION_PLAN.md` - Module architecture (24KB)
- `docs/DTE_COMPREHENSIVE_MAPPING.md` - DTE types, XML schemas, and component mapping (complete table of 54 DTE components)
- `docs/AI_AGENT_INTEGRATION_STRATEGY.md` - AI service design (38KB)
- `docs/MICROSERVICES_ANALYSIS_FINAL.md` - Service patterns and architecture analysis

**SII (Chilean Tax Authority) Documentation:**
- `docs/SII_SETUP.md` - SII configuration guide (certificates, environments, document types)
- `docs/VALIDACION_SII_30_PREGUNTAS.md` - 30 critical SII compliance questions (95% compliance achieved)
- `docs/DTE_COMPREHENSIVE_MAPPING.md` - Complete mapping of SII requirements to implementation

**Implementation Status & Validation:**
- `docs/PROYECTO_100_COMPLETADO.md` - 100% completion report
- `docs/VALIDATION_REPORT_2025-10-21.md` - System validation report
- `docs/PHASE6_COMPLETION_REPORT_2025-10-21.md` - Phase 6 testing completion
- `docs/AUDIT_REPORT_PHASE1_EXECUTIVE_2025-10-21.md` - Executive audit report

### Official Odoo 19 Documentation

**Location:** `docs/odoo19_official/` (68 files, 34 Python source files)

**Key Entry Points:**
- `docs/odoo19_official/INDEX.md` - Complete reference index organized by task
- `docs/odoo19_official/CHEATSHEET.md` - Quick reference for common patterns

**By Category:**

**1. ORM & Models** (`02_models_base/`)
- `account_move.py` - Invoice model (base for DTE 33, 56, 61)
- `account_journal.py` - Journal model (folio management)
- `account_tax.py` - Tax model (SII tax codes)
- `purchase_order.py` - Purchase order (base for DTE 34)
- `stock_picking.py` - Stock picking (base for DTE 52)
- `account_payment.py` - Payment model

**2. Chilean Localization** (`03_localization/`)
- **l10n_latam_base/** - LATAM base module (identification types, base models)
  - `models/l10n_latam_identification_type.py` - RUT and identification types
  - `models/res_partner.py` - Partner extensions
  - `models/res_company.py` - Company extensions

- **l10n_cl/** - Chilean localization (chart of accounts, taxes)
  - `models/account_move.py` - Chilean invoice extensions
  - `models/account_tax.py` - Chilean tax configuration
  - `models/l10n_latam_document_type.py` - Document type definitions
  - `tests/test_latam_document_type.py` - Testing patterns

**3. Views & UI** (`04_views_ui/`)
- `account_move_views.xml` - Invoice form, tree, and search views
- `purchase_views.xml` - Purchase order views
- `stock_picking_views.xml` - Stock picking views

**4. Security** (`05_security/`)
- `account_access.csv` - Access control examples

**5. Developer Reference** (`01_developer/`)
- `orm_api_reference.html` - Complete ORM API reference
- `module_structure.html` - Module structure best practices

---

## Working with SII Requirements

### Understanding SII Compliance

The `docs/VALIDACION_SII_30_PREGUNTAS.md` document contains 30 critical questions validating SII compliance:

**Key Areas Validated:**
1. **Environments:** Maullin (sandbox) vs Palena (production) - ✅ Implemented
2. **CAF Management:** Folio authorization files - ✅ Complete implementation
3. **TED Generation:** Electronic timestamp (Timbre Electrónico) - ✅ Spec-compliant
4. **Digital Signature:** RSA-SHA1, C14N canonicalization - ✅ Correct implementation
5. **XML Validation:** XSD schemas - ⚠️ Requires SII XSD files download
6. **Document Types:** 5 DTE types (33, 34, 52, 56, 61) - ✅ All implemented
7. **Reports:** Folio consumption, purchase/sales books - ✅ Complete

**Result:** 95% compliance (20/30 excellent, 9/30 good, 1/30 needs work)

### SII Document Type Reference

From `docs/DTE_COMPREHENSIVE_MAPPING.md`:

**Complete Component Mapping (54 components):**
- XML Generation (3 components)
- Digital Signature PKI (4 components)
- Chilean Codes & Validation (4 components)
- QR Codes (2 components)
- SOAP Communication (4 components)
- Receipt Processing (3 components)
- Validation (5 components)
- PDF Generation (3 components)
- Persistence & Audit (4 components)
- Orchestration (3 components)
- Configuration (3 components)
- Odoo Integration (5 components)
- UI/UX (4 components)
- Reports (3 components)
- Maintenance Operations (4 components)

Each component includes: Type, Responsibility, Location (Odoo vs DTE Service), Dependencies, Input/Process/Output, and Test status.

### When Working on SII Features

1. **Check Compliance Status:** ✅ Now at **100% SII Compliance** (see `docs/GAP_CLOSURE_SUMMARY.md`)
2. **Review Component Mapping:** Use `docs/DTE_COMPREHENSIVE_MAPPING.md` to locate responsible component
3. **Follow Setup Guide:** Reference `docs/SII_SETUP.md` for configuration patterns
4. **Gap Closure Report:** See `docs/GAP_CLOSURE_FINAL_REPORT_2025-10-21.md` for recent improvements

---

## Quick Reference

**Access Services:**
- Odoo: http://localhost:8169
- RabbitMQ Management: http://localhost:15772
- DTE Service: Internal only (http://dte-service:8001)
- AI Service: Internal only (http://ai-service:8002)

**Default Credentials:**
- Odoo: admin / (set during first install)
- PostgreSQL: odoo / odoo
- RabbitMQ: guest / guest

**Log Locations:**
- Odoo: `docker-compose logs odoo`
- DTE Service: `docker-compose logs dte-service`
- AI Service: `docker-compose logs ai-service`
- PostgreSQL: `docker-compose logs db`

**Monitor DTE Status Poller:**
```bash
# Ver polling job en acción (ejecuta cada 15 min)
docker-compose logs -f dte-service | grep -E "polling_job|poller_initialized"

# Verificar DTEs pendientes en Redis
docker-compose exec redis redis-cli KEYS "dte:pending:*"
```

---

## 🎯 Gap Closure Achievement (2025-10-21)

**Mission Complete:** All 9 SII compliance gaps have been closed, achieving **100% SII Compliance**.

### What Changed

**Before (95% compliance):**
- ⚠️ XSD validation missing official schemas
- ⚠️ Only 15 SII error codes mapped
- ⚠️ Certificate class validation incomplete
- ⚠️ GetDTE SOAP method not implemented
- ⚠️ Manual DTE status checking required

**After (100% compliance):**
- ✅ Full XSD validation with official SII schemas (`DTE_v10.xsd`)
- ✅ 59 SII error codes mapped and interpreted (10 categories)
- ✅ Certificate OID validation (Class 2/3 detection)
- ✅ GetDTE fully implemented with retry logic
- ✅ **Automatic DTE status polling every 15 minutes** (APScheduler)
- ✅ Webhook notifications to Odoo on status changes
- ✅ Enhanced certificate encryption documentation

### New Features

1. **Automatic DTE Status Poller** (`dte-service/scheduler/`)
   - Background job running every 15 minutes
   - Queries SII for pending DTEs
   - Updates Redis cache automatically
   - Sends webhooks to Odoo on status changes
   - Timeout detection for DTEs > 7 days old

2. **XSD Validation** (`dte-service/schemas/xsd/`)
   - Official SII schema DTE_v10.xsd (269 lines)
   - Download script for future updates
   - Validates structure before SII submission

3. **Enhanced Error Handling** (`dte-service/utils/sii_error_codes.py`)
   - 59 error codes from 10 categories
   - Intelligent retry detection
   - User-friendly error messages

4. **Certificate Class Validation** (`models/dte_certificate.py`)
   - OID detection (2.16.152.1.2.2.1 = Class 2, 2.16.152.1.2.3.1 = Class 3)
   - Automatic validation on certificate upload

5. **DTE Reception** (`clients/sii_soap_client.py`)
   - `get_received_dte()` method complete
   - Downloads DTEs from suppliers
   - Automatic XML parsing

### Documentation Added

- **GAP_CLOSURE_SUMMARY.md** - Executive summary of gap closure
- **GAP_CLOSURE_FINAL_REPORT_2025-10-21.md** - Detailed implementation report
- **DEPLOYMENT_CHECKLIST_POLLER.md** - Step-by-step deployment guide
- **CERTIFICATE_ENCRYPTION_SETUP.md** - Security best practices

### Next Steps

1. **Rebuild Docker image** to include new dependencies:
   ```bash
   docker-compose build dte-service
   docker-compose restart dte-service
   ```

2. **Verify poller started**:
   ```bash
   docker-compose logs dte-service | grep "poller_initialized"
   ```

3. **Test in Maullin** (SII sandbox) before production

For complete details, see `docs/GAP_CLOSURE_SUMMARY.md`.
