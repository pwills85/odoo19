# Files_Reference

## Odoo Module Entry Point
- `addons/localization/l10n_cl_dte/__manifest__.py` - Module metadata

## Models (17 total)
- `models/account_move_dte.py` - Invoices/Credit Notes/Debit Notes
- `models/purchase_order_dte.py` - DTE 34 (Fees) + project_id field ⭐⭐
- `models/stock_picking_dte.py` - DTE 52 (Shipping)
- `models/dte_certificate.py` - Digital certificates
- `models/dte_caf.py` - Folio authorization files
- `models/dte_ai_client.py` - AI Service client (abstract model) ⭐⭐
- `models/project_dashboard.py` - Project profitability KPIs (10 computed fields) ⭐⭐
- `models/res_company_dte.py` - Company config + dte_require_analytic_on_purchases ⭐⭐

## Validators
- `tools/rut_validator.py` - RUT validation (módulo 11)

## DTE Service Core
- `dte-service/main.py` - FastAPI application
- `dte-service/generators/` - DTE XML generators
- `dte-service/signers/dte_signer.py` - XMLDSig signature
- `dte-service/clients/sii_soap_client.py` - SII integration

## Authentication & Security (⭐ NUEVO)
- `dte-service/auth/__init__.py` - Auth module exports
- `dte-service/auth/models.py` - User, Role, Token models (120 lines)
- `dte-service/auth/oauth2.py` - OAuth2 handler multi-provider (240 lines)
- `dte-service/auth/permissions.py` - RBAC system (340 lines)
- `dte-service/auth/routes.py` - Auth endpoints (180 lines)

## Testing Suite (⭐ NUEVO)
- `dte-service/pytest.ini` - pytest configuration
- `dte-service/tests/conftest.py` - Shared fixtures (217 lines)
- `dte-service/tests/test_dte_generators.py` - 15 tests (230 lines)
- `dte-service/tests/test_xmldsig_signer.py` - 9 tests (195 lines)
- `dte-service/tests/test_sii_soap_client.py` - 12 tests (360 lines)
- `dte-service/tests/test_dte_status_poller.py` - 12 tests (340 lines)

## AI Service Core
- `ai-service/main.py` - FastAPI application + analytics router ⭐⭐
- `ai-service/clients/anthropic_client.py` - Claude integration
- `ai-service/reconciliation/invoice_matcher.py` - Semantic matching
- **✨ `ai-service/sii_monitor/`** - Sistema monitoreo SII
  - `scraper.py` - Web scraping (182 líneas)
  - `extractor.py` - Extracción texto (158 líneas)
  - `analyzer.py` - Análisis Claude (221 líneas)
  - `classifier.py` - Clasificación impacto (73 líneas)
  - `notifier.py` - Notificaciones Slack (164 líneas)
  - `storage.py` - Persistencia Redis (115 líneas)
  - `orchestrator.py` - Orquestación (157 líneas)
- **✨ `ai-service/analytics/`** - Project matching con IA ⭐⭐
  - `project_matcher_claude.py` - Claude 3.5 Sonnet matching (298 líneas)
  - `__init__.py` - Package init
- **✨ `ai-service/routes/`** - FastAPI routers ⭐⭐
  - `analytics.py` - Analytics endpoints (224 líneas)
  - `__init__.py` - Package init

## Migration & Extraction Scripts (⭐ NUEVO)
- `scripts/extract_odoo11_credentials.py` - Extrae certificado y CAF desde Odoo 11 DB (380 líneas)
  - Clase `Odoo11Extractor` con métodos `extract_certificate()` y `extract_caf_files()`
  - Conecta a PostgreSQL Odoo 11, extrae de tablas `sii.firma` y `caf`
  - Exporta `.p12` + password + 5 archivos `CAF_XX.xml`
- `scripts/import_to_odoo19.sh` - Valida archivos extraídos y guía importación (180 líneas)
  - Validación OpenSSL de certificado PKCS#12
  - Validación xmllint de archivos CAF XML
  - Instrucciones paso a paso para importación manual en UI Odoo 19
