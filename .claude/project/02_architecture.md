# Architecture

## Three-Tier Distributed System

**IMPORTANTE:** A diferencia de Odoo 11/18 (monolíticos), este stack es **distribuido**. Cuando se evalúa paridad funcional, se debe considerar el stack completo:
- **Odoo 11/18:** Toda funcionalidad en un único módulo Python
- **Odoo 19 Stack:** Funcionalidad distribuida entre módulo + 2 microservicios + infraestructura

**Mapeo de Responsabilidades:**
- **UI/UX, Configuración, Vistas, Wizards** → Odoo Module
- **Generación XML, Firma Digital, SOAP SII, Validaciones XSD** → DTE Microservice
- **IA, Monitoreo SII, Reconciliación, Pre-validación** → AI Microservice
- **Procesamiento Asíncrono, Colas, Status Polling** → RabbitMQ + Redis

## Componentes del Stack

### 1. Odoo Module (`addons/localization/l10n_cl_dte/`)
- Extends standard Odoo models (account.move, purchase.order, stock.picking)
- UI/UX for DTE operations, certificate management, folio tracking
- Integration with l10n_cl and l10n_latam_base
- Access control and audit logging
- **Paridad:** Cubre 60% funcionalidad vs Odoo 11 (UI/configuration)

### 2. DTE Microservice (`dte-service/`)
- FastAPI service (port 8001, internal only)
- XML generation for 5 DTE types using factory pattern
- XMLDSig PKCS#1 digital signature (xmlsec)
- SII SOAP client with retry logic
- XSD validation and TED (Timbre Electrónico) generation
- OAuth2/OIDC authentication + RBAC (25 permisos)
- **Paridad:** Cubre 90% funcionalidad core vs Odoo 11 (engine DTE)

### 3. AI Microservice (`ai-service/`) ✨
- FastAPI service (port 8002, internal only)
- Pre-validation using Anthropic Claude API
- Invoice reconciliation with semantic embeddings
- **NUEVO:** Monitoreo automático SII (scraping + análisis)
- **NUEVO:** Notificaciones Slack de cambios normativos
- Singleton pattern for ML model management
- Graceful fallback (doesn't block DTE operations)
- **Ventaja Única:** Odoo 11/18 NO tienen capacidades IA

## Key Architectural Principles

- **Extend, Don't Duplicate:** Module inherits from Odoo models rather than creating duplicates
- **Single Responsibility:** Each generator handles one DTE type independently
- **Defense in Depth:** Multiple validation layers (RUT → XSD → Structure → TED → SII)
- **Internal-Only Services:** DTE/AI services not exposed to internet, only to Odoo
- **Proactive Monitoring:** Sistema automático que monitorea cambios del SII
- **Enterprise Security:** OAuth2/OIDC authentication + RBAC with 25 granular permissions ⭐ NUEVO
- **Test-Driven Quality:** 80% code coverage with comprehensive test suite ⭐ NUEVO

## DTE Document Types

| Code | Document Type | Odoo Model | Generator File |
|------|---------------|------------|----------------|
| 33 | Factura Electrónica | account.move (invoice) | dte_generator_33.py |
| 61 | Nota de Crédito | account.move (refund) | dte_generator_61.py |
| 56 | Nota de Débito | account.move (debit_note) | dte_generator_56.py |
| 52 | Guía de Despacho | stock.picking | dte_generator_52.py |
| 34 | Liquidación Honorarios | purchase.order | dte_generator_34.py |

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
