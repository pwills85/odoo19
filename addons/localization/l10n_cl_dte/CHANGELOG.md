# Changelog - l10n_cl_dte

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [19.0.6.0.0] - 2025-11-04

### 🎉 MAJOR: Module Consolidation (BREAKING CHANGE)

#### Added
- **Enhanced Features** (merged from deprecated l10n_cl_dte_enhanced):
  - **Contact Person:** `contact_id` field on invoices with smart button
  - **Custom Payment Terms:** `forma_pago` field for flexible payment descriptions
  - **CEDIBLE Support:** Checkbox for electronic factoring (Art. 18 Res. SII N° 93/2003)
  - **SII References:** Complete model and views for document references (NC/ND mandatory)

- **New Models:**
  - `account.move.enhanced` - Contact, forma_pago, cedible fields
  - `account.move.reference` - SII document references
  - `res.company.bank.info` - Company bank information
  - `report.helper` - PDF generation utilities

- **New Views:**
  - `views/account_move_enhanced_views.xml` - Enhanced invoice form
  - `views/account_move_reference_views.xml` - SII references management
  - `views/res_company_bank_info_views.xml` - Bank info configuration

- **Dependencies:**
  - `pdf417==0.8.1` - TED barcode generation
  - `pika>=1.3.0` - RabbitMQ async processing
  - `tenacity>=8.0.0` - SII API retry logic

#### Changed
- **Version:** 19.0.5.0.0 → 19.0.6.0.0 (BREAKING CHANGE)
- **Module Description:** Updated to reflect enhanced features
- **Loading Order:** Report files now load before view files (dependency fix)
- **Menu Structure:** SII References menu moved to main menus.xml

#### Deprecated
- **l10n_cl_dte_enhanced:** All features merged into base module
  - See `.deprecated/README.md` for migration instructions
  - Module will be removed in future release

#### Removed
- **l10n_cl_dte_eergygroup:** Deleted (95% code duplication)
  - 2,587 lines of duplicate code eliminated
  - Users should never have used this module

#### Fixed
- Loading order issues causing "External ID not found" errors
- Circular dependencies between reports and views
- ACL header duplication in ir.model.access.csv
- Missing Python dependencies (pika, tenacity, pdf417)

#### Technical Debt
- PDF417 generator temporarily disabled (TODO in report_helper.py)
- Using pdf417 0.8.1 instead of pdf417gen (library compatibility)

### Migration Notes

**For users of l10n_cl_dte_enhanced:**
1. Backup your database
2. Uninstall l10n_cl_dte_enhanced
3. Upgrade l10n_cl_dte to v19.0.6.0.0+
4. All enhanced features are now available in base module

**For users of l10n_cl_dte_eergygroup:**
- This module should never have been used
- Uninstall immediately and use l10n_cl_dte instead

---

## [19.0.5.0.0] - 2025-10-24

### Added
- P0-3: Multi-company record rules (data isolation)
- P0-7: Final cleanup - removed .pyc, __pycache__
- Sprint 3: Contingency Mode features
- Sprint 1: RCV (Registro de Compra/Venta) integration
- Phase 2: AI microservices optimization (90% cost reduction)

### Changed
- Comprehensive unit tests for critical DTE functionality
- README.rst with OCA standard structure

### Fixed
- P0-6: Security fix - removed hardcoded password in RabbitMQ helper
- P0-3: Multi-company rules - removed catalog models (incorrect scope)

---

## [19.0.4.0.0] - 2025-10-20

### Added
- Disaster Recovery features (DTE backups, failed queue)
- Comprehensive SII activity codes catalog (700 official codes)
- Comuna catalog (347 official Chilean communes)

### Changed
- Enhanced PDF report templates (professional layout)

### Fixed
- Menu duplication in invoice views

---

## [19.0.3.0.0] - 2025-10-15

### Added
- Boletas de Honorarios (BHE) module
- Historical retention rates (IUE 2018-2025, BHE)

### Changed
- Improved DTE workflow performance

---

## [19.0.2.0.0] - 2025-10-10

### Added
- Initial Odoo 19 CE migration
- Core DTE functionality (emission, reception)
- CAF (Folio Authorization) management
- Certificate management
- SII Web Services integration

### Known Issues
- Module still in beta
- Some P1 issues pending resolution

---

## [19.0.1.0.0] - 2025-10-01

### Added
- Initial release for Odoo 19 CE
- Basic Chilean electronic invoicing support

---

**Format:** [Version] - YYYY-MM-DD
**Versioning:** `[major].[odoo_version].[minor].[patch].[revision]`
- major: Breaking changes
- odoo_version: Odoo version (19 for Odoo 19)
- minor: New features
- patch: Bug fixes
- revision: Small improvements

**Example:** 19.0.6.0.0 = Odoo 19, version 6 (breaking change), initial release
