# -*- coding: utf-8 -*-
"""
DTE Business Logic Library - Pure Python Classes
=================================================

**REFACTORED:** 2025-11-02 - Odoo 19 CE Architecture Compliance

Professional DTE generation library for Chilean electronic invoicing.

This package contains PURE PYTHON CLASSES (not Odoo AbstractModels) for:
- XML generation (lxml)
- Digital signature (xmlsec, cryptography)
- SII SOAP communication (zeep)
- XSD validation
- TED (Timbre Electrónico) generation
- Commercial responses

**CRITICAL ARCHITECTURAL CHANGE:**

Odoo 19 CE requires that libs/ contain ONLY pure Python classes, NOT AbstractModel.
This refactor converts all classes from:
  ❌ models.AbstractModel (Odoo ORM) → ✅ Pure Python classes

**Why this matters:**
- Odoo 19 validates all model imports must start with 'odoo.addons.'
- libs/ directory cannot use AbstractModel without triggering AssertionError
- Pure Python classes are testable, portable, and Odoo 19 compliant

**Architecture Pattern: Dependency Injection**

Instead of inheriting from models.AbstractModel, classes now use:
- Optional env parameter injection for database access
- Pure business logic with no ORM dependencies
- Clear separation: libs/ = business logic, models/ = ORM integration

**Usage Examples:**

1. **DTEXMLGenerator** (Pure - no env needed):
   ```python
   from ..libs.xml_generator import DTEXMLGenerator

   generator = DTEXMLGenerator()
   xml = generator.generate_dte_xml('33', invoice_data)
   ```

2. **XMLSigner** (Needs env for certificate DB access):
   ```python
   from ..libs.xml_signer import XMLSigner

   signer = XMLSigner(self.env)
   signed_xml = signer.sign_xml_dte(xml, certificate_id)
   ```

3. **SIISoapClient** (Needs env for config and company):
   ```python
   from ..libs.sii_soap_client import SIISoapClient

   client = SIISoapClient(self.env)
   response = client.send_dte_to_sii(signed_xml, rut_emisor, company)
   ```

4. **TEDGenerator** (Needs env for CAF DB access):
   ```python
   from ..libs.ted_generator import TEDGenerator

   generator = TEDGenerator(self.env)
   ted_xml = generator.generate_ted(dte_data, caf_id)
   ```

5. **CommercialResponseGenerator** (Pure - no env needed):
   ```python
   from ..libs.commercial_response_generator import CommercialResponseGenerator

   generator = CommercialResponseGenerator()
   response_xml = generator.generate_commercial_response_xml(response_data)
   ```

6. **XSDValidator** (Pure - no env needed):
   ```python
   from ..libs.xsd_validator import XSDValidator

   validator = XSDValidator()
   is_valid, error_msg = validator.validate_xml_against_xsd(xml, '33')
   ```

**Migration History:**
- 2025-10-24: Migrated from odoo-eergy-services microservice
- 2025-10-29: P0-P1 Gap Closure (signature, TED, authentication)
- 2025-11-02: Refactored to Pure Python (Odoo 19 compliance)
- 2025-11-02: Gap Closure P0 - F-002 CAF signature validation (Resolución Ex. SII N°11)
- 2025-11-02: Gap Closure P0 - S-005 XXE protection (OWASP Top 10 A4:2017)

**Files in this package:**

Core DTE processing (REFACTORED - Production Ready):
- xml_generator.py           → DTEXMLGenerator (pure)
- xml_signer.py              → XMLSigner (env injection)
- sii_soap_client.py         → SIISoapClient (env injection)
- ted_generator.py           → TEDGenerator (env injection)
- commercial_response_generator.py → CommercialResponseGenerator (pure)
- xsd_validator.py           → XSDValidator (pure)

Additional validators (Sprint 4-5):
- dte_structure_validator.py → Reception validation
- ted_validator.py           → TED signature validation
- libro_guias_generator.py   → Libro Guías SII
- caf_handler.py             → CAF management
- caf_signature_validator.py → CAF signature validation (F-002 Gap Closure P0)
- safe_xml_parser.py         → XXE-safe XML parsing (S-005 Gap Closure P0)
- sii_authenticator.py       → SII authentication token
- envio_dte_generator.py     → EnvioDTE wrapper

**DO NOT import these modules here** - they are pure Python classes meant to be
imported directly by models/ using:
  `from ..libs.module_name import ClassName`

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

# NO IMPORTS NEEDED - Pure Python classes are imported directly by models/
# This file serves as documentation only

__all__ = []  # Empty - classes imported directly by consumers
