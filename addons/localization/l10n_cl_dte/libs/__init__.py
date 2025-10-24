# -*- coding: utf-8 -*-
"""
DTE Business Logic Library
===========================

Professional DTE generation library integrated into Odoo 19 CE.

This package contains the core business logic for Chilean electronic invoicing (DTE):
- XML generation (lxml)
- Digital signature (xmlsec, cryptography)
- SII SOAP communication (zeep)
- XSD validation
- TED (Timbre Electrónico) generation

Architecture:
- All logic in Python native (no HTTP overhead)
- Direct access to Odoo ORM and database
- Integrated with Odoo workflows and automation
- Uses Odoo attachment manager for XML storage

Migration: Migrated from odoo-eergy-services microservice (2025-10-24)
Reason: Maximum integration with Odoo 19 CE, better performance, standard ERP practices
"""

from . import xml_generator
from . import xml_signer
from . import sii_soap_client
from . import ted_generator
from . import xsd_validator
from . import dte_structure_validator  # Sprint 4 (2025-10-24): Reception validation
from . import ted_validator             # Sprint 4 (2025-10-24): TED validation
from . import libro_guias_generator     # Sprint 5 (2025-10-24): Libro Guías SII
from . import caf_handler               # Sprint 5 (2025-10-24): CAF management

__all__ = [
    'xml_generator',
    'xml_signer',
    'sii_soap_client',
    'ted_generator',
    'xsd_validator',
    'dte_structure_validator',  # Sprint 4
    'ted_validator',            # Sprint 4
    'libro_guias_generator',    # Sprint 5
    'caf_handler',              # Sprint 5
]
