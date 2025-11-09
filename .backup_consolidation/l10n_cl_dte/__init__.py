# -*- coding: utf-8 -*-
"""
l10n_cl_dte - Chilean Electronic Invoicing for Odoo 19 CE
===========================================================

Migration Note (2025-10-24):
- Migrated from microservice architecture to native Python libs/
- DTE generation, signature, and SII communication now in Odoo
- ~100ms faster performance (no HTTP overhead)
- Better integration with Odoo ORM and workflows
"""

from . import libs       # ⭐ NEW: Native DTE library (xml, sign, SOAP)
from . import models
from . import controllers
from . import wizards
from . import tools
from . import report
