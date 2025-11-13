YOLO mode is enabled. All tool calls will be automatically approved.
Loaded cached credentials.
using macos seatbelt (profile: permissive-open) ...
YOLO mode is enabled. All tool calls will be automatically approved.
Loaded cached credentials.
Okay, entiendo. Para listar los 5 modelos principales en `addons/localization/l10n_cl_dte/models/` y explicar brevemente qué hace cada uno, necesito primero listar los archivos en ese directorio y luego leer su contenido para identificar los modelos y su funcionalidad.

Empezaré listando los archivos Python en el directorio especificado.
He obtenido una lista de 40 archivos Python. Basándome en los nombres, seleccionaré 5 modelos que parecen ser centrales para la funcionalidad DTE (Documento Tributario Electrónico) en Chile.

Mis selecciones iniciales son:
1.  `account_move_dte.py`: Probablemente maneja la funcionalidad DTE principal relacionada con movimientos contables.
2.  `dte_caf.py`: Seguramente gestiona el CAF (Código de Autorización de Folios), esencial para la generación de DTE.
3.  `dte_certificate.py`: Posiblemente se encarga de los certificados digitales para firmar DTEs.
4.  `res_company_dte.py`: Podría extender el modelo `res.company` con configuraciones específicas de DTE.
5.  `dte_inbox.py`: Es probable que gestione la recepción y procesamiento de DTEs entrantes.

Ahora, leeré el contenido de estos archivos para confirmar su propósito y ofrecer una breve explicación.

--- /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/models/account_move_dte.py ---

[WARNING: This file was truncated. To view the full content, use the 'read_file' tool on this specific file.]

# -*- coding: utf-8 -*-
"""
Account Move DTE - Chilean Electronic Invoicing
================================================

Extends account.move with DTE (Chilean electronic invoicing) functionality.

Migration Note (2025-10-24):
- Migrated from microservice architecture to native Odoo libs/
- Eliminates HTTP overhead (~100ms faster)
- Uses Python libraries directly (lxml, xmlsec, zeep)
- Better integration with Odoo ORM and workflows

**REFACTORED:** 2025-11-02 - FASE 2 - Odoo 19 CE Compliance
- Removed AbstractModel inheritance from libs/
- Now uses pure Python classes with Dependency Injection
- Cleaner architecture, better testability
"""

from odoo import models, fields, api, tools, _
from odoo.exceptions import ValidationError, UserError
import logging
import base64
from datetime import datetime

# Import pure Python classes from libs/ (FASE 2 refactor)
from ..libs.xml_generator import DTEXMLGenerator
from ..libs.xml_signer import XMLSigner
from ..libs.sii_soap_client import SIISoapClient
from ..libs.ted_generator import TEDGenerator
from ..libs.xsd_validator import XSDValidator

# P1.3 GAP CLOSURE: Performance metrics instrumentation
from ..libs.performance_metrics import measure_performance

# P3.1 GAP CLOSURE: Structured logging with conditional JSON output
from ..libs.structured_logging import get_dte_logger, log_dte_operation

_logger = get_dte_logger(__name__)

# Safe Redis exception handling (lazy import compatible)
try:
    import redis
    RedisError = redis.RedisError
except ImportError:
    # If redis not installed, treat as generic exception
    RedisError = Exception


class AccountMoveDTE(models.Model):
    """
    Extensión de account.move para Documentos Tributarios Electrónicos (DTE)

    ESTRATEGIA: EXTENDER, NO DUPLICAR
    - Reutilizamos todos los campos de account.move
    - Solo agregamos campos específicos DTE
    - Heredamos workflow de Odoo

    DTE Generation: Uses native Python libs/ (no HTTP microservice)

    **FASE 2 REFACTOR (2025-11-02):** Removed AbstractModel inheritance.
    Now uses pure Python classes from libs/ with Dependency Injection pattern.
    Methods like generate_dte_xml() now delegate to DTEXMLGenerator instance.
    """
    _inherit = 'account.move'
    
    # ════════════════════════════
