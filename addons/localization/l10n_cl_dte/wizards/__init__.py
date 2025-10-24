# -*- coding: utf-8 -*-

# Core wizards
from . import dte_generate_wizard
from . import upload_certificate
from . import send_dte_batch
from . import generate_consumo_folios
from . import generate_libro

# Contingency Mode (Sprint 3 - 2025-10-24)
from . import contingency_wizard

# AI Integration - Phase 2 (2025-10-24)
from . import ai_chat_universal_wizard  # 🆕 Universal AI Chat (RBAC-aware)

# Advanced wizards (optional)
# from . import ai_chat_wizard  # Requires ai_chat_integration
# from . import dte_commercial_response_wizard

