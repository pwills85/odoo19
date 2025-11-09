# -*- coding: utf-8 -*-

from . import dte_service_integration  # ⭐ Integration layer first
from . import ai_chat_integration      # ⭐ AI Chat integration
from . import dte_certificate
from . import dte_caf
from . import dte_communication
from . import dte_consumo_folios
from . import dte_libro
from . import dte_inbox  # ⭐ DTE Reception (Gap #1)
from . import rabbitmq_helper
from . import account_move_dte
from . import account_journal_dte
from . import account_tax_dte
from . import purchase_order_dte
from . import stock_picking_dte
from . import retencion_iue
from . import res_partner_dte
from . import res_company_dte
from . import res_config_settings

