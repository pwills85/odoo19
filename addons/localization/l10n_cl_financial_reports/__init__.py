# -*- coding: utf-8 -*-

# Nota: Evitamos importar tests desde __init__ para no afectar instalación

# Manifest y hooks

# Import specific hook functions for Odoo
from .hooks import post_init_hook

# Subpaquetes Odoo convencionales
from . import utils
from . import wizards










from . import controllers
from . import models
from . import report
