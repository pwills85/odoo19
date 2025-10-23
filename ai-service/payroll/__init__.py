# -*- coding: utf-8 -*-
"""
Payroll Module for AI-Service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Módulo de nóminas chilenas con extracción automática de indicadores
y validación inteligente usando Claude API.
"""

from .previred_scraper import PreviredScraper
from .payroll_validator import PayrollValidator

__all__ = ['PreviredScraper', 'PayrollValidator']
