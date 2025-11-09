"""
SII Monitoring Module

Módulo para monitoreo automático de noticias, circulares y resoluciones
del Servicio de Impuestos Internos (SII) de Chile.

Componentes:
- scraper: Web scraping de URLs SII
- extractor: Extracción de texto de HTML/PDF
- analyzer: Análisis con Claude API
- classifier: Clasificación de impacto
- notifier: Notificaciones multi-canal
- storage: Persistencia en Redis + Odoo
"""

__version__ = "1.0.0"
__author__ = "Eergygroup"
