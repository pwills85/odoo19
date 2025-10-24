# -*- coding: utf-8 -*-
"""
Generador de XML para Consumo de Folios
Reporte mensual al SII de folios utilizados
"""

from lxml import etree
from datetime import datetime
import structlog
from utils.rut_utils import format_rut_for_sii

logger = structlog.get_logger()


class ConsumoFoliosGenerator:
    """Generador de XML para reporte de Consumo de Folios al SII"""
    
    def __init__(self):
        pass
    
    def generate(self, consumo_data: dict) -> str:
        """
        Genera XML de Consumo de Folios según formato SII.
        
        Args:
            consumo_data: Dict con datos del consumo
                - rut_emisor
                - periodo (YYYY-MM)
                - dte_type
                - folio_inicio
                - folio_fin
                - cantidad
        
        Returns:
            str: XML generado
        """
        logger.info("generating_consumo_folios",
                    periodo=consumo_data.get('periodo'),
                    dte_type=consumo_data.get('dte_type'))
        
        # Crear elemento raíz
        consumo = etree.Element('ConsumoFolios', version="1.0")
        
        # DocumentoConsumoFolios
        doc_consumo = etree.SubElement(consumo, 'DocumentoConsumoFolios', ID="CF")
        
        # Caratula
        caratula = etree.SubElement(doc_consumo, 'Caratula')
        
        etree.SubElement(caratula, 'RutEmisor').text = self._format_rut(consumo_data['rut_emisor'])
        etree.SubElement(caratula, 'RutEnvia').text = self._format_rut(consumo_data['rut_emisor'])
        
        # Período (YYYY-MM)
        etree.SubElement(caratula, 'PeriodoTributario').text = consumo_data['periodo']
        
        # FchResol y NroResol (datos de autorización SII)
        if consumo_data.get('fecha_resolucion'):
            etree.SubElement(caratula, 'FchResol').text = consumo_data['fecha_resolucion']
        if consumo_data.get('nro_resolucion'):
            etree.SubElement(caratula, 'NroResol').text = str(consumo_data['nro_resolucion'])
        
        # TipoDocumento
        etree.SubElement(caratula, 'TipoDocumento').text = str(consumo_data['dte_type'])
        
        # Resumen (rango de folios)
        resumen = etree.SubElement(doc_consumo, 'Resumen')
        
        etree.SubElement(resumen, 'TipoDocumento').text = str(consumo_data['dte_type'])
        etree.SubElement(resumen, 'MntNeto').text = str(consumo_data.get('monto_neto', 0))
        etree.SubElement(resumen, 'MntIva').text = str(consumo_data.get('monto_iva', 0))
        etree.SubElement(resumen, 'MntTotal').text = str(consumo_data.get('monto_total', 0))
        etree.SubElement(resumen, 'FoliosEmitidos').text = str(consumo_data.get('cantidad', 0))
        etree.SubElement(resumen, 'FoliosAnulados').text = str(consumo_data.get('anulados', 0))
        etree.SubElement(resumen, 'FoliosUtilizados').text = str(consumo_data.get('cantidad', 0))
        
        # Rangos de folios
        rangos = etree.SubElement(resumen, 'RangoUtilizados')
        etree.SubElement(rangos, 'Inicial').text = str(consumo_data['folio_inicio'])
        etree.SubElement(rangos, 'Final').text = str(consumo_data['folio_fin'])
        
        # Convertir a string
        xml_string = etree.tostring(
            consumo,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("consumo_folios_generated",
                    periodo=consumo_data.get('periodo'),
                    folios=f"{consumo_data['folio_inicio']}-{consumo_data['folio_fin']}")
        
        return xml_string
    
    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE. Delegado a utils.rut_utils."""
        return format_rut_for_sii(rut)

