# -*- coding: utf-8 -*-
"""
Parser de XML para DTEs recibidos
Extrae datos de DTEs de proveedores
"""

from lxml import etree
import structlog
from typing import Dict, List

logger = structlog.get_logger()


class XMLParser:
    """Parser de XML de DTEs recibidos"""
    
    def __init__(self):
        pass
    
    def parse_dte(self, dte_xml: str) -> Dict:
        """
        Parsea un DTE recibido y extrae datos relevantes.
        
        Args:
            dte_xml: XML del DTE
        
        Returns:
            Dict con datos extraídos:
                - tipo_dte
                - folio
                - fecha_emision
                - rut_emisor
                - razon_social_emisor
                - rut_receptor
                - monto_neto
                - monto_iva
                - monto_total
                - lineas: []
        """
        logger.info("parsing_dte_xml")
        
        try:
            # Parsear XML
            root = etree.fromstring(dte_xml.encode('ISO-8859-1'))
            
            # Extraer datos del encabezado
            tipo_dte = self._extract_text(root, './/IdDoc/TipoDTE')
            folio = self._extract_text(root, './/IdDoc/Folio')
            fecha = self._extract_text(root, './/IdDoc/FchEmis')
            
            # Emisor (proveedor)
            rut_emisor = self._extract_text(root, './/Emisor/RUTEmisor')
            razon_social_emisor = self._extract_text(root, './/Emisor/RznSoc')
            giro_emisor = self._extract_text(root, './/Emisor/GiroEmis')
            
            # Receptor (nuestra empresa)
            rut_receptor = self._extract_text(root, './/Receptor/RUTRecep')
            razon_social_receptor = self._extract_text(root, './/Receptor/RznSocRecep')
            
            # Totales
            monto_neto = self._extract_text(root, './/Totales/MntNeto', default='0')
            monto_iva = self._extract_text(root, './/Totales/IVA', default='0')
            monto_total = self._extract_text(root, './/Totales/MntTotal', default='0')
            
            # Líneas de detalle
            lineas = self._extract_lineas(root)
            
            dte_data = {
                'tipo_dte': tipo_dte,
                'folio': folio,
                'fecha_emision': fecha,
                'rut_emisor': rut_emisor,
                'razon_social_emisor': razon_social_emisor,
                'giro_emisor': giro_emisor,
                'rut_receptor': rut_receptor,
                'razon_social_receptor': razon_social_receptor,
                'monto_neto': float(monto_neto),
                'monto_iva': float(monto_iva),
                'monto_total': float(monto_total),
                'lineas': lineas,
            }
            
            logger.info("dte_parsed",
                       tipo=tipo_dte,
                       folio=folio,
                       lineas_count=len(lineas))
            
            return dte_data
            
        except Exception as e:
            logger.error("parsing_error", error=str(e))
            raise Exception(f"Error al parsear DTE: {str(e)}")
    
    def _extract_text(self, root: etree.Element, xpath: str, default: str = '') -> str:
        """Extrae texto de elemento XML usando xpath"""
        element = root.find(xpath)
        return element.text if element is not None else default
    
    def _extract_lineas(self, root: etree.Element) -> List[Dict]:
        """
        Extrae líneas de detalle del DTE.
        
        Returns:
            List[Dict]: Lista de líneas con datos
        """
        lineas = []
        
        # Buscar todos los elementos Detalle
        detalles = root.findall('.//Detalle')
        
        for detalle in detalles:
            linea = {
                'numero_linea': self._extract_text(detalle, 'NroLinDet'),
                'nombre': self._extract_text(detalle, 'NmbItem'),
                'descripcion': self._extract_text(detalle, 'DscItem'),
                'cantidad': float(self._extract_text(detalle, 'QtyItem', '0')),
                'unidad': self._extract_text(detalle, 'UnmdItem', 'UN'),
                'precio_unitario': float(self._extract_text(detalle, 'PrcItem', '0')),
                'monto': float(self._extract_text(detalle, 'MontoItem', '0')),
            }
            lineas.append(linea)
        
        return lineas

