# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 56 (Nota de Débito Electrónica)
Según especificación técnica del SII - Aumentos/cargos adicionales
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class DTEGenerator56:
    """
    Generador de XML para DTE Tipo 56 (Nota de Débito)
    
    Similar a DTE 33 pero SIEMPRE referencia a documento original
    """
    
    def __init__(self):
        self.dte_type = '56'
    
    def generate(self, nd_data: dict) -> str:
        """
        Genera XML DTE 56 según norma SII.
        
        Args:
            nd_data: Dict con datos de la nota de débito
        
        Returns:
            str: XML generado (sin firmar)
        """
        logger.info("generating_dte_56", folio=nd_data.get('folio'))
        
        # Estructura similar a DTE 33
        dte = etree.Element('DTE', version="1.0")
        documento = etree.SubElement(dte, 'Documento', ID=f"DTE-{nd_data['folio']}")
        
        # Encabezado (igual que DTE 33)
        self._add_encabezado(documento, nd_data)
        
        # Detalle
        self._add_detalle(documento, nd_data)
        
        # Referencia (OBLIGATORIA para ND)
        self._add_referencia(documento, nd_data)
        
        xml_string = etree.tostring(
            dte,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("dte_56_generated", folio=nd_data.get('folio'))
        
        return xml_string
    
    def _add_encabezado(self, documento: etree.Element, data: dict):
        """Encabezado (igual que DTE 33)"""
        encabezado = etree.SubElement(documento, 'Encabezado')
        
        id_doc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(id_doc, 'TipoDTE').text = '56'
        etree.SubElement(id_doc, 'Folio').text = str(data['folio'])
        etree.SubElement(id_doc, 'FchEmis').text = data['fecha_emision']
        
        # Emisor, Receptor, Totales (igual que DTE 33)
        # Código similar a dte_generator_33.py
        # ... (simplificado por brevedad, seguir mismo patrón)
    
    def _add_detalle(self, documento: etree.Element, data: dict):
        """Detalle (igual que DTE 33)"""
        for linea_data in data['lineas']:
            detalle = etree.SubElement(documento, 'Detalle')
            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])
            etree.SubElement(detalle, 'NmbItem').text = linea_data['nombre'][:80]
            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])
            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data['precio_unitario']))
            etree.SubElement(detalle, 'MontoItem').text = str(int(linea_data['subtotal']))
    
    def _add_referencia(self, documento: etree.Element, data: dict):
        """
        Referencia al documento original (OBLIGATORIO)
        
        ND debe referenciar el documento que modifica
        """
        ref_data = data['documento_referencia']
        referencia = etree.SubElement(documento, 'Referencia')
        
        etree.SubElement(referencia, 'NroLinRef').text = '1'
        etree.SubElement(referencia, 'TpoDocRef').text = str(ref_data.get('tipo_doc', '33'))
        etree.SubElement(referencia, 'FolioRef').text = str(ref_data['folio'])
        etree.SubElement(referencia, 'FchRef').text = ref_data['fecha']
        etree.SubElement(referencia, 'RazonRef').text = data.get('motivo_nd', 'Nota de Débito')[:90]
    
    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE"""
        rut_clean = rut.replace('.', '').replace(' ', '')
        if '-' not in rut_clean:
            rut_clean = rut_clean[:-1] + '-' + rut_clean[-1]
        return rut_clean.upper()

