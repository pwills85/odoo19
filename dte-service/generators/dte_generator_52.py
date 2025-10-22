# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 52 (Guía de Despacho Electrónica)  
Según especificación técnica del SII - Traslado de mercancías
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class DTEGenerator52:
    """
    Generador de XML para DTE Tipo 52 (Guía de Despacho)
    
    Documenta movimiento físico de mercancías
    """
    
    def __init__(self):
        self.dte_type = '52'
    
    def generate(self, guia_data: dict) -> str:
        """
        Genera XML DTE 52 según norma SII.
        
        Args:
            guia_data: Dict con datos de la guía
        
        Returns:
            str: XML generado (sin firmar)
        """
        logger.info("generating_dte_52", folio=guia_data.get('folio'))
        
        # Crear elemento raíz
        dte = etree.Element('DTE', version="1.0")
        documento = etree.SubElement(dte, 'Documento', ID=f"DTE-{guia_data['folio']}")
        
        # Encabezado
        self._add_encabezado(documento, guia_data)
        
        # Detalle
        self._add_detalle(documento, guia_data)
        
        # Referencia a factura (si aplica)
        if guia_data.get('factura_referencia'):
            self._add_referencia(documento, guia_data)
        
        xml_string = etree.tostring(
            dte,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("dte_52_generated", folio=guia_data.get('folio'))
        
        return xml_string
    
    def _add_encabezado(self, documento: etree.Element, data: dict):
        """Encabezado DTE 52"""
        encabezado = etree.SubElement(documento, 'Encabezado')
        
        # IdDoc
        id_doc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(id_doc, 'TipoDTE').text = '52'
        etree.SubElement(id_doc, 'Folio').text = str(data['folio'])
        etree.SubElement(id_doc, 'FchEmis').text = data['fecha_emision']
        etree.SubElement(id_doc, 'IndTraslado').text = str(data.get('tipo_traslado', '1'))
        
        # Emisor
        emisor = etree.SubElement(encabezado, 'Emisor')
        etree.SubElement(emisor, 'RUTEmisor').text = self._format_rut_dte(data['emisor']['rut'])
        etree.SubElement(emisor, 'RznSoc').text = data['emisor']['razon_social']
        etree.SubElement(emisor, 'GiroEmis').text = data['emisor']['giro']
        etree.SubElement(emisor, 'DirOrigen').text = data['emisor']['direccion']
        etree.SubElement(emisor, 'CmnaOrigen').text = data['emisor']['comuna']
        
        # Receptor
        receptor = etree.SubElement(encabezado, 'Receptor')
        etree.SubElement(receptor, 'RUTRecep').text = self._format_rut_dte(data['receptor']['rut'])
        etree.SubElement(receptor, 'RznSocRecep').text = data['receptor']['razon_social']
        etree.SubElement(receptor, 'DirRecep').text = data['receptor']['direccion']
        etree.SubElement(receptor, 'CmnaRecep').text = data['receptor']['comuna']
        
        # Transporte
        if data.get('patente_vehiculo'):
            transporte = etree.SubElement(encabezado, 'Transporte')
            etree.SubElement(transporte, 'Patente').text = data['patente_vehiculo'][:8]
        
        # Totales
        totales = etree.SubElement(encabezado, 'Totales')
        etree.SubElement(totales, 'MntNeto').text = str(int(data.get('totales', {}).get('monto_neto', 0)))
        etree.SubElement(totales, 'TasaIVA').text = '19'
        etree.SubElement(totales, 'IVA').text = str(int(data.get('totales', {}).get('monto_iva', 0)))
        etree.SubElement(totales, 'MntTotal').text = str(int(data.get('totales', {}).get('monto_total', 0)))
    
    def _add_detalle(self, documento: etree.Element, data: dict):
        """Detalle de productos"""
        for linea_data in data['productos']:
            detalle = etree.SubElement(documento, 'Detalle')
            
            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])
            etree.SubElement(detalle, 'NmbItem').text = linea_data['nombre'][:80]
            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])
            etree.SubElement(detalle, 'UnmdItem').text = linea_data.get('unidad', 'UN')
            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data.get('precio_unitario', 0)))
            etree.SubElement(detalle, 'MontoItem').text = str(int(linea_data.get('subtotal', 0)))
    
    def _add_referencia(self, documento: etree.Element, data: dict):
        """Referencia a factura asociada"""
        ref_data = data['factura_referencia']
        referencia = etree.SubElement(documento, 'Referencia')
        
        etree.SubElement(referencia, 'NroLinRef').text = '1'
        etree.SubElement(referencia, 'TpoDocRef').text = '33'
        etree.SubElement(referencia, 'FolioRef').text = str(ref_data['folio'])
        etree.SubElement(referencia, 'FchRef').text = ref_data['fecha']
    
    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE"""
        rut_clean = rut.replace('.', '').replace(' ', '')
        if '-' not in rut_clean:
            rut_clean = rut_clean[:-1] + '-' + rut_clean[-1]
        return rut_clean.upper()
