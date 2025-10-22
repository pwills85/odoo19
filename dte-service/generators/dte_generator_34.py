# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 34 (Liquidación de Honorarios)
Según especificación técnica del SII - Pago a profesionales independientes
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class DTEGenerator34:
    """
    Generador de XML para DTE Tipo 34 (Liquidación de Honorarios)
    
    Reutiliza patrón de DTE 33 con campos específicos de retenciones IUE
    """
    
    def __init__(self):
        self.dte_type = '34'
    
    def generate(self, honorarios_data: dict) -> str:
        """
        Genera XML DTE 34 según norma SII.
        
        Similar a DTE 33 pero incluye:
        - Retención IUE (Impuesto Único Empleador)
        - Período de servicios
        - Datos del profesional (receptor del pago)
        
        Args:
            honorarios_data: Dict con datos de la liquidación
        
        Returns:
            str: XML generado (sin firmar)
        """
        logger.info("generating_dte_34", folio=honorarios_data.get('folio'))
        
        # Crear elemento raíz (mismo que DTE 33)
        dte = etree.Element('DTE', version="1.0")
        documento = etree.SubElement(dte, 'Documento', ID=f"DTE-{honorarios_data['folio']}")
        
        # Encabezado
        self._add_encabezado(documento, honorarios_data)
        
        # Detalle (líneas de servicios)
        self._add_detalle(documento, honorarios_data)
        
        # Retenciones (ESPECÍFICO DTE 34)
        self._add_retenciones(documento, honorarios_data)
        
        # Convertir a string
        xml_string = etree.tostring(
            dte,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("dte_34_generated", folio=honorarios_data.get('folio'))
        
        return xml_string
    
    def _add_encabezado(self, documento: etree.Element, data: dict):
        """Agrega encabezado del DTE 34"""
        encabezado = etree.SubElement(documento, 'Encabezado')
        
        # IdDoc
        id_doc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(id_doc, 'TipoDTE').text = '34'
        etree.SubElement(id_doc, 'Folio').text = str(data['folio'])
        etree.SubElement(id_doc, 'FchEmis').text = data['fecha_emision']
        
        # Emisor (empresa que paga)
        emisor = etree.SubElement(encabezado, 'Emisor')
        etree.SubElement(emisor, 'RUTEmisor').text = self._format_rut_dte(data['emisor']['rut'])
        etree.SubElement(emisor, 'RznSoc').text = data['emisor']['razon_social']
        etree.SubElement(emisor, 'GiroEmis').text = data['emisor']['giro']
        etree.SubElement(emisor, 'DirOrigen').text = data['emisor']['direccion']
        etree.SubElement(emisor, 'CmnaOrigen').text = data['emisor']['comuna']
        
        # Receptor (profesional que recibe pago)
        receptor = etree.SubElement(encabezado, 'Receptor')
        etree.SubElement(receptor, 'RUTRecep').text = self._format_rut_dte(data['profesional']['rut'])
        etree.SubElement(receptor, 'RznSocRecep').text = data['profesional']['nombre']
        etree.SubElement(receptor, 'GiroRecep').text = data['profesional'].get('giro', 'Profesional Independiente')
        
        # Totales (sin IVA en honorarios)
        totales = etree.SubElement(encabezado, 'Totales')
        etree.SubElement(totales, 'MntNeto').text = str(int(data['montos']['monto_bruto']))
        etree.SubElement(totales, 'MntTotal').text = str(int(data['montos']['monto_bruto']))
    
    def _add_detalle(self, documento: etree.Element, data: dict):
        """Agrega detalles de servicios prestados"""
        for linea_data in data['servicios']:
            detalle = etree.SubElement(documento, 'Detalle')
            
            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])
            etree.SubElement(detalle, 'NmbItem').text = linea_data['descripcion'][:80]
            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])
            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data['precio_unitario']))
            etree.SubElement(detalle, 'MontoItem').text = str(int(linea_data['subtotal']))
    
    def _add_retenciones(self, documento: etree.Element, data: dict):
        """
        Agrega información de retenciones IUE.
        
        CRÍTICO PARA DTE 34: Campo obligatorio
        """
        # Crear elemento DscRcgGlobal (Descuentos y Recargos Globales)
        # para incluir la retención
        dsc_rcg = etree.SubElement(documento, 'DscRcgGlobal')
        
        etree.SubElement(dsc_rcg, 'TpoMov').text = 'D'  # D = Descuento (retención)
        etree.SubElement(dsc_rcg, 'GlosaDR').text = 'Retención IUE'
        etree.SubElement(dsc_rcg, 'TpoValor').text = '$'  # Valor en pesos
        etree.SubElement(dsc_rcg, 'ValorDR').text = str(int(data['montos']['monto_retencion']))
    
    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE (sin puntos, con guión)"""
        rut_clean = rut.replace('.', '').replace(' ', '')
        if '-' not in rut_clean:
            rut_clean = rut_clean[:-1] + '-' + rut_clean[-1]
        return rut_clean.upper()

