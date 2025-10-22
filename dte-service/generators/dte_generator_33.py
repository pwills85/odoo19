# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 33 (Factura Electrónica)
Según especificación técnica del SII
"""

from lxml import etree
from datetime import datetime
import structlog

logger = structlog.get_logger()


class DTEGenerator33:
    """Generador de XML para DTE Tipo 33 (Factura Electrónica)"""
    
    def __init__(self):
        self.dte_type = '33'
    
    def generate(self, invoice_data: dict) -> str:
        """
        Genera XML DTE 33 según norma SII.
        
        Args:
            invoice_data: Dict con datos de la factura
        
        Returns:
            str: XML generado (sin firmar)
        """
        logger.info("generating_dte_33", folio=invoice_data.get('folio'))
        
        # Crear elemento raíz
        dte = etree.Element('DTE', version="1.0")
        documento = etree.SubElement(dte, 'Documento', ID=f"DTE-{invoice_data['folio']}")
        
        # Encabezado
        self._add_encabezado(documento, invoice_data)
        
        # Detalle (líneas)
        self._add_detalle(documento, invoice_data)
        
        # Descuentos y recargos (si aplica)
        self._add_descuentos_recargos(documento, invoice_data)
        
        # Convertir a string
        xml_string = etree.tostring(
            dte,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("dte_33_generated", folio=invoice_data.get('folio'))
        
        return xml_string
    
    def _add_encabezado(self, documento: etree.Element, data: dict):
        """Agrega encabezado del DTE"""
        encabezado = etree.SubElement(documento, 'Encabezado')
        
        # IdDoc
        id_doc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(id_doc, 'TipoDTE').text = '33'
        etree.SubElement(id_doc, 'Folio').text = str(data['folio'])
        etree.SubElement(id_doc, 'FchEmis').text = data['fecha_emision']
        
        # Emisor
        emisor = etree.SubElement(encabezado, 'Emisor')
        etree.SubElement(emisor, 'RUTEmisor').text = self._format_rut_dte(data['emisor']['rut'])
        etree.SubElement(emisor, 'RznSoc').text = data['emisor']['razon_social']
        etree.SubElement(emisor, 'GiroEmis').text = data['emisor']['giro']
        
        # Dirección emisor
        etree.SubElement(emisor, 'DirOrigen').text = data['emisor']['direccion']
        etree.SubElement(emisor, 'CmnaOrigen').text = data['emisor']['comuna']
        etree.SubElement(emisor, 'CiudadOrigen').text = data['emisor']['ciudad']
        
        # Receptor
        receptor = etree.SubElement(encabezado, 'Receptor')
        etree.SubElement(receptor, 'RUTRecep').text = self._format_rut_dte(data['receptor']['rut'])
        etree.SubElement(receptor, 'RznSocRecep').text = data['receptor']['razon_social']
        etree.SubElement(receptor, 'GiroRecep').text = data['receptor']['giro']
        
        # Dirección receptor
        etree.SubElement(receptor, 'DirRecep').text = data['receptor']['direccion']
        etree.SubElement(receptor, 'CmnaRecep').text = data['receptor']['comuna']
        etree.SubElement(receptor, 'CiudadRecep').text = data['receptor']['ciudad']
        
        # Totales
        totales = etree.SubElement(encabezado, 'Totales')
        etree.SubElement(totales, 'MntNeto').text = str(int(data['totales']['monto_neto']))
        etree.SubElement(totales, 'TasaIVA').text = '19'  # IVA 19% Chile
        etree.SubElement(totales, 'IVA').text = str(int(data['totales']['monto_iva']))
        etree.SubElement(totales, 'MntTotal').text = str(int(data['totales']['monto_total']))
    
    def _add_detalle(self, documento: etree.Element, data: dict):
        """Agrega detalles (líneas) del DTE"""
        for linea_data in data['lineas']:
            detalle = etree.SubElement(documento, 'Detalle')
            
            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])
            etree.SubElement(detalle, 'NmbItem').text = linea_data['nombre'][:80]  # Max 80 chars
            
            if linea_data.get('descripcion'):
                etree.SubElement(detalle, 'DscItem').text = linea_data['descripcion'][:1000]
            
            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])
            etree.SubElement(detalle, 'UnmdItem').text = linea_data.get('unidad', 'UN')
            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data['precio_unitario']))
            
            if linea_data.get('descuento_pct') and linea_data['descuento_pct'] > 0:
                etree.SubElement(detalle, 'DescuentoPct').text = str(linea_data['descuento_pct'])
            
            etree.SubElement(detalle, 'MontoItem').text = str(int(linea_data['subtotal']))
    
    def _add_descuentos_recargos(self, documento: etree.Element, data: dict):
        """Agrega descuentos o recargos globales (si aplica)"""
        # TODO: Implementar si se requieren descuentos/recargos globales
        pass
    
    def add_ted_to_dte(self, dte_xml: str, ted_xml: str) -> str:
        """
        Agrega el TED (Timbre Electrónico) al DTE.
        
        Args:
            dte_xml: XML del DTE sin TED
            ted_xml: XML del TED generado
        
        Returns:
            str: XML del DTE con TED incluido
        """
        # Parsear ambos XML
        dte_root = etree.fromstring(dte_xml.encode('ISO-8859-1'))
        ted_element = etree.fromstring(ted_xml.encode('ISO-8859-1'))
        
        # Buscar elemento Documento
        documento = dte_root.find('.//Documento')
        
        if documento is not None:
            # Insertar TED después del último elemento y antes de Signature
            # Buscar Signature si existe
            signature = documento.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            
            if signature is not None:
                # Insertar antes de Signature
                index = list(documento).index(signature)
                documento.insert(index, ted_element)
            else:
                # Insertar al final
                documento.append(ted_element)
        
        # Retornar XML completo
        return etree.tostring(
            dte_root,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
    
    def _format_rut_dte(self, rut: str) -> str:
        """
        Formatea RUT para DTE (sin puntos, con guión).
        Ejemplo: 12345678-9
        """
        # Remover puntos
        rut_clean = rut.replace('.', '').replace(' ', '')
        
        # Asegurar guión
        if '-' not in rut_clean:
            rut_clean = rut_clean[:-1] + '-' + rut_clean[-1]
        
        return rut_clean.upper()

