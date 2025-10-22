# -*- coding: utf-8 -*-
"""
Generador de XML para Libro de Compra/Venta
Reporte mensual al SII con detalle de operaciones
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class LibroGenerator:
    """Generador de XML para Libro Electrónico de Compra/Venta"""
    
    def __init__(self):
        pass
    
    def generate(self, libro_data: dict) -> str:
        """
        Genera XML de Libro según formato SII.
        
        Args:
            libro_data: Dict con datos del libro
                - tipo: 'venta' o 'compra'
                - rut_emisor
                - periodo (YYYY-MM)
                - documentos: lista de DTEs
                - totales
        
        Returns:
            str: XML generado
        """
        tipo = libro_data.get('tipo', 'venta')
        
        logger.info("generating_libro",
                    tipo=tipo,
                    periodo=libro_data.get('periodo'),
                    docs_count=len(libro_data.get('documentos', [])))
        
        # Crear elemento raíz según tipo
        if tipo == 'venta':
            libro = etree.Element('LibroCompraVenta')
            env_libro = etree.SubElement(libro, 'EnvioLibro', ID="Libro")
        else:  # compra
            libro = etree.Element('LibroCompraVenta')
            env_libro = etree.SubElement(libro, 'EnvioLibro', ID="Libro")
        
        # Carátula
        self._add_caratula(env_libro, libro_data)
        
        # Resumen
        self._add_resumen(env_libro, libro_data)
        
        # Detalles (cada documento)
        for doc in libro_data.get('documentos', []):
            self._add_detalle_documento(env_libro, doc, tipo)
        
        # Convertir a string
        xml_string = etree.tostring(
            libro,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("libro_generated",
                    tipo=tipo,
                    docs_count=len(libro_data.get('documentos', [])))
        
        return xml_string
    
    def _add_caratula(self, env_libro: etree.Element, data: dict):
        """Agrega carátula del libro"""
        caratula = etree.SubElement(env_libro, 'Caratula')
        
        etree.SubElement(caratula, 'RutEmisorLibro').text = self._format_rut(data['rut_emisor'])
        etree.SubElement(caratula, 'RutEnvia').text = self._format_rut(data['rut_emisor'])
        etree.SubElement(caratula, 'PeriodoTributario').text = data['periodo']
        
        if data.get('fecha_resolucion'):
            etree.SubElement(caratula, 'FchResol').text = data['fecha_resolucion']
        if data.get('nro_resolucion'):
            etree.SubElement(caratula, 'NroResol').text = str(data['nro_resolucion'])
        
        # Tipo de libro
        tipo_libro = '1' if data['tipo'] == 'venta' else '2'
        etree.SubElement(caratula, 'TipoLibro').text = tipo_libro
        
        # Tipo de envío (TOTAL o PARCIAL)
        etree.SubElement(caratula, 'TipoEnvio').text = 'TOTAL'
    
    def _add_resumen(self, env_libro: etree.Element, data: dict):
        """Agrega resumen con totales"""
        resumen = etree.SubElement(env_libro, 'ResumenPeriodo')
        
        totales = data.get('totales', {})
        
        etree.SubElement(resumen, 'TpoDoc').text = '33'  # Por ahora solo facturas
        etree.SubElement(resumen, 'TotDoc').text = str(len(data.get('documentos', [])))
        etree.SubElement(resumen, 'TotMntNeto').text = str(int(totales.get('monto_neto', 0)))
        etree.SubElement(resumen, 'TotMntIva').text = str(int(totales.get('monto_iva', 0)))
        etree.SubElement(resumen, 'TotMntTotal').text = str(int(totales.get('monto_total', 0)))
    
    def _add_detalle_documento(self, env_libro: etree.Element, doc: dict, tipo_libro: str):
        """Agrega detalle de cada documento"""
        detalle = etree.SubElement(env_libro, 'Detalle')
        
        etree.SubElement(detalle, 'TpoDoc').text = str(doc.get('tipo_dte', '33'))
        etree.SubElement(detalle, 'NroDoc').text = str(doc['folio'])
        etree.SubElement(detalle, 'FchDoc').text = doc['fecha']
        etree.SubElement(detalle, 'RUTDoc').text = self._format_rut(doc['rut_contraparte'])
        etree.SubElement(detalle, 'RznSoc').text = doc['razon_social'][:50]
        etree.SubElement(detalle, 'MntNeto').text = str(int(doc['monto_neto']))
        etree.SubElement(detalle, 'MntIVA').text = str(int(doc['monto_iva']))
        etree.SubElement(detalle, 'MntTotal').text = str(int(doc['monto_total']))
    
    def _format_rut(self, rut: str) -> str:
        """Formatea RUT"""
        return rut.replace('.', '').replace(' ', '').upper()

