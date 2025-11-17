# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 56 (Nota de Débito Electrónica)
Según especificación técnica del SII - Aumentos/cargos adicionales
"""

from lxml import etree
import structlog
from utils.rut_utils import format_rut_for_sii

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

        # IdDoc
        id_doc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(id_doc, 'TipoDTE').text = '56'
        etree.SubElement(id_doc, 'Folio').text = str(data['folio'])
        etree.SubElement(id_doc, 'FchEmis').text = data['fecha_emision']

        # Fecha vencimiento (opcional)
        if data.get('fecha_vencimiento'):
            etree.SubElement(id_doc, 'FchVenc').text = data['fecha_vencimiento']

        # Forma de pago (opcional)
        if data.get('forma_pago'):
            etree.SubElement(id_doc, 'FmaPago').text = str(data['forma_pago'])

        # Emisor
        emisor = etree.SubElement(encabezado, 'Emisor')
        etree.SubElement(emisor, 'RUTEmisor').text = self._format_rut_dte(data['emisor']['rut'])
        etree.SubElement(emisor, 'RznSoc').text = data['emisor']['razon_social']
        etree.SubElement(emisor, 'GiroEmis').text = data['emisor']['giro']

        # Acteco (puede ser múltiple)
        if data['emisor'].get('acteco'):
            acteco_codes = data['emisor']['acteco'] if isinstance(data['emisor']['acteco'], list) else [data['emisor']['acteco']]
            for acteco in acteco_codes[:4]:
                etree.SubElement(emisor, 'Acteco').text = str(acteco).strip()

        etree.SubElement(emisor, 'DirOrigen').text = data['emisor']['direccion']

        if data['emisor'].get('comuna'):
            etree.SubElement(emisor, 'CmnaOrigen').text = data['emisor']['comuna']

        etree.SubElement(emisor, 'CiudadOrigen').text = data['emisor']['ciudad']

        # Receptor
        receptor = etree.SubElement(encabezado, 'Receptor')
        etree.SubElement(receptor, 'RUTRecep').text = self._format_rut_dte(data['receptor']['rut'])
        etree.SubElement(receptor, 'RznSocRecep').text = data['receptor']['razon_social']
        etree.SubElement(receptor, 'GiroRecep').text = data['receptor']['giro']
        etree.SubElement(receptor, 'DirRecep').text = data['receptor']['direccion']

        if data['receptor'].get('comuna'):
            etree.SubElement(receptor, 'CmnaRecep').text = data['receptor']['comuna']

        etree.SubElement(receptor, 'CiudadRecep').text = data['receptor']['ciudad']

        # Totales
        totales = etree.SubElement(encabezado, 'Totales')

        if data['totales'].get('monto_neto'):
            etree.SubElement(totales, 'MntNeto').text = str(int(data['totales']['monto_neto']))

        if data['totales'].get('monto_exento'):
            etree.SubElement(totales, 'MntExe').text = str(int(data['totales']['monto_exento']))

        if data['totales'].get('monto_neto'):
            tasa_iva = data['totales'].get('tasa_iva', 19)
            etree.SubElement(totales, 'TasaIVA').text = str(tasa_iva)

        if data['totales'].get('monto_iva'):
            etree.SubElement(totales, 'IVA').text = str(int(data['totales']['monto_iva']))

        etree.SubElement(totales, 'MntTotal').text = str(int(data['totales']['monto_total']))
    
    def _add_detalle(self, documento: etree.Element, data: dict):
        """Detalle (igual que DTE 33)"""
        for linea_data in data['lineas']:
            detalle = etree.SubElement(documento, 'Detalle')

            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])
            etree.SubElement(detalle, 'NmbItem').text = linea_data['nombre'][:80]

            if linea_data.get('descripcion'):
                etree.SubElement(detalle, 'DscItem').text = linea_data['descripcion'][:1000]

            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])
            etree.SubElement(detalle, 'UnmdItem').text = linea_data.get('unidad', 'UN')
            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data['precio_unitario']))

            if linea_data.get('descuento_pct') and linea_data['descuento_pct'] > 0:
                etree.SubElement(detalle, 'DescuentoPct').text = str(linea_data['descuento_pct'])

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

        # Indicador de referencia global (opcional)
        if ref_data.get('ind_global'):
            etree.SubElement(referencia, 'IndGlobal').text = str(ref_data['ind_global'])

        etree.SubElement(referencia, 'FolioRef').text = str(ref_data['folio'])

        # RUT otro contribuyente (opcional)
        if ref_data.get('rut_otro'):
            etree.SubElement(referencia, 'RUTOtr').text = self._format_rut_dte(ref_data['rut_otro'])

        etree.SubElement(referencia, 'FchRef').text = ref_data['fecha']

        # Código de referencia (recomendado)
        # 1 = Anula documento, 2 = Corrige texto, 3 = Corrige montos
        if ref_data.get('codigo'):
            etree.SubElement(referencia, 'CodRef').text = str(ref_data['codigo'])

        # Razón de la Nota de Débito
        motivo = data.get('motivo_nd', 'Nota de Débito - Cargo adicional')
        etree.SubElement(referencia, 'RazonRef').text = motivo[:90]
    
    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE. Delegado a utils.rut_utils."""
        return format_rut_for_sii(rut)

