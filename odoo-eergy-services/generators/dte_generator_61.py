# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 61 (Nota de Crédito Electrónica)
Según especificación técnica del SII - Devoluciones/descuentos
"""

from lxml import etree
import structlog
from utils.rut_utils import format_rut_for_sii

logger = structlog.get_logger()


class DTEGenerator61:
    """
    Generador de XML para DTE Tipo 61 (Nota de Crédito)
    
    Similar a DTE 33 pero SIEMPRE referencia a documento original
    """
    
    def __init__(self):
        self.dte_type = '61'
    
    def generate(self, nc_data: dict) -> str:
        """
        Genera XML DTE 61 según norma SII.
        
        Args:
            nc_data: Dict con datos de la nota de crédito
        
        Returns:
            str: XML generado (sin firmar)
        """
        logger.info("generating_dte_61", folio=nc_data.get('folio'))
        
        # Estructura similar a DTE 33
        dte = etree.Element('DTE', version="1.0")
        documento = etree.SubElement(dte, 'Documento', ID=f"DTE-{nc_data['folio']}")
        
        # Encabezado
        self._add_encabezado(documento, nc_data)
        
        # Detalle
        self._add_detalle(documento, nc_data)
        
        # Referencia (OBLIGATORIA para NC)
        self._add_referencia(documento, nc_data)
        
        xml_string = etree.tostring(
            dte,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("dte_61_generated", folio=nc_data.get('folio'))
        
        return xml_string
    
    def _add_encabezado(self, documento: etree.Element, data: dict):
        """Encabezado DTE 61 (similar a DTE 33)"""
        encabezado = etree.SubElement(documento, 'Encabezado')

        # IdDoc
        id_doc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(id_doc, 'TipoDTE').text = '61'
        etree.SubElement(id_doc, 'Folio').text = str(data['folio'])
        etree.SubElement(id_doc, 'FchEmis').text = data['fecha_emision']

        # IndNoRebaja: Indicador NC sin derecho a descontar débito (opcional pero importante)
        # 1 = NC no da derecho a descontar débito fiscal del período
        if data.get('ind_no_rebaja'):
            etree.SubElement(id_doc, 'IndNoRebaja').text = '1'

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

        etree.SubElement(emisor, 'CiudadOrigen').text = data['emisor'].get('ciudad', '')

        # Receptor
        receptor = etree.SubElement(encabezado, 'Receptor')
        etree.SubElement(receptor, 'RUTRecep').text = self._format_rut_dte(data['receptor']['rut'])
        etree.SubElement(receptor, 'RznSocRecep').text = data['receptor']['razon_social']
        etree.SubElement(receptor, 'GiroRecep').text = data['receptor'].get('giro', '')
        etree.SubElement(receptor, 'DirRecep').text = data['receptor']['direccion']

        if data['receptor'].get('comuna'):
            etree.SubElement(receptor, 'CmnaRecep').text = data['receptor']['comuna']

        etree.SubElement(receptor, 'CiudadRecep').text = data['receptor'].get('ciudad', '')

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
        """Detalle de la NC"""
        for linea_data in data['lineas']:
            detalle = etree.SubElement(documento, 'Detalle')
            
            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])
            etree.SubElement(detalle, 'NmbItem').text = linea_data['nombre'][:80]
            
            if linea_data.get('descripcion'):
                etree.SubElement(detalle, 'DscItem').text = linea_data['descripcion'][:1000]
            
            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])
            etree.SubElement(detalle, 'UnmdItem').text = linea_data.get('unidad', 'UN')
            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data['precio_unitario']))
            etree.SubElement(detalle, 'MontoItem').text = str(int(linea_data['subtotal']))
    
    def _add_referencia(self, documento: etree.Element, data: dict):
        """
        Referencia al documento original (OBLIGATORIO).

        NC debe referenciar la factura que anula/modifica
        """
        ref_data = data['documento_referencia']
        referencia = etree.SubElement(documento, 'Referencia')

        etree.SubElement(referencia, 'NroLinRef').text = '1'
        etree.SubElement(referencia, 'TpoDocRef').text = str(ref_data.get('tipo_doc', '33'))  # Generalmente factura

        # Indicador de referencia global (opcional)
        if ref_data.get('ind_global'):
            etree.SubElement(referencia, 'IndGlobal').text = str(ref_data['ind_global'])

        etree.SubElement(referencia, 'FolioRef').text = str(ref_data['folio'])

        # RUT otro contribuyente (opcional)
        if ref_data.get('rut_otro'):
            etree.SubElement(referencia, 'RUTOtr').text = self._format_rut_dte(ref_data['rut_otro'])

        etree.SubElement(referencia, 'FchRef').text = ref_data['fecha']

        # CodRef: Código de referencia según tabla SII (IMPORTANTE)
        # 1 = Anula documento de referencia
        # 2 = Corrige texto documento de referencia
        # 3 = Corrige montos
        codigo_ref = data.get('codigo_referencia', 1)
        etree.SubElement(referencia, 'CodRef').text = str(codigo_ref)

        # Razón de la NC
        motivo = data.get('motivo_nc', 'Anula Documento de Referencia')
        etree.SubElement(referencia, 'RazonRef').text = motivo[:90]
    
    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE. Delegado a utils.rut_utils."""
        return format_rut_for_sii(rut)

