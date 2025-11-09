# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 34 (Factura No Afecta o Exenta Electrónica)
Según especificación técnica del SII - Ventas exentas de IVA
"""

from lxml import etree
import structlog
from utils.rut_utils import format_rut_for_sii

logger = structlog.get_logger()


class DTEGenerator34:
    """
    Generador de XML para DTE Tipo 34 (Factura No Afecta o Exenta Electrónica)

    Para ventas de bienes o servicios exentos de IVA:
    - Exportaciones de servicios
    - Productos agrícolas exentos
    - Servicios educacionales exentos
    - Proyectos internacionales exentos
    """

    def __init__(self):
        self.dte_type = '34'
    
    def generate(self, factura_exenta_data: dict) -> str:
        """
        Genera XML DTE 34 según norma SII.

        Factura para ventas EXENTAS de IVA (sin retenciones):
        - NO tiene IVA (0%)
        - NO tiene retenciones (eso es solo Boleta de Honorarios)
        - Usa MntExe (Monto Exento) en vez de MntNeto

        Args:
            factura_exenta_data: Dict con datos de la factura exenta

        Returns:
            str: XML generado (sin firmar)
        """
        logger.info("generating_dte_34", folio=factura_exenta_data.get('folio'))

        # Crear elemento raíz
        dte = etree.Element('DTE', version="1.0")
        documento = etree.SubElement(dte, 'Documento', ID=f"DTE-{factura_exenta_data['folio']}")

        # Encabezado
        self._add_encabezado(documento, factura_exenta_data)

        # Detalle (productos/servicios exentos)
        self._add_detalle(documento, factura_exenta_data)

        # Referencias (opcional, si aplica)
        if factura_exenta_data.get('referencias'):
            self._add_referencias(documento, factura_exenta_data)

        # Convertir a string
        xml_string = etree.tostring(
            dte,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')

        logger.info("dte_34_generated", folio=factura_exenta_data.get('folio'))

        return xml_string
    
    def _add_encabezado(self, documento: etree.Element, data: dict):
        """Encabezado DTE 34 (Factura Exenta)"""
        encabezado = etree.SubElement(documento, 'Encabezado')

        # IdDoc
        id_doc = etree.SubElement(encabezado, 'IdDoc')
        etree.SubElement(id_doc, 'TipoDTE').text = '34'
        etree.SubElement(id_doc, 'Folio').text = str(data['folio'])
        etree.SubElement(id_doc, 'FchEmis').text = data['fecha_emision']

        # Campos opcionales IdDoc
        if data.get('fecha_vencimiento'):
            etree.SubElement(id_doc, 'FchVenc').text = data['fecha_vencimiento']

        if data.get('forma_pago'):
            etree.SubElement(id_doc, 'FmaPago').text = str(data['forma_pago'])

        if data.get('periodo_desde'):
            etree.SubElement(id_doc, 'PeriodoDesde').text = data['periodo_desde']

        if data.get('periodo_hasta'):
            etree.SubElement(id_doc, 'PeriodoHasta').text = data['periodo_hasta']

        # Emisor (empresa que vende)
        emisor = etree.SubElement(encabezado, 'Emisor')
        etree.SubElement(emisor, 'RUTEmisor').text = self._format_rut_dte(data['emisor']['rut'])
        etree.SubElement(emisor, 'RznSoc').text = data['emisor']['razon_social']
        etree.SubElement(emisor, 'GiroEmis').text = data['emisor']['giro']

        # Acteco (puede ser múltiple, hasta 4)
        if data['emisor'].get('acteco'):
            acteco_codes = data['emisor']['acteco'] if isinstance(data['emisor']['acteco'], list) else [data['emisor']['acteco']]
            for acteco in acteco_codes[:4]:
                etree.SubElement(emisor, 'Acteco').text = str(acteco).strip()

        etree.SubElement(emisor, 'DirOrigen').text = data['emisor']['direccion']

        if data['emisor'].get('comuna'):
            etree.SubElement(emisor, 'CmnaOrigen').text = data['emisor']['comuna']

        etree.SubElement(emisor, 'CiudadOrigen').text = data['emisor'].get('ciudad', '')

        # Receptor (empresa o persona que compra)
        receptor = etree.SubElement(encabezado, 'Receptor')
        etree.SubElement(receptor, 'RUTRecep').text = self._format_rut_dte(data['receptor']['rut'])
        etree.SubElement(receptor, 'RznSocRecep').text = data['receptor']['razon_social']

        if data['receptor'].get('giro'):
            etree.SubElement(receptor, 'GiroRecep').text = data['receptor']['giro']

        etree.SubElement(receptor, 'DirRecep').text = data['receptor']['direccion']

        if data['receptor'].get('comuna'):
            etree.SubElement(receptor, 'CmnaRecep').text = data['receptor']['comuna']

        if data['receptor'].get('ciudad'):
            etree.SubElement(receptor, 'CiudadRecep').text = data['receptor']['ciudad']

        # Totales (SOLO exento, sin IVA)
        totales = etree.SubElement(encabezado, 'Totales')

        # CRÍTICO: Usar MntExe (Monto Exento) NO MntNeto
        etree.SubElement(totales, 'MntExe').text = str(int(data['montos']['monto_exento']))

        # Total = Exento (sin IVA)
        etree.SubElement(totales, 'MntTotal').text = str(int(data['montos']['monto_total']))
    
    def _add_detalle(self, documento: etree.Element, data: dict):
        """Detalle de productos/servicios exentos"""
        for linea_data in data['productos']:
            detalle = etree.SubElement(documento, 'Detalle')

            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])

            # CRÍTICO: IndExe = Indicador de exención
            # 1 = No afecto o exento de IVA
            etree.SubElement(detalle, 'IndExe').text = '1'

            etree.SubElement(detalle, 'NmbItem').text = linea_data['nombre'][:80]

            # Descripción adicional (opcional)
            if linea_data.get('descripcion'):
                etree.SubElement(detalle, 'DscItem').text = linea_data['descripcion'][:1000]

            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])

            if linea_data.get('unidad'):
                etree.SubElement(detalle, 'UnmdItem').text = linea_data['unidad']

            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data['precio_unitario']))

            # Descuentos/recargos (opcional)
            if linea_data.get('descuento_pct'):
                etree.SubElement(detalle, 'DescuentoPct').text = str(linea_data['descuento_pct'])

            if linea_data.get('recargo_pct'):
                etree.SubElement(detalle, 'RecargoPct').text = str(linea_data['recargo_pct'])

            etree.SubElement(detalle, 'MontoItem').text = str(int(linea_data['subtotal']))

    def _add_referencias(self, documento: etree.Element, data: dict):
        """
        Referencias a documentos asociados (opcional)

        Factura Exenta puede referenciar:
        - Orden de Compra (OC)
        - Guía de Despacho previa
        - Factura anterior (correcciones)
        """
        for idx, ref_data in enumerate(data['referencias'], start=1):
            referencia = etree.SubElement(documento, 'Referencia')

            etree.SubElement(referencia, 'NroLinRef').text = str(idx)

            # Tipo de documento referenciado
            tipo_doc = ref_data.get('tipo_doc', '801')  # Default: OC
            etree.SubElement(referencia, 'TpoDocRef').text = str(tipo_doc)

            if ref_data.get('ind_global'):
                etree.SubElement(referencia, 'IndGlobal').text = str(ref_data['ind_global'])

            etree.SubElement(referencia, 'FolioRef').text = str(ref_data['folio'])

            if ref_data.get('rut_otro'):
                etree.SubElement(referencia, 'RUTOtr').text = self._format_rut_dte(ref_data['rut_otro'])

            if ref_data.get('fecha'):
                etree.SubElement(referencia, 'FchRef').text = ref_data['fecha']

            if ref_data.get('codigo_ref'):
                etree.SubElement(referencia, 'CodRef').text = str(ref_data['codigo_ref'])

            if ref_data.get('razon_ref'):
                etree.SubElement(referencia, 'RazonRef').text = ref_data['razon_ref'][:90]

    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE. Delegado a utils.rut_utils."""
        return format_rut_for_sii(rut)

