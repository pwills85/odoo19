# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 33 (Factura Electrónica)
Según especificación técnica del SII
"""

from lxml import etree
from datetime import datetime
import structlog
from utils.rut_utils import format_rut_for_sii

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

        # Referencias (si aplica - común en Notas de Crédito/Débito)
        self._add_referencias(documento, invoice_data)

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

        # FchVenc: Fecha vencimiento (opcional)
        if data.get('fecha_vencimiento'):
            etree.SubElement(id_doc, 'FchVenc').text = data['fecha_vencimiento']

        # IndNoRebaja: Indicador nota crédito sin derecho a rebaja (opcional)
        if data.get('ind_no_rebaja'):
            etree.SubElement(id_doc, 'IndNoRebaja').text = '1'

        # TipoDespacho: Tipo de despacho (opcional, pero común en facturas)
        if data.get('tipo_despacho'):
            etree.SubElement(id_doc, 'TipoDespacho').text = str(data['tipo_despacho'])

        # IndTraslado: Indicador de traslado (para guías, opcional)
        if data.get('ind_traslado'):
            etree.SubElement(id_doc, 'IndTraslado').text = str(data['ind_traslado'])

        # FmaPago: Forma de pago (1=Contado, 2=Crédito, 3=Otro)
        if data.get('forma_pago'):
            etree.SubElement(id_doc, 'FmaPago').text = str(data['forma_pago'])

        # FchCancel: Fecha cancelación si forma pago = crédito (opcional)
        if data.get('fecha_cancelacion'):
            etree.SubElement(id_doc, 'FchCancel').text = data['fecha_cancelacion']

        # MntCancel: Monto cancelado (opcional)
        if data.get('monto_cancelado'):
            etree.SubElement(id_doc, 'MntCancel').text = str(int(data['monto_cancelado']))

        # SaldoInsol: Saldo insoluto (opcional)
        if data.get('saldo_insoluto'):
            etree.SubElement(id_doc, 'SaldoInsol').text = str(int(data['saldo_insoluto']))
        
        # Emisor
        emisor = etree.SubElement(encabezado, 'Emisor')
        etree.SubElement(emisor, 'RUTEmisor').text = self._format_rut_dte(data['emisor']['rut'])
        etree.SubElement(emisor, 'RznSoc').text = data['emisor']['razon_social']
        etree.SubElement(emisor, 'GiroEmis').text = data['emisor']['giro']

        # Acteco: OBLIGATORIO (minOccurs default=1, maxOccurs=4)
        # Código actividad económica de 6 dígitos según CIIU4.CL 2012
        if data['emisor'].get('acteco'):
            # Puede haber hasta 4 códigos de actividad
            acteco_codes = data['emisor']['acteco'] if isinstance(data['emisor']['acteco'], list) else [data['emisor']['acteco']]
            for acteco in acteco_codes[:4]:  # Máximo 4 según XSD
                etree.SubElement(emisor, 'Acteco').text = str(acteco).strip()

        # Dirección emisor
        etree.SubElement(emisor, 'DirOrigen').text = data['emisor']['direccion']

        # CmnaOrigen: OPCIONAL (minOccurs="0") pero RECOMENDADO
        if data['emisor'].get('comuna'):
            etree.SubElement(emisor, 'CmnaOrigen').text = data['emisor']['comuna']

        etree.SubElement(emisor, 'CiudadOrigen').text = data['emisor']['ciudad']
        
        # Receptor
        receptor = etree.SubElement(encabezado, 'Receptor')
        etree.SubElement(receptor, 'RUTRecep').text = self._format_rut_dte(data['receptor']['rut'])
        etree.SubElement(receptor, 'RznSocRecep').text = data['receptor']['razon_social']
        etree.SubElement(receptor, 'GiroRecep').text = data['receptor']['giro']

        # Dirección receptor
        etree.SubElement(receptor, 'DirRecep').text = data['receptor']['direccion']

        # CmnaRecep: OPCIONAL (minOccurs="0") pero RECOMENDADO
        if data['receptor'].get('comuna'):
            etree.SubElement(receptor, 'CmnaRecep').text = data['receptor']['comuna']

        etree.SubElement(receptor, 'CiudadRecep').text = data['receptor']['ciudad']
        
        # Totales
        totales = etree.SubElement(encabezado, 'Totales')

        # MntNeto: Monto neto (afecto a IVA)
        if data['totales'].get('monto_neto'):
            etree.SubElement(totales, 'MntNeto').text = str(int(data['totales']['monto_neto']))

        # MntExe: Monto exento de IVA
        if data['totales'].get('monto_exento'):
            etree.SubElement(totales, 'MntExe').text = str(int(data['totales']['monto_exento']))

        # TasaIVA: Tasa de IVA (19% en Chile)
        if data['totales'].get('monto_neto'):
            tasa_iva = data['totales'].get('tasa_iva', 19)
            etree.SubElement(totales, 'TasaIVA').text = str(tasa_iva)

        # IVA: Monto IVA
        if data['totales'].get('monto_iva'):
            etree.SubElement(totales, 'IVA').text = str(int(data['totales']['monto_iva']))

        # IVAProp: IVA propio (opcional, para ventas y servicios)
        if data['totales'].get('iva_propio'):
            etree.SubElement(totales, 'IVAProp').text = str(int(data['totales']['iva_propio']))

        # IVATerc: IVA de terceros (opcional)
        if data['totales'].get('iva_terceros'):
            etree.SubElement(totales, 'IVATerc').text = str(int(data['totales']['iva_terceros']))

        # MntTotal: Monto total del DTE
        etree.SubElement(totales, 'MntTotal').text = str(int(data['totales']['monto_total']))

        # MontoNF: Monto no facturable (opcional)
        if data['totales'].get('monto_no_facturable'):
            etree.SubElement(totales, 'MontoNF').text = str(int(data['totales']['monto_no_facturable']))

        # TotalPeriodo: Total período (para servicios periódicos)
        if data['totales'].get('total_periodo'):
            etree.SubElement(totales, 'TotalPeriodo').text = str(int(data['totales']['total_periodo']))

        # VlrPagar: Valor a pagar (puede diferir de MntTotal por pagos parciales)
        if data['totales'].get('valor_pagar'):
            etree.SubElement(totales, 'VlrPagar').text = str(int(data['totales']['valor_pagar']))
    
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
        if not data.get('descuentos_recargos'):
            return

        for dr in data['descuentos_recargos']:
            tipo = dr.get('tipo')  # 'D' = Descuento, 'R' = Recargo

            if tipo == 'D':
                dsc_rcg = etree.SubElement(documento, 'DscRcgGlobal')
                etree.SubElement(dsc_rcg, 'TpoMov').text = 'D'
            elif tipo == 'R':
                dsc_rcg = etree.SubElement(documento, 'DscRcgGlobal')
                etree.SubElement(dsc_rcg, 'TpoMov').text = 'R'
            else:
                continue

            # Glosa descriptiva
            if dr.get('glosa'):
                etree.SubElement(dsc_rcg, 'GlosaDR').text = dr['glosa'][:45]

            # Tipo de valor: 1 = Porcentaje, 2 = Valor
            tipo_valor = dr.get('tipo_valor', 2)
            etree.SubElement(dsc_rcg, 'TpoValor').text = str(tipo_valor)

            # Valor del descuento/recargo
            if tipo_valor == 1:
                # Porcentaje
                etree.SubElement(dsc_rcg, 'ValorDR').text = str(dr.get('valor_pct', 0))
            else:
                # Monto fijo
                etree.SubElement(dsc_rcg, 'ValorDR').text = str(int(dr.get('valor_monto', 0)))

            # Indicador de afecto/exento si aplica
            if dr.get('ind_exe_exento'):
                etree.SubElement(dsc_rcg, 'IndExeDR').text = str(dr['ind_exe_exento'])

    def _add_referencias(self, documento: etree.Element, data: dict):
        """
        Agrega referencias a otros documentos.
        Común en Notas de Crédito/Débito que referencian facturas originales.
        """
        if not data.get('referencias'):
            return

        for idx, ref in enumerate(data['referencias'], start=1):
            referencia = etree.SubElement(documento, 'Referencia')

            # NroLinRef: Número de línea de referencia
            etree.SubElement(referencia, 'NroLinRef').text = str(idx)

            # TpoDocRef: Tipo documento referenciado (33, 34, 52, etc)
            if ref.get('tipo_doc'):
                etree.SubElement(referencia, 'TpoDocRef').text = str(ref['tipo_doc'])

            # IndGlobal: Indicador referencia global (opcional)
            if ref.get('ind_global'):
                etree.SubElement(referencia, 'IndGlobal').text = str(ref['ind_global'])

            # FolioRef: Folio del documento referenciado
            if ref.get('folio'):
                etree.SubElement(referencia, 'FolioRef').text = str(ref['folio'])

            # RUTOtr: RUT de otro contribuyente (opcional)
            if ref.get('rut_otro'):
                etree.SubElement(referencia, 'RUTOtr').text = self._format_rut_dte(ref['rut_otro'])

            # FchRef: Fecha documento referenciado
            if ref.get('fecha'):
                etree.SubElement(referencia, 'FchRef').text = ref['fecha']

            # CodRef: Código de referencia (motivo)
            # 1 = Anula documento referencia
            # 2 = Corrige texto documento referencia
            # 3 = Corrige montos
            if ref.get('codigo'):
                etree.SubElement(referencia, 'CodRef').text = str(ref['codigo'])

            # RazonRef: Razón de la referencia (texto libre)
            if ref.get('razon'):
                etree.SubElement(referencia, 'RazonRef').text = ref['razon'][:90]

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
        Delegado a utils.rut_utils (python-stdnum).
        """
        return format_rut_for_sii(rut)

