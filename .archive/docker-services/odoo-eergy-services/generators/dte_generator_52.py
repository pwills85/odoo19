# -*- coding: utf-8 -*-
"""
Generador de XML para DTE 52 (Guía de Despacho Electrónica)  
Según especificación técnica del SII - Traslado de mercancías
"""

from lxml import etree
import structlog
from utils.rut_utils import format_rut_for_sii

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

        # IndTraslado: OBLIGATORIO para Guía de Despacho
        # 1 = Operación constituye venta
        # 2 = Venta por efectuar
        # 3 = Consignación
        # 4 = Entrega gratuita
        # 5 = Traslado interno
        # 6 = Otros traslados no venta
        # 7 = Guía de devolución
        # 8 = Traslado para exportación
        ind_traslado = data.get('tipo_traslado', 5)  # Default: traslado interno
        etree.SubElement(id_doc, 'IndTraslado').text = str(ind_traslado)

        # TipoDespacho: Tipo de despacho (opcional pero importante)
        # 1 = Despacho por cuenta del comprador
        # 2 = Despacho por cuenta del emisor a instalaciones del comprador
        # 3 = Despacho por cuenta del emisor a otras instalaciones
        if data.get('tipo_despacho'):
            etree.SubElement(id_doc, 'TipoDespacho').text = str(data['tipo_despacho'])

        # FmaPago: Forma de pago (opcional)
        if data.get('forma_pago'):
            etree.SubElement(id_doc, 'FmaPago').text = str(data['forma_pago'])

        # FchVenc: Fecha vencimiento (opcional)
        if data.get('fecha_vencimiento'):
            etree.SubElement(id_doc, 'FchVenc').text = data['fecha_vencimiento']

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

        if data['receptor'].get('giro'):
            etree.SubElement(receptor, 'GiroRecep').text = data['receptor']['giro']

        etree.SubElement(receptor, 'DirRecep').text = data['receptor']['direccion']

        if data['receptor'].get('comuna'):
            etree.SubElement(receptor, 'CmnaRecep').text = data['receptor']['comuna']

        if data['receptor'].get('ciudad'):
            etree.SubElement(receptor, 'CiudadRecep').text = data['receptor']['ciudad']

        # Transporte: IMPORTANTE para empresas de ingeniería (traslado equipos a obra)
        if data.get('transporte'):
            transporte = etree.SubElement(encabezado, 'Transporte')

            # Patente vehículo (máx 8 caracteres)
            if data['transporte'].get('patente'):
                etree.SubElement(transporte, 'Patente').text = data['transporte']['patente'][:8].upper()

            # RUT transportista
            if data['transporte'].get('rut_transportista'):
                etree.SubElement(transporte, 'RUTTrans').text = self._format_rut_dte(data['transporte']['rut_transportista'])

            # Chofer
            if data['transporte'].get('chofer'):
                chofer = etree.SubElement(transporte, 'Chofer')
                etree.SubElement(chofer, 'RUTChofer').text = self._format_rut_dte(data['transporte']['chofer']['rut'])
                etree.SubElement(chofer, 'NombreChofer').text = data['transporte']['chofer']['nombre'][:30]

            # Dirección destino (importante para obras)
            if data['transporte'].get('direccion_destino'):
                etree.SubElement(transporte, 'DirDest').text = data['transporte']['direccion_destino']

            if data['transporte'].get('comuna_destino'):
                etree.SubElement(transporte, 'CmnaDest').text = data['transporte']['comuna_destino']

            if data['transporte'].get('ciudad_destino'):
                etree.SubElement(transporte, 'CiudadDest').text = data['transporte']['ciudad_destino']

        # Totales (pueden ser 0 en guías sin valorización)
        totales = etree.SubElement(encabezado, 'Totales')

        # Si hay valorización
        if data.get('totales'):
            if data['totales'].get('monto_neto'):
                etree.SubElement(totales, 'MntNeto').text = str(int(data['totales']['monto_neto']))

            if data['totales'].get('monto_exento'):
                etree.SubElement(totales, 'MntExe').text = str(int(data['totales']['monto_exento']))

            if data['totales'].get('monto_neto'):
                tasa_iva = data['totales'].get('tasa_iva', 19)
                etree.SubElement(totales, 'TasaIVA').text = str(tasa_iva)

            if data['totales'].get('monto_iva'):
                etree.SubElement(totales, 'IVA').text = str(int(data['totales']['monto_iva']))

            etree.SubElement(totales, 'MntTotal').text = str(int(data['totales'].get('monto_total', 0)))
        else:
            # Guía sin valorización (solo movimiento)
            etree.SubElement(totales, 'MntTotal').text = '0'
    
    def _add_detalle(self, documento: etree.Element, data: dict):
        """Detalle de productos/equipos"""
        for linea_data in data['productos']:
            detalle = etree.SubElement(documento, 'Detalle')

            etree.SubElement(detalle, 'NroLinDet').text = str(linea_data['numero_linea'])

            # Tipo de documento interno (opcional pero útil para control)
            if linea_data.get('tipo_doc_interno'):
                etree.SubElement(detalle, 'TpoDocLiq').text = linea_data['tipo_doc_interno']

            # Indicador de exención (si aplica)
            if linea_data.get('ind_exento'):
                etree.SubElement(detalle, 'IndExe').text = str(linea_data['ind_exento'])

            # Nombre del ítem/equipo (máx 80 caracteres)
            etree.SubElement(detalle, 'NmbItem').text = linea_data['nombre'][:80]

            # Descripción adicional (útil para especificaciones técnicas de equipos)
            if linea_data.get('descripcion'):
                etree.SubElement(detalle, 'DscItem').text = linea_data['descripcion'][:1000]

            # Cantidad
            etree.SubElement(detalle, 'QtyItem').text = str(linea_data['cantidad'])

            # Unidad de medida (UN, KG, MT, etc.)
            etree.SubElement(detalle, 'UnmdItem').text = linea_data.get('unidad', 'UN')

            # Precio unitario (puede ser 0 en guías sin valorización)
            etree.SubElement(detalle, 'PrcItem').text = str(int(linea_data.get('precio_unitario', 0)))

            # Descuento porcentual (opcional)
            if linea_data.get('descuento_pct'):
                etree.SubElement(detalle, 'DescuentoPct').text = str(linea_data['descuento_pct'])

            # Descuento monto (opcional)
            if linea_data.get('descuento_monto'):
                etree.SubElement(detalle, 'DescuentoMonto').text = str(int(linea_data['descuento_monto']))

            # Recargo porcentual (opcional)
            if linea_data.get('recargo_pct'):
                etree.SubElement(detalle, 'RecargoPct').text = str(linea_data['recargo_pct'])

            # Recargo monto (opcional)
            if linea_data.get('recargo_monto'):
                etree.SubElement(detalle, 'RecargoMonto').text = str(int(linea_data['recargo_monto']))

            # Monto total del ítem
            etree.SubElement(detalle, 'MontoItem').text = str(int(linea_data.get('subtotal', 0)))

            # Número de serie (útil para equipos como inversores, paneles)
            if linea_data.get('numero_serie'):
                etree.SubElement(detalle, 'NumeroSerie').text = linea_data['numero_serie'][:80]

            # Fecha de elaboración/fabricación (útil para equipos)
            if linea_data.get('fecha_elaboracion'):
                etree.SubElement(detalle, 'FchElaboracion').text = linea_data['fecha_elaboracion']

            # Fecha de vencimiento (si aplica)
            if linea_data.get('fecha_vencimiento'):
                etree.SubElement(detalle, 'FchVencim').text = linea_data['fecha_vencimiento']
    
    def _add_referencia(self, documento: etree.Element, data: dict):
        """
        Referencias a documentos asociados (opcional pero frecuente)

        Guía de Despacho puede referenciar:
        - Factura 33 (entrega asociada a venta)
        - Orden de Compra (OC)
        - Guía de Despacho anterior (devolución)
        - Nota de Venta
        """
        ref_data = data['factura_referencia']
        referencia = etree.SubElement(documento, 'Referencia')

        etree.SubElement(referencia, 'NroLinRef').text = '1'

        # Tipo de documento referenciado
        # 33 = Factura Electrónica
        # 52 = Guía de Despacho (para devoluciones)
        # 801 = Orden de Compra
        # 802 = Nota de Venta
        # HES = Hoja de Entrada de Servicios
        tipo_doc = ref_data.get('tipo_doc', '33')
        etree.SubElement(referencia, 'TpoDocRef').text = str(tipo_doc)

        # Indicador de referencia global (opcional)
        if ref_data.get('ind_global'):
            etree.SubElement(referencia, 'IndGlobal').text = str(ref_data['ind_global'])

        # Folio del documento referenciado
        etree.SubElement(referencia, 'FolioRef').text = str(ref_data['folio'])

        # RUT otro emisor (si referencia doc externo)
        if ref_data.get('rut_otro'):
            etree.SubElement(referencia, 'RUTOtr').text = self._format_rut_dte(ref_data['rut_otro'])

        # Fecha del documento referenciado
        etree.SubElement(referencia, 'FchRef').text = ref_data['fecha']

        # Código de referencia (opcional)
        # 1 = Anula documento referenciado
        # 2 = Corrige texto documento referenciado
        # 3 = Corrige montos
        if ref_data.get('codigo_ref'):
            etree.SubElement(referencia, 'CodRef').text = str(ref_data['codigo_ref'])

        # Razón de la referencia (texto libre, máx 90 chars)
        if ref_data.get('razon_ref'):
            etree.SubElement(referencia, 'RazonRef').text = ref_data['razon_ref'][:90]
    
    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE. Delegado a utils.rut_utils."""
        return format_rut_for_sii(rut)
