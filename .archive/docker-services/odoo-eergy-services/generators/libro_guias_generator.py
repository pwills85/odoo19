# -*- coding: utf-8 -*-
"""
Generador de XML para Libro de Guías de Despacho
Reporte mensual opcional al SII con detalle de guías emitidas (DTE 52)
"""

from lxml import etree
import structlog
from utils.rut_utils import format_rut_for_sii

logger = structlog.get_logger()


class LibroGuiasGenerator:
    """
    Generador de XML para Libro de Guías de Despacho.

    Reporte mensual opcional (pero recomendado) que agrupa todas las
    guías de despacho (DTE 52) emitidas en un período.

    Similar a Libro Compra/Venta pero específico para guías.
    """

    def __init__(self):
        pass

    def generate(self, libro_data: dict) -> str:
        """
        Genera XML de Libro de Guías según formato SII.

        Args:
            libro_data: Dict con datos del libro
                - rut_emisor: RUT de la empresa emisora
                - periodo: Período (YYYY-MM)
                - fecha_resolucion: Fecha resolución SII
                - nro_resolucion: Número resolución SII
                - guias: Lista de guías de despacho
                    [
                        {
                            'folio': int,
                            'fecha': 'YYYY-MM-DD',
                            'rut_destinatario': str,
                            'razon_social': str,
                            'monto_total': float (puede ser 0 para traslados)
                        },
                        ...
                    ]

        Returns:
            str: XML generado según formato SII
        """
        guias_count = len(libro_data.get('guias', []))

        logger.info("generating_libro_guias",
                    periodo=libro_data.get('periodo'),
                    guias_count=guias_count,
                    rut_emisor=libro_data.get('rut_emisor'))

        # Validar datos mínimos
        self._validate_libro_data(libro_data)

        # Crear elemento raíz
        libro = etree.Element('LibroGuia',
                              xmlns="http://www.sii.cl/SiiDte",
                              version="1.0")

        env_libro = etree.SubElement(libro, 'EnvioLibro', ID="LibroGuia")

        # Carátula
        self._add_caratula(env_libro, libro_data)

        # Resumen por período
        self._add_resumen(env_libro, libro_data)

        # Detalles (cada guía)
        for guia in libro_data.get('guias', []):
            self._add_detalle_guia(env_libro, guia)

        # Convertir a string
        xml_string = etree.tostring(
            libro,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')

        logger.info("libro_guias_generated",
                    periodo=libro_data.get('periodo'),
                    guias_count=guias_count,
                    total_monto=sum(g.get('monto_total', 0) for g in libro_data.get('guias', [])))

        return xml_string

    def _validate_libro_data(self, data: dict):
        """Valida datos mínimos requeridos"""
        required_fields = ['rut_emisor', 'periodo', 'fecha_resolucion', 'nro_resolucion']

        for field in required_fields:
            if not data.get(field):
                raise ValueError(f"Campo requerido faltante: {field}")

        if not data.get('guias'):
            raise ValueError("Debe incluir al menos una guía de despacho")

        logger.debug("libro_data_validated", fields_ok=len(required_fields))

    def _add_caratula(self, env_libro: etree.Element, data: dict):
        """
        Agrega carátula del libro de guías.

        Información del emisor, período y resolución SII.
        """
        caratula = etree.SubElement(env_libro, 'Caratula')

        # RUT del emisor
        etree.SubElement(caratula, 'RutEmisorLibro').text = self._format_rut(data['rut_emisor'])
        etree.SubElement(caratula, 'RutEnvia').text = self._format_rut(data['rut_emisor'])

        # Período tributario (YYYY-MM)
        etree.SubElement(caratula, 'PeriodoTributario').text = data['periodo']

        # Resolución SII
        etree.SubElement(caratula, 'FchResol').text = data['fecha_resolucion']
        etree.SubElement(caratula, 'NroResol').text = str(data['nro_resolucion'])

        # Tipo de libro: Guías de Despacho = 3
        # (1=Venta, 2=Compra, 3=Guías)
        etree.SubElement(caratula, 'TipoLibro').text = '3'

        # Tipo de envío (TOTAL o PARCIAL)
        # TOTAL = todas las guías del período
        # PARCIAL = rectificatorio
        tipo_envio = data.get('tipo_envio', 'TOTAL')
        etree.SubElement(caratula, 'TipoEnvio').text = tipo_envio

        # Folio notificación (solo si es rectificatorio)
        if tipo_envio == 'PARCIAL' and data.get('folio_notificacion'):
            etree.SubElement(caratula, 'FolioNotificacion').text = str(data['folio_notificacion'])

        logger.debug("caratula_added",
                     rut=data['rut_emisor'],
                     periodo=data['periodo'],
                     tipo_envio=tipo_envio)

    def _add_resumen(self, env_libro: etree.Element, data: dict):
        """
        Agrega resumen del período con totales.

        Totaliza cantidad de guías y montos (si aplica).
        """
        resumen = etree.SubElement(env_libro, 'ResumenPeriodo')

        guias = data.get('guias', [])

        # Tipo de documento: 52 (Guía de Despacho)
        etree.SubElement(resumen, 'TpoDoc').text = '52'

        # Cantidad total de guías
        etree.SubElement(resumen, 'TotDoc').text = str(len(guias))

        # Folios
        folios = [g['folio'] for g in guias if g.get('folio')]
        if folios:
            etree.SubElement(resumen, 'FolioDesde').text = str(min(folios))
            etree.SubElement(resumen, 'FolioHasta').text = str(max(folios))

        # Montos totales (puede ser 0 para traslados sin venta)
        total_monto = sum(g.get('monto_total', 0) for g in guias)
        etree.SubElement(resumen, 'TotMntTotal').text = str(int(total_monto))

        logger.debug("resumen_added",
                     total_guias=len(guias),
                     folio_desde=min(folios) if folios else None,
                     folio_hasta=max(folios) if folios else None,
                     total_monto=int(total_monto))

    def _add_detalle_guia(self, env_libro: etree.Element, guia: dict):
        """
        Agrega detalle de cada guía de despacho.

        Información individual de cada DTE 52 incluido en el libro.
        """
        detalle = etree.SubElement(env_libro, 'Detalle')

        # Tipo documento: 52 (Guía de Despacho)
        etree.SubElement(detalle, 'TpoDoc').text = '52'

        # Número de documento (folio)
        etree.SubElement(detalle, 'NroDoc').text = str(guia['folio'])

        # Fecha emisión
        etree.SubElement(detalle, 'FchDoc').text = guia['fecha']

        # RUT destinatario
        if guia.get('rut_destinatario'):
            etree.SubElement(detalle, 'RUTDoc').text = self._format_rut(guia['rut_destinatario'])

        # Razón social destinatario (máximo 50 caracteres)
        razon_social = guia.get('razon_social', 'Sin nombre')
        etree.SubElement(detalle, 'RznSoc').text = razon_social[:50]

        # Monto total (puede ser 0 para traslados sin venta)
        monto_total = guia.get('monto_total', 0)
        etree.SubElement(detalle, 'MntTotal').text = str(int(monto_total))

        # Estado: 1=Aceptado, 2=Rechazado, 3=Pendiente
        # Por defecto, guías ya aceptadas por SII
        estado = guia.get('estado_sii', 1)
        etree.SubElement(detalle, 'TpoOperacion').text = str(estado)

        logger.debug("detalle_guia_added",
                     folio=guia['folio'],
                     fecha=guia['fecha'],
                     monto=int(monto_total))

    def _format_rut_dte(self, rut: str) -> str:
        """Formatea RUT para DTE. Delegado a utils.rut_utils."""
        return format_rut_for_sii(rut)
