# -*- coding: utf-8 -*-
"""
Libro de Guías de Despacho Generator - Native Implementation
=============================================================

Generación Libro de Guías de Despacho para SII (OBLIGATORIO).

Migration from: odoo-eergy-services/generators/libro_guias_generator.py (2025-10-24)

SPRINT 5: Cierre total de brechas

Normativa SII:
- OBLIGATORIO para empresas que emiten Guías de Despacho Electrónicas (DTE 52)
- Generación mensual
- Formato XML según schema SII oficial
- Debe estar firmado digitalmente
- Envío al SII antes del día 10 del mes siguiente

Contenido:
- Caratula (período, RUT emisor, totales)
- Detalle por cada guía emitida
- Resumen montos por tipo operación
"""

from lxml import etree
from datetime import datetime
import logging

_logger = logging.getLogger(__name__)


class LibroGuiasGenerator:
    """
    Generador de Libro de Guías de Despacho para SII.

    Genera XML según schema oficial SII:
    - LibroGuia_v10.xsd

    Libro de Guías es OBLIGATORIO mensualmente para empresas
    que emiten DTE 52 (Guías de Despacho Electrónicas).
    """

    # ═══════════════════════════════════════════════════════════════════════
    # CONSTANTES SII
    # ═══════════════════════════════════════════════════════════════════════

    LIBRO_GUIAS_VERSION = '1.0'
    SCHEMA_VERSION = 'LibroGuia_v10'

    TIPO_OPERACION_CHOICES = {
        1: 'Operaciones del Giro',
        2: 'Ventas y Servicios no incluidos en el Giro',
        3: 'Traslados Internos',
        4: 'Traslados a Terceros'
    }

    TIPO_TRASLADO_CHOICES = {
        1: 'Operación constituye venta',
        2: 'Ventas por efectuar',
        3: 'Consignaciones',
        4: 'Entrega gratuita',
        5: 'Traslados internos',
        6: 'Otros traslados no venta',
        7: 'Guía de devolución',
        8: 'Traslado para exportación (no venta)',
        9: 'Venta para exportación'
    }

    # ═══════════════════════════════════════════════════════════════════════
    # GENERACIÓN LIBRO GUÍAS
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def generate_libro_guias(libro_data):
        """
        Genera XML Libro de Guías de Despacho.

        Args:
            libro_data (dict): Datos del libro:
                - rut_emisor (str): RUT emisor sin puntos ni guión
                - razon_social (str): Razón social emisor
                - periodo_tributario (str): YYYY-MM
                - fecha_resolucion (str): YYYY-MM-DD
                - numero_resolucion (str): Número resolución SII
                - guias (list): Lista de guías:
                    - folio (int)
                    - fecha_emision (str): YYYY-MM-DD
                    - rut_receptor (str)
                    - razon_social_receptor (str)
                    - monto_neto (float)
                    - monto_iva (float)
                    - monto_exento (float)
                    - monto_total (float)
                    - tipo_operacion (int): 1-4
                    - tipo_traslado (int): 1-9
                    - anulada (bool): True si guía anulada
                - totales (dict):
                    - total_guias (int)
                    - total_anuladas (int)
                    - total_utilizadas (int)
                    - monto_neto (float)
                    - monto_iva (float)
                    - monto_exento (float)
                    - monto_total (float)

        Returns:
            str: XML del Libro de Guías
        """
        _logger.info(
            f"Generating Libro Guías: emisor={libro_data.get('rut_emisor')}, "
            f"periodo={libro_data.get('periodo_tributario')}, "
            f"guias={len(libro_data.get('guias', []))}"
        )

        # Namespace SII
        nsmap = {
            None: 'http://www.sii.cl/SiiDte',
            'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
        }

        # Root element
        root = etree.Element(
            'LibroGuia',
            nsmap=nsmap,
            attrib={
                '{http://www.w3.org/2001/XMLSchema-instance}schemaLocation':
                    'http://www.sii.cl/SiiDte LibroGuia_v10.xsd',
                'version': LibroGuiasGenerator.LIBRO_GUIAS_VERSION
            }
        )

        # EnvioLibro
        envio_libro = etree.SubElement(root, 'EnvioLibro')
        envio_libro.set('ID', 'LibroGuia')

        # Caratula
        LibroGuiasGenerator._generate_caratula(envio_libro, libro_data)

        # ResumenPeriodo (opcional pero recomendado)
        LibroGuiasGenerator._generate_resumen_periodo(envio_libro, libro_data)

        # Detalle por cada guía
        for guia in libro_data.get('guias', []):
            LibroGuiasGenerator._generate_detalle_guia(envio_libro, guia)

        # TmstFirma (timestamp)
        timestamp = etree.SubElement(envio_libro, 'TmstFirma')
        timestamp.text = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

        # Convert to string
        xml_string = etree.tostring(
            root,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')

        _logger.info(f"✅ Libro Guías generated successfully: {len(xml_string)} bytes")

        return xml_string

    @staticmethod
    def _generate_caratula(parent, libro_data):
        """Genera elemento Caratula del Libro de Guías."""
        caratula = etree.SubElement(parent, 'Caratula')

        # RutEmisorLibro
        rut_emisor = etree.SubElement(caratula, 'RutEmisorLibro')
        rut_emisor.text = libro_data['rut_emisor']

        # RutEnvia (mismo que emisor si es auto-envío)
        rut_envia = etree.SubElement(caratula, 'RutEnvia')
        rut_envia.text = libro_data.get('rut_envia', libro_data['rut_emisor'])

        # PeriodoTributario (YYYY-MM)
        periodo = etree.SubElement(caratula, 'PeriodoTributario')
        periodo.text = libro_data['periodo_tributario']

        # FchResol
        fch_resol = etree.SubElement(caratula, 'FchResol')
        fch_resol.text = libro_data['fecha_resolucion']

        # NroResol
        nro_resol = etree.SubElement(caratula, 'NroResol')
        nro_resol.text = str(libro_data['numero_resolucion'])

        # TipoLibro (ESPECIAL para Guías de Despacho)
        tipo_libro = etree.SubElement(caratula, 'TipoLibro')
        tipo_libro.text = 'ESPECIAL'

        # TipoEnvio (TOTAL = libro completo del período)
        tipo_envio = etree.SubElement(caratula, 'TipoEnvio')
        tipo_envio.text = libro_data.get('tipo_envio', 'TOTAL')

        # FolioNotificacion (opcional)
        if libro_data.get('folio_notificacion'):
            folio_notif = etree.SubElement(caratula, 'FolioNotificacion')
            folio_notif.text = str(libro_data['folio_notificacion'])

        return caratula

    @staticmethod
    def _generate_resumen_periodo(parent, libro_data):
        """Genera ResumenPeriodo con totales del mes."""
        resumen = etree.SubElement(parent, 'ResumenPeriodo')

        totales = libro_data.get('totales', {})

        # TotFolAnulado
        tot_anulado = etree.SubElement(resumen, 'TotFolAnulado')
        tot_anulado.text = str(totales.get('total_anuladas', 0))

        # TotGuiaAnulada (puede ser diferente de TotFolAnulado)
        tot_guia_anulada = etree.SubElement(resumen, 'TotGuiaAnulada')
        tot_guia_anulada.text = str(totales.get('total_anuladas', 0))

        # TotGuiaVenta
        tot_venta = etree.SubElement(resumen, 'TotGuiaVenta')
        tot_venta.text = str(totales.get('total_utilizadas', 0))

        # TotMntGuia
        tot_mnt = etree.SubElement(resumen, 'TotMntGuia')
        tot_mnt.text = str(int(totales.get('monto_total', 0)))

        # TotMntModificado (opcional - para correcciones)
        if totales.get('monto_modificado'):
            tot_modificado = etree.SubElement(resumen, 'TotMntModificado')
            tot_modificado.text = str(int(totales['monto_modificado']))

        # TotMntExento
        if totales.get('monto_exento', 0) > 0:
            tot_exento = etree.SubElement(resumen, 'TotMntExento')
            tot_exento.text = str(int(totales['monto_exento']))

        # TotMntNeto
        if totales.get('monto_neto', 0) > 0:
            tot_neto = etree.SubElement(resumen, 'TotMntNeto')
            tot_neto.text = str(int(totales['monto_neto']))

        # TotMntIVA
        if totales.get('monto_iva', 0) > 0:
            tot_iva = etree.SubElement(resumen, 'TotMntIVA')
            tot_iva.text = str(int(totales['monto_iva']))

        return resumen

    @staticmethod
    def _generate_detalle_guia(parent, guia):
        """Genera elemento Detalle para una guía individual."""
        detalle = etree.SubElement(parent, 'Detalle')

        # Folio
        folio = etree.SubElement(detalle, 'Folio')
        folio.text = str(guia['folio'])

        # Anulado (si guía anulada)
        if guia.get('anulada', False):
            anulado = etree.SubElement(detalle, 'Anulado')
            anulado.text = 'A'  # A = Anulado

            # Si anulada, no agregar más datos
            return detalle

        # TipoOperacion
        tipo_op = etree.SubElement(detalle, 'TipoOperacion')
        tipo_op.text = str(guia.get('tipo_operacion', 1))

        # FchDoc
        fch_doc = etree.SubElement(detalle, 'FchDoc')
        fch_doc.text = guia['fecha_emision']

        # RUTDoc (receptor)
        rut_doc = etree.SubElement(detalle, 'RUTDoc')
        rut_doc.text = guia['rut_receptor']

        # RznSoc (razón social receptor)
        rzn_soc = etree.SubElement(detalle, 'RznSoc')
        rzn_soc.text = guia.get('razon_social_receptor', 'Receptor')[:50]  # Max 50 chars

        # TpoTraslado
        tpo_traslado = etree.SubElement(detalle, 'TpoTraslado')
        tpo_traslado.text = str(guia.get('tipo_traslado', 1))

        # MntNeto (si aplica)
        if guia.get('monto_neto', 0) > 0:
            mnt_neto = etree.SubElement(detalle, 'MntNeto')
            mnt_neto.text = str(int(guia['monto_neto']))

        # MntIVA (si aplica)
        if guia.get('monto_iva', 0) > 0:
            mnt_iva = etree.SubElement(detalle, 'MntIVA')
            mnt_iva.text = str(int(guia['monto_iva']))

        # MntExento (si aplica)
        if guia.get('monto_exento', 0) > 0:
            mnt_exento = etree.SubElement(detalle, 'MntExento')
            mnt_exento.text = str(int(guia['monto_exento']))

        # MntTotal
        mnt_total = etree.SubElement(detalle, 'MntTotal')
        mnt_total.text = str(int(guia['monto_total']))

        # TasaImp (opcional - tasa impuesto si diferente de 19%)
        if guia.get('tasa_iva') and guia['tasa_iva'] != 19:
            tasa_imp = etree.SubElement(detalle, 'TasaImp')
            tasa_imp.text = str(guia['tasa_iva'])

        # FolioNotificacion (opcional - para modificaciones)
        if guia.get('folio_notificacion'):
            folio_notif = etree.SubElement(detalle, 'FolioNotificacion')
            folio_notif.text = str(guia['folio_notificacion'])

        return detalle

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN LIBRO GUÍAS
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_libro_data(libro_data):
        """
        Valida datos antes de generar Libro de Guías.

        Args:
            libro_data (dict): Datos del libro

        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        errors = []

        # Validar campos requeridos
        required_fields = [
            'rut_emisor',
            'razon_social',
            'periodo_tributario',
            'fecha_resolucion',
            'numero_resolucion',
            'guias'
        ]

        for field in required_fields:
            if field not in libro_data or not libro_data[field]:
                errors.append(f"Campo requerido faltante: {field}")

        # Validar formato período (YYYY-MM)
        periodo = libro_data.get('periodo_tributario', '')
        if not LibroGuiasGenerator._validate_periodo_format(periodo):
            errors.append(f"Formato período inválido: {periodo} (esperado YYYY-MM)")

        # Validar guías
        guias = libro_data.get('guias', [])
        if len(guias) == 0:
            errors.append("Libro sin guías (debe contener al menos 1)")

        # Validar cada guía
        for idx, guia in enumerate(guias):
            guia_errors = LibroGuiasGenerator._validate_guia(guia, idx)
            errors.extend(guia_errors)

        return (len(errors) == 0, errors)

    @staticmethod
    def _validate_periodo_format(periodo):
        """Valida formato YYYY-MM."""
        if not periodo or not isinstance(periodo, str):
            return False

        parts = periodo.split('-')
        if len(parts) != 2:
            return False

        try:
            year = int(parts[0])
            month = int(parts[1])

            if year < 2000 or year > 2100:
                return False

            if month < 1 or month > 12:
                return False

            return True
        except ValueError:
            return False

    @staticmethod
    def _validate_guia(guia, idx):
        """Valida datos de una guía individual."""
        errors = []

        # Si anulada, solo validar folio
        if guia.get('anulada', False):
            if 'folio' not in guia:
                errors.append(f"Guía {idx}: Folio requerido (anulada)")
            return errors

        # Campos requeridos guía normal
        required = ['folio', 'fecha_emision', 'rut_receptor', 'monto_total']
        for field in required:
            if field not in guia or guia[field] is None:
                errors.append(f"Guía {idx} (folio {guia.get('folio', '?')}): Campo requerido faltante: {field}")

        # Validar folio
        if 'folio' in guia:
            try:
                folio_int = int(guia['folio'])
                if folio_int <= 0:
                    errors.append(f"Guía {idx}: Folio debe ser > 0")
            except (ValueError, TypeError):
                errors.append(f"Guía {idx}: Folio debe ser numérico")

        # Validar montos
        if 'monto_total' in guia:
            try:
                monto = float(guia['monto_total'])
                if monto < 0:
                    errors.append(f"Guía {idx}: Monto total negativo")
            except (ValueError, TypeError):
                errors.append(f"Guía {idx}: Monto total debe ser numérico")

        # Validar tipo_operacion (1-4)
        if 'tipo_operacion' in guia:
            tipo_op = guia['tipo_operacion']
            if tipo_op not in [1, 2, 3, 4]:
                errors.append(f"Guía {idx}: tipo_operacion inválido: {tipo_op} (debe ser 1-4)")

        # Validar tipo_traslado (1-9)
        if 'tipo_traslado' in guia:
            tipo_tras = guia['tipo_traslado']
            if tipo_tras not in range(1, 10):
                errors.append(f"Guía {idx}: tipo_traslado inválido: {tipo_tras} (debe ser 1-9)")

        return errors
