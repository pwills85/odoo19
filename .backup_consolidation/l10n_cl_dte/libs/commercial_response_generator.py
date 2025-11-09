# -*- coding: utf-8 -*-
"""
Commercial Response Generator - Native Python Class for Odoo 19 CE
===================================================================

Genera XML de respuestas comerciales para DTEs recibidos:
- RecepciónDTE (código 0): Aceptación conforme
- RCD (código 1): Reclamo por contenido del documento
- RechazoMercaderías (código 2): Rechazo de mercaderías

**REFACTORED:** 2025-11-02 - Converted from AbstractModel to pure Python class
**Reason:** Odoo 19 CE requires libs/ to be normal Python, not ORM models
**Pattern:** Pure business logic - no database dependencies

P1-7 GAP CLOSURE: Implementación nativa (sin microservicio).

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-10-29
License: LGPL-3
Reference: http://www.sii.cl/factura_electronica/formato_respuesta_dte.pdf
"""

from lxml import etree
from datetime import datetime
import logging

_logger = logging.getLogger(__name__)


class CommercialResponseGenerator:
    """
    Professional generator for commercial responses to received DTEs.

    Pure Python class (no Odoo ORM dependency).
    Used by dte.inbox model.

    Usage:
        generator = CommercialResponseGenerator()
        xml = generator.generate_commercial_response_xml(response_data)
    """

    def __init__(self):
        """No dependencies required - pure business logic."""
        pass

    def generate_commercial_response_xml(self, response_data):
        """
        Generate XML for commercial response (RecepciónDTE, RCD, etc.).

        Args:
            response_data (dict): Response data:
                - response_type: str ('RecepcionDTE', 'RCD', 'RechazoMercaderias')
                - dte_type: str (33, 34, etc.)
                - folio: int
                - emisor_rut: str
                - receptor_rut: str (company RUT)
                - fecha_recepcion: str (YYYY-MM-DD)
                - estado_recepcion: str ('0'=Accept, '1'=Reject, '2'=Claim)
                - recinto: str (optional)
                - declaracion: str (reason/observations, required if reject/claim)
                - rutas: list of dicts (optional, for delivery validation)

        Returns:
            str: Commercial response XML (unsigned)

        Raises:
            ValueError: If required data missing
        """
        response_type = response_data.get('response_type', 'RecepcionDTE')

        _logger.info(
            f"[CommResponse] Generating {response_type} for DTE "
            f"{response_data.get('dte_type')} folio {response_data.get('folio')}"
        )

        # Validate inputs
        self._validate_response_data(response_data)

        # Generate XML based on response type
        if response_type == 'RecepcionDTE':
            xml = self._generate_recepcion_dte(response_data)
        elif response_type == 'RCD':
            xml = self._generate_rcd(response_data)
        elif response_type == 'RechazoMercaderias':
            xml = self._generate_rechazo_mercaderias(response_data)
        else:
            raise ValueError(
                f'Unknown response type: {response_type}.\n'
                f'Valid types: RecepcionDTE, RCD, RechazoMercaderias'
            )

        _logger.info(f"[CommResponse] ✅ XML generated ({len(xml)} bytes)")

        return xml

    def _generate_recepcion_dte(self, data):
        """
        Generate RecepciónDTE XML (acknowledgment of receipt).

        This is the standard response to confirm DTE was received.

        Pure method - works without env injection.

        Args:
            data (dict): Response data

        Returns:
            str: RecepciónDTE XML
        """
        # Create root
        root = etree.Element(
            '{http://www.sii.cl/SiiDte}RespuestaDTE',
            nsmap={'': 'http://www.sii.cl/SiiDte'},
            attrib={'version': '1.0'}
        )

        # Resultado element
        resultado = etree.SubElement(root, 'Resultado', ID='Resultado-1')

        # Caratula
        caratula = etree.SubElement(resultado, 'Caratula', version='1.0')
        etree.SubElement(caratula, 'RutResponde').text = data['receptor_rut']
        etree.SubElement(caratula, 'RutRecibe').text = data['emisor_rut']
        etree.SubElement(caratula, 'FchRespuesta').text = datetime.now().strftime('%Y-%m-%d')
        etree.SubElement(caratula, 'NmbContacto').text = data.get('contacto_nombre', 'Sistema Odoo')
        if data.get('contacto_email'):
            etree.SubElement(caratula, 'MailContacto').text = data['contacto_email']

        # RecepcionEnvio
        recepcion = etree.SubElement(resultado, 'RecepcionEnvio')
        etree.SubElement(recepcion, 'NmbEnvio').text = f"EnvioDTE_{data['folio']}"
        etree.SubElement(recepcion, 'FchRecep').text = data['fecha_recepcion']
        etree.SubElement(recepcion, 'CodEnvio').text = '0'  # 0 = Envío OK
        etree.SubElement(recepcion, 'EnvioDTEID').text = f"DTE-{data['folio']}"
        etree.SubElement(recepcion, 'Digest').text = data.get('digest', 'N/A')

        # Estado de cada DTE
        resultado_dte = etree.SubElement(recepcion, 'ResultadoDTE')
        etree.SubElement(resultado_dte, 'TipoDTE').text = str(data['dte_type'])
        etree.SubElement(resultado_dte, 'Folio').text = str(data['folio'])
        etree.SubElement(resultado_dte, 'FchProceso').text = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        etree.SubElement(resultado_dte, 'Estado').text = data['estado_recepcion']

        # Opcional: Recinto (lugar de recepción física)
        if data.get('recinto'):
            etree.SubElement(resultado_dte, 'Recinto').text = data['recinto']

        # Convert to string
        xml_string = etree.tostring(
            root,
            encoding='ISO-8859-1',
            xml_declaration=True,
            pretty_print=True
        ).decode('ISO-8859-1')

        return xml_string

    def _generate_rcd(self, data):
        """
        Generate RCD XML (Reclamo de Contenido).

        Used to dispute the content of a received DTE.

        Pure method - works without env injection.

        Args:
            data (dict): Response data

        Returns:
            str: RCD XML
        """
        # RCD es similar a RecepciónDTE pero con código de estado 1 (reclamo)
        return self._generate_recepcion_dte({
            **data,
            'estado_recepcion': '1',  # 1 = Reclamo
        })

    def _generate_rechazo_mercaderias(self, data):
        """
        Generate RechazoMercaderías XML.

        Used to reject goods described in a DTE (e.g., damaged, incorrect).

        Pure method - works without env injection.

        Args:
            data (dict): Response data

        Returns:
            str: RechazoMercaderías XML
        """
        # Similar structure, estado 2
        return self._generate_recepcion_dte({
            **data,
            'estado_recepcion': '2',  # 2 = Rechazo mercaderías
        })

    def _validate_response_data(self, data):
        """
        Validate response data before generating XML.

        Pure method - works without env injection.

        Args:
            data: dict with response data

        Raises:
            ValueError: If required fields missing
        """
        required_fields = ['dte_type', 'folio', 'emisor_rut', 'receptor_rut', 'fecha_recepcion']
        missing = [f for f in required_fields if not data.get(f)]

        if missing:
            raise ValueError(
                f'Missing required fields for commercial response:\n{", ".join(missing)}'
            )

        # Validate estado_recepcion
        if data.get('estado_recepcion') not in ['0', '1', '2']:
            raise ValueError(
                f'Invalid estado_recepcion: {data.get("estado_recepcion")}\n'
                f'Valid values: 0 (Accept), 1 (Claim), 2 (Reject Goods)'
            )

        # If rejecting/claiming, reason is required
        if data.get('estado_recepcion') in ['1', '2'] and not data.get('declaracion'):
            raise ValueError(
                'Declaracion (reason) is required when rejecting or claiming a DTE'
            )

        _logger.debug("[CommResponse] Validation passed")
