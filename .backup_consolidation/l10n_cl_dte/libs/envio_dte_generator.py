# -*- coding: utf-8 -*-
"""
EnvioDTE Generator - SII Compliant DTE Envelope Generator

This module creates the EnvioDTE structure required by Chilean SII.
According to SII specs, DTEs cannot be sent individually - they must be
wrapped in an EnvioDTE structure with a Carátula (cover sheet).

Structure:
<EnvioDTE>
  <SetDTE>
    <Caratula>
      ... metadata ...
    </Caratula>
    <DTE>
      <Documento>
        ... DTE content ...
      </Documento>
    </DTE>
    <!-- More DTEs can be included -->
  </SetDTE>
  <Signature>
    ... Digital signature of SetDTE ...
  </Signature>
</EnvioDTE>

Author: Pedro Troncoso
Date: 2025-10-29
License: LGPL-3
Reference: http://www.sii.cl/factura_electronica/formato_dte.pdf
"""

import logging
from datetime import datetime
from lxml import etree
from odoo import _
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)

# XML Namespaces for SII DTEs
NAMESPACES = {
    'sii': 'http://www.sii.cl/SiiDte',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


class EnvioDTEGenerator:
    """
    Generator for EnvioDTE structure compliant with SII specifications.

    The EnvioDTE is the envelope that wraps one or more DTEs for transmission
    to SII. It includes:
    - Carátula: Metadata about the shipment
    - SetDTE: Container for DTEs
    - Signature: Digital signature of the entire SetDTE

    Usage:
        generator = EnvioDTEGenerator(company)

        caratula_data = {
            'RutEmisor': '12345678-9',
            'RutEnvia': '11111111-1',
            'RutReceptor': '60803000-K',  # SII RUT
            'FchResol': '2020-01-15',
            'NroResol': '80',
        }

        envio_xml = generator.generate_envio_dte(
            dtes=[dte1_xml, dte2_xml],
            caratula=caratula_data
        )
    """

    def __init__(self, company=None):
        """
        Initialize generator

        Args:
            company: res.company record (optional, for defaults)
        """
        self.company = company

    def generate_envio_dte(self, dtes, caratula_data):
        """
        Generate complete EnvioDTE structure

        Args:
            dtes: List of DTE XML strings (already signed individual DTEs)
            caratula_data: Dict with Carátula fields:
                - RutEmisor: str (required)
                - RutEnvia: str (required)
                - RutReceptor: str (required, usually '60803000-K' for SII)
                - FchResol: str (required, YYYY-MM-DD)
                - NroResol: str (required)
                - TmstFirmaEnv: str (optional, will be auto-generated)
                - SubTotDTE: list of dicts (optional, will be auto-generated)

        Returns:
            str: EnvioDTE XML string (unsigned - caller must sign it)

        Raises:
            ValidationError: If required data is missing or invalid
        """
        _logger.info(
            f"[EnvioDTE] Generating EnvioDTE with {len(dtes)} DTE(s)"
        )

        # Validate inputs
        self._validate_inputs(dtes, caratula_data)

        # Create root element
        envio_dte = etree.Element(
            '{http://www.sii.cl/SiiDte}EnvioDTE',
            nsmap={'': 'http://www.sii.cl/SiiDte', 'xsi': 'http://www.w3.org/2001/XMLSchema-instance'},
            attrib={
                'version': '1.0',
                '{http://www.w3.org/2001/XMLSchema-instance}schemaLocation':
                    'http://www.sii.cl/SiiDte EnvioDTE_v10.xsd'
            }
        )

        # Create SetDTE
        set_dte = etree.SubElement(
            envio_dte,
            '{http://www.sii.cl/SiiDte}SetDTE',
            attrib={'ID': 'SetDTE'}  # ID required for signature reference
        )

        # Generate Carátula
        caratula = self._generate_caratula(dtes, caratula_data)
        set_dte.append(caratula)

        # Add each DTE
        for idx, dte_xml in enumerate(dtes, 1):
            try:
                # Parse DTE XML
                if isinstance(dte_xml, str):
                    dte_element = etree.fromstring(dte_xml.encode('utf-8'))
                elif isinstance(dte_xml, bytes):
                    dte_element = etree.fromstring(dte_xml)
                else:
                    dte_element = dte_xml

                # Add to SetDTE
                set_dte.append(dte_element)

                _logger.debug(f"[EnvioDTE] Added DTE {idx}/{len(dtes)}")

            except etree.XMLSyntaxError as e:
                _logger.error(f"[EnvioDTE] Invalid DTE XML at index {idx}: {e}")
                raise ValidationError(_(
                    "DTE #%d has invalid XML format:\n%s"
                ) % (idx, str(e)))

        # Convert to string
        envio_xml = etree.tostring(
            envio_dte,
            encoding='ISO-8859-1',
            xml_declaration=True,
            pretty_print=True
        ).decode('ISO-8859-1')

        _logger.info(
            f"[EnvioDTE] ✅ EnvioDTE generated successfully "
            f"({len(envio_xml)} bytes, {len(dtes)} DTEs)"
        )

        return envio_xml

    def _generate_caratula(self, dtes, caratula_data):
        """
        Generate Carátula (cover sheet) element

        The Carátula contains metadata about the EnvioDTE shipment.

        Args:
            dtes: List of DTE XML strings
            caratula_data: Dict with Carátula fields

        Returns:
            lxml.etree.Element: Carátula element
        """
        caratula = etree.Element('{http://www.sii.cl/SiiDte}Caratula')

        # RutEmisor (required)
        rut_emisor = etree.SubElement(caratula, '{http://www.sii.cl/SiiDte}RutEmisor')
        rut_emisor.text = caratula_data['RutEmisor']

        # RutEnvia (required) - Who is sending (can be same as emisor or representative)
        rut_envia = etree.SubElement(caratula, '{http://www.sii.cl/SiiDte}RutEnvia')
        rut_envia.text = caratula_data.get('RutEnvia', caratula_data['RutEmisor'])

        # RutReceptor (required) - Usually SII RUT: 60803000-K
        rut_receptor = etree.SubElement(caratula, '{http://www.sii.cl/SiiDte}RutReceptor')
        rut_receptor.text = caratula_data.get('RutReceptor', '60803000-K')

        # FchResol (required) - Resolution date from SII authorization
        fch_resol = etree.SubElement(caratula, '{http://www.sii.cl/SiiDte}FchResol')
        fch_resol.text = caratula_data['FchResol']

        # NroResol (required) - Resolution number from SII authorization
        nro_resol = etree.SubElement(caratula, '{http://www.sii.cl/SiiDte}NroResol')
        nro_resol.text = str(caratula_data['NroResol'])

        # TmstFirmaEnv (required) - Timestamp of envelope signature
        tmst_firma = etree.SubElement(caratula, '{http://www.sii.cl/SiiDte}TmstFirmaEnv')
        tmst_firma.text = caratula_data.get(
            'TmstFirmaEnv',
            datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        )

        # SubTotDTE (optional but recommended) - Summary by DTE type
        subtotales = self._calculate_subtotales(dtes, caratula_data)
        for subtotal_data in subtotales:
            subtot_dte = etree.SubElement(caratula, '{http://www.sii.cl/SiiDte}SubTotDTE')

            # TpoDTE (DTE type code: 33, 34, 52, etc.)
            tipo_dte = etree.SubElement(subtot_dte, '{http://www.sii.cl/SiiDte}TpoDTE')
            tipo_dte.text = str(subtotal_data['TipoDTE'])

            # NroDTE (count of DTEs of this type)
            nro_dte = etree.SubElement(subtot_dte, '{http://www.sii.cl/SiiDte}NroDTE')
            nro_dte.text = str(subtotal_data['Cantidad'])

        _logger.debug(
            f"[EnvioDTE] Carátula generated: "
            f"Emisor={caratula_data['RutEmisor']}, "
            f"Resol={caratula_data['NroResol']}, "
            f"DTEs={len(subtotales)} types"
        )

        return caratula

    def _calculate_subtotales(self, dtes, caratula_data):
        """
        Calculate subtotals by DTE type

        Args:
            dtes: List of DTE XML strings
            caratula_data: Dict (may contain pre-calculated SubTotDTE)

        Returns:
            List of dicts: [{'TipoDTE': 33, 'Cantidad': 5}, ...]
        """
        # If subtotals provided, use them
        if 'SubTotDTE' in caratula_data:
            return caratula_data['SubTotDTE']

        # Otherwise, calculate from DTEs
        subtotales = {}

        for dte_xml in dtes:
            try:
                # Parse DTE to extract type
                if isinstance(dte_xml, str):
                    dte = etree.fromstring(dte_xml.encode('utf-8'))
                elif isinstance(dte_xml, bytes):
                    dte = etree.fromstring(dte_xml)
                else:
                    dte = dte_xml

                # Find TipoDTE element
                # Path: DTE/Documento/Encabezado/IdDoc/TipoDTE
                tipo_dte_elem = dte.find('.//{http://www.sii.cl/SiiDte}TipoDTE')

                if tipo_dte_elem is not None and tipo_dte_elem.text:
                    tipo_dte = int(tipo_dte_elem.text)

                    if tipo_dte in subtotales:
                        subtotales[tipo_dte] += 1
                    else:
                        subtotales[tipo_dte] = 1
                else:
                    _logger.warning("[EnvioDTE] DTE without TipoDTE, skipping in subtotals")

            except Exception as e:
                _logger.warning(f"[EnvioDTE] Error extracting TipoDTE: {e}")

        # Convert to list of dicts
        result = [
            {'TipoDTE': tipo, 'Cantidad': cantidad}
            for tipo, cantidad in sorted(subtotales.items())
        ]

        return result

    def _validate_inputs(self, dtes, caratula_data):
        """
        Validate inputs before generating EnvioDTE

        Args:
            dtes: List of DTE XMLs
            caratula_data: Dict with Carátula data

        Raises:
            ValidationError: If validation fails
        """
        # Validate DTEs list
        if not dtes:
            raise ValidationError(_("At least one DTE is required"))

        if not isinstance(dtes, (list, tuple)):
            raise ValidationError(_("DTEs must be a list"))

        # Validate required Carátula fields
        required_fields = ['RutEmisor', 'FchResol', 'NroResol']
        missing_fields = [f for f in required_fields if f not in caratula_data]

        if missing_fields:
            raise ValidationError(_(
                "Missing required Carátula fields: %s"
            ) % ', '.join(missing_fields))

        # Validate RUT format (basic)
        rut_emisor = caratula_data['RutEmisor']
        if not self._is_valid_rut_format(rut_emisor):
            raise ValidationError(_(
                "Invalid RutEmisor format: %s (expected format: 12345678-9)"
            ) % rut_emisor)

        _logger.debug("[EnvioDTE] Input validation passed")

    def _is_valid_rut_format(self, rut):
        """
        Validate RUT format (basic check)

        Args:
            rut: str (format: 12345678-9 or 12.345.678-9)

        Returns:
            bool: True if format is valid
        """
        if not rut or not isinstance(rut, str):
            return False

        # Remove dots and check format
        rut_clean = rut.replace('.', '')

        # Should have format: NNNNNNNN-D (8 digits + hyphen + check digit)
        if '-' not in rut_clean:
            return False

        parts = rut_clean.split('-')
        if len(parts) != 2:
            return False

        numero, dv = parts

        # Numero should be numeric
        if not numero.isdigit():
            return False

        # DV should be digit or 'K'
        if dv not in '0123456789Kk':
            return False

        return True

    def create_caratula_from_company(self, company):
        """
        Helper: Create Carátula data dict from company record

        Args:
            company: res.company record

        Returns:
            dict: Carátula data ready for generate_envio_dte()

        Raises:
            UserError: If company is missing required DTE configuration
        """
        # Validate company has DTE config
        if not company.dte_fecha_resolucion or not company.dte_numero_resolucion:
            raise UserError(_(
                "Company %s is missing DTE resolution configuration.\n"
                "Please go to Settings → DTE Configuration and configure:\n"
                "- Resolution Date (Fecha Resolución)\n"
                "- Resolution Number (Número Resolución)"
            ) % company.name)

        # Get RutEmisor from company
        rut_emisor = company.partner_id.vat
        if not rut_emisor:
            raise UserError(_(
                "Company %s does not have RUT (VAT) configured"
            ) % company.name)

        # Build Carátula
        caratula = {
            'RutEmisor': rut_emisor,
            'RutEnvia': rut_emisor,  # Usually same, can be overridden
            'RutReceptor': '60803000-K',  # SII RUT (standard)
            'FchResol': company.dte_resolution_date.strftime('%Y-%m-%d'),
            'NroResol': str(company.dte_resolution_number),
            'TmstFirmaEnv': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        }

        _logger.debug(
            f"[EnvioDTE] Carátula created from company {company.name}: "
            f"Resol {caratula['NroResol']} ({caratula['FchResol']})"
        )

        return caratula

    def __str__(self):
        """String representation"""
        if self.company:
            return f"EnvioDTEGenerator(company={self.company.name})"
        return "EnvioDTEGenerator(no company)"


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def create_envio_dte_simple(dte_xml, company):
    """
    Convenience function: Create EnvioDTE for a single DTE

    Args:
        dte_xml: str - Single DTE XML
        company: res.company - Company record

    Returns:
        str: EnvioDTE XML (unsigned)

    Usage:
        envio_xml = create_envio_dte_simple(dte_xml, company)
    """
    generator = EnvioDTEGenerator(company)
    caratula = generator.create_caratula_from_company(company)
    return generator.generate_envio_dte([dte_xml], caratula)


def create_envio_dte_batch(dte_xmls, company):
    """
    Convenience function: Create EnvioDTE for multiple DTEs

    Args:
        dte_xmls: list - List of DTE XML strings
        company: res.company - Company record

    Returns:
        str: EnvioDTE XML (unsigned)

    Usage:
        envio_xml = create_envio_dte_batch([dte1, dte2, dte3], company)
    """
    generator = EnvioDTEGenerator(company)
    caratula = generator.create_caratula_from_company(company)
    return generator.generate_envio_dte(dte_xmls, caratula)
