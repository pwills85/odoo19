# -*- coding: utf-8 -*-
"""
TED Validator - Native Python Implementation
=============================================

Validación del TED (Timbre Electrónico Digital) de DTEs recibidos.

Migration from: odoo-eergy-services/validators/ted_validator.py (2025-10-24)

SPRINT 4: DTE Reception + AI-Powered Validation

TED (Timbre Electrónico Digital):
- Código de barras PDF417 en DTEs
- Contiene datos críticos: RUT, folio, monto, fecha
- Firmado digitalmente por emisor
- OBLIGATORIO validar coherencia TED vs DTE

Validaciones:
1. Presencia de TED en XML
2. Estructura DD (Datos del Documento)
3. Coherencia campos TED vs resto del DTE
4. Validación firma RSA (opcional)
"""

from lxml import etree
import base64
import logging
from datetime import datetime

_logger = logging.getLogger(__name__)


class TEDValidator:
    """
    Validador de TED (Timbre Electrónico Digital) para DTEs recibidos.

    El TED es un código de barras PDF417 que contiene:
    - RE: RUT Emisor
    - TD: Tipo DTE
    - F: Folio
    - FE: Fecha Emisión (YYYY-MM-DD)
    - RR: RUT Receptor
    - RSR: Razón Social Receptor
    - MNT: Monto Total
    - IT1: Descripción item 1
    - CAF: Firma CAF
    - FRMT: Firma digital TED
    """

    # ═══════════════════════════════════════════════════════════════════════
    # EXTRACCIÓN TED DESDE XML
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def extract_ted_from_xml(xml_string):
        """
        Extrae TED desde XML del DTE.

        Args:
            xml_string (str): XML completo del DTE

        Returns:
            dict or None: {
                'DD': {...},  # Datos del Documento
                'FRMT': str   # Firma RSA
            } o None si no se encuentra TED
        """
        try:
            root = etree.fromstring(xml_string.encode('ISO-8859-1'))

            # Buscar elemento TED
            # Puede estar en diferentes ubicaciones según versión XML
            ted_element = root.find('.//TED')
            if ted_element is None:
                ted_element = root.find('.//{http://www.sii.cl/SiiDte}TED')

            if ted_element is None:
                _logger.warning("TED element not found in XML")
                return None

            # Extraer DD (Datos del Documento)
            dd_element = ted_element.find('.//DD') or ted_element.find('.//{http://www.sii.cl/SiiDte}DD')

            if dd_element is None:
                _logger.warning("DD element not found in TED")
                return None

            dd_data = {}

            # Mapeo de campos DD
            fields_map = {
                'RE': 'rut_emisor',
                'TD': 'tipo_dte',
                'F': 'folio',
                'FE': 'fecha_emision',
                'RR': 'rut_receptor',
                'RSR': 'razon_social_receptor',
                'MNT': 'monto_total',
                'IT1': 'item_1',
                'TSTED': 'timestamp'
            }

            for xml_tag, dict_key in fields_map.items():
                element = dd_element.find(f'.//{xml_tag}')
                if element is not None and element.text:
                    dd_data[dict_key] = element.text.strip()

            # Extraer FRMT (Firma)
            frmt_element = ted_element.find('.//FRMT') or ted_element.find('.//{http://www.sii.cl/SiiDte}FRMT')
            frmt = frmt_element.text.strip() if frmt_element is not None and frmt_element.text else None

            return {
                'DD': dd_data,
                'FRMT': frmt
            }

        except Exception as e:
            _logger.error(f"Error extracting TED from XML: {e}")
            return None

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN PRESENCIA TED
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_ted_presence(xml_string):
        """
        Valida que DTE contenga TED.

        Args:
            xml_string (str): XML del DTE

        Returns:
            tuple: (has_ted: bool, error: str or None)
        """
        ted = TEDValidator.extract_ted_from_xml(xml_string)

        if ted is None:
            return (False, "TED no encontrado en DTE")

        if not ted.get('DD'):
            return (False, "TED sin datos DD")

        if not ted.get('FRMT'):
            return (False, "TED sin firma FRMT")

        return (True, None)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN COHERENCIA TED VS DTE
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_ted_consistency(ted_data, dte_data):
        """
        Valida coherencia entre TED y datos del DTE.

        Los campos críticos deben coincidir:
        - RUT emisor
        - Tipo DTE
        - Folio
        - Fecha emisión
        - Monto total

        Args:
            ted_data (dict): Datos extraídos del TED
            dte_data (dict): Datos del DTE completo

        Returns:
            tuple: (is_consistent: bool, errors: list)
        """
        errors = []

        dd = ted_data.get('DD', {})

        # 1. Validar RUT emisor
        ted_rut_emisor = dd.get('rut_emisor', '').strip()
        dte_rut_emisor = str(dte_data.get('rut_emisor', '')).strip()

        # Normalizar RUTs (quitar puntos, guiones)
        ted_rut_clean = ted_rut_emisor.replace('.', '').replace('-', '').upper()
        dte_rut_clean = dte_rut_emisor.replace('.', '').replace('-', '').upper()

        if ted_rut_clean != dte_rut_clean:
            errors.append(
                f"RUT emisor no coincide: TED={ted_rut_emisor}, DTE={dte_rut_emisor}"
            )

        # 2. Validar tipo DTE
        ted_tipo = str(dd.get('tipo_dte', '')).strip()
        dte_tipo = str(dte_data.get('tipo_dte', '')).strip()

        if ted_tipo != dte_tipo:
            errors.append(
                f"Tipo DTE no coincide: TED={ted_tipo}, DTE={dte_tipo}"
            )

        # 3. Validar folio
        ted_folio = str(dd.get('folio', '')).strip()
        dte_folio = str(dte_data.get('folio', '')).strip()

        if ted_folio != dte_folio:
            errors.append(
                f"Folio no coincide: TED={ted_folio}, DTE={dte_folio}"
            )

        # 4. Validar fecha emisión
        ted_fecha = dd.get('fecha_emision', '').strip()
        dte_fecha_raw = dte_data.get('fecha_emision')

        # Normalizar fecha DTE a string YYYY-MM-DD
        if isinstance(dte_fecha_raw, datetime):
            dte_fecha = dte_fecha_raw.strftime('%Y-%m-%d')
        elif isinstance(dte_fecha_raw, str):
            dte_fecha = dte_fecha_raw
        else:
            dte_fecha = str(dte_fecha_raw)

        if ted_fecha != dte_fecha:
            errors.append(
                f"Fecha emisión no coincide: TED={ted_fecha}, DTE={dte_fecha}"
            )

        # 5. Validar monto total
        ted_monto = dd.get('monto_total', '').strip()
        dte_monto = dte_data.get('monto_total', 0)

        try:
            ted_monto_int = int(ted_monto)
            dte_monto_int = int(float(dte_monto))

            if ted_monto_int != dte_monto_int:
                errors.append(
                    f"Monto total no coincide: TED={ted_monto_int}, DTE={dte_monto_int}"
                )
        except (ValueError, TypeError):
            errors.append(
                f"Monto total inválido: TED={ted_monto}, DTE={dte_monto}"
            )

        return (len(errors) == 0, errors)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN FIRMA TED (AVANZADO - OPCIONAL)
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_ted_signature(ted_data):
        """
        Valida firma RSA del TED (AVANZADO - opcional).

        NOTA: Esta validación requiere certificado público del emisor.
        Por ahora retorna siempre True (placeholder).

        Args:
            ted_data (dict): TED con DD y FRMT

        Returns:
            tuple: (is_valid: bool, error: str or None)
        """
        # TODO: Implementar validación firma RSA
        # Requiere:
        # 1. Certificado público del emisor (desde SII o almacenado)
        # 2. Reconstruir DD canónico
        # 3. Verificar firma FRMT con certificado público

        _logger.debug("TED signature validation skipped (not implemented)")

        return (True, None)  # Placeholder

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN COMPLETA TED
    # ═══════════════════════════════════════════════════════════════════════

    @classmethod
    def validate_ted(cls, xml_string, dte_data):
        """
        Validación completa del TED.

        Args:
            xml_string (str): XML completo del DTE
            dte_data (dict): Datos parseados del DTE

        Returns:
            dict: {
                'valid': bool,
                'errors': list,
                'warnings': list,
                'ted_data': dict or None
            }
        """
        errors = []
        warnings = []

        _logger.info(f"Validating TED for DTE: type={dte_data.get('tipo_dte')}, folio={dte_data.get('folio')}")

        # 1. Verificar presencia TED
        has_ted, error = cls.validate_ted_presence(xml_string)
        if not has_ted:
            errors.append(error)
            return {
                'valid': False,
                'errors': errors,
                'warnings': warnings,
                'ted_data': None
            }

        # 2. Extraer TED
        ted_data = cls.extract_ted_from_xml(xml_string)

        # 3. Validar coherencia TED vs DTE
        is_consistent, consistency_errors = cls.validate_ted_consistency(ted_data, dte_data)
        if not is_consistent:
            errors.extend(consistency_errors)

        # 4. Validar firma TED (opcional)
        # is_valid_signature, signature_error = cls.validate_ted_signature(ted_data)
        # if not is_valid_signature:
        #     warnings.append(f"TED signature validation: {signature_error}")

        valid = len(errors) == 0

        if valid:
            _logger.info(f"✅ TED validation PASSED: {dte_data.get('tipo_dte')} {dte_data.get('folio')}")
        else:
            _logger.warning(f"❌ TED validation FAILED: {len(errors)} errors")

        return {
            'valid': valid,
            'errors': errors,
            'warnings': warnings,
            'ted_data': ted_data
        }
