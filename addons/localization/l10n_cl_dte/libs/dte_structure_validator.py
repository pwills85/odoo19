# -*- coding: utf-8 -*-
"""
DTE Structure Validator - Native Python Implementation
=======================================================

Validación estructural de DTEs recibidos (NATIVA - sin AI).

Migration from: odoo-eergy-services/validators/structure_validator.py (2025-10-24)

SPRINT 4: DTE Reception + AI-Powered Validation

Validaciones nativas (rápidas, sin costo):
- Estructura XML básica
- Campos requeridos
- Rangos de valores
- RUTs válidos
- Fechas coherentes
- Códigos DTE válidos
- Montos matemáticamente correctos

AI Service se usa DESPUÉS de pasar validación nativa para:
- Detección de anomalías semánticas
- Matching con POs
- Sugerencias de cuentas contables
"""

from lxml import etree
from datetime import datetime, date
import re
import logging
from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

_logger = logging.getLogger(__name__)


class DTEStructureValidator:
    """
    Validador estructural de DTEs recibidos (sin IA).

    Validaciones rápidas pre-AI para filtrar DTEs mal formados.
    """

    # ═══════════════════════════════════════════════════════════════════════
    # CONSTANTES
    # ═══════════════════════════════════════════════════════════════════════

    # EERGYGROUP B2B Scope - SII authorized DTE types only
    # Contract dated: 2024-Q4
    # Excluded: 39,41,46,70 (Boletas Honorarios/Venta - out of scope)
    DTE_TYPES_VALID = [
        '33',  # Factura Electrónica
        '34',  # Factura Exenta Electrónica
        '52',  # Guía de Despacho Electrónica
        '56',  # Nota de Débito Electrónica
        '61',  # Nota de Crédito Electrónica
    ]

    IVA_RATE_CHILE = 0.19  # 19% IVA Chile

    MAX_AMOUNT = 999999999999  # Max monto DTE

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN ESTRUCTURA XML
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_xml_structure(xml_string):
        """
        Valida estructura básica XML.

        Args:
            xml_string (str): XML del DTE

        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        errors = []

        try:
            # Parse XML
            root = fromstring_safe(xml_string)

            # Verificar namespace SII
            if 'sii.cl' not in etree.tostring(root, encoding='unicode'):
                errors.append("XML no contiene namespace SII válido")

            # Verificar elementos básicos
            if root.find('.//Documento') is None and root.find('.//{http://www.sii.cl/SiiDte}Documento') is None:
                errors.append("XML no contiene elemento <Documento>")

            return (len(errors) == 0, errors)

        except etree.XMLSyntaxError as e:
            errors.append(f"XML mal formado: {str(e)}")
            return (False, errors)

        except Exception as e:
            errors.append(f"Error parsing XML: {str(e)}")
            return (False, errors)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN RUT CHILENO
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_rut(rut):
        """
        Valida RUT chileno (algoritmo módulo 11).

        Args:
            rut (str): RUT formato "12345678-9" o "12345678-K"

        Returns:
            bool: True si RUT válido
        """
        if not rut or not isinstance(rut, str):
            return False

        # Limpiar RUT
        rut = rut.replace('.', '').replace('-', '').upper().strip()

        if len(rut) < 2:
            return False

        # Separar número y dígito verificador
        rut_num = rut[:-1]
        dv = rut[-1]

        # Validar que número sea numérico
        if not rut_num.isdigit():
            return False

        # Calcular dígito verificador esperado
        reversed_digits = map(int, reversed(rut_num))
        factors = [2, 3, 4, 5, 6, 7] * 3  # Ciclo 2-7

        s = sum(d * f for d, f in zip(reversed_digits, factors))
        verification = 11 - (s % 11)

        if verification == 11:
            expected_dv = '0'
        elif verification == 10:
            expected_dv = 'K'
        else:
            expected_dv = str(verification)

        return dv == expected_dv

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN CAMPOS REQUERIDOS
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_required_fields(dte_data):
        """
        Valida que DTE tenga todos los campos requeridos.

        Args:
            dte_data (dict): Datos parseados del DTE

        Returns:
            tuple: (is_valid: bool, missing_fields: list)
        """
        required_fields = [
            'tipo_dte',
            'folio',
            'fecha_emision',
            'rut_emisor',
            'razon_social_emisor',
            'monto_total'
        ]

        missing = []

        for field in required_fields:
            if field not in dte_data or not dte_data[field]:
                missing.append(field)

        return (len(missing) == 0, missing)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN TIPO DTE
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_dte_type(dte_type):
        """
        Valida que tipo de DTE sea válido.

        Args:
            dte_type (str): Código DTE (ej: '33', '34', '52')

        Returns:
            tuple: (is_valid: bool, error: str or None)
        """
        if not dte_type:
            return (False, "Tipo DTE no especificado")

        dte_type_str = str(dte_type)

        if dte_type_str not in DTEStructureValidator.DTE_TYPES_VALID:
            return (False, f"Tipo DTE inválido: {dte_type_str}. Válidos: {', '.join(DTEStructureValidator.DTE_TYPES_VALID)}")

        return (True, None)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN MONTOS
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_amounts(dte_data):
        """
        Valida coherencia matemática de montos.

        Validaciones:
        - Monto total = Monto neto + IVA + Monto exento
        - IVA = Monto neto * 19%
        - Montos > 0
        - Montos < MAX_AMOUNT

        Args:
            dte_data (dict): Datos del DTE con campos:
                - monto_neto (float)
                - monto_iva (float)
                - monto_exento (float)
                - monto_total (float)

        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        errors = []

        monto_total = float(dte_data.get('monto_total', 0))
        monto_neto = float(dte_data.get('monto_neto', 0))
        monto_iva = float(dte_data.get('monto_iva', 0))
        monto_exento = float(dte_data.get('monto_exento', 0))

        # Validar montos positivos
        if monto_total <= 0:
            errors.append("Monto total debe ser mayor a 0")

        if monto_total > DTEStructureValidator.MAX_AMOUNT:
            errors.append(f"Monto total excede máximo permitido ({DTEStructureValidator.MAX_AMOUNT})")

        # Validar coherencia matemática
        # Monto total = Neto + IVA + Exento
        expected_total = monto_neto + monto_iva + monto_exento

        # Tolerancia 1 peso (por redondeos)
        if abs(monto_total - expected_total) > 1:
            errors.append(
                f"Monto total incoherente: "
                f"Total={monto_total}, Esperado={expected_total} "
                f"(Neto={monto_neto} + IVA={monto_iva} + Exento={monto_exento})"
            )

        # Validar IVA = Neto * 19%
        if monto_neto > 0:
            expected_iva = round(monto_neto * DTEStructureValidator.IVA_RATE_CHILE)

            # Tolerancia 2 pesos (por redondeos)
            if abs(monto_iva - expected_iva) > 2:
                errors.append(
                    f"IVA incoherente: "
                    f"IVA={monto_iva}, Esperado={expected_iva} "
                    f"(19% de Neto={monto_neto})"
                )

        return (len(errors) == 0, errors)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN FECHAS
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_dates(dte_data):
        """
        Valida coherencia de fechas.

        Validaciones:
        - Fecha emisión no futura (max +1 día por diferencia horaria)
        - Fecha emisión no muy antigua (max 6 meses atrás)

        Args:
            dte_data (dict): Datos con campo 'fecha_emision' (str YYYY-MM-DD o datetime)

        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        errors = []

        fecha_emision_raw = dte_data.get('fecha_emision')

        if not fecha_emision_raw:
            errors.append("Fecha emisión no especificada")
            return (False, errors)

        # Convertir a date
        if isinstance(fecha_emision_raw, str):
            try:
                fecha_emision = datetime.strptime(fecha_emision_raw, '%Y-%m-%d').date()
            except ValueError:
                errors.append(f"Formato fecha inválido: {fecha_emision_raw} (esperado YYYY-MM-DD)")
                return (False, errors)
        elif isinstance(fecha_emision_raw, datetime):
            fecha_emision = fecha_emision_raw.date()
        elif isinstance(fecha_emision_raw, date):
            fecha_emision = fecha_emision_raw
        else:
            errors.append(f"Tipo fecha inválido: {type(fecha_emision_raw)}")
            return (False, errors)

        # Fecha actual
        hoy = date.today()

        # Validar no futura (tolerancia +1 día por zona horaria)
        from datetime import timedelta
        if fecha_emision > (hoy + timedelta(days=1)):
            errors.append(f"Fecha emisión futura: {fecha_emision}")

        # Validar no muy antigua (max 6 meses)
        if fecha_emision < (hoy - timedelta(days=180)):
            errors.append(f"Fecha emisión muy antigua: {fecha_emision} (>6 meses)")

        return (len(errors) == 0, errors)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN FOLIO
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_folio(folio):
        """
        Valida folio DTE.

        Args:
            folio (int or str): Número de folio

        Returns:
            tuple: (is_valid: bool, error: str or None)
        """
        if not folio:
            return (False, "Folio no especificado")

        try:
            folio_int = int(folio)
        except (ValueError, TypeError):
            return (False, f"Folio inválido: {folio} (debe ser numérico)")

        if folio_int <= 0:
            return (False, f"Folio debe ser mayor a 0: {folio_int}")

        if folio_int > 999999999:
            return (False, f"Folio excede máximo: {folio_int}")

        return (True, None)

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN COMPLETA
    # ═══════════════════════════════════════════════════════════════════════

    @classmethod
    def validate_dte(cls, dte_data, xml_string=None):
        """
        Validación completa de DTE (nativa, sin AI).

        Args:
            dte_data (dict): Datos parseados del DTE
            xml_string (str, optional): XML completo para validación estructura

        Returns:
            dict: {
                'valid': bool,
                'errors': list,
                'warnings': list
            }
        """
        errors = []
        warnings = []

        _logger.info(f"Validating DTE structure: type={dte_data.get('tipo_dte')}, folio={dte_data.get('folio')}")

        # 1. Validar XML estructura (si se provee)
        if xml_string:
            is_valid, xml_errors = cls.validate_xml_structure(xml_string)
            if not is_valid:
                errors.extend(xml_errors)

        # 2. Validar campos requeridos
        is_valid, missing = cls.validate_required_fields(dte_data)
        if not is_valid:
            errors.append(f"Campos requeridos faltantes: {', '.join(missing)}")

        # 3. Validar tipo DTE
        is_valid, error = cls.validate_dte_type(dte_data.get('tipo_dte'))
        if not is_valid:
            errors.append(error)

        # 4. Validar folio
        is_valid, error = cls.validate_folio(dte_data.get('folio'))
        if not is_valid:
            errors.append(error)

        # 5. Validar RUT emisor
        if not cls.validate_rut(dte_data.get('rut_emisor', '')):
            errors.append(f"RUT emisor inválido: {dte_data.get('rut_emisor')}")

        # 6. Validar montos
        is_valid, amount_errors = cls.validate_amounts(dte_data)
        if not is_valid:
            errors.extend(amount_errors)

        # 7. Validar fechas
        is_valid, date_errors = cls.validate_dates(dte_data)
        if not is_valid:
            # Fechas antiguas son warning, no error
            for err in date_errors:
                if 'antigua' in err.lower():
                    warnings.append(err)
                else:
                    errors.append(err)

        valid = len(errors) == 0

        if valid:
            _logger.info(f"✅ DTE structure validation PASSED: {dte_data.get('tipo_dte')} {dte_data.get('folio')}")
        else:
            _logger.warning(f"❌ DTE structure validation FAILED: {len(errors)} errors")

        return {
            'valid': valid,
            'errors': errors,
            'warnings': warnings
        }
