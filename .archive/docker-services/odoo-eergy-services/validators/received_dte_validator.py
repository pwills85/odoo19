"""
Received DTE Validator
======================

Validates DTEs received from suppliers/SII.

Performs structural, business, and signature validation.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple
import logging
from datetime import datetime
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReceivedDTEValidator:
    """Validator for received DTEs."""

    # Valid DTE types for reception
    VALID_DTE_TYPES = ['33', '34', '39', '41', '43', '46', '52', '56', '61', '70', '71']

    def __init__(self):
        """Initialize validator."""
        self.validation_errors = []
        self.validation_warnings = []

    def validate(self, dte_data: Dict) -> Tuple[bool, List[str], List[str]]:
        """
        Validate received DTE.

        Args:
            dte_data: Parsed DTE data from DTEParser

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.validation_errors = []
        self.validation_warnings = []

        # Run all validations
        self._validate_structure(dte_data)
        self._validate_dte_type(dte_data)
        self._validate_dates(dte_data)
        self._validate_rut(dte_data)
        self._validate_amounts(dte_data)
        self._validate_items(dte_data)
        self._validate_ted(dte_data)
        self._validate_signature(dte_data)
        self._validate_bhe_specific(dte_data)

        is_valid = len(self.validation_errors) == 0

        if is_valid:
            logger.info(f"✅ DTE validation passed: Type {dte_data.get('dte_type')} Folio {dte_data.get('folio')}")
        else:
            logger.warning(f"❌ DTE validation failed: {len(self.validation_errors)} errors")

        return is_valid, self.validation_errors, self.validation_warnings

    def _validate_structure(self, dte_data: Dict):
        """Validate DTE has required structure."""
        required_fields = ['dte_type', 'folio', 'fecha_emision', 'emisor', 'receptor', 'totales']

        for field in required_fields:
            if field not in dte_data or not dte_data[field]:
                self.validation_errors.append(f"Missing required field: {field}")

        # Validate emisor structure
        if 'emisor' in dte_data:
            emisor = dte_data['emisor']
            if not emisor.get('rut'):
                self.validation_errors.append("Emisor RUT is required")
            if not emisor.get('razon_social'):
                self.validation_errors.append("Emisor razon social is required")

        # Validate receptor structure
        if 'receptor' in dte_data:
            receptor = dte_data['receptor']
            if not receptor.get('rut'):
                self.validation_errors.append("Receptor RUT is required")
            if not receptor.get('razon_social'):
                self.validation_warnings.append("Receptor razon social is missing")

    def _validate_dte_type(self, dte_data: Dict):
        """Validate DTE type is valid."""
        dte_type = dte_data.get('dte_type')

        if not dte_type:
            self.validation_errors.append("DTE type is required")
            return

        if dte_type not in self.VALID_DTE_TYPES:
            self.validation_errors.append(f"Invalid DTE type: {dte_type}")

    def _validate_dates(self, dte_data: Dict):
        """Validate dates are valid."""
        fecha_emision = dte_data.get('fecha_emision')

        if not fecha_emision:
            self.validation_errors.append("Fecha emision is required")
            return

        # Validate date format (YYYY-MM-DD)
        try:
            date_obj = datetime.strptime(fecha_emision, '%Y-%m-%d')

            # Check date is not in future
            if date_obj > datetime.now():
                self.validation_errors.append(f"Fecha emision is in the future: {fecha_emision}")

            # Check date is not too old (e.g., > 10 years)
            years_old = (datetime.now() - date_obj).days / 365
            if years_old > 10:
                self.validation_warnings.append(f"Fecha emision is very old: {fecha_emision} ({years_old:.1f} years)")

        except ValueError:
            self.validation_errors.append(f"Invalid date format: {fecha_emision} (expected YYYY-MM-DD)")

    def _validate_rut(self, dte_data: Dict):
        """Validate RUTs (Chilean tax IDs)."""
        # Validate emisor RUT
        if 'emisor' in dte_data:
            emisor_rut = dte_data['emisor'].get('rut')
            if emisor_rut and not self._is_valid_rut(emisor_rut):
                self.validation_errors.append(f"Invalid emisor RUT: {emisor_rut}")

        # Validate receptor RUT
        if 'receptor' in dte_data:
            receptor_rut = dte_data['receptor'].get('rut')
            if receptor_rut and not self._is_valid_rut(receptor_rut):
                self.validation_errors.append(f"Invalid receptor RUT: {receptor_rut}")

    def _is_valid_rut(self, rut: str) -> bool:
        """
        Validate Chilean RUT using módulo 11 algorithm.

        Args:
            rut: RUT string (format: 12345678-9 or 123456789)

        Returns:
            True if valid, False otherwise
        """
        # Remove dots and dashes
        rut_clean = rut.replace('.', '').replace('-', '').upper()

        if len(rut_clean) < 2:
            return False

        # Split RUT and DV
        rut_num = rut_clean[:-1]
        dv = rut_clean[-1]

        # Validate rut_num is numeric
        if not rut_num.isdigit():
            return False

        # Calculate expected DV using módulo 11
        suma = 0
        multiplicador = 2

        for digit in reversed(rut_num):
            suma += int(digit) * multiplicador
            multiplicador += 1
            if multiplicador > 7:
                multiplicador = 2

        resto = suma % 11
        dv_esperado = 11 - resto

        # Convert to character
        if dv_esperado == 11:
            dv_esperado = '0'
        elif dv_esperado == 10:
            dv_esperado = 'K'
        else:
            dv_esperado = str(dv_esperado)

        return dv == dv_esperado

    def _validate_amounts(self, dte_data: Dict):
        """Validate monetary amounts are consistent."""
        totales = dte_data.get('totales', {})

        monto_neto = totales.get('monto_neto', 0)
        monto_exento = totales.get('monto_exento', 0)
        iva = totales.get('iva', 0)
        monto_total = totales.get('total', 0)

        # Validate total calculation
        # Total should equal: Neto + IVA + Exento
        calculated_total = monto_neto + iva + monto_exento

        # Allow small rounding differences (up to 1 peso)
        if abs(calculated_total - monto_total) > 1:
            self.validation_errors.append(
                f"Total mismatch: Neto({monto_neto}) + IVA({iva}) + Exento({monto_exento}) "
                f"= {calculated_total} != Total({monto_total})"
            )

        # Validate IVA calculation (should be ~19% of Neto)
        if monto_neto > 0:
            tasa_iva = totales.get('tasa_iva', 19)
            iva_esperado = round(monto_neto * tasa_iva / 100)

            # Allow small rounding differences
            if abs(iva_esperado - iva) > 1:
                self.validation_warnings.append(
                    f"IVA calculation may be incorrect: Expected {iva_esperado}, got {iva} "
                    f"(Neto={monto_neto}, Tasa={tasa_iva}%)"
                )

        # Validate amounts are non-negative
        if monto_total < 0:
            self.validation_errors.append(f"Total amount is negative: {monto_total}")

    def _validate_items(self, dte_data: Dict):
        """Validate line items."""
        items = dte_data.get('items', [])

        if not items or len(items) == 0:
            self.validation_errors.append("DTE must have at least one line item")
            return

        # Validate each item
        for idx, item in enumerate(items, 1):
            # Check required fields
            if not item.get('nombre'):
                self.validation_warnings.append(f"Item {idx}: Missing nombre")

            if not item.get('cantidad') or item.get('cantidad', 0) <= 0:
                self.validation_errors.append(f"Item {idx}: Invalid cantidad: {item.get('cantidad')}")

            if not item.get('precio_unitario'):
                self.validation_errors.append(f"Item {idx}: Missing precio_unitario")

            # Validate monto_item calculation
            cantidad = item.get('cantidad', 0)
            precio_unitario = item.get('precio_unitario', 0)
            descuento_monto = item.get('descuento_monto', 0)
            recargo_monto = item.get('recargo_monto', 0)
            monto_item = item.get('monto_item', 0)

            # Calculate expected monto
            monto_esperado = (cantidad * precio_unitario) - descuento_monto + recargo_monto

            # Allow small rounding differences
            if abs(monto_esperado - monto_item) > 1:
                self.validation_warnings.append(
                    f"Item {idx}: Monto mismatch: Expected {monto_esperado}, got {monto_item}"
                )

    def _validate_ted(self, dte_data: Dict):
        """Validate TED (Timbre Electrónico)."""
        ted = dte_data.get('ted', {})

        if not ted:
            self.validation_errors.append("TED (Timbre Electrónico) is required")
            return

        # Validate TED has required fields
        required_ted_fields = ['rut_emisor', 'tipo_dte', 'folio', 'fecha_emision', 'monto_total']

        for field in required_ted_fields:
            if not ted.get(field):
                self.validation_errors.append(f"TED missing required field: {field}")

        # Validate TED data matches DTE header
        if ted.get('tipo_dte') != dte_data.get('dte_type'):
            self.validation_errors.append(
                f"TED tipo_dte ({ted.get('tipo_dte')}) does not match DTE type ({dte_data.get('dte_type')})"
            )

        if ted.get('folio') != dte_data.get('folio'):
            self.validation_errors.append(
                f"TED folio ({ted.get('folio')}) does not match DTE folio ({dte_data.get('folio')})"
            )

        if ted.get('rut_emisor') != dte_data.get('emisor', {}).get('rut'):
            self.validation_errors.append(
                f"TED RUT emisor ({ted.get('rut_emisor')}) does not match DTE emisor RUT"
            )

        # Validate TED has firma
        if not ted.get('firma'):
            self.validation_errors.append("TED firma (signature) is missing")

    def _validate_signature(self, dte_data: Dict):
        """Validate digital signature."""
        signature = dte_data.get('signature', {})

        if not signature:
            self.validation_warnings.append("Digital signature information not found")
            return

        # Check signature value exists
        if not signature.get('signature_value'):
            self.validation_warnings.append("Signature value is missing")

        # Check certificate exists
        key_info = signature.get('key_info', {})
        if not key_info.get('x509_certificate'):
            self.validation_warnings.append("X509 certificate is missing from signature")

        # Note: Full signature cryptographic validation would require
        # xmlsec library and certificate chain verification
        # This is a basic structural check only

    def _validate_bhe_specific(self, dte_data: Dict):
        """
        Validaciones específicas para DTE 71 (Boleta de Honorarios Electrónica).

        BHE tiene características especiales:
        - Retención variable según año (10% a 14.5% gradual 2018-2025)
        - Monto bruto (antes de retención)
        - Sin IVA (servicios profesionales exentos)

        Tasas históricas según Ley 21.133:
        - 2018-2020: 10.0%
        - 2021: 11.5%
        - 2022: 12.25%
        - 2023: 13.0%
        - 2024: 13.75%
        - 2025+: 14.5%
        """
        if dte_data.get('dte_type') != '71':
            return

        logger.info("Validating BHE specific rules (DTE 71)")

        totales = dte_data.get('totales', {})
        fecha_emision = dte_data.get('fecha_emision', '')

        # Determinar tasa esperada según fecha
        tasa_esperada = self._get_expected_bhe_retention_rate(fecha_emision)

        # BHE debe tener retención
        retencion = totales.get('retencion', 0) or totales.get('monto_retencion', 0)
        monto_bruto = totales.get('monto_bruto', 0) or totales.get('total', 0)

        if retencion == 0:
            self.validation_warnings.append(
                f"BHE (DTE 71) normalmente tiene retención {tasa_esperada}% para {fecha_emision[:4]}. "
                f"Verificar si es correcto."
            )
        else:
            # Validar que retención sea aproximadamente la tasa esperada
            retencion_esperada = monto_bruto * (tasa_esperada / 100)
            diferencia = abs(retencion - retencion_esperada)

            # Tolerancia 2% (permite variación entre tasas históricas)
            if diferencia > (monto_bruto * 0.02):
                tasa_real = (retencion / monto_bruto * 100) if monto_bruto > 0 else 0
                self.validation_warnings.append(
                    f"Retención BHE ({retencion:,.0f} = {tasa_real:.2f}%) "
                    f"difiere del {tasa_esperada}% esperado para {fecha_emision[:4]} "
                    f"({retencion_esperada:,.0f})"
                )

        # BHE no debe tener IVA
        iva = totales.get('iva', 0) or totales.get('monto_iva', 0)
        if iva > 0:
            self.validation_errors.append(
                f"BHE (DTE 71) no debe tener IVA. Encontrado: ${iva:,.0f}"
            )

        logger.info(f"BHE validation completed - Warnings: {len([w for w in self.validation_warnings if 'BHE' in w])}")

    def _get_expected_bhe_retention_rate(self, fecha_emision: str) -> float:
        """
        Determina la tasa de retención BHE esperada según fecha de emisión.

        Args:
            fecha_emision: Fecha en formato YYYY-MM-DD

        Returns:
            float: Tasa de retención esperada (ej: 14.5 para 14.5%)
        """
        if not fecha_emision or len(fecha_emision) < 4:
            return 14.5  # Default actual

        year = int(fecha_emision[:4])

        # Tasas históricas según Ley 21.133
        if year <= 2020:
            return 10.0
        elif year == 2021:
            return 11.5
        elif year == 2022:
            return 12.25
        elif year == 2023:
            return 13.0
        elif year == 2024:
            return 13.75
        else:  # 2025+
            return 14.5


class ReceivedDTEBusinessValidator:
    """Business-level validation for received DTEs."""

    def __init__(self, company_rut: str):
        """
        Initialize business validator.

        Args:
            company_rut: Our company's RUT (to validate we're the receptor)
        """
        self.company_rut = company_rut
        self.validation_errors = []
        self.validation_warnings = []

    def validate(self, dte_data: Dict) -> Tuple[bool, List[str], List[str]]:
        """
        Validate DTE from business perspective.

        Args:
            dte_data: Parsed DTE data

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.validation_errors = []
        self.validation_warnings = []

        self._validate_receptor_is_us(dte_data)
        self._validate_duplicate(dte_data)
        self._check_suspicious_amounts(dte_data)

        is_valid = len(self.validation_errors) == 0

        return is_valid, self.validation_errors, self.validation_warnings

    def _validate_receptor_is_us(self, dte_data: Dict):
        """Validate that we are the receptor of this DTE."""
        receptor_rut = dte_data.get('receptor', {}).get('rut', '')

        # Normalize RUTs for comparison (remove dots and dashes)
        receptor_rut_clean = receptor_rut.replace('.', '').replace('-', '').upper()
        company_rut_clean = self.company_rut.replace('.', '').replace('-', '').upper()

        if receptor_rut_clean != company_rut_clean:
            self.validation_errors.append(
                f"Receptor RUT ({receptor_rut}) does not match our company RUT ({self.company_rut})"
            )

    def _validate_duplicate(self, dte_data: Dict):
        """Check if this DTE already exists (duplicate detection)."""
        # This would typically query the database
        # For now, just a placeholder

        # TODO: Implement database query
        # query = "SELECT id FROM dte_inbox WHERE emisor_rut=? AND tipo_dte=? AND folio=?"
        # if exists: self.validation_errors.append("Duplicate DTE")

        pass

    def _check_suspicious_amounts(self, dte_data: Dict):
        """Check for suspicious amounts (fraud detection)."""
        total = dte_data.get('totales', {}).get('total', 0)

        # Check for unusually large amounts (> $100M CLP)
        if total > 100_000_000:
            self.validation_warnings.append(
                f"Unusually large amount: ${total:,.0f} CLP - Please review carefully"
            )

        # Check for zero or negative totals
        if total <= 0:
            self.validation_warnings.append(
                f"Zero or negative total: ${total:,.0f} CLP"
            )


def main():
    """Test validator."""
    print("=" * 80)
    print("RECEIVED DTE VALIDATOR TEST")
    print("=" * 80)
    print()

    # Sample DTE data (from parser)
    sample_dte = {
        'dte_type': '33',
        'folio': '12345',
        'fecha_emision': '2025-10-22',
        'emisor': {
            'rut': '76123456-7',
            'razon_social': 'EMPRESA EMISORA LTDA'
        },
        'receptor': {
            'rut': '77654321-K',
            'razon_social': 'EMPRESA RECEPTORA SA'
        },
        'totales': {
            'monto_neto': 100000,
            'iva': 19000,
            'total': 119000,
            'tasa_iva': 19
        },
        'items': [
            {
                'numero_linea': 1,
                'nombre': 'Producto Test',
                'cantidad': 10,
                'precio_unitario': 10000,
                'monto_item': 100000
            }
        ],
        'ted': {
            'rut_emisor': '76123456-7',
            'tipo_dte': '33',
            'folio': '12345',
            'fecha_emision': '2025-10-22',
            'monto_total': '119000',
            'firma': 'ABC123...'
        },
        'signature': {
            'signature_value': 'XYZ789...',
            'key_info': {
                'x509_certificate': 'CERT123...'
            }
        }
    }

    # Test structural validation
    print("1. Structural Validation:")
    validator = ReceivedDTEValidator()
    is_valid, errors, warnings = validator.validate(sample_dte)

    print(f"   Valid: {is_valid}")
    print(f"   Errors: {len(errors)}")
    print(f"   Warnings: {len(warnings)}")

    if errors:
        print("\n   Errors:")
        for error in errors:
            print(f"   - {error}")

    if warnings:
        print("\n   Warnings:")
        for warning in warnings:
            print(f"   - {warning}")

    # Test business validation
    print("\n2. Business Validation:")
    business_validator = ReceivedDTEBusinessValidator(company_rut='77654321-K')
    is_valid_biz, errors_biz, warnings_biz = business_validator.validate(sample_dte)

    print(f"   Valid: {is_valid_biz}")
    print(f"   Errors: {len(errors_biz)}")
    print(f"   Warnings: {len(warnings_biz)}")

    if errors_biz:
        print("\n   Errors:")
        for error in errors_biz:
            print(f"   - {error}")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()
