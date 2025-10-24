"""
DTE Parser for Received DTEs
============================

Parses received DTE XML and extracts all relevant data.

Based on Odoo 18: l10n_cl_fe/models/mail_dte.py parsing logic
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from datetime import datetime
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DTEParser:
    """Parser for received DTE XML documents."""

    # Namespace mapping (SII uses these)
    NAMESPACES = {
        'sii': 'http://www.sii.cl/SiiDte',
        'ds': 'http://www.w3.org/2000/09/xmldsig#'
    }

    def __init__(self):
        """Initialize parser."""
        self.parsed_data = {}

    def parse(self, xml_content: str) -> Dict:
        """
        Parse DTE XML and extract all data.

        Args:
            xml_content: DTE XML as string

        Returns:
            Dict with parsed DTE data:
                - dte_type: Document type code
                - folio: Document number
                - fecha_emision: Emission date
                - emisor: Issuer data (RUT, name, address, etc.)
                - receptor: Receiver data
                - totales: Totals (subtotal, IVA, total)
                - items: List of line items
                - referencias: References to other documents
                - ted: TED (Timbre Electrónico) data
                - signature: Digital signature info
        """
        try:
            # Parse XML
            root = ET.fromstring(xml_content)

            # Detect structure (SetDTE vs single DTE)
            documento = self._find_documento(root)

            if not documento:
                raise ValueError("No valid Documento found in XML")

            # Parse all sections
            parsed = {
                'raw_xml': xml_content,
                'documento': self._parse_documento(documento),
                'ted': self._parse_ted(documento),
                'signature': self._parse_signature(root),
                'timestamp': datetime.now().isoformat()
            }

            # Flatten for easier access
            if parsed['documento']:
                parsed.update({
                    'dte_type': parsed['documento'].get('id_doc', {}).get('tipo_dte'),
                    'folio': parsed['documento'].get('id_doc', {}).get('folio'),
                    'fecha_emision': parsed['documento'].get('id_doc', {}).get('fecha_emision'),
                    'emisor': parsed['documento'].get('emisor', {}),
                    'receptor': parsed['documento'].get('receptor', {}),
                    'totales': parsed['documento'].get('totales', {}),
                    'items': parsed['documento'].get('detalle', []),
                    'referencias': parsed['documento'].get('referencias', [])
                })

            self.parsed_data = parsed
            logger.info(f"✅ Parsed DTE Type {parsed.get('dte_type')} Folio {parsed.get('folio')}")

            return parsed

        except ET.ParseError as e:
            logger.error(f"❌ XML Parse Error: {e}")
            raise ValueError(f"Invalid XML: {e}")
        except Exception as e:
            logger.error(f"❌ Parse Error: {e}")
            raise

    def _find_documento(self, root: ET.Element) -> Optional[ET.Element]:
        """Find Documento element in XML tree."""
        # Try with namespace
        doc = root.find('.//sii:Documento', self.NAMESPACES)
        if doc is not None:
            return doc

        # Try without namespace
        for elem in root.iter():
            if elem.tag.endswith('Documento'):
                return elem

        return None

    def _parse_documento(self, documento: ET.Element) -> Dict:
        """Parse Documento section."""
        encabezado = self._find_child(documento, 'Encabezado')

        if not encabezado:
            return {}

        return {
            'id_doc': self._parse_id_doc(encabezado),
            'emisor': self._parse_emisor(encabezado),
            'receptor': self._parse_receptor(encabezado),
            'totales': self._parse_totales(encabezado),
            'detalle': self._parse_detalle(documento),
            'descuentos_recargos': self._parse_dsctos_recargos(documento),
            'referencias': self._parse_referencias(documento),
            'observaciones': self._get_text(encabezado, 'Observaciones')
        }

    def _parse_id_doc(self, encabezado: ET.Element) -> Dict:
        """Parse IdDoc section."""
        id_doc = self._find_child(encabezado, 'IdDoc')

        if not id_doc:
            return {}

        return {
            'tipo_dte': self._get_text(id_doc, 'TipoDTE'),
            'folio': self._get_text(id_doc, 'Folio'),
            'fecha_emision': self._get_text(id_doc, 'FchEmis'),
            'forma_pago': self._get_text(id_doc, 'FmaPago'),
            'fecha_vencimiento': self._get_text(id_doc, 'FchVenc'),
            'tipo_traslado': self._get_text(id_doc, 'TipoTraslado'),
            'ind_traslado': self._get_text(id_doc, 'IndTraslado'),
            'tipo_impresion': self._get_text(id_doc, 'TipoImpresion'),
            'ind_servicio': self._get_text(id_doc, 'IndServicio'),
            'monto_bruto': self._get_text(id_doc, 'MntBruto'),
            'folio_ref': self._get_text(id_doc, 'FolioRef'),
            'periodo_desde': self._get_text(id_doc, 'PeriodoDesde'),
            'periodo_hasta': self._get_text(id_doc, 'PeriodoHasta'),
        }

    def _parse_emisor(self, encabezado: ET.Element) -> Dict:
        """Parse Emisor section."""
        emisor = self._find_child(encabezado, 'Emisor')

        if not emisor:
            return {}

        return {
            'rut': self._get_text(emisor, 'RUTEmisor'),
            'razon_social': self._get_text(emisor, 'RznSoc') or self._get_text(emisor, 'RznSocEmisor'),
            'giro': self._get_text(emisor, 'GiroEmis'),
            'actividad_economica': self._get_text(emisor, 'Acteco'),
            'direccion': self._get_text(emisor, 'DirOrigen'),
            'comuna': self._get_text(emisor, 'CmnaOrigen'),
            'ciudad': self._get_text(emisor, 'CiudadOrigen'),
            'telefono': self._get_text(emisor, 'Telefono'),
            'email': self._get_text(emisor, 'CorreoEmisor'),
            'codigo_sii': self._get_text(emisor, 'CdgSIISucur'),
        }

    def _parse_receptor(self, encabezado: ET.Element) -> Dict:
        """Parse Receptor section."""
        receptor = self._find_child(encabezado, 'Receptor')

        if not receptor:
            return {}

        return {
            'rut': self._get_text(receptor, 'RUTRecep'),
            'razon_social': self._get_text(receptor, 'RznSocRecep'),
            'giro': self._get_text(receptor, 'GiroRecep'),
            'contacto': self._get_text(receptor, 'Contacto'),
            'direccion': self._get_text(receptor, 'DirRecep'),
            'comuna': self._get_text(receptor, 'CmnaRecep'),
            'ciudad': self._get_text(receptor, 'CiudadRecep'),
            'email': self._get_text(receptor, 'CorreoRecep'),
        }

    def _parse_totales(self, encabezado: ET.Element) -> Dict:
        """Parse Totales section."""
        totales = self._find_child(encabezado, 'Totales')

        if not totales:
            return {}

        return {
            'monto_neto': float(self._get_text(totales, 'MntNeto') or 0),
            'monto_exento': float(self._get_text(totales, 'MntExe') or 0),
            'monto_base': float(self._get_text(totales, 'MntBase') or 0),
            'tasa_iva': float(self._get_text(totales, 'TasaIVA') or 0),
            'iva': float(self._get_text(totales, 'IVA') or 0),
            'iva_retenido': float(self._get_text(totales, 'IVARetenido') or 0),
            'iva_no_retenido': float(self._get_text(totales, 'IVANoRet') or 0),
            'credito_empresa_constructora': float(self._get_text(totales, 'CredEC') or 0),
            'garantia_deposito': float(self._get_text(totales, 'GrntDep') or 0),
            'comisiones': float(self._get_text(totales, 'Comisiones') or 0),
            'total': float(self._get_text(totales, 'MntTotal') or 0),
            'monto_no_facturable': float(self._get_text(totales, 'MontoNF') or 0),
            'monto_periodo': float(self._get_text(totales, 'MontoPeriodo') or 0),
            'saldo_anterior': float(self._get_text(totales, 'SaldoAnterior') or 0),
            'valor_pagar': float(self._get_text(totales, 'VlrPagar') or 0),
        }

    def _parse_detalle(self, documento: ET.Element) -> List[Dict]:
        """Parse Detalle (line items) section."""
        detalles = []

        for detalle in documento.findall('.//Detalle') or documento.findall('.//{*}Detalle'):
            item = {
                'numero_linea': int(self._get_text(detalle, 'NroLinDet') or 0),
                'indicador_exencion': self._get_text(detalle, 'IndExe'),
                'nombre': self._get_text(detalle, 'NmbItem'),
                'descripcion': self._get_text(detalle, 'DscItem'),
                'cantidad': float(self._get_text(detalle, 'QtyItem') or 0),
                'unidad_medida': self._get_text(detalle, 'UnmdItem'),
                'precio_unitario': float(self._get_text(detalle, 'PrcItem') or 0),
                'descuento_pct': float(self._get_text(detalle, 'DescuentoPct') or 0),
                'descuento_monto': float(self._get_text(detalle, 'DescuentoMonto') or 0),
                'recargo_pct': float(self._get_text(detalle, 'RecargoPct') or 0),
                'recargo_monto': float(self._get_text(detalle, 'RecargoMonto') or 0),
                'monto_item': float(self._get_text(detalle, 'MontoItem') or 0),
            }

            # Parse códigos (product codes)
            codigos = []
            for codigo in detalle.findall('.//CdgItem') or detalle.findall('.//{*}CdgItem'):
                codigos.append({
                    'tipo': self._get_text(codigo, 'TpoCodigo'),
                    'valor': self._get_text(codigo, 'VlrCodigo'),
                })
            item['codigos'] = codigos

            detalles.append(item)

        return detalles

    def _parse_dsctos_recargos(self, documento: ET.Element) -> List[Dict]:
        """Parse DscRcgGlobal (global discounts/charges) section."""
        dsctos_recargos = []

        for dr in documento.findall('.//DscRcgGlobal') or documento.findall('.//{*}DscRcgGlobal'):
            dsctos_recargos.append({
                'numero_linea': int(self._get_text(dr, 'NroLinDR') or 0),
                'tipo_movimiento': self._get_text(dr, 'TpoMov'),  # D=Descuento, R=Recargo
                'glosa': self._get_text(dr, 'GlosaDR'),
                'tipo_valor': self._get_text(dr, 'TpoValor'),  # %=Porcentaje, $=Monto
                'valor': float(self._get_text(dr, 'ValorDR') or 0),
                'indicador_exencion': self._get_text(dr, 'IndExeDR'),
            })

        return dsctos_recargos

    def _parse_referencias(self, documento: ET.Element) -> List[Dict]:
        """Parse Referencia (references to other documents) section."""
        referencias = []

        for ref in documento.findall('.//Referencia') or documento.findall('.//{*}Referencia'):
            referencias.append({
                'numero_linea': int(self._get_text(ref, 'NroLinRef') or 0),
                'tipo_documento': self._get_text(ref, 'TpoDocRef'),
                'indicador_global': self._get_text(ref, 'IndGlobal'),
                'folio_referencia': self._get_text(ref, 'FolioRef'),
                'rut_otro': self._get_text(ref, 'RUTOtr'),
                'fecha_referencia': self._get_text(ref, 'FchRef'),
                'codigo_referencia': self._get_text(ref, 'CodRef'),
                'razon_referencia': self._get_text(ref, 'RazonRef'),
            })

        return referencias

    def _parse_ted(self, documento: ET.Element) -> Dict:
        """Parse TED (Timbre Electrónico) section."""
        ted = self._find_child(documento, 'TED')

        if not ted:
            return {}

        # Find DD (Datos del Timbre)
        dd = self._find_child(ted, 'DD')

        if not dd:
            return {}

        return {
            'version': self._get_attribute(dd, 'version'),
            'rut_emisor': self._get_text(dd, 'RE'),
            'tipo_dte': self._get_text(dd, 'TD'),
            'folio': self._get_text(dd, 'F'),
            'fecha_emision': self._get_text(dd, 'FE'),
            'rut_receptor': self._get_text(dd, 'RR'),
            'razon_social_receptor': self._get_text(dd, 'RSR'),
            'monto_total': self._get_text(dd, 'MNT'),
            'item1': self._get_text(dd, 'IT1'),
            'caf': self._get_text(dd, 'CAF'),
            'timestamp_timbraje': self._get_text(dd, 'TSTED'),
            'firma': self._get_text(ted, 'FRMT'),  # Firma del timbre
        }

    def _parse_signature(self, root: ET.Element) -> Dict:
        """Parse digital signature information."""
        signature = root.find('.//ds:Signature', self.NAMESPACES)

        if signature is None:
            # Try without namespace
            for elem in root.iter():
                if elem.tag.endswith('Signature'):
                    signature = elem
                    break

        if signature is None:
            return {}

        signed_info = self._find_child(signature, 'SignedInfo')
        signature_value = self._find_child(signature, 'SignatureValue')
        key_info = self._find_child(signature, 'KeyInfo')

        return {
            'signature_value': signature_value.text if signature_value is not None else None,
            'signed_info': self._parse_signed_info(signed_info) if signed_info is not None else {},
            'key_info': self._parse_key_info(key_info) if key_info is not None else {},
        }

    def _parse_signed_info(self, signed_info: ET.Element) -> Dict:
        """Parse SignedInfo section."""
        return {
            'canonicalization_method': self._get_attribute(
                self._find_child(signed_info, 'CanonicalizationMethod'),
                'Algorithm'
            ),
            'signature_method': self._get_attribute(
                self._find_child(signed_info, 'SignatureMethod'),
                'Algorithm'
            ),
        }

    def _parse_key_info(self, key_info: ET.Element) -> Dict:
        """Parse KeyInfo section."""
        x509_data = self._find_child(key_info, 'X509Data')

        if not x509_data:
            return {}

        return {
            'x509_certificate': self._get_text(x509_data, 'X509Certificate'),
        }

    def _find_child(self, element: ET.Element, tag: str) -> Optional[ET.Element]:
        """Find child element by tag (namespace-agnostic)."""
        # Try with namespace
        for ns_prefix in ['sii:', 'ds:', '']:
            child = element.find(f'.//{ns_prefix}{tag}', self.NAMESPACES)
            if child is not None:
                return child

        # Try without namespace
        for child in element.iter():
            if child.tag.endswith(tag):
                return child

        return None

    def _get_text(self, element: ET.Element, tag: str) -> Optional[str]:
        """Get text from child element."""
        if element is None:
            return None

        child = self._find_child(element, tag)
        return child.text if child is not None else None

    def _get_attribute(self, element: ET.Element, attr: str) -> Optional[str]:
        """Get attribute from element."""
        if element is None:
            return None

        return element.get(attr)

    def to_dict(self) -> Dict:
        """Return parsed data as dict."""
        return self.parsed_data


def main():
    """Test DTE parser."""
    print("=" * 80)
    print("DTE PARSER TEST")
    print("=" * 80)
    print()

    # Sample DTE XML (minimal structure for testing)
    sample_xml = """<?xml version="1.0" encoding="ISO-8859-1"?>
    <DTE version="1.0">
        <Documento ID="DTE-33-12345">
            <Encabezado>
                <IdDoc>
                    <TipoDTE>33</TipoDTE>
                    <Folio>12345</Folio>
                    <FchEmis>2025-10-22</FchEmis>
                </IdDoc>
                <Emisor>
                    <RUTEmisor>76123456-7</RUTEmisor>
                    <RznSoc>EMPRESA EMISORA LTDA</RznSoc>
                </Emisor>
                <Receptor>
                    <RUTRecep>77654321-K</RUTRecep>
                    <RznSocRecep>EMPRESA RECEPTORA SA</RznSocRecep>
                </Receptor>
                <Totales>
                    <MntNeto>100000</MntNeto>
                    <IVA>19000</IVA>
                    <MntTotal>119000</MntTotal>
                </Totales>
            </Encabezado>
            <Detalle>
                <NroLinDet>1</NroLinDet>
                <NmbItem>Producto Test</NmbItem>
                <QtyItem>10</QtyItem>
                <PrcItem>10000</PrcItem>
                <MontoItem>100000</MontoItem>
            </Detalle>
        </Documento>
    </DTE>
    """

    # Parse
    parser = DTEParser()
    try:
        parsed = parser.parse(sample_xml)

        print("✅ Parse successful!\n")
        print(f"DTE Type: {parsed['dte_type']}")
        print(f"Folio: {parsed['folio']}")
        print(f"Fecha: {parsed['fecha_emision']}")
        print(f"\nEmisor: {parsed['emisor']['razon_social']} ({parsed['emisor']['rut']})")
        print(f"Receptor: {parsed['receptor']['razon_social']} ({parsed['receptor']['rut']})")
        print(f"\nMonto Neto: {parsed['totales']['monto_neto']}")
        print(f"IVA: {parsed['totales']['iva']}")
        print(f"Total: {parsed['totales']['total']}")
        print(f"\nItems: {len(parsed['items'])}")

        for item in parsed['items']:
            print(f"  - {item['nombre']}: {item['cantidad']} x {item['precio_unitario']} = {item['monto_item']}")

    except Exception as e:
        print(f"❌ Parse failed: {e}")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()
