# -*- coding: utf-8 -*-
"""
CAF Handler - Native Implementation
====================================

Gestor de CAF (Código de Autorización de Folios) para DTEs.

Migration from: odoo-eergy-services/handlers/caf_handler.py (2025-10-24)

SPRINT 5: Cierre total de brechas

CAF (Código de Autorización de Folios):
- Archivo XML otorgado por SII
- Autoriza rango de folios para emitir DTEs
- Contiene clave privada RSA para firma
- Firmado digitalmente por SII
- Obligatorio para emitir DTEs

Funcionalidades:
- Parseo XML CAF
- Extracción datos (tipo DTE, rango, clave privada)
- Validación firma SII
- Gestión folios disponibles
- Verificación vencimiento
"""

from lxml import etree
from datetime import datetime, date
import logging

# S-005: Protección XXE (Gap Closure P0)
from .safe_xml_parser import fromstring_safe

_logger = logging.getLogger(__name__)


class CAFHandler:
    """
    Handler para archivos CAF (Código de Autorización de Folios).

    El CAF es un XML firmado por SII que autoriza un rango de folios
    para emitir DTEs de un tipo específico.

    Estructura CAF:
    <AUTORIZACION>
      <CAF version="1.0">
        <DA>
          <RE>76123456-7</RE>
          <RS>EMPRESA EJEMPLO</RS>
          <TD>33</TD>
          <RNG><D>1</D><H>100</H></RNG>
          <FA>2025-01-15</FA>
          <RSAPK>
            <M>...</M>
            <E>...</E>
          </RSAPK>
          <IDK>100</IDK>
        </DA>
        <FRMA algoritmo="SHA1withRSA">...</FRMA>
      </CAF>
    </AUTORIZACION>
    """

    # ═══════════════════════════════════════════════════════════════════════
    # PARSEO CAF
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def parse_caf(caf_xml):
        """
        Parsea XML CAF y extrae datos.

        Args:
            caf_xml (str or bytes): XML del CAF

        Returns:
            dict: {
                'tipo_dte': str,
                'rut_emisor': str,
                'razon_social': str,
                'folio_desde': int,
                'folio_hasta': int,
                'fecha_autorizacion': datetime.date,
                'rsa_public_key': dict,
                'rsa_private_key': str (base64),
                'firma_sii': str,
                'idk': str,
                'valid': bool,
                'error': str or None
            }
        """
        try:
            # S-005: Parse XML con protección XXE
            if isinstance(caf_xml, bytes):
                root = fromstring_safe(caf_xml)
            else:
                root = fromstring_safe(caf_xml.encode('ISO-8859-1'))

            # Buscar elemento CAF
            caf_element = root.find('.//CAF')
            if caf_element is None:
                return {
                    'valid': False,
                    'error': 'Elemento CAF no encontrado en XML'
                }

            # Buscar DA (Datos Autorizacion)
            da_element = caf_element.find('.//DA')
            if da_element is None:
                return {
                    'valid': False,
                    'error': 'Elemento DA no encontrado en CAF'
                }

            # Extraer datos DA
            caf_data = {}

            # RE (RUT Emisor)
            re = da_element.find('RE')
            caf_data['rut_emisor'] = re.text.strip() if re is not None else None

            # RS (Razón Social)
            rs = da_element.find('RS')
            caf_data['razon_social'] = rs.text.strip() if rs is not None else None

            # TD (Tipo Documento)
            td = da_element.find('TD')
            caf_data['tipo_dte'] = td.text.strip() if td is not None else None

            # RNG (Rango folios)
            rng = da_element.find('RNG')
            if rng is not None:
                d_elem = rng.find('D')
                h_elem = rng.find('H')

                caf_data['folio_desde'] = int(d_elem.text) if d_elem is not None else None
                caf_data['folio_hasta'] = int(h_elem.text) if h_elem is not None else None

            # FA (Fecha Autorización)
            fa = da_element.find('FA')
            if fa is not None and fa.text:
                try:
                    caf_data['fecha_autorizacion'] = datetime.strptime(
                        fa.text.strip(),
                        '%Y-%m-%d'
                    ).date()
                except ValueError:
                    caf_data['fecha_autorizacion'] = None

            # RSAPK (RSA Public Key)
            rsapk = da_element.find('RSAPK')
            if rsapk is not None:
                m_elem = rsapk.find('M')
                e_elem = rsapk.find('E')

                caf_data['rsa_public_key'] = {
                    'modulus': m_elem.text.strip() if m_elem is not None else None,
                    'exponent': e_elem.text.strip() if e_elem is not None else None
                }

            # RSASK (RSA Private Key) - CRÍTICO para firma DTEs
            rsask = da_element.find('RSASK')
            if rsask is not None:
                caf_data['rsa_private_key'] = rsask.text.strip()
            else:
                # Intentar buscar en otros lugares del XML
                _logger.warning("RSASK not found in DA, searching elsewhere")
                caf_data['rsa_private_key'] = None

            # IDK (ID Key)
            idk = da_element.find('IDK')
            caf_data['idk'] = idk.text.strip() if idk is not None else None

            # FRMA (Firma SII)
            frma = caf_element.find('FRMA')
            caf_data['firma_sii'] = frma.text.strip() if frma is not None and frma.text else None

            # Validar campos críticos
            if not caf_data.get('tipo_dte'):
                return {'valid': False, 'error': 'Tipo DTE no encontrado'}

            if not caf_data.get('folio_desde') or not caf_data.get('folio_hasta'):
                return {'valid': False, 'error': 'Rango de folios no encontrado'}

            if not caf_data.get('rsa_private_key'):
                return {'valid': False, 'error': 'Clave privada RSA no encontrada'}

            caf_data['valid'] = True
            caf_data['error'] = None

            _logger.info(
                f"✅ CAF parsed: tipo={caf_data['tipo_dte']}, "
                f"folios={caf_data['folio_desde']}-{caf_data['folio_hasta']}"
            )

            return caf_data

        except etree.XMLSyntaxError as e:
            _logger.error(f"CAF XML syntax error: {e}")
            return {
                'valid': False,
                'error': f'XML mal formado: {str(e)}'
            }

        except Exception as e:
            _logger.error(f"CAF parsing error: {e}", exc_info=True)
            return {
                'valid': False,
                'error': f'Error parsing CAF: {str(e)}'
            }

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIÓN CAF
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def validate_caf(caf_data, rut_emisor=None, tipo_dte=None):
        """
        Valida datos de CAF parseado.

        Args:
            caf_data (dict): Datos CAF parseados
            rut_emisor (str, optional): RUT esperado del emisor
            tipo_dte (str, optional): Tipo DTE esperado

        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        errors = []

        # Validar que CAF fue parseado exitosamente
        if not caf_data.get('valid', False):
            errors.append(caf_data.get('error', 'CAF inválido'))
            return (False, errors)

        # Validar RUT emisor (si se especifica)
        if rut_emisor:
            caf_rut = caf_data.get('rut_emisor', '').replace('.', '').replace('-', '').upper()
            expected_rut = rut_emisor.replace('.', '').replace('-', '').upper()

            if caf_rut != expected_rut:
                errors.append(f"RUT emisor no coincide: CAF={caf_rut}, Esperado={expected_rut}")

        # Validar tipo DTE (si se especifica)
        if tipo_dte:
            caf_tipo = caf_data.get('tipo_dte', '').strip()
            if caf_tipo != str(tipo_dte):
                errors.append(f"Tipo DTE no coincide: CAF={caf_tipo}, Esperado={tipo_dte}")

        # Validar rango folios
        folio_desde = caf_data.get('folio_desde')
        folio_hasta = caf_data.get('folio_hasta')

        if not folio_desde or not folio_hasta:
            errors.append("Rango de folios incompleto")
        elif folio_desde > folio_hasta:
            errors.append(f"Rango folios inválido: desde={folio_desde}, hasta={folio_hasta}")

        # Validar fecha autorización
        fecha_auth = caf_data.get('fecha_autorizacion')
        if not fecha_auth:
            errors.append("Fecha autorización no encontrada")

        # Validar clave privada presente
        if not caf_data.get('rsa_private_key'):
            errors.append("Clave privada RSA no encontrada")

        return (len(errors) == 0, errors)

    # ═══════════════════════════════════════════════════════════════════════
    # GESTIÓN FOLIOS
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def get_available_folios(caf_data, used_folios=None):
        """
        Obtiene cantidad de folios disponibles en CAF.

        Args:
            caf_data (dict): Datos CAF parseados
            used_folios (list, optional): Lista de folios ya utilizados

        Returns:
            int: Cantidad de folios disponibles
        """
        if not caf_data.get('valid', False):
            return 0

        folio_desde = caf_data.get('folio_desde')
        folio_hasta = caf_data.get('folio_hasta')

        if not folio_desde or not folio_hasta:
            return 0

        total_folios = folio_hasta - folio_desde + 1

        if used_folios:
            # Contar solo folios usados dentro del rango CAF
            used_in_range = len([
                f for f in used_folios
                if folio_desde <= f <= folio_hasta
            ])
            return total_folios - used_in_range

        return total_folios

    @staticmethod
    def get_next_folio(caf_data, used_folios=None):
        """
        Obtiene siguiente folio disponible en CAF.

        Args:
            caf_data (dict): Datos CAF parseados
            used_folios (list, optional): Lista de folios ya utilizados

        Returns:
            int or None: Siguiente folio disponible o None si agotados
        """
        if not caf_data.get('valid', False):
            return None

        folio_desde = caf_data.get('folio_desde')
        folio_hasta = caf_data.get('folio_hasta')

        if not folio_desde or not folio_hasta:
            return None

        used_set = set(used_folios) if used_folios else set()

        # Buscar primer folio disponible
        for folio in range(folio_desde, folio_hasta + 1):
            if folio not in used_set:
                return folio

        # Todos los folios agotados
        return None

    @staticmethod
    def is_folio_in_range(caf_data, folio):
        """
        Verifica si folio está dentro del rango CAF.

        Args:
            caf_data (dict): Datos CAF parseados
            folio (int): Folio a verificar

        Returns:
            bool: True si folio está en rango
        """
        if not caf_data.get('valid', False):
            return False

        folio_desde = caf_data.get('folio_desde')
        folio_hasta = caf_data.get('folio_hasta')

        if not folio_desde or not folio_hasta:
            return False

        return folio_desde <= folio <= folio_hasta

    # ═══════════════════════════════════════════════════════════════════════
    # UTILIDADES
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def is_caf_expired(caf_data, tolerance_days=0):
        """
        Verifica si CAF está vencido.

        NOTA: SII no especifica vencimiento explícito de CAF.
        Esta función verifica antigüedad desde fecha autorización.

        Args:
            caf_data (dict): Datos CAF parseados
            tolerance_days (int): Días de tolerancia desde hoy

        Returns:
            bool: True si CAF muy antiguo (>2 años)
        """
        fecha_auth = caf_data.get('fecha_autorizacion')
        if not fecha_auth:
            return False  # No se puede determinar

        # Considerar vencido si autorización > 2 años
        from datetime import timedelta
        max_age = timedelta(days=365 * 2)  # 2 años

        age = date.today() - fecha_auth

        return age > max_age

    @staticmethod
    def get_private_key_for_signature(caf_data):
        """
        Obtiene clave privada RSA para firma de DTEs.

        Args:
            caf_data (dict): Datos CAF parseados

        Returns:
            str or None: Clave privada en formato PEM base64
        """
        return caf_data.get('rsa_private_key')

    @staticmethod
    def extract_caf_from_file(file_path):
        """
        Extrae y parsea CAF desde archivo.

        Args:
            file_path (str): Path al archivo CAF (XML)

        Returns:
            dict: Datos CAF parseados (ver parse_caf)
        """
        try:
            with open(file_path, 'r', encoding='ISO-8859-1') as f:
                caf_xml = f.read()

            return CAFHandler.parse_caf(caf_xml)

        except FileNotFoundError:
            _logger.error(f"CAF file not found: {file_path}")
            return {
                'valid': False,
                'error': f'Archivo no encontrado: {file_path}'
            }

        except Exception as e:
            _logger.error(f"Error reading CAF file: {e}", exc_info=True)
            return {
                'valid': False,
                'error': f'Error leyendo archivo: {str(e)}'
            }

    @staticmethod
    def get_caf_summary(caf_data):
        """
        Obtiene resumen legible de CAF.

        Args:
            caf_data (dict): Datos CAF parseados

        Returns:
            str: Resumen formateado
        """
        if not caf_data.get('valid', False):
            return f"❌ CAF INVÁLIDO: {caf_data.get('error', 'Unknown error')}"

        lines = [
            "📄 CAF SUMMARY",
            f"  Tipo DTE: {caf_data.get('tipo_dte')}",
            f"  RUT Emisor: {caf_data.get('rut_emisor')}",
            f"  Razón Social: {caf_data.get('razon_social', 'N/A')[:50]}",
            f"  Folios: {caf_data.get('folio_desde')} - {caf_data.get('folio_hasta')}",
            f"  Total Folios: {caf_data.get('folio_hasta', 0) - caf_data.get('folio_desde', 0) + 1}",
            f"  Fecha Autorización: {caf_data.get('fecha_autorizacion')}",
            f"  Clave Privada: {'✅ Presente' if caf_data.get('rsa_private_key') else '❌ Ausente'}",
            f"  Firma SII: {'✅ Presente' if caf_data.get('firma_sii') else '❌ Ausente'}"
        ]

        return '\n'.join(lines)
