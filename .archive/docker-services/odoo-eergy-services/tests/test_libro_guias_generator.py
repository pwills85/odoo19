# -*- coding: utf-8 -*-
"""
Tests para LibroGuiasGenerator

Valida generación de XML de Libro de Guías según formato SII.
"""

import pytest
from lxml import etree
from generators.libro_guias_generator import LibroGuiasGenerator


class TestLibroGuiasGenerator:
    """Test cases for Libro Guías XML generation"""

    # Namespace del SII
    NS = {'sii': 'http://www.sii.cl/SiiDte'}

    def test_generate_libro_guias_basic(self):
        """Test generación básica de libro de guías con datos mínimos"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'fecha_resolucion': '2023-05-15',
            'nro_resolucion': 80,
            'guias': [
                {
                    'folio': 1001,
                    'fecha': '2025-10-15',
                    'rut_destinatario': '96874030-K',
                    'razon_social': 'EMPRESA DE PRUEBA LTDA',
                    'monto_total': 1500000
                },
                {
                    'folio': 1002,
                    'fecha': '2025-10-16',
                    'rut_destinatario': '77123456-K',
                    'razon_social': 'OTRA EMPRESA SA',
                    'monto_total': 2300000
                }
            ]
        }

        xml_string = generator.generate(libro_data)

        # Validar que es XML válido
        assert xml_string.startswith('<?xml')
        assert 'LibroGuia' in xml_string

        # Parsear para validar estructura
        root = etree.fromstring(xml_string.encode('ISO-8859-1'))

        assert root.tag == '{http://www.sii.cl/SiiDte}LibroGuia'
        assert root.find('.//sii:Caratula', self.NS) is not None
        assert root.find('.//sii:ResumenPeriodo', self.NS) is not None

        # Validar carátula
        caratula = root.find('.//sii:Caratula', self.NS)
        assert caratula.find('sii:RutEmisorLibro', self.NS).text == '76086428-5'
        assert caratula.find('sii:PeriodoTributario', self.NS).text == '2025-10'
        assert caratula.find('sii:TipoLibro', self.NS).text == '3'  # 3 = Guías

        # Validar resumen
        resumen = root.find('.//sii:ResumenPeriodo', self.NS)
        assert resumen.find('sii:TpoDoc', self.NS).text == '52'  # DTE 52
        assert resumen.find('sii:TotDoc', self.NS).text == '2'  # 2 guías
        assert resumen.find('sii:FolioDesde', self.NS).text == '1001'
        assert resumen.find('sii:FolioHasta', self.NS).text == '1002'
        assert resumen.find('sii:TotMntTotal', self.NS).text == '3800000'  # 1500000 + 2300000

        # Validar detalles (2 guías)
        detalles = root.findall('.//sii:Detalle', self.NS)
        assert len(detalles) == 2

        detalle1 = detalles[0]
        assert detalle1.find('sii:TpoDoc', self.NS).text == '52'
        assert detalle1.find('sii:NroDoc', self.NS).text == '1001'
        assert detalle1.find('sii:RUTDoc', self.NS).text == '96874030-K'

        print("✅ Libro de Guías básico generado correctamente")

    def test_generate_libro_guias_sin_monto(self):
        """Test libro con guías de traslado (monto 0)"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'fecha_resolucion': '2023-05-15',
            'nro_resolucion': 80,
            'guias': [
                {
                    'folio': 2001,
                    'fecha': '2025-10-20',
                    'rut_destinatario': '96874030-K',
                    'razon_social': 'CLIENTE',
                    'monto_total': 0  # Traslado sin venta
                }
            ]
        }

        xml_string = generator.generate(libro_data)
        root = etree.fromstring(xml_string.encode('ISO-8859-1'))

        # Validar que acepta monto 0
        resumen = root.find('.//sii:ResumenPeriodo', self.NS)
        assert resumen.find('sii:TotMntTotal', self.NS).text == '0'

        detalle = root.find('.//sii:Detalle', self.NS)
        assert detalle.find('sii:MntTotal', self.NS).text == '0'

        print("✅ Libro de Guías con monto 0 (traslado) generado correctamente")

    def test_generate_libro_guias_tipo_envio_parcial(self):
        """Test libro rectificatorio (tipo envío PARCIAL)"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'fecha_resolucion': '2023-05-15',
            'nro_resolucion': 80,
            'tipo_envio': 'PARCIAL',
            'folio_notificacion': 123456,
            'guias': [
                {
                    'folio': 3001,
                    'fecha': '2025-10-25',
                    'rut_destinatario': '96874030-K',
                    'razon_social': 'CLIENTE',
                    'monto_total': 500000
                }
            ]
        }

        xml_string = generator.generate(libro_data)
        root = etree.fromstring(xml_string.encode('ISO-8859-1'))

        # Validar tipo envío PARCIAL
        caratula = root.find('.//sii:Caratula', self.NS)
        assert caratula.find('sii:TipoEnvio', self.NS).text == 'PARCIAL'
        assert caratula.find('sii:FolioNotificacion', self.NS).text == '123456'

        print("✅ Libro de Guías PARCIAL (rectificatorio) generado correctamente")

    def test_validation_missing_required_fields(self):
        """Test validación de campos requeridos faltantes"""
        generator = LibroGuiasGenerator()

        # Datos incompletos (sin rut_emisor)
        libro_data = {
            'periodo': '2025-10',
            'fecha_resolucion': '2023-05-15',
            'nro_resolucion': 80,
            'guias': []
        }

        with pytest.raises(ValueError, match="Campo requerido faltante"):
            generator.generate(libro_data)

        print("✅ Validación de campos requeridos OK")

    def test_validation_empty_guias(self):
        """Test validación de libro sin guías"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'fecha_resolucion': '2023-05-15',
            'nro_resolucion': 80,
            'guias': []  # Sin guías
        }

        with pytest.raises(ValueError, match="al menos una guía"):
            generator.generate(libro_data)

        print("✅ Validación de libro sin guías OK")

    def test_format_rut(self):
        """Test formateo de RUT (sin puntos)"""
        generator = LibroGuiasGenerator()

        assert generator._format_rut('76.086.428-5') == '76086428-5'
        assert generator._format_rut('76086428-5') == '76086428-5'
        assert generator._format_rut('96.874.030-k') == '96874030-K'

        print("✅ Formateo de RUT OK")

    def test_razon_social_truncation(self):
        """Test truncamiento de razón social a 50 caracteres"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'fecha_resolucion': '2023-05-15',
            'nro_resolucion': 80,
            'guias': [
                {
                    'folio': 4001,
                    'fecha': '2025-10-30',
                    'rut_destinatario': '96874030-K',
                    'razon_social': 'A' * 100,  # 100 caracteres
                    'monto_total': 100000
                }
            ]
        }

        xml_string = generator.generate(libro_data)
        root = etree.fromstring(xml_string.encode('ISO-8859-1'))

        detalle = root.find('.//sii:Detalle', self.NS)
        razon_social = detalle.find('sii:RznSoc', self.NS).text

        # Debe truncarse a 50 caracteres
        assert len(razon_social) == 50

        print("✅ Truncamiento de razón social OK")

    def test_xml_encoding_iso_8859_1(self):
        """Test que XML se genera con encoding ISO-8859-1"""
        generator = LibroGuiasGenerator()

        libro_data = {
            'rut_emisor': '76086428-5',
            'periodo': '2025-10',
            'fecha_resolucion': '2023-05-15',
            'nro_resolucion': 80,
            'guias': [
                {
                    'folio': 5001,
                    'fecha': '2025-10-31',
                    'rut_destinatario': '96874030-K',
                    'razon_social': 'EMPRESA CON ÑANDÚ',  # Caracteres especiales
                    'monto_total': 200000
                }
            ]
        }

        xml_string = generator.generate(libro_data)

        # Validar encoding en declaración XML (puede ser con comillas simples o dobles)
        assert ("encoding='ISO-8859-1'" in xml_string or 'encoding="ISO-8859-1"' in xml_string)

        # Validar que se puede parsear con ISO-8859-1
        root = etree.fromstring(xml_string.encode('ISO-8859-1'))
        assert root is not None

        print("✅ Encoding ISO-8859-1 OK")


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v', '--tb=short'])
