# SET DE PRUEBAS SII - Plan de Implementación

**Fecha:** 2025-10-22
**Objetivo:** Implementar suite de tests comprehensiva para certificación SII
**Estimación Original:** 3-4 días
**Enfoque:** Tests basados en documentación oficial SII

---

## Contexto

El SET DE PRUEBAS oficial del SII consiste en 70 casos de prueba que validan:
- DTEs válidos (casos happy path)
- DTEs inválidos (validaciones)
- Edge cases y escenarios especiales
- Todos los tipos de documentos (33, 34, 52, 56, 61, 71)

**Problema:** El SET oficial requiere descarga manual desde Maullin (certificado digital SII)

**Solución:** Crear suite comprehensiva basada en:
1. Documentación técnica SII
2. Esquemas XSD oficiales
3. Ejemplos reales de producción
4. Casos de error documentados

---

## Estrategia de Implementación

### Fase 1: Tests de Validación Estructural (Día 1)

**Objetivo:** Validar que nuestros generators producen XML correcto

**Categorías:**
1. **Estructura XML básica** (10 tests)
   - Namespace correcto
   - Encoding ISO-8859-1
   - Elementos requeridos presentes
   - Orden de elementos correcto

2. **Validación XSD** (10 tests)
   - DTE.xsd validation
   - EnvioDTE.xsd validation
   - Libro.xsd validation
   - Consumo.xsd validation

3. **TED (Timbre Electrónico)** (10 tests)
   - Formato DD correcto
   - Hash SHA-1 válido
   - Firma RSA válida
   - QR code generation

### Fase 2: Tests de Lógica de Negocio (Día 2)

**Objetivo:** Validar cálculos y reglas tributarias

**Categorías:**
4. **Cálculos Tributarios** (15 tests)
   - IVA 19% correcto
   - Monto neto vs bruto
   - Descuentos y recargos
   - Totales coinciden
   - Redondeo correcto

5. **Validaciones de Campos** (10 tests)
   - RUT válido (módulo 11)
   - Fechas válidas
   - Folios en rango CAF
   - Montos > 0
   - Caracteres especiales

### Fase 3: Tests por Tipo de Documento (Día 3)

**Objetivo:** Validar cada DTE type específicamente

**Categorías:**
6. **Tests DTE 33, 34, 52, 56, 61** (10 tests c/u = 50 tests)
   - Caso válido básico
   - Con múltiples líneas
   - Con descuentos
   - Con referencias (56, 61)
   - Edge cases específicos

7. **DTE 71 (BHE)** (5 tests)
   - Con retención 10%
   - Sin retención (warning)
   - Validación campos específicos

### Fase 4: Tests de Integración (Día 3-4)

**Objetivo:** Validar flujo completo end-to-end

8. **Tests de SOAP** (10 tests)
   - Envío exitoso
   - Errores SII (59 códigos)
   - Timeout handling
   - Retry logic

9. **Tests de Libro** (5 tests)
   - Libro Compra/Venta
   - Libro Guías
   - IECV

---

## Implementación Técnica

### Estructura de Directorios

```
dte-service/tests/
├── sii_certification/           # ← NUEVO
│   ├── __init__.py
│   ├── conftest.py             # Fixtures compartidas
│   ├── test_01_estructura_xml.py
│   ├── test_02_validacion_xsd.py
│   ├── test_03_ted.py
│   ├── test_04_calculos_tributarios.py
│   ├── test_05_validaciones_campos.py
│   ├── test_06_dte_33.py
│   ├── test_07_dte_34.py
│   ├── test_08_dte_52.py
│   ├── test_09_dte_56.py
│   ├── test_10_dte_61.py
│   ├── test_11_dte_71.py
│   ├── test_12_soap_integration.py
│   └── test_13_libros.py
└── README_CERTIFICATION.md
```

###fixtures Reutilizables

```python
# conftest.py
import pytest

@pytest.fixture
def valid_empresa_data():
    """Datos válidos de empresa emisora"""
    return {
        'rut': '76086428-5',
        'razon_social': 'MI EMPRESA DE INGENIERIA LTDA',
        'giro': 'Ingeniería y desarrollo',
        'direccion': 'Av Principal 123',
        'comuna': 'Santiago',
        'ciudad': 'Santiago',
    }

@pytest.fixture
def valid_receptor_data():
    """Datos válidos de receptor"""
    return {
        'rut': '96874030-K',
        'razon_social': 'CLIENTE EJEMPLO SA',
        'giro': 'Comercio',
        'direccion': 'Calle Test 456',
        'comuna': 'Providencia',
        'ciudad': 'Santiago',
    }

@pytest.fixture
def valid_dte_33_data(valid_empresa_data, valid_receptor_data):
    """DTE 33 completo y válido"""
    return {
        'dte_type': '33',
        'folio': 12345,
        'fecha_emision': '2025-10-22',
        'emisor': valid_empresa_data,
        'receptor': valid_receptor_data,
        'totales': {
            'monto_neto': 1000000,
            'monto_iva': 190000,
            'monto_total': 1190000,
        },
        'items': [
            {
                'numero_linea': 1,
                'nombre': 'Servicio de Ingeniería',
                'cantidad': 10,
                'precio_unitario': 100000,
                'monto_total': 1000000,
            }
        ]
    }
```

### Ejemplo de Test Comprehensivo

```python
# test_01_estructura_xml.py
import pytest
from lxml import etree
from generators.dte_generator_33 import DTEGenerator33

class TestEstructuraXML:
    """
    Tests de estructura XML según normativa SII.
    Valida elementos requeridos, namespace, encoding.
    """

    def test_namespace_sii_correcto(self, valid_dte_33_data):
        """XML debe tener namespace http://www.sii.cl/SiiDte"""
        generator = DTEGenerator33()
        xml_string = generator.generate(valid_dte_33_data)

        root = etree.fromstring(xml_string.encode('ISO-8859-1'))

        expected_ns = 'http://www.sii.cl/SiiDte'
        assert expected_ns in root.nsmap.values()

    def test_encoding_iso_8859_1(self, valid_dte_33_data):
        """XML debe declarar encoding ISO-8859-1"""
        generator = DTEGenerator33()
        xml_string = generator.generate(valid_dte_33_data)

        assert 'ISO-8859-1' in xml_string

        # Debe poder parsearse con ISO-8859-1
        root = etree.fromstring(xml_string.encode('ISO-8859-1'))
        assert root is not None

    def test_elementos_requeridos_dte(self, valid_dte_33_data):
        """DTE debe tener todos los elementos obligatorios"""
        generator = DTEGenerator33()
        xml_string = generator.generate(valid_dte_33_data)
        root = etree.fromstring(xml_string.encode('ISO-8859-1'))

        # Elementos obligatorios según SII
        required = [
            './/Encabezado',
            './/IdDoc',
            './/Emisor',
            './/Receptor',
            './/Totales',
            './/Detalle',
        ]

        for xpath in required:
            elem = root.find(xpath, root.nsmap)
            assert elem is not None, f"Elemento requerido faltante: {xpath}"
```

---

## Casos de Test Prioritarios

### Top 20 Tests Críticos (Mínimo para certificación)

1. ✅ **DTE 33 válido** - Caso básico happy path
2. ✅ **DTE con múltiples líneas** - 10+ items
3. ✅ **Cálculo IVA correcto** - 19% exacto
4. ✅ **RUT válido (módulo 11)** - Validación algorítmica
5. ✅ **Validación XSD** - Schema compliance
6. ✅ **TED generation** - Hash + firma válidos
7. ✅ **Encoding ISO-8859-1** - Caracteres especiales
8. ✅ **Folios en rango CAF** - Folio dentro de autorización
9. ✅ **Nota de Crédito (61)** - Con referencia a factura
10. ✅ **Nota de Débito (56)** - Con referencia a factura
11. ✅ **Guía de Despacho (52)** - Monto 0 permitido
12. ✅ **Liquidación Honorarios (34)** - Retención obligatoria
13. ✅ **BHE (71)** - Retención 10%
14. ✅ **Libro Compra/Venta** - Resumen mensual
15. ✅ **Libro Guías** - TipoLibro=3
16. ✅ **Error SII - RUT inválido** - Debe fallar validation
17. ✅ **Error SII - Folio fuera de rango** - Debe fallar validation
18. ✅ **SOAP timeout** - Retry logic funciona
19. ✅ **SOAP error 59 códigos** - Interpretación correcta
20. ✅ **Firma digital válida** - XMLDsig verification

---

## Métricas de Éxito

| Métrica | Target | Método |
|---------|--------|--------|
| **Tests totales** | 100+ | pytest count |
| **Coverage** | ≥ 80% | pytest-cov |
| **Tiempo ejecución** | < 5 min | pytest duration |
| **Tests passing** | 100% | pytest result |
| **XSD validations** | 100% | lxml validation |
| **TED válidos** | 100% | Hash verification |
| **Cálculos correctos** | 100% | Assert equality |

---

## Comandos de Ejecución

```bash
# Ejecutar todos los tests de certificación
docker-compose exec dte-service pytest tests/sii_certification/ -v

# Con coverage
docker-compose exec dte-service pytest tests/sii_certification/ \
  --cov=generators \
  --cov=validators \
  --cov=signers \
  --cov-report=html \
  --cov-report=term

# Solo tests críticos (fast)
docker-compose exec dte-service pytest tests/sii_certification/ -v -m "critical"

# Generar reporte HTML
docker-compose exec dte-service pytest tests/sii_certification/ \
  --html=report.html \
  --self-contained-html
```

---

## Entregables

1. ✅ **Suite de 100+ tests** organizados por categoría
2. ✅ **Fixtures reutilizables** para todos los DTEs
3. ✅ **Documentación** de cada test case
4. ✅ **Reporte de cobertura** ≥ 80%
5. ✅ **Reporte HTML** con resultados detallados
6. ✅ **README_CERTIFICATION.md** con instrucciones

---

## Notas Importantes

### Diferencia con SET oficial

**SET oficial SII:**
- 70 casos específicos pre-definidos
- Requiere descarga manual con certificado
- Enfoque: Certificación formal en Maullin

**Nuestra suite (100+ tests):**
- Más comprehensiva que SET oficial
- Automatizada y repetible
- Enfoque: Validación continua + certificación
- Ejecutable sin acceso a Maullin

### Ventajas de este enfoque

1. **Ejecución inmediata** - No requiere SET oficial
2. **CI/CD ready** - Automatizable
3. **Más comprehensivo** - 100+ casos vs 70
4. **Documentado** - Cada test explica qué valida
5. **Mantenible** - Fácil agregar nuevos casos

### Cuando tener SET oficial

Cuando tengamos acceso al SET oficial SII:
1. Descargar los 70 casos
2. Agregar como `test_14_set_oficial.py`
3. Validar que pasamos 70/70
4. Complementar con nuestros 100+ tests

---

## Cronograma Detallado

### Día 1 (8 horas)
- **H1-2:** Setup estructura + fixtures (2h)
- **H3-4:** Tests estructura XML (2h)
- **H5-6:** Tests validación XSD (2h)
- **H7-8:** Tests TED (2h)

### Día 2 (8 horas)
- **H1-4:** Tests cálculos tributarios (4h)
- **H5-8:** Tests validaciones campos (4h)

### Día 3 (8 horas)
- **H1-2:** Tests DTE 33, 34 (2h)
- **H3-4:** Tests DTE 52, 56 (2h)
- **H5-6:** Tests DTE 61, 71 (2h)
- **H7-8:** Tests SOAP integration (2h)

### Día 4 (4 horas)
- **H1-2:** Tests libros (2h)
- **H3-4:** Documentación + reporte (2h)

**Total:** 28 horas (3.5 días)

---

## Próximo Paso Inmediato

Crear estructura base:

```bash
cd /Users/pedro/Documents/odoo19/dte-service/tests
mkdir sii_certification
cd sii_certification
touch __init__.py conftest.py README_CERTIFICATION.md

# Crear archivos de test
for i in {01..13}; do
  touch test_${i}_placeholder.py
done
```

Luego implementar fixture básicas en `conftest.py` y comenzar con `test_01_estructura_xml.py`.

---

**Documento generado:** 2025-10-22 21:30 UTC
**Siguiendo plan:** IMPLEMENTATION_ROADMAP_GAPS.md - FASE 2
**Status:** ✅ PLAN LISTO PARA EJECUCIÓN
