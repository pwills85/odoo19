#!/usr/bin/env python3
"""
Script de validación de dependencias para SII Monitoring
Verifica que todas las librerías nuevas estén instaladas correctamente
"""

import sys

def test_imports():
    """Prueba importar todas las librerías nuevas"""
    
    tests = []
    
    # BeautifulSoup4
    try:
        from bs4 import BeautifulSoup
        tests.append(("beautifulsoup4", "✅ OK"))
    except ImportError as e:
        tests.append(("beautifulsoup4", f"❌ ERROR: {e}"))
    
    # html5lib
    try:
        import html5lib
        tests.append(("html5lib", "✅ OK"))
    except ImportError as e:
        tests.append(("html5lib", f"❌ ERROR: {e}"))
    
    # slack-sdk
    try:
        from slack_sdk import WebClient
        tests.append(("slack-sdk", "✅ OK"))
    except ImportError as e:
        tests.append(("slack-sdk", f"❌ ERROR: {e}"))
    
    # slowapi
    try:
        from slowapi import Limiter
        tests.append(("slowapi", "✅ OK"))
    except ImportError as e:
        tests.append(("slowapi", f"❌ ERROR: {e}"))
    
    # validators
    try:
        import validators
        tests.append(("validators", "✅ OK"))
    except ImportError as e:
        tests.append(("validators", f"❌ ERROR: {e}"))
    
    # Librerías ya existentes (verificar que no se rompieron)
    try:
        import anthropic
        tests.append(("anthropic [existing]", "✅ OK"))
    except ImportError as e:
        tests.append(("anthropic [existing]", f"❌ ERROR: {e}"))
    
    try:
        import requests
        tests.append(("requests [existing]", "✅ OK"))
    except ImportError as e:
        tests.append(("requests [existing]", f"❌ ERROR: {e}"))
    
    try:
        from lxml import etree
        tests.append(("lxml [existing]", "✅ OK"))
    except ImportError as e:
        tests.append(("lxml [existing]", f"❌ ERROR: {e}"))
    
    return tests


def test_functionality():
    """Prueba funcionalidad básica de las librerías"""
    
    tests = []
    
    # BeautifulSoup - Parse simple HTML
    try:
        from bs4 import BeautifulSoup
        html = "<html><body><h1>Test</h1></body></html>"
        soup = BeautifulSoup(html, 'html.parser')
        assert soup.h1.text == "Test"
        tests.append(("BeautifulSoup parsing", "✅ OK"))
    except Exception as e:
        tests.append(("BeautifulSoup parsing", f"❌ ERROR: {e}"))
    
    # validators - Validar URL
    try:
        import validators
        assert validators.url("https://www.sii.cl")
        assert not validators.url("not-a-url")
        tests.append(("validators URL", "✅ OK"))
    except Exception as e:
        tests.append(("validators URL", f"❌ ERROR: {e}"))
    
    # requests - HTTP simple
    try:
        import requests
        # Mock request (no hacemos call real)
        tests.append(("requests import", "✅ OK"))
    except Exception as e:
        tests.append(("requests import", f"❌ ERROR: {e}"))
    
    return tests


def main():
    """Ejecuta todas las validaciones"""
    
    print("=" * 60)
    print("🔍 VALIDACIÓN DE DEPENDENCIAS - SII MONITORING")
    print("=" * 60)
    print()
    
    # Test imports
    print("📦 Verificando imports...")
    import_tests = test_imports()
    for lib, status in import_tests:
        print(f"  {lib:30} {status}")
    print()
    
    # Test functionality
    print("🧪 Verificando funcionalidad...")
    func_tests = test_functionality()
    for test, status in func_tests:
        print(f"  {test:30} {status}")
    print()
    
    # Summary
    all_tests = import_tests + func_tests
    total = len(all_tests)
    passed = sum(1 for _, status in all_tests if "✅" in status)
    failed = total - passed
    
    print("=" * 60)
    print(f"📊 RESUMEN: {passed}/{total} tests pasaron")
    
    if failed > 0:
        print(f"❌ {failed} tests fallaron")
        sys.exit(1)
    else:
        print("✅ Todas las dependencias instaladas correctamente")
        sys.exit(0)


if __name__ == "__main__":
    main()
