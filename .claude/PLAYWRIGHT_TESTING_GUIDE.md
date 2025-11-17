# Playwright MCP Server - Guía de Testing E2E para Odoo19

**Fecha configuración:** 2025-11-17  
**Estado:** ✅ Activo en `.claude/mcp.json`

---

## 🎯 Propósito

Servidor MCP de Playwright agregado para automatizar testing E2E de:
- **Módulo DTE** (l10n_cl_dte): Validación de facturas electrónicas chilenas
- **Módulo Nómina** (l10n_cl_hr_payroll): Verificación de cálculos y vistas
- **Vistas XML**: Validación de UI/UX de localization chilena

---

## 📋 Herramientas Disponibles (21 total)

### Navegación y Control
- `browser_navigate` - Navegar a URL (ej: http://localhost:8169)
- `browser_navigate_back` - Volver atrás
- `browser_close` - Cerrar navegador
- `browser_tabs` - Gestionar pestañas

### Interacción con Elementos
- `browser_click` - Click en elementos
- `browser_type` - Escribir texto
- `browser_fill_form` - Llenar formularios completos
- `browser_select_option` - Seleccionar opciones de dropdown
- `browser_hover` - Hover sobre elementos
- `browser_drag` - Arrastrar elementos
- `browser_press_key` - Presionar teclas
- `browser_handle_dialog` - Manejar diálogos (alert, confirm)

### Inspección y Debugging
- `browser_snapshot` - Capturar snapshot del DOM
- `browser_take_screenshot` - Tomar screenshot
- `browser_console_messages` - Obtener mensajes de consola
- `browser_network_requests` - Listar peticiones de red
- `browser_evaluate` - Ejecutar JavaScript en página

### Utilidades
- `browser_file_upload` - Subir archivos
- `browser_resize` - Redimensionar ventana
- `browser_wait_for` - Esperar condiciones
- `browser_install` - Instalar navegador si es necesario

---

## 🔥 Casos de Uso Prioritarios

### 1. Testing DTE Tipo 33 (Factura Electrónica)

**Escenario:** Validar flujo completo de creación de factura DTE

```bash
# Herramientas a usar:
1. browser_navigate → http://localhost:8169/web/login
2. browser_fill_form → Credenciales Odoo
3. browser_navigate → /web#action=account.action_move_out_invoice_type
4. browser_click → "Crear" factura
5. browser_fill_form → Datos cliente + productos
6. browser_click → "Validar" factura
7. browser_wait_for → Esperar cálculo de DTE
8. browser_take_screenshot → Capturar comprobante
9. browser_console_messages → Verificar no hay errores JS
10. browser_network_requests → Inspeccionar llamada a SII (si aplica)
```

**Validaciones:**
- ✅ Campo `l10n_cl_dte_type_id` = 33
- ✅ Campo `l10n_cl_sii_barcode` (TED) generado
- ✅ Estado `l10n_cl_dte_status` = 'draft' o 'validated'

---

### 2. Testing Nómina Chilena (hr_payslip)

**Escenario:** Validar cálculos automáticos de AFP, ISAPRE, impuesto único

```bash
# Herramientas a usar:
1. browser_navigate → /web#model=hr.payslip
2. browser_click → "Crear" payslip
3. browser_fill_form → Seleccionar empleado
4. browser_click → "Calcular hoja de pago"
5. browser_wait_for → Esperar cálculo
6. browser_evaluate → Extraer valores calculados
   - document.querySelector('[name="l10n_cl_total_imponible"]').value
   - document.querySelector('[name="l10n_cl_afp_amount"]').value
7. browser_take_screenshot → Documentar resultados
```

**Validaciones:**
- ✅ Total imponible calculado correctamente
- ✅ AFP = min(total_imponible, 90.3 UF) * 0.10
- ✅ ISAPRE >= 7% de total imponible
- ✅ Impuesto único aplicado según tabla SII

---

### 3. Smoke Test de Vistas XML

**Escenario:** Verificar que vistas chilenas rendericen sin errores

```bash
# Test rápido de vistas principales:
VISTAS_CRITICAS = [
  "/web#model=account.move",
  "/web#model=hr.payslip",
  "/web#model=hr.economic.indicators",
  "/web#model=res.partner&view_type=form",
]

Para cada vista:
1. browser_navigate → vista
2. browser_wait_for → Esperar carga completa
3. browser_console_messages → Verificar sin errores
4. browser_snapshot → Capturar DOM para análisis
```

---

### 4. Testing de Integración SII (Ambiente de Certificación)

**Escenario:** Validar envío de DTE a SII maullin (test)

```bash
# NOTA: Requiere VPN/acceso a ambiente SII certificación

1. browser_navigate → https://maullin.sii.cl/DTEWS/
2. browser_fill_form → Credenciales certificación
3. browser_evaluate → Simular envío XML DTE
4. browser_network_requests → Capturar respuesta SOAP
5. browser_take_screenshot → Documentar resultado
```

⚠️ **IMPORTANTE:** Solo usar en ambiente de certificación, NUNCA producción

---

## 📊 Ejemplo de Test Completo: DTE Factura

```python
# Script conceptual (se ejecutaría desde Claude con herramientas MCP)

def test_dte_factura_completa():
    # 1. Login
    navigate("http://localhost:8169/web/login")
    fill_form({
        "login": "admin",
        "password": "admin"
    })
    
    # 2. Ir a facturas
    navigate("/web#action=account.action_move_out_invoice_type")
    click("Crear")
    
    # 3. Llenar datos
    fill_form({
        "partner_id": "Cliente Test RUT 76876876-8",
        "l10n_cl_dte_type_id": "33 - Factura Electrónica",
        "invoice_line_ids": [{
            "product_id": "Producto Test",
            "quantity": 10,
            "price_unit": 1000
        }]
    })
    
    # 4. Validar
    click("Validar")
    wait_for("l10n_cl_sii_barcode")  # Esperar TED
    
    # 5. Verificaciones
    screenshot("factura_validada.png")
    console = console_messages()
    assert not any("error" in msg.lower() for msg in console)
    
    # 6. Inspeccionar DOM
    ted_value = evaluate("document.querySelector('[name=\"l10n_cl_sii_barcode\"]').value")
    assert ted_value.startswith("TIMBRE ELECTRÓNICO")
    
    return "✅ Test DTE Factura PASSED"
```

---

## 🚀 Cómo Usar desde Claude

### Iniciar Test E2E
```
Claude, necesito probar el módulo DTE:
1. Abre Odoo en localhost:8169
2. Login con admin/admin
3. Crea una factura tipo 33
4. Valídala y captura screenshot del TED
5. Verifica que no haya errores en consola
```

### Debugging de Vista
```
Claude, la vista de payslip no carga bien:
1. Navega a /web#model=hr.payslip
2. Toma snapshot del DOM
3. Revisa mensajes de consola
4. Captura network requests
5. Dame un reporte de qué está fallando
```

### Validación Masiva
```
Claude, ejecuta smoke test de todas las vistas chilenas:
1. Lista de vistas: account.move, hr.payslip, hr.economic.indicators
2. Para cada una: navegar, esperar carga, verificar consola
3. Genera reporte con screenshots y errores encontrados
```

---

## ⚠️ Limitaciones y Consideraciones

### Performance
- Playwright consume ~500MB RAM por instancia de navegador
- Tests E2E son lentos: esperar 5-10s por test
- Usar `browser_wait_for` para evitar race conditions

### Seguridad
- NO usar credenciales de producción en tests
- Tests en ambiente local o staging únicamente
- Limpiar datos de test después de cada ejecución

### Debugging
- Si browser falla: `browser_install` reinstala navegador
- Screenshots son la mejor forma de debugging visual
- `browser_console_messages` captura errores JS no visibles

---

## 🔄 Integración con CI/CD (Futuro)

Cuando el proyecto madure, integrar Playwright en pipeline:

```yaml
# .github/workflows/e2e-tests.yml (ejemplo futuro)
name: E2E Tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Start Odoo stack
        run: docker compose up -d
      - name: Run Playwright tests
        run: npx playwright test tests/e2e/
      - name: Upload screenshots
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: test-results/
```

---

## 📚 Referencias

- **Playwright Docs:** https://playwright.dev/
- **MCP Playwright Server:** https://github.com/modelcontextprotocol/servers/tree/main/src/playwright
- **Odoo Testing:** https://www.odoo.com/documentation/19.0/developer/reference/backend/testing.html

---

## ✅ Checklist de Configuración

- [x] Servidor Playwright agregado a `.claude/mcp.json`
- [x] Configuración validada (JSON correcto)
- [x] Servidor puede inicializarse correctamente
- [ ] Ejecutar primer test E2E de DTE (pendiente uso real)
- [ ] Crear suite de tests reutilizables (futuro)
- [ ] Integrar en CI/CD (futuro)

---

**Configurado por:** GitHub Copilot (Claude Sonnet 4.5)  
**Última actualización:** 2025-11-17
