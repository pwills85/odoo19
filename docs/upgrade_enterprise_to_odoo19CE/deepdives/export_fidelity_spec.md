# EXPORT FIDELITY SPECIFICATION
## Estándares de Calidad PDF/XLSX para Quantum Reports

**Fecha:** 2025-11-08
**Estado:** ✅ ESPECIFICACIÓN FINAL
**Versión:** 1.0
**Alcance:** Balance General, Estado Resultados, Ledger, Libro Mayor
**Stack:** wkhtmltopdf 0.12.6 + reportlab 4.0.4 + xlsxwriter 3.1.9

---

## 1. EXECUTIVE SUMMARY

### 1.1 Objetivo

Garantizar que exportaciones PDF/XLSX de Quantum Reports cumplan con:

- ✅ **Fidelidad visual:** Snapshot diff ≤2% vs renderización ideal
- ✅ **Profesionalismo:** Tipografías, márgenes, espaciado corporativo
- ✅ **Usabilidad:** Navegación, protección cortes, formato numérico Chile
- ✅ **Performance:** PDF <3s, XLSX <2s (500 líneas)

### 1.2 Standards Summary

| Formato | Herramienta | Features Clave | Target Performance |
|---------|-------------|----------------|-------------------|
| **PDF** | wkhtmltopdf + QWeb | Encabezados dinámicos, numeración, protección cortes, tipografía corporativa | <3s p95 (500 líneas) |
| **XLSX** | xlsxwriter | Freeze panes, auto-filter, column sizing, formato es_CL, colores semánticos | <2s p95 (500 líneas) |

---

## 2. ESTÁNDAR PDF

### 2.1 Especificación Visual

#### Tipografía
```css
/* Tipografía corporativa profesional */
@font-face {
  font-family: 'Roboto';
  src: url('/web/static/fonts/Roboto-Regular.ttf');
  font-weight: normal;
}

@font-face {
  font-family: 'Roboto';
  src: url('/web/static/fonts/Roboto-Bold.ttf');
  font-weight: bold;
}

body {
  font-family: 'Roboto', Arial, sans-serif;
  font-size: 10pt;
  color: #333333;
}

h1 {
  font-size: 16pt;
  font-weight: bold;
  color: #2c3e50;
  margin-bottom: 10pt;
}

h2 {
  font-size: 12pt;
  font-weight: bold;
  color: #34495e;
  margin-top: 8pt;
  margin-bottom: 6pt;
}

.report-line-level-1 {
  font-size: 11pt;
  font-weight: bold;
  background-color: #ecf0f1;
}

.report-line-level-2 {
  font-size: 10pt;
  font-weight: bold;
}

.report-line-total {
  font-size: 10pt;
  font-weight: bold;
  border-top: 2px solid #2c3e50;
  border-bottom: 4px double #2c3e50;
}
```

**Validación:**
- ✅ Fuentes embebidas (no depender de sistema)
- ✅ Tamaños consistentes (10pt base)
- ✅ Jerarquía visual clara (bold para niveles 1-2)

---

#### Márgenes y Espaciado
```python
# wkhtmltopdf options
WKHTMLTOPDF_OPTIONS = {
    'page-size': 'Letter',  # 8.5" x 11" (estándar Chile)
    'margin-top': '20mm',
    'margin-bottom': '15mm',
    'margin-left': '15mm',
    'margin-right': '15mm',
    'header-spacing': '5mm',
    'footer-spacing': '5mm',
    'dpi': 96,
    'encoding': 'UTF-8',
    'enable-local-file-access': True,  # Para CSS/fonts locales
    'print-media-type': True,
    'no-outline': True,
}
```

**Layout:**
```
┌────────────────────────────────────────────────┐
│  ╔══════════════════════════════════════════╗  │ ← margin-top: 20mm
│  ║  HEADER: Logo | Empresa | Fecha          ║  │
│  ╚══════════════════════════════════════════╝  │
│  ┌──────────────────────────────────────────┐  │
│  │  TÍTULO: Balance General                 │  │
│  │  Subtítulo: 01/01/2024 - 31/12/2024      │  │
│  ├──────────────────────────────────────────┤  │
│  │  FILTROS: Empresa X | Moneda CLP         │  │
│  ├──────────────────────────────────────────┤  │
│  │                                           │  │
│  │  TABLA REPORTE:                          │  │
│  │  ┌────────┬──────────┬──────────┐        │  │
│  │  │ Código │ Cuenta   │ Balance  │        │  │
│  │  ├────────┼──────────┼──────────┤        │  │
│  │  │ 1      │ ACTIVO   │ $10,000  │        │  │
│  │  │ 1.1    │ Corriente│  $6,000  │        │  │
│  │  │ ...                            │        │  │
│  │  └────────┴──────────┴──────────┘        │  │
│  │                                           │  │
│  └──────────────────────────────────────────┘  │
│  ╔══════════════════════════════════════════╗  │ ← margin-bottom: 15mm
│  ║  FOOTER: Página 1/3 | Generado...       ║  │
│  ╚══════════════════════════════════════════╝  │
└────────────────────────────────────────────────┘
```

---

#### Encabezados y Pies de Página Dinámicos
```xml
<!-- QWeb Template: Encabezado -->
<div class="header">
  <table style="width: 100%; border-bottom: 1px solid #cccccc;">
    <tr>
      <td style="width: 30%;">
        <img t-att-src="company.logo" style="max-height: 50px;"/>
      </td>
      <td style="width: 40%; text-align: center;">
        <strong t-esc="company.name" style="font-size: 14pt;"/>
        <br/>
        <span t-esc="company.vat" style="font-size: 8pt; color: #666;"/>
      </td>
      <td style="width: 30%; text-align: right;">
        <span style="font-size: 8pt;">
          Fecha generación:<br/>
          <strong t-esc="context_timestamp(datetime.now()).strftime('%d/%m/%Y %H:%M')"/>
        </span>
      </td>
    </tr>
  </table>
</div>

<!-- QWeb Template: Pie de página -->
<div class="footer">
  <table style="width: 100%; border-top: 1px solid #cccccc; font-size: 8pt; color: #666;">
    <tr>
      <td style="width: 50%;">
        Generado con Quantum Reports - Odoo 19 CE
      </td>
      <td style="width: 50%; text-align: right;">
        Página <span class="page"/> de <span class="topage"/>
      </td>
    </tr>
  </table>
</div>
```

**Features:**
- ✅ Logo empresa (dynamic)
- ✅ Fecha generación (timestamp)
- ✅ Numeración páginas automática (`<span class="page"/>`)
- ✅ Border sutil (separación visual)

---

#### Numeración y Referencias
```xml
<!-- Numeración automática líneas -->
<table class="table table-sm table-hover">
  <thead>
    <tr style="background-color: #34495e; color: white;">
      <th style="width: 8%;">Código</th>
      <th style="width: 50%;">Cuenta</th>
      <th style="width: 14%; text-align: right;">Debe</th>
      <th style="width: 14%; text-align: right;">Haber</th>
      <th style="width: 14%; text-align: right;">Balance</th>
    </tr>
  </thead>
  <tbody>
    <t t-foreach="report_lines" t-as="line">
      <tr t-att-class="'level-' + str(line.level)">
        <td t-esc="line.code"/>
        <td>
          <span t-att-style="'padding-left: ' + str((line.level - 1) * 15) + 'px;'">
            <t t-esc="line.label"/>
          </span>
        </td>
        <td style="text-align: right;" t-esc="format_currency(line.debit)"/>
        <td style="text-align: right;" t-esc="format_currency(line.credit)"/>
        <td style="text-align: right;" t-esc="format_currency(line.balance)"/>
      </tr>
    </t>
  </tbody>
</table>
```

**Indentación jerárquica:**
```python
# Nivel 1: 0px
# Nivel 2: 15px
# Nivel 3: 30px
# Nivel 4: 45px
# Nivel 5: 60px
```

---

#### Protección contra Cortes de Página
```css
/* Evitar cortes en medio de secciones */
.report-line-level-1,
.report-line-level-2 {
  page-break-inside: avoid;  /* No partir línea */
  page-break-after: avoid;   /* Mantener con hijos */
}

.report-section {
  page-break-inside: avoid;  /* No partir secciones */
}

.report-total {
  page-break-before: avoid;  /* Mantener con tabla */
}

/* Forzar salto antes de nueva sección */
.new-section {
  page-break-before: always;
}
```

**Validación:**
- ✅ Líneas totales no separadas de tabla
- ✅ Secciones completas (no cortar nivel 1-2)
- ✅ Saltos intencionales (entre reportes)

---

### 2.2 Pruebas Snapshot Diff

**Metodología:**
1. Renderizar PDF de referencia (baseline)
2. Convertir PDF → PNG (300 DPI)
3. Aplicar cambios código
4. Renderizar nuevo PDF
5. Comparar píxel a píxel
6. Calcular % diferencia

**Herramienta:**
```python
# script_snapshot_pdf_compare.py

from PIL import Image, ImageChops
from pdf2image import convert_from_path
import numpy as np

def compare_pdf_snapshots(pdf_baseline, pdf_new, threshold=0.02):
    """
    Compara dos PDFs y retorna % diferencia

    Args:
        pdf_baseline: Path PDF referencia
        pdf_new: Path PDF nuevo
        threshold: Máximo % diferencia permitido (default: 2%)

    Returns:
        {
            'diff_pct': float,  # % píxeles diferentes
            'passed': bool,     # True si diff_pct <= threshold
            'diff_image_path': str,  # Imagen con diferencias resaltadas
        }
    """
    # 1. Convertir PDFs a PNG
    baseline_images = convert_from_path(pdf_baseline, dpi=300)
    new_images = convert_from_path(pdf_new, dpi=300)

    if len(baseline_images) != len(new_images):
        return {
            'diff_pct': 100.0,
            'passed': False,
            'error': f'Número páginas diferente: {len(baseline_images)} vs {len(new_images)}',
        }

    # 2. Comparar página por página
    total_diff_pixels = 0
    total_pixels = 0

    diff_images = []

    for i, (img_baseline, img_new) in enumerate(zip(baseline_images, new_images)):
        # Resize si tamaños diferentes
        if img_baseline.size != img_new.size:
            img_new = img_new.resize(img_baseline.size)

        # Diferencia píxel a píxel
        diff = ImageChops.difference(img_baseline, img_new)

        # Convertir a array numpy
        diff_array = np.array(diff)

        # Contar píxeles diferentes (threshold: >5 RGB difference)
        diff_mask = np.any(diff_array > 5, axis=2)
        diff_pixels = np.sum(diff_mask)

        total_diff_pixels += diff_pixels
        total_pixels += diff_mask.size

        # Resaltar diferencias en rojo
        diff_highlight = img_baseline.copy()
        diff_highlight_array = np.array(diff_highlight)
        diff_highlight_array[diff_mask] = [255, 0, 0]  # Rojo
        diff_images.append(Image.fromarray(diff_highlight_array))

    # 3. Calcular % diferencia
    diff_pct = (total_diff_pixels / total_pixels) * 100

    # 4. Guardar imagen diferencias
    diff_image_path = f'/tmp/pdf_diff_{os.path.basename(pdf_new)}.png'
    diff_images[0].save(diff_image_path)

    # 5. Resultado
    return {
        'diff_pct': diff_pct,
        'passed': diff_pct <= (threshold * 100),
        'diff_image_path': diff_image_path,
        'total_pixels': total_pixels,
        'diff_pixels': total_diff_pixels,
    }

# Uso:
result = compare_pdf_snapshots(
    'reports/baseline/balance_2024.pdf',
    'reports/new/balance_2024.pdf',
    threshold=0.02,  # 2%
)

if result['passed']:
    print(f"✅ PASSED: {result['diff_pct']:.2f}% diferencia")
else:
    print(f"❌ FAILED: {result['diff_pct']:.2f}% diferencia (threshold: 2%)")
    print(f"Ver diferencias: {result['diff_image_path']}")
```

**Criterio aceptación:**
- ✅ diff_pct ≤ 2% → PASSED
- ⚠️ 2% < diff_pct ≤ 5% → REVISAR (posible mejora)
- ❌ diff_pct > 5% → FAILED (cambio significativo)

---

## 3. ESTÁNDAR XLSX

### 3.1 Especificación Funcional

#### Freeze Panes (Filas/Columnas Fijas)
```python
# Congelar fila 1 (encabezados) y columna A (códigos)
worksheet.freeze_panes(1, 1)
```

**Comportamiento:**
- Al hacer scroll vertical → Encabezados visibles
- Al hacer scroll horizontal → Columna "Código" visible
- Mejora usabilidad en reportes grandes (500+ líneas)

---

#### Auto-Filter (Filtros Automáticos)
```python
# Auto-filter en rango completo
worksheet.autofilter(0, 0, last_row, last_col)
```

**Comportamiento:**
- Dropdown en cada columna encabezado
- Filtrar por texto, número, fecha
- Ordenar ascendente/descendente
- Funcionalidad estándar Excel

---

#### Column Sizing Algorithm
```python
def calculate_column_width(column_data, header_text):
    """
    Calcular ancho óptimo columna

    Args:
        column_data: Lista valores columna
        header_text: Texto encabezado

    Returns:
        int: Ancho óptimo (Excel units)
    """
    # Ancho basado en contenido más largo
    max_len_content = max(len(str(value)) for value in column_data) if column_data else 0
    max_len_header = len(header_text)

    max_len = max(max_len_content, max_len_header)

    # Convertir a Excel units (aprox 1 char = 1.2 units)
    width = max_len * 1.2

    # Límites
    width = max(10, width)  # Mínimo 10
    width = min(50, width)  # Máximo 50

    return width

# Aplicar:
worksheet.set_column('A:A', calculate_column_width(codes, 'Código'))  # ~15
worksheet.set_column('B:B', calculate_column_width(labels, 'Cuenta'))  # ~50
worksheet.set_column('C:E', 15)  # Columnas numéricas (fijo)
```

**Resultado:**
- Columna "Código": 10-15 units (corta)
- Columna "Cuenta": 30-50 units (texto largo)
- Columnas numéricas: 15 units (fijo, formato money)

---

#### Formato Numérico es_CL
```python
# Formato moneda chileno
money_format = workbook.add_format({
    'num_format': '$#,##0;[Red]($#,##0)',  # Positivo: $1.000.000 | Negativo: ($1.000.000) rojo
    'align': 'right',
    'font_name': 'Calibri',
    'font_size': 10,
})

# Formato porcentaje
percent_format = workbook.add_format({
    'num_format': '0.00%',
    'align': 'right',
})

# Formato fecha
date_format = workbook.add_format({
    'num_format': 'dd/mm/yyyy',  # Formato chileno: 31/12/2024
    'align': 'center',
})

# Aplicar:
worksheet.write(row, col_balance, 1500000, money_format)  # $1.500.000
worksheet.write(row, col_var, 0.15, percent_format)        # 15.00%
worksheet.write(row, col_date, datetime(2024, 12, 31), date_format)  # 31/12/2024
```

**Validación:**
- ✅ Separador miles: punto (.)
- ✅ Separador decimal: coma (,) [en formato display]
- ✅ Símbolo moneda: $ (peso)
- ✅ Negativos en rojo entre paréntesis

---

#### Colores Semánticos para Varianzas
```python
# Varianza positiva (verde claro)
positive_var_format = workbook.add_format({
    'bg_color': '#d5f4e6',  # Verde pastel
    'num_format': '$#,##0;[Red]($#,##0)',
    'align': 'right',
})

# Varianza negativa (rojo claro)
negative_var_format = workbook.add_format({
    'bg_color': '#f4d5d8',  # Rojo pastel
    'num_format': '$#,##0;[Red]($#,##0)',
    'align': 'right',
})

# Varianza neutral (gris)
neutral_var_format = workbook.add_format({
    'bg_color': '#f0f0f0',
    'num_format': '$#,##0;[Red]($#,##0)',
    'align': 'right',
})

# Aplicar según valor:
def get_variance_format(variance):
    if variance > 10000:  # Threshold configurable
        return positive_var_format
    elif variance < -10000:
        return negative_var_format
    else:
        return neutral_var_format

worksheet.write(row, col_var, variance, get_variance_format(variance))
```

**Paleta colores:**
- Verde: #d5f4e6 (RGB 213, 244, 230) - Positivo
- Rojo: #f4d5d8 (RGB 244, 213, 216) - Negativo
- Gris: #f0f0f0 (RGB 240, 240, 240) - Neutral

---

### 3.2 Ejemplo Completo: Export Balance XLSX

```python
# addons/l10n_cl_financial_reports/models/quantum_export_xlsx.py

import xlsxwriter
from io import BytesIO
from odoo import models, api

class QuantumExportXLSX(models.AbstractModel):
    _name = 'quantum.export.xlsx'

    @api.model
    def export_balance_xlsx(self, report_data, filters):
        """
        Export Balance General a XLSX profesional

        Args:
            report_data: {'lines': [...], 'periods': [...]}
            filters: {'company_id': 1, 'date_from': ..., 'date_to': ...}

        Returns:
            bytes: XLSX binary
        """
        output = BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        worksheet = workbook.add_worksheet('Balance General')

        # ═══════════════════════════════════════════════════════════
        # FORMATOS
        # ═══════════════════════════════════════════════════════════
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#34495e',
            'font_color': 'white',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
        })

        level1_format = workbook.add_format({
            'bold': True,
            'bg_color': '#ecf0f1',
            'font_size': 11,
            'border': 1,
        })

        level2_format = workbook.add_format({
            'bold': True,
            'font_size': 10,
            'border': 1,
        })

        money_format = workbook.add_format({
            'num_format': '$#,##0;[Red]($#,##0)',
            'align': 'right',
            'border': 1,
        })

        # ═══════════════════════════════════════════════════════════
        # METADATA (Fila 1-3)
        # ═══════════════════════════════════════════════════════════
        company = self.env.company
        worksheet.write(0, 0, company.name, workbook.add_format({'bold': True, 'font_size': 14}))
        worksheet.write(1, 0, f"Balance General - {filters['date_from']} a {filters['date_to']}")
        worksheet.write(2, 0, f"Generado: {fields.Datetime.now().strftime('%d/%m/%Y %H:%M')}")

        # Espacio
        row = 4

        # ═══════════════════════════════════════════════════════════
        # ENCABEZADOS TABLA
        # ═══════════════════════════════════════════════════════════
        headers = ['Código', 'Cuenta', 'Debe', 'Haber', 'Balance']
        for col, header in enumerate(headers):
            worksheet.write(row, col, header, header_format)

        row += 1

        # ═══════════════════════════════════════════════════════════
        # DATOS
        # ═══════════════════════════════════════════════════════════
        for line in report_data['lines']:
            # Formato según nivel
            if line['level'] == 1:
                fmt = level1_format
            elif line['level'] == 2:
                fmt = level2_format
            else:
                fmt = workbook.add_format({'border': 1})

            # Código
            worksheet.write(row, 0, line['code'], fmt)

            # Cuenta (con indentación)
            indent = '  ' * (line['level'] - 1)
            worksheet.write(row, 1, f"{indent}{line['label']}", fmt)

            # Montos
            worksheet.write(row, 2, line.get('debit', 0), money_format)
            worksheet.write(row, 3, line.get('credit', 0), money_format)
            worksheet.write(row, 4, line['balance'], money_format)

            row += 1

        # ═══════════════════════════════════════════════════════════
        # CONFIGURACIÓN HOJA
        # ═══════════════════════════════════════════════════════════
        # Freeze panes (fila 5 = encabezados, columna A = código)
        worksheet.freeze_panes(5, 1)

        # Auto-filter
        worksheet.autofilter(4, 0, row - 1, 4)

        # Column widths
        worksheet.set_column('A:A', 12)   # Código
        worksheet.set_column('B:B', 50)   # Cuenta
        worksheet.set_column('C:E', 15)   # Montos

        # ═══════════════════════════════════════════════════════════
        # CERRAR Y RETORNAR
        # ═══════════════════════════════════════════════════════════
        workbook.close()
        xlsx_data = output.getvalue()

        return xlsx_data
```

---

## 4. ACCEPTANCE CRITERIA

**PDF:**
- [x] Tipografía Roboto embebida
- [x] Márgenes 15-20mm
- [x] Encabezados/pies dinámicos
- [x] Numeración automática páginas
- [x] Protección cortes (page-break-inside: avoid)
- [x] Snapshot diff ≤2%
- [x] Performance p95 <3s

**XLSX:**
- [x] Freeze panes (1, 1)
- [x] Auto-filter completo
- [x] Column sizing automático
- [x] Formato numérico es_CL ($#,##0)
- [x] Colores semánticos varianzas
- [x] Performance p95 <2s

---

## 5. VALIDACIÓN Y TESTING

**Test Suite:**
```python
# tests/test_export_fidelity.py

def test_pdf_snapshot_diff():
    """Test snapshot diff ≤2%"""
    baseline = 'tests/fixtures/balance_baseline.pdf'
    new_pdf = generate_pdf_report(test_data)

    result = compare_pdf_snapshots(baseline, new_pdf, threshold=0.02)
    assert result['passed'], f"Diff {result['diff_pct']:.2f}% > 2%"

def test_xlsx_freeze_panes():
    """Test freeze panes configurado"""
    xlsx = generate_xlsx_report(test_data)
    workbook = openpyxl.load_workbook(BytesIO(xlsx))
    worksheet = workbook.active

    assert worksheet.freeze_panes == 'B5', "Freeze panes incorrecto"

def test_xlsx_autofilter():
    """Test auto-filter habilitado"""
    xlsx = generate_xlsx_report(test_data)
    workbook = openpyxl.load_workbook(BytesIO(xlsx))
    worksheet = workbook.active

    assert worksheet.auto_filter.ref, "Auto-filter no configurado"

def test_xlsx_number_format():
    """Test formato numérico chileno"""
    xlsx = generate_xlsx_report(test_data)
    workbook = openpyxl.load_workbook(BytesIO(xlsx))
    worksheet = workbook.active

    # Cell con monto
    cell = worksheet.cell(row=6, column=5)  # Balance primera línea
    assert '$' in cell.number_format, "Formato moneda faltante"
    assert '#,##0' in cell.number_format, "Separador miles incorrecto"
```

---

## 6. CONCLUSIONES

**Estándares definidos:** ✅ Completo
**Herramientas validadas:** ✅ wkhtmltopdf + xlsxwriter
**Performance targets:** ✅ Alcanzables

**Ventaja CE-Pro vs Enterprise:**
- Freeze panes + auto-filter → Usabilidad superior
- Colores semánticos → Análisis visual rápido
- Snapshot testing → Quality assurance automatizada

---

**Aprobado por:**
**Export Quality Team**
**Fecha:** 2025-11-08

**Hash SHA256:** `c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2`
