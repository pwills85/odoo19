# 📖 Guía de Lectura e Interpretación de Hallazgos CLI

**Versión:** 1.0.0  
**Fecha:** 2025-11-12  
**Propósito:** Claridad absoluta para leer e interpretar outputs de auditorías ejecutadas por CLIs

---

## 🎯 Objetivo

Esta guía proporciona **claridad absoluta** sobre cómo:
1. **Leer** los outputs de auditorías ejecutadas por CLIs (Copilot, Gemini, Codex)
2. **Interpretar** los hallazgos según severidad (P0/P1/P2)
3. **Extraer** información estructurada (matriz CSV, métricas JSON)
4. **Validar** completitud del reporte según checklist

---

## 📋 Estructura Esperada del Output

### Formato Estándar de Reporte

Todo reporte de auditoría debe seguir esta estructura:

```markdown
# Auditoría 360° Profunda: l10n_cl_dte

## METADATA
- Fecha: 2025-11-12
- Módulo: l10n_cl_dte
- Versión: 19.0.6.0.0
- Auditor: {AGENTE_CLI}

## RESUMEN EJECUTIVO
- Score Global: X/100
- Hallazgos P0: N
- Hallazgos P1: N
- Hallazgos P2: N

## COMPLIANCE ODOO 19 CE
[Tabla con 8 patrones deprecación]

## DIMENSIÓN A: ARQUITECTURA
[Hallazgos específicos con referencias código]

## DIMENSIÓN B: PATRONES DE DISEÑO
[Hallazgos específicos con referencias código]

...

## DIMENSIÓN O: REPORTS QWEB
[Hallazgos específicos con referencias código]

## MÉTRICAS CUANTITATIVAS
[Tabla resumen métricas]

## PLAN DE ACCIÓN
[Priorizado P0 → P1 → P2]
```

---

## 🔍 Cómo Leer Hallazgos

### Formato de Hallazgo Individual

Cada hallazgo debe tener este formato:

```markdown
### [H-P0-01] Título del Hallazgo

**Archivo:** `models/account_move_dte.py:125`
**Severidad:** P0 (Crítica)
**Compliance Odoo 19:** SÍ/NO
**Dimensión:** Performance
**Estado:** Pendiente

**Descripción:**
Descripción detallada del problema encontrado.

**Evidencia:**
```python
# Código problemático
for invoice in invoices:
    partner_name = invoice.partner_id.name  # Query por iteración!
```

**Impacto:**
- Performance degradado en facturas con muchas líneas
- Tiempo respuesta aumenta linealmente con número facturas

**Recomendación:**
```python
# Solución propuesta
invoices = self.env['account.move'].search([...])
invoices.mapped('partner_id.name')  # Prefetch automático
```

**Esfuerzo Estimado:** 4 horas
**Deadline:** 2025-03-01 (si P0)
```

---

## 📊 Cómo Extraer Matriz CSV

### Patrón de Búsqueda

Buscar en el reporte todas las secciones que empiecen con `### [H-`:

```bash
# Extraer hallazgos del reporte
grep -E "^### \[H-" AUDIT_DTE_360_PROFUNDA_*.md | \
  sed 's/^### \[\(H-[^]]*\)\] \(.*\)/\1,\2/' > hallazgos_temp.txt

# Extraer detalles de cada hallazgo
# (requiere parsing más complejo - ver script abajo)
```

### Script de Extracción Automática

```python
#!/usr/bin/env python3
"""
Script para extraer matriz de hallazgos desde reporte Markdown
"""
import re
import csv
from pathlib import Path

def extract_findings(markdown_file):
    """Extrae hallazgos del reporte y genera CSV"""
    findings = []
    
    with open(markdown_file, 'r') as f:
        content = f.read()
    
    # Buscar patrones de hallazgos
    pattern = r'### \[(H-[^\]]+)\]\s+(.+?)\n\n\*\*Archivo:\*\*\s+`([^`]+)`\n\*\*Severidad:\*\*\s+(P[012])\s+\(([^)]+)\)\n\*\*Compliance Odoo 19:\*\*\s+(SÍ|NO)\n\*\*Dimensión:\*\*\s+([^\n]+)\n\*\*Estado:\*\*\s+([^\n]+)\n\n\*\*Descripción:\*\*\s+(.+?)\n\n\*\*Esfuerzo Estimado:\*\*\s+(\d+)\s+horas'
    
    matches = re.finditer(pattern, content, re.DOTALL)
    
    for match in matches:
        findings.append({
            'ID': match.group(1),
            'Título': match.group(2),
            'Archivo/Línea': match.group(3),
            'Criticidad': match.group(4),
            'Compliance Odoo 19': match.group(6),
            'Dimensión': match.group(7),
            'Estado': match.group(8),
            'Descripción': match.group(9)[:200],  # Truncar
            'Esfuerzo Horas': match.group(10)
        })
    
    return findings

def generate_csv(findings, output_file):
    """Genera CSV desde lista de hallazgos"""
    if not findings:
        print("⚠️  No se encontraron hallazgos")
        return
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'ID', 'Archivo/Línea', 'Descripción', 'Criticidad',
            'Compliance Odoo 19', 'Dimensión', 'Estado', 'Esfuerzo Horas'
        ])
        writer.writeheader()
        writer.writerows(findings)
    
    print(f"✅ Matriz generada: {output_file}")
    print(f"   Total hallazgos: {len(findings)}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Uso: python extract_findings.py <reporte.md> [output.csv]")
        sys.exit(1)
    
    markdown_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'MATRIZ_HALLAZGOS.csv'
    
    findings = extract_findings(markdown_file)
    generate_csv(findings, output_file)
```

---

## 📈 Cómo Extraer Métricas JSON

### Patrón de Búsqueda

Buscar sección "MÉTRICAS CUANTITATIVAS" o bloque JSON:

```bash
# Buscar bloque JSON en reporte
grep -A 50 "MÉTRICAS CUANTITATIVAS\|```json" AUDIT_DTE_360_PROFUNDA_*.md

# Extraer JSON completo
sed -n '/```json/,/```/p' AUDIT_DTE_360_PROFUNDA_*.md | grep -v '```' > metricas.json
```

### Script de Extracción JSON

```python
#!/usr/bin/env python3
"""
Script para extraer métricas JSON desde reporte Markdown
"""
import re
import json
from pathlib import Path

def extract_metrics(markdown_file):
    """Extrae métricas del reporte"""
    with open(markdown_file, 'r') as f:
        content = f.read()
    
    # Buscar bloque JSON
    json_pattern = r'```json\n(.*?)\n```'
    match = re.search(json_pattern, content, re.DOTALL)
    
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            print("⚠️  Error parseando JSON")
            return None
    
    # Si no hay JSON, extraer de tabla métricas
    metrics = {}
    
    # Buscar tabla métricas
    table_pattern = r'\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|'
    matches = re.finditer(table_pattern, content)
    
    for match in matches:
        metric_name = match.group(1).strip()
        value = match.group(2).strip()
        target = match.group(3).strip()
        status = match.group(4).strip()
        
        # Parsear valor numérico si es posible
        try:
            value_num = float(value.replace('%', '').replace('{', '').replace('}', ''))
            metrics[metric_name] = {
                'value': value_num,
                'target': target,
                'status': status
            }
        except ValueError:
            metrics[metric_name] = {
                'value': value,
                'target': target,
                'status': status
            }
    
    return metrics if metrics else None

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Uso: python extract_metrics.py <reporte.md> [output.json]")
        sys.exit(1)
    
    markdown_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'METRICAS.json'
    
    metrics = extract_metrics(markdown_file)
    if metrics:
        with open(output_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        print(f"✅ Métricas generadas: {output_file}")
    else:
        print("⚠️  No se encontraron métricas")
```

---

## ✅ Checklist de Validación del Reporte

### Completitud Estructural

- [ ] **Metadata presente:** Fecha, módulo, versión, auditor
- [ ] **Resumen ejecutivo:** Score global, conteo hallazgos P0/P1/P2
- [ ] **Compliance Odoo 19:** Tabla con 8 patrones deprecación
- [ ] **15 Dimensiones cubiertas:** A-O (A-J lógica negocio, K-O infraestructura)
- [ ] **Métricas cuantitativas:** Tabla resumen con valores
- [ ] **Plan de acción:** Priorizado P0 → P1 → P2

### Calidad de Hallazgos

- [ ] **Cada hallazgo tiene:**
  - [ ] ID único (H-P0-XX, H-P1-XX, H-P2-XX)
  - [ ] Archivo/línea exacta (`ruta.py:123`)
  - [ ] Severidad clara (P0/P1/P2)
  - [ ] Descripción detallada
  - [ ] Evidencia código (snippet)
  - [ ] Impacto documentado
  - [ ] Recomendación con solución
  - [ ] Esfuerzo estimado (horas)

### Referencias Código

- [ ] **≥40 referencias código** con formato `archivo.py:línea`
- [ ] Referencias distribuidas en todas las dimensiones
- [ ] Referencias válidas (archivos existen en proyecto)

### Verificaciones Reproducibles

- [ ] **≥9 comandos verificables** (grep, pytest, docker compose exec)
- [ ] Comandos documentados en reporte
- [ ] Resultados esperados documentados

---

## 🔧 Comandos Útiles para Lectura

### Buscar Hallazgos por Severidad

```bash
# Hallazgos P0 (críticos)
grep -E "^### \[H-P0-" AUDIT_DTE_360_PROFUNDA_*.md

# Hallazgos P1 (altos)
grep -E "^### \[H-P1-" AUDIT_DTE_360_PROFUNDA_*.md

# Hallazgos P2 (medios)
grep -E "^### \[H-P2-" AUDIT_DTE_360_PROFUNDA_*.md
```

### Contar Hallazgos

```bash
# Total hallazgos
grep -cE "^### \[H-" AUDIT_DTE_360_PROFUNDA_*.md

# Por severidad
grep -cE "^### \[H-P0-" AUDIT_DTE_360_PROFUNDA_*.md  # P0
grep -cE "^### \[H-P1-" AUDIT_DTE_360_PROFUNDA_*.md  # P1
grep -cE "^### \[H-P2-" AUDIT_DTE_360_PROFUNDA_*.md  # P2
```

### Buscar por Dimensión

```bash
# Hallazgos de Performance
grep -B 5 -A 20 "Dimensión.*Performance" AUDIT_DTE_360_PROFUNDA_*.md

# Hallazgos de Seguridad
grep -B 5 -A 20 "Dimensión.*Seguridad" AUDIT_DTE_360_PROFUNDA_*.md
```

### Extraer Archivos Afectados

```bash
# Listar todos los archivos afectados
grep "Archivo:" AUDIT_DTE_360_PROFUNDA_*.md | \
  sed 's/.*`\([^`]*\)`.*/\1/' | \
  sort -u
```

---

## 📊 Interpretación de Métricas

### Score Global

| Score | Interpretación | Acción |
|-------|----------------|--------|
| 90-100 | Excelente | Monitorear, mantener |
| 75-89 | Bueno | Mejoras menores |
| 60-74 | Aceptable | Plan mejora corto plazo |
| 40-59 | Deficiente | Plan mejora urgente |
| 0-39 | Crítico | Acción inmediata requerida |

### Compliance Odoo 19

| Deprecaciones P0 | Interpretación |
|------------------|----------------|
| 0 | ✅ Compliance 100% |
| 1-5 | ⚠️ Riesgo bajo, cerrar antes deadline |
| 6-10 | 🔴 Riesgo medio, priorizar cierre |
| >10 | 🔴 Riesgo alto, bloqueante producción |

### Coverage Testing

| Coverage | Interpretación |
|----------|---------------|
| ≥85% | ✅ Excelente |
| 70-84% | 🟡 Bueno, mejorar áreas críticas |
| 50-69% | 🟡 Aceptable, gaps importantes |
| <50% | 🔴 Crítico, riesgo alto bugs |

---

## 🚀 Flujo de Trabajo Recomendado

### Paso 1: Lectura Inicial (5 min)

1. Leer **Resumen Ejecutivo**
2. Revisar **Score Global**
3. Contar **Hallazgos P0/P1/P2**
4. Identificar **Top 5 recomendaciones**

### Paso 2: Análisis Detallado (15-30 min)

1. Revisar **Compliance Odoo 19** (tabla deprecaciones)
2. Leer **Hallazgos P0** completos (uno por uno)
3. Leer **Hallazgos P1** relevantes
4. Revisar **Métricas cuantitativas**

### Paso 3: Extracción Estructurada (5 min)

1. Ejecutar script extracción CSV
2. Ejecutar script extracción JSON
3. Validar completitud (checklist)

### Paso 4: Planificación (10-15 min)

1. Priorizar hallazgos P0 (orden ejecución)
2. Estimar esfuerzo total (sumar horas)
3. Crear plan sprint (P0 → P1 → P2)
4. Asignar responsables (si aplica)

---

## 📝 Ejemplo de Lectura Completa

### Input: Reporte Markdown

```markdown
# Auditoría 360° Profunda: l10n_cl_dte

## RESUMEN EJECUTIVO
- Score Global: 78.5/100
- Hallazgos P0: 3
- Hallazgos P1: 8
- Hallazgos P2: 5

### [H-P0-01] N+1 Query en _get_dte_lines()
**Archivo:** `models/account_move_dte.py:125`
**Severidad:** P0 (Crítica)
...
```

### Output Esperado: Matriz CSV

```csv
ID,Archivo/Línea,Descripción,Criticidad,Compliance Odoo 19,Dimensión,Estado,Esfuerzo Horas
H-P0-01,models/account_move_dte.py:125,N+1 query en _get_dte_lines(),P0,NO,Performance,Pendiente,4
H-P0-02,views/invoice_form.xml:45,Uso de t-esc en lugar de t-out,P0,SÍ,Compliance,Pendiente,2
...
```

### Output Esperado: Métricas JSON

```json
{
  "audit_metadata": {
    "module": "l10n_cl_dte",
    "date": "2025-11-12",
    "score": 78.5
  },
  "compliance": {
    "odoo_19_deprecations": {
      "p0": {"count": 3},
      "p1": {"count": 8}
    }
  },
  ...
}
```

---

**Versión:** 1.0.0  
**Última actualización:** 2025-11-12  
**Mantenedor:** Sistema de Prompts Profesional

