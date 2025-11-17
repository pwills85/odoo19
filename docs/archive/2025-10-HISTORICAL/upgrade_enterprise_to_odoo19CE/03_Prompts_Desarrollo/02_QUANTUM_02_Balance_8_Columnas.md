---
id: QUANTUM-02-BALANCE-8COL
pilar: Quantum
fase: P1
owner: Backend Lead
fecha: 2025-11-08
version: 1.0
estado: Ready
relacionados:
  - ../04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md
  - ../04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md
  - ../04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md
---

# PROMPT: Implementación de Balance Tributario de 8 Columnas

**PROYECTO:** Quantum (Advanced Financial Reporting)

**TÍTULO:** Implementación de Reporte Avanzado: Balance Tributario de 8 Columnas

---

## 1. Objetivo

Implementar un reporte financiero avanzado chileno (Balance Tributario 8 Columnas) que cumpla requisitos legales SII, priorizando exactitud de cálculos y funcionalidad exportación XLSX para uso contable.

**Objetivos específicos:**

1. Investigar y documentar arquitectura óptima (extensión account.report vs modelo custom)
2. Implementar reporte con estructura 8 columnas: Saldo Inicial, Movimientos (Debe/Haber), Saldo Final, Correcciones, Saldo Ajustado
3. Validar cuadratura perfecta de totales con datos contables
4. Priorizar exportación XLSX con formato usable para contadores y organismos reguladores

---

## 2. Alcance

### Incluye

- Investigación arquitectura e informe decisión (extensión account.report vs custom model)
- Implementación reporte 8 columnas según arquitectura validada
- Listado completo cuentas con movimiento (sin límite registros)
- Funcionalidad exportación XLSX con formato profesional
- Cálculos exactos validados mediante unit tests
- Documentación técnica arquitectura reporte

### Fuera de Alcance

- Reportes consolidados multiempresa
- Análisis comparativos multiperiodo (responsabilidad reportes base)
- Integración automática SII (responsabilidad módulo l10n_cl_dte)
- Correcciones manuales post-generación

---

## 3. Entradas y Dependencias

### Archivos de Referencia

- `addons/localization/l10n_cl_financial_reports/models/`
- `addons/localization/l10n_cl_financial_reports/reports/`
- Especificación técnica `account.report` Odoo 19 (docs oficiales)
- `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md` (datos test)

### Artefactos Relacionados

- `MASTER_PLAN_v2.md` → Fase 2 (Mes 2-3): Reportes avanzados
- `MATRIZ_SII_CUMPLIMIENTO.md` → Requisitos legales 8 columnas
- `DATASET_SINTETICO_SPEC.md` → Dataset test 1000+ movimientos
- `QUANTUM-01-REPORTES-BASE.md` → Reportes base (dependencia)

### Entorno Necesario

- Odoo 19 CE con módulos account, l10n_cl_financial_reports
- Dataset sintético con 1000+ asientos contables y correcciones
- Docker compose configurado
- Acceso documentación oficial Odoo 19 account.report

---

## 4. Tareas

### Fase 1: Investigación Arquitectónica (Lead Backend)

1. Revisar framework `account.report` Odoo 19 → verificar soporte multi-columna
2. Estudiar implementaciones alternativas: AbstractModel + Wizard, ReportModel custom
3. Analizar dataset sintético para entender volumen datos y complejidad cálculos
4. Documentar arquitecturas candidatas: ventajas/desventajas
5. Validar con Tech Lead → seleccionar arquitectura final

### Fase 2: Diseño Estructura 8 Columnas

6. Definir estructura exacta: Saldo Inicial → Debe → Haber → Saldo Final → Correcciones → Saldo Ajustado
7. Especificar fórmulas cálculo: validaciones, reglas negocio
8. Diseñar queries SQL optimizadas para consultar todas las cuentas
9. Documentar data flow: desde account.move hasta columnas reporte

### Fase 3: Implementación Núcleo

10. Crear modelo base reporte (heredar account.report o custom model según decisión)
11. Implementar métodos cálculo saldos iniciales (desde fecha inicio hasta fecha corte)
12. Implementar métodos cálculo movimientos (debe/haber filtrado por período)
13. Implementar métodos cálculo correcciones y saldo ajustado

### Fase 4: Funcionalidades Exportación y UI

14. Implementar exportación a XLSX con formato profesional (alineación, números, encabezados)
15. Implementar filtros UI: rango fechas, empresa, cuentas específicas
16. Validar drill-down navegable a asientos individuales (si arquitectura lo permite)
17. Implementar validación cuadratura (alert si no cuadra)

### Fase 5: Pruebas y Validación

18. Crear fixtures test con dataset sintético
19. Implementar unit tests: exactitud saldos, cálculos columnas, cuadratura
20. Ejecutar smoke tests: generación reporte sin errores
21. Validar exportación XLSX: formato, números, cálculos
22. Benchmark performance: render 1000+ cuentas <10s
23. Validación final criterios aceptación

---

## 5. Entregables

| Archivo | Ubicación | Contenido |
|---------|-----------|-----------|
| `ARQUITECTURA_BALANCE_8_COLUMNAS.md` | `docs/quantum/` | Informe decisión arquitectónica |
| `balance_8_columnas_model.py` | `addons/localization/l10n_cl_financial_reports/models/` | Modelo core reporte |
| `balance_8_columnas_report.py` | `addons/localization/l10n_cl_financial_reports/report/` | Lógica cálculo reporte |
| `balance_8_columnas_views.xml` | `addons/localization/l10n_cl_financial_reports/views/` | Vistas UI reporte |
| `test_balance_8_columnas.py` | `addons/localization/l10n_cl_financial_reports/tests/` | Unit tests |
| `fixtures_balance_8_columnas.py` | `addons/localization/l10n_cl_financial_reports/tests/` | Fixtures test |

### Estructura Informe Arquitectónico

```markdown
# ARQUITECTURA_BALANCE_8_COLUMNAS.md

## 1. Opciones Evaluadas

### Opción A: Extensión account.report
- Ventajas: Integración nativa, drill-down automático
- Desventajas: Limitaciones para estructuras complejas

### Opción B: Modelo Custom + Wizard
- Ventajas: Máxima flexibilidad, cálculos exactos
- Desventajas: Desarrollo custom, mantenimiento

## 2. Decisión Final
[Arquitectura seleccionada + justificación]

## 3. Data Flow
[Diagrama flujo datos]

## 4. Queries Optimizadas
[SQLs principales]
```

---

## 6. Criterios de Aceptación

| Criterio | Métrica | Umbral | Verificación |
|----------|---------|--------|--------------|
| **Investigación Completa** | % opciones arquitectónicas analizadas | 100% | Informe arquitectónico |
| **Exactitud Saldos Iniciales** | Varianza vs GL | ≤0% | Unit test `test_saldo_inicial` |
| **Exactitud Movimientos** | Debe + Haber = total movimientos | ≤0% | Unit test `test_movimientos_exactitud` |
| **Exactitud Saldo Final** | Saldo Inicial + Debe - Haber | ≤0% | Unit test `test_saldo_final` |
| **Exactitud Correcciones** | Correcciones aplicadas exactamente | ≤0% | Unit test `test_correcciones` |
| **Cuadratura Total** | Gran total activo = pasivo + capital | ≤0% | Unit test `test_cuadratura_total` |
| **Exportación XLSX** | Archivo generado, legible, números exactos | Sí | Validación manual |
| **Performance Render** | Reporte 1000+ cuentas | <10s | Benchmark pytest |
| **Cobertura Tests** | % código cubierto por tests | ≥80% | Coverage report |
| **Documentación** | Arquitectura documentada completamente | Sí | Informe ARQUITECTURA |

---

## 7. Pruebas

### 7.1 Pruebas Unitarias

**Test 1: Exactitud Saldos Iniciales**

```python
def test_saldo_inicial_exactitud(self):
    # Setup: crear asientos pre-fecha corte
    # Assert: saldo inicial = suma saldos cuentas
```

**Test 2: Exactitud Movimientos Debe/Haber**

```python
def test_movimientos_debe_haber(self):
    # Setup: asientos en periodo
    # Assert: debe = suma líneas debe
    # Assert: haber = suma líneas haber
```

**Test 3: Exactitud Saldo Final**

```python
def test_saldo_final(self):
    # Setup: datos completos
    # Assert: saldo final = inicial + debe - haber
```

**Test 4: Exactitud Correcciones**

```python
def test_correcciones_exactitud(self):
    # Setup: asientos corrección
    # Assert: correcciones aplicadas exactamente
```

**Test 5: Cuadratura Total**

```python
def test_cuadratura_total(self):
    # Setup: todas las cuentas
    # Assert: activo = pasivo + capital
```

### 7.2 Smoke Tests

**Test 6: Generación Reporte sin Errores**

- Reporte se genera sin excepción
- Todas las cuentas con movimiento incluidas
- Números son válidos (no NaN, inf)

**Test 7: Exportación XLSX Funcional**

- XLSX se crea correctamente
- Datos importables en Excel
- Formato legible (encabezados, alineación)

### 7.3 Pruebas Performance

**Test 8: Benchmark Render**

- 1000+ cuentas: p95 <10s
- Memoria utilizada <500MB

---

## 8. Clean-Room (Protocolo Legal)

### Roles y Restricciones

| Rol | Persona | Restricciones | Evidencia |
|-----|---------|---------------|-----------|
| **Backend Lead** | Developer | ✅ Investigación framework público<br>✅ Implementación Odoo 19 nativo | Commits + informe arquitectura |
| **Tech Lead Review** | Senior Architect | ✅ Validación arquitectura<br>✅ Revisión decisiones técnicas | Review informe + PR |
| **QA Lead** | QA Engineer | ✅ Ejecución tests completa<br>✅ Validación criterios | Test report final |

### Secuencia Clean-Room

```mermaid
graph LR
    A[Backend Lead: Investiga] -->|Documenta opciones| B[Informe Arquitectónico]
    B -->|Presenta a Tech Lead| C[Tech Lead: Aprueba]
    C -->|Autoriza implementación| D[Backend Lead: Implementa]
    D -->|Push rama| E[Code Review]
    E -->|Aprueba| F[QA: Tests]
    F -->|Valida| G[Merge]
```

---

## 9. Riesgos y Mitigaciones

| ID | Riesgo | Probabilidad | Impacto | Severidad | Mitigación |
|----|--------|--------------|---------|-----------|------------|
| **R-QUANTUM-05** | account.report no soporta 8 columnas | Media (0.5) | Alto (4) | 2.0 | Plan fallback: custom model + wizard |
| **R-QUANTUM-06** | Saldos no cuadran en reporte final | Media (0.4) | Alto (4) | 1.6 | Unit tests exactitud + reconciliación manual |
| **R-QUANTUM-07** | Performance export XLSX >10s | Baja (0.3) | Medio (3) | 0.9 | Optimizar SQL, considerar caché |
| **R-QUANTUM-08** | Correcciones complejas no calculadas correctamente | Baja (0.2) | Alto (4) | 0.8 | Tests rigurosos + validación manual SII |

### Triggers de Decisión

- Si **R-QUANTUM-05** ocurre: Activar plan fallback (custom model)
- Si **R-QUANTUM-06** ocurre: STOP merge, investigar discrepancias
- Si **R-QUANTUM-07** ocurre: Optimizar consultas SQL

---

## 10. Trazabilidad

### Brecha que Cierra

| Brecha P1 | Artefacto que la cierra | Métrica Validación |
|-----------|------------------------|--------------------|
| Reportes financieros avanzados (Master Plan v2 § Quantum) | Reporte 8 columnas + tests | Tests PASS + criteria acceptance |
| Cumplimiento SII requisitos reportería | Reporte genera datos exactos | Tests exactitud + validación SII |

### Relación con Master Plan v2

- **Fase 2 (Mes 2-3):** Hito Quantum II — "La Precisión Fiscal"
- **POC-4:** Advanced Financial Reports → Validar 8 columnas exactitud

### Referencias Cruzadas

- `QUANTUM-01-REPORTES-BASE.md` → Reportes base (dependencia)
- `MATRIZ_SII_CUMPLIMIENTO.md` → Requisitos regulatorios
- `DATASET_SINTETICO_SPEC.md` → Datos para validación

---

## 11. Governance y QA Gates

### Gates Aplicables

| Gate | Criterio | Status |
|------|----------|--------|
| **Gate-Arquitectura** | Informe arquitectónico aprobado por Tech Lead | Pending |
| **Gate-Exactitud** | Tests exactitud PASS (0% varianza) | Pending |
| **Gate-Cuadratura** | Reporte cuadra (activo = pasivo + capital) | Pending |
| **Gate-Performance** | Render 1000+ cuentas <10s | Pending |
| **Gate-Export** | XLSX exportable y legible | Pending |

### Checklist Pre-Merge

- [ ] Informe arquitectónico completo y aprobado
- [ ] Unit tests ejecutados PASS
- [ ] Coverage ≥80%
- [ ] Exactitud saldos validada (0% varianza)
- [ ] Cuadratura total validada
- [ ] Performance benchmark ejecutado
- [ ] XLSX exportación probada manualmente
- [ ] Code review aprobado

---

## 12. Próximos Pasos

1. **Fase 1 (Semana 1):** Backend Lead investiga arquitecturas + entrega informe
2. **Tech Lead Review:** Aprueba arquitectura seleccionada
3. **Fase 2-5 (Semanas 2-4):** Implementación iterativa + tests
4. **QA Validation:** Ejecución test suite completa
5. **Performance Tuning:** Si benchmark >10s, optimizar
6. **Merge Main:** Integración rama feature
7. **POC-4 Kickoff:** Usar reporte para validación SII compliance

---

## 13. Notas Adicionales

### Supuestos

- Odoo 19 CE ofrece suficiente flexibilidad para implementar 8 columnas
- Dataset sintético incluye correcciones y casos complejos
- SII proporciona especificación exacta del reporte (referencia legal)

### Decisiones Técnicas

- **Prioridad 1:** Exactitud de cálculos > funcionalidades avanzadas
- **Prioridad 2:** Exportación XLSX > drill-down (para contadores)
- **Performance:** Caché resultados si necesario (consideración posterior)

### Recursos Requeridos

- Backend Lead: 50 horas estimadas (investigación + implementación)
- Tech Lead: 8 horas (revisión arquitectura)
- QA Lead: 16 horas (testing completo)
- Total: 74 horas sprint P1

### Documentos de Referencia

- Especificación SII Balance Tributario (si disponible)
- Documentación Odoo 19 account.report (framework oficial)
- Examples Odoo l10n_cl (módulos existentes)

---

**Versión:** 1.0
**Estado:** Ready para ejecución
**Owner:** Backend Lead
**Aprobado por:** Tech Lead (2025-11-08)
