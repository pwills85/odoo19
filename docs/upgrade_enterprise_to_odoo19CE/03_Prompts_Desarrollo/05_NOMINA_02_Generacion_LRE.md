---
id: NOMINA-02-LRE
pilar: Nómina
fase: P1
owner: Payroll Lead
fecha: 2025-11-08
version: 1.0
estado: Ready
relacionados:
  - ../04_Artefactos_Mejora/CLEAN_ROOM_PROTOCOL_OPERATIVO.md
  - ../04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md
  - ../04_Artefactos_Mejora/MASTER_PLAN_v2.md
---

# PROMPT: Generación del Libro de Remuneraciones Electrónico (LRE)

**PROYECTO:** Nómina Chilena

**TÍTULO:** Wizard de Generación LRE (Libro de Remuneraciones Electrónico) — Fase P1

---

## 1. Objetivo

Implementar un **wizard funcional** en Odoo 19 que permita generar automáticamente el Libro de Remuneraciones Electrónico (LRE) en formato CSV conforme a las especificaciones oficiales de la Dirección del Trabajo de Chile, consumiendo datos de `hr.payslip` previamente calculados en Fase P0.

**Objetivos específicos:**

1. Investigar y documentar layout oficial actual del LRE (2025) desde Dirección del Trabajo
2. Crear wizard `hr.lre.wizard` con UI intuitiva para seleccionar periodo (mes/año) y empresa
3. Implementar lógica de mapeo: `hr.payslip.line` → columnas CSV LRE
4. Generar CSV validado contra formato DT (estructura, separadores, encodings)
5. Permitir descarga directa del archivo desde wizard
6. Incluir validaciones: payslips completos, sin errores, período coherente

---

## 2. Alcance

### Incluye

- Investigación oficial: Layout LRE Dirección del Trabajo (2025)
- Diseño wizard `hr.lre.wizard` con formulario selección período
- Especificación de mapeo: `hr.salary.rule` → columnas LRE
- Implementación generador CSV conforme formato DT
- Validaciones pre-generación (integridad datos, periodo válido)
- Tests de generación LRE (casos: 1 empleado, múltiples, con ajustes)
- Documentación de layout LRE y mapeos
- Soporte para descarga binaria CSV directa

### Fuera de Alcance

- Integración directa con SII (subida/validación SII es NOMINA-03)
- Encriptación/firmado digital (es P2)
- Auditoría SII compliance detallada (es P2)
- Interfaz Web avanzada (es P1, pero minimista)
- Soportar múltiples formatos (solo CSV)

---

## 3. Entradas y Dependencias

### Archivos de Referencia

- `addons/localization/l10n_cl_hr_payroll/models/hr_lre_wizard.py`
- `addons/localization/l10n_cl_hr_payroll/views/hr_lre_wizard_views.xml`
- Documentación DT: Layout LRE (sitio oficial Dirección del Trabajo)
- `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md`

### Artefactos Relacionados

- `CLEAN_ROOM_PROTOCOL_OPERATIVO.md` → Roles Equipo A vs B
- `MATRIZ_SII_CUMPLIMIENTO.md` → Requisitos DT para LRE
- `NOMINA-01-MOTOR-CALC` → Payslips ya calculados disponibles

### Entorno Necesario

- Odoo 19 con `l10n_cl_hr_payroll` instalado
- Payslips Fase P0 generados y disponibles en database
- Documentación DT descargable (PDF o web oficial)
- Docker compose para tests

---

## 4. Tareas

### Fase 1: Investigación y Especificación (Payroll Lead)

1. Descargar layout oficial LRE desde sitio Dirección del Trabajo (2025)
2. Documentar estructura CSV: encabezados, columnas, tipos datos, validaciones
3. Crear matriz mapeo: `hr.salary.rule.category` → columnas LRE
4. Especificar validaciones pre-generación (qué campos son obligatorios)
5. Documentar en `ESPECIFICACION_LRE_LAYOUT.md`

### Fase 2: Diseño Wizard

6. Diseñar formulario wizard: seleccionar mes, año, empresa (si multicompany)
7. Especificar botones: "Generar", "Descargar", "Cancelar"
8. Definir confirmación antes de generar (es acción irreversible)
9. Crear modelo `hr.lre.wizard` con campos: date_from, date_to, company_id

### Fase 3: Implementación Generador

10. Implementar método `_generate_lre_data()` que extrae payslips del período
11. Mapear cada `hr.payslip.line` a columna CSV usando matriz especificada
12. Implementar validaciones: cheques de integridad, campos obligatorios
13. Generar CSV con encoding UTF-8, separador según DT (coma o tabulación)
14. Crear método `download_lre()` que retorna binario CSV para descarga

### Fase 4: Validaciones y Casos Borde

15. Implementar validación: "Payslips en periodo sin errores"
16. Implementar validación: "Todos empleados tienen datos obligatorios (RUT, nombre, etc.)"
17. Implementar validación: "Descuentos y haberes no son negativos (excepto ajustes)"
18. Implementar manejo de casos: empleado sin ISAPRE/AFP (campos 0 o vacío)

### Fase 5: Tests e Integración

19. Crear test: generar LRE con 1 empleado, validar estructura CSV
20. Crear test: generar LRE con múltiples empleados, comparar totales
21. Crear test: LRE con descuentos especiales (licencia, bonificación)
22. Crear test de integración: calcular payslip P0 → generar LRE → validar CSV

### Fase 6: Documentación y Entrega

23. Documentar layout LRE y ejemplos
24. Documentar cómo usar wizard (pasos UI)
25. Crear README: "Cómo generar LRE en Odoo 19"
26. Validar contra MATRIZ_SII_CUMPLIMIENTO.md

---

## 5. Entregables

| Archivo | Ubicación | Contenido |
|---------|-----------|-----------|
| `hr_lre_wizard.py` | `addons/localization/l10n_cl_hr_payroll/models/` | Modelo wizard + generador CSV |
| `hr_lre_wizard_views.xml` | `addons/localization/l10n_cl_hr_payroll/views/` | Formulario wizard UI |
| `test_generacion_lre_p1.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests generación y validación CSV |
| `ESPECIFICACION_LRE_LAYOUT.md` | `docs/l10n_cl_hr_payroll/` | Layout oficial + mapeos + ejemplos |
| `GUIA_GENERACION_LRE.md` | `docs/l10n_cl_hr_payroll/` | Tutorial usuario: cómo generar LRE |
| `muestras_lre/*.csv` | `docs/l10n_cl_hr_payroll/muestras/` | Ejemplos CSV generados (anonimizados) |

---

## 6. Criterios de Aceptación

| Criterio | Métrica | Umbral | Verificación |
|----------|---------|--------|--------------|
| **Completitud Investigación** | Layout DT documentado + campos mapeados | 100% | Checklist vs DT oficial |
| **Funcionalidad Wizard** | Wizard visible, formulario carga, genera CSV | Sí | Manual test en UI |
| **Formato CSV Correcto** | CSV cumple estructura DT (columnas, separadores, encoding) | 100% | Validación structure.csv |
| **Precisión Datos** | Valores CSV = valores payslip originales | ±0.01 CLP | Tests unitarios |
| **Cobertura Tests** | % tests generador LRE | ≥85% | Reporte coverage |
| **Descarga Funcional** | Usuario descarga CSV desde wizard sin errores | Sí | Manual test |
| **Documentación** | Especificación completa + guía usuario + ejemplos | Sí | Revisión manual |

---

## 7. Pruebas

### 7.1 Pruebas Unitarias

**Test 1: Estructura CSV Básica**
- Generar LRE mes 10/2025, 1 empleado
- Validar: encabezados presentes, tipos datos correctos, separadores válidos
- Esperado: CSV parseable con 1 línea datos

**Test 2: Múltiples Empleados**
- Generar LRE mes 10/2025, 5 empleados
- Validar: CSV tiene 5 líneas datos + encabezados
- Verificar: totales fila = suma valores payslips

**Test 3: Descuentos Especiales**
- Payslip con descuento APV, préstamo, bonificación
- Generar LRE
- Verificar: columnas corresponden a descuentos especiales, valores correctos

**Test 4: Casos Nulos**
- Empleado sin ISAPRE (campo nulo en payslip)
- Generar LRE
- Esperado: CSV maneja nulos según especificación DT (0 o vacío)

**Test 5: Validación Pre-Generación**
- Intentar generar LRE sin payslips en periodo
- Esperado: error + mensaje "No payslips for period"
- Intentar generar con payslip incompleto (falta campo RUT)
- Esperado: error + mensaje "Incomplete payslip data"

### 7.2 Pruebas de Integración

**Test 6: Flujo Completo P0→LRE**
- Cargar indicadores P0 (UF, IPC)
- Generar payslip Fase P0
- Ejecutar wizard generación LRE
- Validar: CSV contiene datos calculados en P0

**Test 7: Descarga Binaria**
- Generar LRE desde wizard
- Presionar "Descargar"
- Validar: archivo binario recibido, nombre correcto (ej: `LRE_2025_10.csv`)

---

## 8. Clean-Room (Protocolo Legal)

### Roles y Restricciones

| Rol | Persona | Restricciones | Evidencia |
|-----|---------|---------------|-----------|
| **Payroll Lead (Equipo A)** | Nómina Specialist | ✅ Acceso docs DT oficial<br>✅ Puede revisar Enterprise (si existe)<br>❌ NO copiar código literal | `ESPECIFICACION_LRE_LAYOUT.md` |
| **Auditor Legal** | Legal Counsel | ✅ Revisa layout vs legislación DT | `audits/nomina_02_lre_review.md` |
| **Desarrollador CE (Equipo B)** | Backend Dev | ❌ NO acceso Enterprise<br>✅ Solo specs layout DT | Commits en `l10n_cl_hr_payroll` |

### Evidencias Requeridas

1. Especificación layout LRE desde fuente oficial (Dirección del Trabajo)
2. Matriz mapeo: `hr.salary.rule` → columnas LRE (no código literal)
3. Ejemplos CSV anonimizados (sin datos reales clientes)
4. Aprobación auditor legal: "CSV cumple formato DT"

---

## 9. Riesgos y Mitigaciones

| ID | Riesgo | Probabilidad | Impacto | Severidad | Mitigación |
|----|--------|--------------|---------|-----------|------------|
| **R-LRE-01** | Layout DT desactualizado o incompleto | Media (0.3) | Alto (4) | 1.2 | Validar con DT oficial antes codificar |
| **R-LRE-02** | CSV generado rechazado por SII (validación formato) | Baja (0.2) | Crítico (5) | 1.0 | Tests estructura vs spec DT + auditoría |
| **R-LRE-03** | Descuentos duplicados o faltantes en CSV | Media (0.4) | Alto (4) | 1.6 | Tests exhaustivos mapeo payslip→CSV |
| **R-LRE-04** | Encoding UTF-8 problemas (caracteres especiales) | Baja (0.2) | Medio (3) | 0.6 | Tests con nombres acentuados/caracteres |

### Triggers de Decisión

- Si **R-LRE-01** ocurre: Pausar desarrollo hasta obtener layout DT actualizado
- Si **R-LRE-02** ocurre: Ejecutar auditoría formal con SII antes entrega

---

## 10. Trazabilidad

### Brecha que Cierra

| Brecha P1 | Artefacto que la cierra | Métrica |
|-----------|------------------------|---------|
| Generación LRE manual ineficiente | `hr_lre_wizard.py` + `ESPECIFICACION_LRE_LAYOUT.md` | Wizard funcional + CSV validado |
| Falta integración datos Odoo → DT | Test integración P0→LRE exitoso | Payslip → CSV con precisión ±0.01 CLP |

### Relación con Master Plan v2

- **Fase 1 (Mes 1-2):** Hito Nómina — "LRE Automático"
- **P0:** Motor cálculo (NOMINA-01) → datos payslip
- **P1:** Wizard LRE (NOMINA-02) → CSV DT
- **P1:** Tests integración (NOMINA-03) → validación E2E

---

## 11. Governance y QA Gates

### Gates Aplicables

| Gate | Criterio | Responsable |
|------|----------|-------------|
| **Gate-Legal** | Auditor Legal valida CSV vs DT spec | Legal |
| **Gate-Calidad** | Tests ≥85% + estructura CSV correcta | QA |
| **Gate-SII** | Layout confirmado vs Dirección del Trabajo | Payroll Lead |

### Checklist Pre-Entrega

- [ ] Layout LRE documentado (fuente DT oficial)
- [ ] Matriz mapeo `hr.salary.rule` → columnas CSV completa
- [ ] Wizard funcional: formulario carga, genera CSV, descargable
- [ ] Tests generación ≥85% cobertura, todos pasan
- [ ] Ejemplos CSV generados (anonimizados)
- [ ] Documentación técnica + guía usuario completas
- [ ] Auditor legal revisó y aprobó layout vs DT

---

## 12. Próximos Pasos

1. **Ejecutar Prompt:** Payroll Lead implementa tareas Fases 1-6
2. **Validación Layout:** Confirmar layout DT vs implementación
3. **QA Testing:** Ejecutar tests, validar cobertura
4. **Legal Review:** Auditor Legal aprueba CSV vs DT spec
5. **Entrega:** Código merged, NOMINA-03 (Tests Integración) puede iniciar

---

## 13. Notas Adicionales

### Supuestos

- Payslips Fase P0 están completos y sin errores
- Layout LRE 2025 disponible en sitio Dirección del Trabajo (público)
- Equipo tiene acceso a documentación DT oficial
- Cambios legislativos 2025 ya contemplados en MATRIZ_SII_CUMPLIMIENTO.md

### Decisiones Técnicas

- **Modelo:** `TransientModel` para wizard (no persiste datos generación)
- **CSV:** UTF-8 encoding, separador coma (conforme DT 2025)
- **Descarga:** Binario directo vía Odoo `ir.attachment` temporal
- **Validaciones:** Python puro (NO SQL/ORM queries pesadas)

---

**Versión:** 1.0
**Estado:** Ready para ejecución
**Owner:** Payroll Lead
**Aprobado por:** Tech Lead (2025-11-08)
