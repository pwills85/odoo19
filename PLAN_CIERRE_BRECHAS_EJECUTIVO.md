# 🎯 Plan Ejecutivo de Cierre de Brechas DTE

**Ingeniero Senior:** Pedro  
**Fecha:** 2025-10-30  
**Duración:** 2 días (8-10 horas)  
**Objetivo:** Cerrar 4 brechas críticas identificadas

---

## ✅ SÍ, Tengo Todo el Conocimiento Necesario

### 📚 Información Disponible

✅ **Código fuente completo** analizado línea por línea  
✅ **Arquitectura del sistema** comprendida (libs + models + reports)  
✅ **Hallazgos verificados** con evidencias técnicas precisas  
✅ **Soluciones diseñadas** con código exacto a implementar  
✅ **Tests definidos** para cada corrección  
✅ **Experiencia Odoo 19 CE** + localización chilena DTE

---

## 🚀 Plan de Ejecución (2 Días)

### Day 1 - Morning (4h): Correcciones Críticas

#### 1️⃣ Corregir Firma XML (30 min) - P0 🔴

**Archivo:** `libs/xml_signer.py`

**Cambios:**
- Línea 76: `state != 'active'` → `state not in ('valid', 'expiring_soon')`
- Línea 93: `certificate_file` → `cert_file`
- Línea 94: `password` → `cert_password`

**Test:** Firmar con certificado válido y expiring_soon

---

#### 2️⃣ Crear Adaptadores DTE (3h) - P1 🟠

**Archivo:** `models/account_move_dte.py`

**Implementar:**
- `_prepare_base_dte_data()` - Datos comunes
- `_adapt_dte_33()` - Factura con IVA
- `_adapt_dte_34()` - Factura exenta (MntExe)
- `_adapt_dte_52()` - Guía despacho (transporte)
- `_adapt_dte_56()` - Nota débito (referencia)
- `_adapt_dte_61()` - Nota crédito (referencia)

**Tests:** Validar estructura de cada tipo DTE

---

### Day 1 - Afternoon (2h): Reportes

#### 3️⃣ Corregir Reportes PDF (30 min) - P1 🟡

**Archivos:**
- `reports/dte_invoice_report.xml` - Cambiar `dte_type` → `dte_code`
- `report/account_move_dte_report.py` - Corregir nombre helper

**Test:** Generar PDF y verificar nombre archivo

---

#### 4️⃣ Tests Integración (1.5h)

**Crear:** `tests/test_dte_integration_complete.py`

**Flujos completos:**
- DTE 33: Factura → Generar → Firmar → PDF
- DTE 34: Factura exenta completa
- DTE 56/61: Con referencia obligatoria

---

### Day 2 - Morning (2h): Limpieza y Docs

#### 5️⃣ Corregir Herencia (5 min) - P2 🟢

**Archivo:** `models/account_move_dte.py`  
**Cambio:** Remover `_name = 'account.move'` (línea 35)

---

#### 6️⃣ Documentación (1h)

**Actualizar:**
- `README.md` - Tipos DTE soportados
- `CHANGELOG.md` - Correcciones realizadas
- Docstrings en métodos nuevos

---

### Day 2 - Afternoon (2h): Validación Final

#### 7️⃣ Tests Completos

```bash
# Ejecutar suite completa
python3 odoo-bin -d test_db -i l10n_cl_dte --test-enable

# Tests específicos
python3 -m pytest tests/test_dte_*.py -v --cov
```

#### 8️⃣ Validación Manual

- ✅ Crear factura DTE 33
- ✅ Crear factura exenta DTE 34
- ✅ Crear guía despacho DTE 52
- ✅ Crear nota crédito DTE 61
- ✅ Generar PDFs de todos
- ✅ Validar XMLs contra XSD

---

## 📊 Criterios de Aceptación

### ✅ Mínimo para Producción

- [ ] P0 corregido: Sistema firma DTEs
- [ ] P1 datos: DTEs 34/52/56/61 generan XML válido
- [ ] P1 reportes: PDFs correctos
- [ ] Tests: 85%+ coverage
- [ ] Validación XSD: 100% tipos pasan
- [ ] Documentación: Actualizada

### ✅ Opcional (Nice to Have)

- [ ] P2: Herencia limpia
- [ ] CI/CD: Pipeline automatizado
- [ ] Monitoring: Health checks
- [ ] Performance: Benchmarks

---

## 🎯 Entregables

1. **Código corregido** (4 archivos modificados)
2. **Tests nuevos** (3 archivos test)
3. **Documentación** (README + CHANGELOG)
4. **Reporte validación** (PDF con evidencias)

---

## 💪 Confianza Técnica

**Nivel de confianza:** 95%

**Razones:**
- ✅ Código analizado completamente
- ✅ Soluciones probadas en Odoo similar
- ✅ Tests diseñados antes de implementar
- ✅ Arquitectura bien estructurada
- ✅ Documentación SII disponible

**Riesgos identificados:**
- ⚠️ Certificado de prueba (necesario para tests)
- ⚠️ Ambiente Maullín (pruebas SII reales)

---

## 🚦 Semáforo de Ejecución

| Tarea | Complejidad | Riesgo | Tiempo |
|-------|-------------|--------|--------|
| Firma XML | 🟢 Baja | 🟢 Bajo | 30 min |
| Adaptadores | 🟡 Media | 🟡 Medio | 3h |
| Reportes | 🟢 Baja | 🟢 Bajo | 30 min |
| Tests | 🟡 Media | 🟢 Bajo | 2h |
| Herencia | 🟢 Baja | 🟢 Bajo | 5 min |

**Total:** 8-10 horas | Riesgo General: 🟢 BAJO

---

## ✅ Conclusión

**SÍ, dispongo de TODO el conocimiento e información necesaria para:**

1. ✅ Planificar el cierre completo
2. ✅ Implementar las correcciones
3. ✅ Crear tests de validación
4. ✅ Documentar los cambios
5. ✅ Validar el resultado final

**Próximo paso:** Iniciar implementación siguiendo este plan.
