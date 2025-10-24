# 🔄 PLAN DE MIGRACIÓN: NÓMINAS ODOO 11 → ODOO 19

**Fecha:** 2025-10-22  
**Origen:** Odoo 11 CE (l10n_cl_hr v11.0.2.7.0) - Producción desde 2018  
**Destino:** Odoo 19 CE (l10n_cl_hr_payroll - nuevo)  
**Arquitectura destino:** Microservicios + IA

---

## 🎯 RESUMEN EJECUTIVO

### **Desafío**
Migrar 7 años de datos de nóminas (2018-2025) preservando:
- ✅ Historial completo de liquidaciones (~50,000 registros)
- ✅ Contratos y cambios históricos
- ✅ Indicadores económicos mensuales
- ✅ Audit trail (Art. 54 CT - 7 años retención)
- ✅ Integridad referencial

### **Complejidad Identificada**
- **Modelos a migrar:** 25+ modelos
- **Registros totales:** ~800,000
- **Cambio arquitectónico:** Monolito → Microservicios
- **Sistema dual:** Legacy + SOPA 2025 (fecha corte: 1 agosto 2025)

---

## 📊 ANÁLISIS MÓDULO ODOO 11

### **l10n_cl_hr v11.0.2.7.0**

**Características:**
- ✅ Sistema SOPA 2025 (Sistema Optimizado Payroll Avanzado)
- ✅ Reforma Previsional 2025 implementada
- ✅ Audit trail compliance (Art. 54 CT)
- ✅ Analytics enterprise (NumPy/Pandas)
- ✅ AI Chat integration (microservicio)
- ✅ 80+ modelos Python
- ✅ Previred + Finiquito

**Arquitectura:**
- 13 niveles de herencia en `compute_sheet()`
- 35 archivos heredan de `hr.payslip`
- Sistema dual: Legacy (pre-2025) + SOPA (post-2025)

---

## 🗂️ MODELOS A MIGRAR

### **MAESTROS (60 registros)**
- `hr.afp` → 10 registros
- `hr.isapre` → 15 registros
- `hr.apv` → 8 registros
- `hr.ccaf` → 5 registros
- `hr.mutualidad` → 3 registros
- `hr.centroscostos` → 20 registros

### **EMPLEADOS + CONTRATOS (450 registros)**
- `hr.employee` → 150 empleados
- `hr.contract` → 300 contratos (historial)

**Campos críticos:**
- AFP, ISAPRE, APV (Many2one)
- Cotizaciones en UF
- Cargas familiares (3 tipos)
- Colación, movilización (Art. 41 CT)
- Gratificación legal
- Centro de costos

### **LIQUIDACIONES (750,000 registros)**
- `hr.payslip` → 50,000 liquidaciones
- `hr.payslip.line` → 500,000 líneas
- `hr.payslip.input` → 200,000 inputs

**Campos críticos:**
- `indicators_snapshot` (JSON - SOPA 2025)
- `movimientos_personal` (códigos 0-12)
- Sistema dual (Legacy/SOPA según fecha)

### **INDICADORES (672 registros)**
- `hr.indicadores` → 84 meses (2018-2025)
- `hr.indicadores.impuesto.tramo` → 588 tramos

### **AUDIT TRAIL (50,000 registros)**
- `hr.payroll.audit.trail` → Compliance Art. 54 CT

---

## 🔧 ESTRATEGIA DE MIGRACIÓN

### **ENFOQUE: 6 FASES**

```
FASE 1: Maestros (1 día)
FASE 2: Empleados + Contratos (2 días)
FASE 3: Indicadores Económicos (1 día)
FASE 4: Liquidaciones por año (5 días)
FASE 5: Audit Trail (1 día)
FASE 6: Validación (2 días)

TOTAL: 12 días
```

---

## 📋 SCRIPTS DE MIGRACIÓN

### **1. Maestros**

```python
# migration/migrate_masters.py
class MasterDataMigrator:
    def migrate_afp(self):
        # Extrae de Odoo 11
        # Inserta en Odoo 19
        # Retorna mapeo old_id → new_id
```

### **2. Contratos**

```python
# migration/migrate_contracts.py
class ContractMigrator:
    def migrate_contracts(self, employee_id_map):
        # Migra historial completo
        # Preserva fechas y cambios
        # Mapea relaciones (AFP, ISAPRE)
```

### **3. Liquidaciones (por año)**

```python
# migration/migrate_payslips.py
class PayslipMigrator:
    def migrate_payslips_by_year(self, year):
        # Migra año completo
        # Preserva indicators_snapshot (JSON)
        # Migra líneas e inputs
```

### **4. Validación**

```python
# migration/validate_migration.py
class MigrationValidator:
    def validate_counts(self):
        # Verifica conteos
    
    def validate_totals(self):
        # Compara totales por año
    
    def validate_relationships(self):
        # Verifica integridad referencial
```

---

## ⚠️ CONSIDERACIONES CRÍTICAS

### **1. Sistema Dual (Legacy/SOPA)**

**Fecha corte:** 1 agosto 2025

```python
SOPA_REFORMA_DATE = datetime(2025, 8, 1).date()

# Liquidaciones pre-agosto 2025 → Legacy
# Liquidaciones post-agosto 2025 → SOPA 2025
```

**Impacto:**
- Diferentes categorías salariales
- Diferentes reglas de cálculo
- Snapshot de indicadores (solo SOPA)

### **2. Indicadores Económicos**

**Crítico:** Valores históricos necesarios para recálculos

- UF, UTM, UTA mensuales (2018-2025)
- Tramos impuesto único (7 tramos x 84 meses)
- Topes imponibles (AFP, IPS, AFC)
- Asignaciones familiares

### **3. Audit Trail**

**Legal:** Art. 54 Código del Trabajo (7 años retención)

- Todos los cambios en liquidaciones
- Usuario, timestamp, IP
- Valores antes/después (JSON)

### **4. Valores en UF**

**Conversión:** Cotizaciones ISAPRE, APV en UF

- Almacenar valor UF del mes
- Permitir recálculo histórico

---

## 🚀 EJECUCIÓN

### **Comando principal**

```bash
# Ejecutar migración completa
python migration/run_migration.py \
  --source-db "postgresql://user:pass@host:5432/odoo11" \
  --target-db "postgresql://user:pass@host:5432/odoo19" \
  --start-year 2018 \
  --end-year 2025 \
  --validate
```

### **Opciones**

```bash
--dry-run          # Simular sin escribir
--year 2023        # Migrar solo un año
--skip-validation  # Saltar validación
--rollback         # Revertir migración
```

---

## ✅ CHECKLIST DE VALIDACIÓN

- [ ] Conteo de registros (±5%)
- [ ] Totales por año (±$1,000)
- [ ] Integridad referencial (0 huérfanos)
- [ ] Snapshot JSON válido
- [ ] Audit trail completo
- [ ] Indicadores 2018-2025
- [ ] Contratos con historial
- [ ] Recálculo liquidación muestra

---

## 📊 ESTIMACIÓN

**Esfuerzo:** 12 días (96 horas)  
**Equipo:** 1 dev Python + 1 DBA  
**Riesgo:** 🟡 Medio  
**Rollback:** ✅ Posible

---

## 📄 PRÓXIMOS PASOS

1. ✅ Aprobar plan de migración
2. ⏳ Crear backup completo Odoo 11
3. ⏳ Preparar ambiente Odoo 19 (staging)
4. ⏳ Ejecutar FASE 1 (maestros)
5. ⏳ Validar FASE 1
6. ⏳ Continuar fases 2-6

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ LISTO PARA REVISIÓN
