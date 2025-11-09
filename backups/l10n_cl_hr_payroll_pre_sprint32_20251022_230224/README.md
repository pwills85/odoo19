# 💼 l10n_cl_hr_payroll - Gestión de Nóminas Chile

**Versión:** 19.0.1.0.0  
**Odoo:** 19.0 Community Edition  
**Fecha Inicio:** 2025-10-22

---

## 🎯 OBJETIVO

Módulo enterprise-grade de gestión de nóminas para Chile, cumpliendo 100% normativa vigente 2025.

---

## ✅ PROGRESO DE IMPLEMENTACIÓN

### **FASE 1: Fundamentos** (En Progreso)

#### Sprint 1 - Estructura Base ✅ COMPLETADO
- [x] Estructura de carpetas
- [x] `__manifest__.py` completo
- [x] `__init__.py` principal
- [x] models/__init__.py

#### Sprint 1 - Modelos Maestros ✅ COMPLETADO
- [x] `hr_afp.py` - 10 AFPs Chile
- [x] `hr_isapre.py` - ISAPREs
- [x] `hr_apv.py` - APV
- [x] `hr_economic_indicators.py` - UF, UTM, UTA

#### Sprint 1 - Extensión Contratos ✅ COMPLETADO
- [x] `hr_contract_cl.py` - Extiende hr.contract
  - AFP, ISAPRE, APV
  - Colación, movilización
  - Cargas familiares
  - Gratificación
  - Jornada semanal
  - Zona extrema

#### Sprint 1 - Pendiente
- [ ] `hr_payslip.py` - Liquidaciones
- [ ] `hr_payslip_line.py` - Líneas de liquidación
- [ ] `res_company_payroll.py` - Configuración empresa
- [ ] Datos base (AFPs, ISAPREs)
- [ ] Vistas XML básicas
- [ ] Seguridad

---

## 📊 ARQUITECTURA

### **Patrón: EXTENDER, NO DUPLICAR**

```
ODOO 19 CE BASE
├─ hr (empleados) ✅ Usamos
├─ hr_contract ✅ Extendemos
└─ account ✅ Integramos

NUESTRO MÓDULO
├─ Maestros (AFP, ISAPRE, APV)
├─ hr.contract extendido (campos Chile)
├─ hr.payslip (nuevo modelo)
└─ Integración Payroll-Service
```

---

## 🔧 CARACTERÍSTICAS IMPLEMENTADAS

### **Modelos Maestros** ✅
- **hr.afp**: 10 AFPs con tasas actualizadas
- **hr.isapre**: ISAPREs vigentes
- **hr.apv**: Instituciones APV
- **hr.economic.indicators**: Indicadores mensuales (UF, UTM, UTA)

### **Contratos Extendidos** ✅
- AFP con tasa automática
- Sistema salud (FONASA/ISAPRE)
- APV (Régimen A/B)
- Asignaciones Art. 41 CT
- Cargas familiares (3 tipos)
- Gratificación (legal/mensual)
- Jornada semanal (44h estándar)
- Zona extrema

### **Validaciones** ✅
- ISAPRE requiere plan en UF
- Jornada entre 1-45 horas
- Cargas no negativas
- Tasas AFP en rangos válidos

---

## 📋 PRÓXIMOS PASOS

### **Inmediato (Hoy)**
1. Crear modelo `hr_payslip.py`
2. Crear modelo `hr_payslip_line.py`
3. Agregar datos base (AFPs, ISAPREs)
4. Crear vistas XML básicas
5. Configurar seguridad

### **Sprint 2 (Semana 2)**
1. Integración con Payroll-Service
2. Calculadoras (AFP, Salud, Impuesto)
3. Wizard Previred
4. Reportes PDF

---

## 🚀 INSTALACIÓN

```bash
# 1. Copiar módulo
cp -r l10n_cl_hr_payroll /path/to/odoo19/addons/localization/

# 2. Actualizar lista de módulos
./odoo-bin -c odoo.conf -d odoo19_db -u all

# 3. Instalar módulo
# Ir a Apps → Buscar "Chilean Payroll" → Instalar
```

---

## 📚 DOCUMENTACIÓN

Ver carpeta `/docs/payroll-project/` para:
- Plan maestro completo
- Arquitectura detallada
- Fases de implementación
- Modelo de datos
- API contracts
- Testing strategy

---

## ✅ VALIDACIÓN TÉCNICA

✅ **100% validado contra Odoo 19 CE**
- Patrones oficiales
- Nomenclatura correcta
- Herencia con `_inherit`
- Campos válidos
- Validaciones correctas

Ver: `docs/payroll-project/13_VALIDACION_TECNICA_ODOO19.md`

---

**Estado:** 🟡 **EN DESARROLLO**  
**Progreso:** 30% (Fundamentos completados)  
**Siguiente:** Modelo hr_payslip
