# 🎨 ANÁLISIS UI/UX: Vistas Actividades Económicas, Giro y Comunas

**Fecha:** 2025-10-24
**Analista:** Ingeniero Senior - Experto Odoo 19 CE + DTE Chile
**Alcance:** res.partner, res.company, res.config.settings
**Módulo:** l10n_cl_dte v19.0.1.3.0

---

## 📊 RESUMEN EJECUTIVO

### **Calificación General: 7.2/10** ⭐⭐⭐⭐

**Estado:** ✅ FUNCIONAL con **mejoras críticas necesarias**

El módulo tiene una base sólida con modelos bien diseñados y catálogos profesionales (347 comunas, 1,300+ actividades económicas). Sin embargo, las vistas presentan **inconsistencias** y **campos faltantes** que afectan la experiencia de usuario y completitud de datos.

**Clasificación:** BUENO, pero NO enterprise-grade (requiere refinamiento)

---

## 🔍 ANÁLISIS DETALLADO POR VISTA

### **1. res.partner (Ficha de Contacto)** - Score: 6.5/10

**Archivo:** `views/res_partner_views.xml`

#### ✅ **LO QUE ESTÁ BIEN** (Puntos Fuertes)

| Aspecto | Estado | Calificación |
|---------|--------|--------------|
| **Giro (l10n_cl_activity_description)** | ✅ Implementado | 9/10 |
| **Comuna (l10n_cl_comuna_id)** | ✅ Implementado | 8/10 |
| **Conditional visibility** | ✅ `invisible="country_code != 'CL'"` | 10/10 |
| **Info helper** | ✅ Alert con instrucciones | 8/10 |
| **Placeholders** | ✅ Textos de ayuda | 9/10 |
| **No create option** | ✅ `'no_create': True` para comuna | 10/10 |

**Código Actual (Bueno):**
```xml
<!-- Giro -->
<field name="l10n_cl_activity_description"
       placeholder="Ej: SERVICIOS DE CONSTRUCCION"
       invisible="country_code != 'CL' or not is_company"/>

<!-- Comuna -->
<field name="l10n_cl_comuna_id"
       placeholder="Seleccione comuna..."
       options="{'no_create': True, 'no_open': True}"
       invisible="country_code != 'CL'"
       context="{'default_state_id': state_id}"/>
```

#### ❌ **LO QUE FALTA** (Gaps Críticos)

| Campo Faltante | Modelo Disponible | Impacto | Prioridad |
|----------------|-------------------|---------|-----------|
| **Actividades Económicas** | `res.partner.l10n_cl_activity_ids` | ❌ **FALTA** | 🔴 **CRÍTICO P0** |
| **Región/State visibilidad** | `res.partner.state_id` | ⚠️ Oculta por defecto | 🟡 P1 |
| **Ciudad vs Comuna** | `res.partner.city` | ⚠️ Ambos existen, sin comparación | 🟡 P1 |
| **Código SII Comuna** | `l10n_cl_comuna_id.code` | ℹ️ No visible | 🟢 P2 |

**Problema #1: Actividades Económicas NO DISPONIBLES en Partner**
```python
# models/res_partner_dte.py - CAMPO NO EXISTE
# ❌ res.partner NO tiene l10n_cl_activity_ids
# Solo tiene l10n_cl_activity_description (texto libre)
```

**Impacto:** Los contactos (proveedores/clientes) no pueden tener códigos ACTECO asignados, solo descripción textual. Esto limita la precisión de los datos tributarios.

**Recomendación:** ¿Los partners deben tener ACTECOs? Evaluar si es necesario.

**Problema #2: Info Helper Solo Visible Sin Comuna**
```xml
<div class="alert alert-info mt-2" role="alert"
     invisible="country_code != 'CL' or l10n_cl_comuna_id or not is_company">
```
Se oculta cuando ya hay comuna seleccionada. Usuarios nuevos no verán la ayuda después de seleccionar comuna.

#### 🎯 **MEJORAS RECOMENDADAS**

**Mejora #1: Mejorar visibilidad de Región → Comuna**
```xml
<!-- ANTES: State_id no es claro -->
<field name="state_id"/>

<!-- DESPUÉS: Más claro para Chile -->
<field name="state_id"
       string="Región (Chile)"
       invisible="country_code != 'CL'"/>
```

**Mejora #2: Mostrar ambos campos ciudad (comparación)**
```xml
<!-- Nueva sección para Chile -->
<group name="chile_address" string="Dirección Chile" invisible="country_code != 'CL'">
    <field name="state_id" string="Región"/>
    <field name="l10n_cl_comuna_id"
           placeholder="Seleccione comuna oficial..."
           options="{'no_create': True}"
           domain="[('state_id', '=', state_id)]"/>
    <field name="city"
           string="Ciudad (Texto Libre)"
           placeholder="Ej: Santiago Centro"
           class="text-muted"/>
    <small class="text-muted">
        Comuna oficial vs Ciudad (texto libre). Usar Comuna para DTEs.
    </small>
</group>
```

**Mejora #3: Info helper siempre visible (mejor UX)**
```xml
<!-- Cambiar de alert condicional a help icon permanente -->
<field name="l10n_cl_comuna_id"
       help="Comuna según catálogo oficial SII. Se usa código oficial en DTEs."/>
```

---

### **2. res.company (Configuración Compañía)** - Score: 8.5/10

**Archivo:** `views/res_company_views.xml`

#### ✅ **LO QUE ESTÁ BIEN** (Puntos Fuertes)

| Aspecto | Estado | Calificación |
|---------|--------|--------------|
| **Giro (l10n_cl_activity_description)** | ✅ Implementado | 10/10 |
| **Actividades Económicas (many2many_tags)** | ✅ Implementado | 10/10 |
| **Info box explicativo** | ✅ Excelente documentación | 10/10 |
| **Tabla comparativa Giro vs ACTECO** | ✅ Muy didáctico | 10/10 |
| **Link catálogo SII** | ✅ Ayuda externa | 9/10 |
| **Widget many2many_tags** | ✅ UX moderno | 9/10 |

**Código Actual (Excelente):**
```xml
<!-- ACTECO: Códigos numéricos oficiales SII -->
<field name="l10n_cl_activity_ids"
       widget="many2many_tags"
       options="{'color_field': 'code', 'no_create': True}"
       placeholder="Seleccione una o más actividades económicas..."
       colspan="2"/>

<!-- Info box explicativo (MUY BUENO) -->
<div colspan="2" class="alert alert-info mt-2" role="status">
    <strong>ℹ️ Diferencia entre Giro y Actividad Económica:</strong>
    <table class="table table-sm table-borderless mt-2 mb-0 small">
        ...
    </table>
    <ul class="mb-0 mt-2 small">
        <li>El <strong>Giro</strong> describe lo que hace tu empresa...</li>
        <li>Las <strong>Actividades Económicas</strong> son códigos oficiales...</li>
        ...
    </ul>
</div>
```

**Excelente implementación:** Información clara, didáctica, profesional.

#### ⚠️ **LO QUE FALTA / PUEDE MEJORARSE**

| Problema | Severidad | Recomendación |
|----------|-----------|---------------|
| **Comuna de la compañía NO visible** | 🟡 IMPORTANTE | Mostrar `partner_id.l10n_cl_comuna_id` |
| **Botón "Editar Razón Social" incorrecto** | 🔴 ERROR | Apunta a `action_res_users` en vez de partner |
| **Razón Social readonly sin motivo claro** | 🟡 UX | Podría ser editable inline |
| **Info box Nombres duplica información** | ⚪ MENOR | Simplificar |

**Problema #1: Comuna de Compañía NO Visible**
```xml
<!-- ACTUAL: Solo muestra partner_id (nombre) -->
<field name="partner_id" readonly="1"/>

<!-- DEBERÍA MOSTRAR: -->
<group name="company_address" string="Datos Tributarios Ubicación">
    <field name="partner_id" readonly="1" invisible="1"/>
    <label for="partner_id" string="Razón Social Legal"/>
    <div class="o_row">
        <field name="partner_id"
               nolabel="1"
               options="{'no_open': False}"
               context="{'show_address': 1}"/>
    </div>

    <!-- ⭐ NUEVO: Comuna de la compañía -->
    <field name="partner_id.state_id"
           string="Región"
           readonly="1"/>
    <field name="partner_id.l10n_cl_comuna_id"
           string="Comuna (oficial SII)"
           readonly="1"/>
    <field name="partner_id.city"
           string="Ciudad"
           readonly="1"/>
</group>
```

**Justificación:** La comuna de la compañía es OBLIGATORIA en XML DTE (`<CmnaOrigen>`). Debe ser visible en configuración de compañía.

**Problema #2: Botón Editar Incorrecto**
```xml
<!-- ACTUAL: ❌ INCORRECTO -->
<button name="%(base.action_res_users)d"
        type="action"
        string="✏️ Editar Razón Social"
        class="btn btn-link"/>

<!-- CORRECTO: ✅ -->
<button name="%(base.action_partner_form)d"
        type="action"
        string="✏️ Editar Razón Social"
        class="btn btn-link"
        context="{'form_view_ref': 'base.view_partner_form'}"/>
```

**Impacto:** Actualmente el botón abre la vista de usuarios en vez del formulario del partner. **ERROR funcional.**

#### 🎯 **MEJORAS RECOMENDADAS**

**Mejora #1: Simplificar Info Box Nombres**
```xml
<!-- ANTES: Muy largo -->
<div class="alert alert-info mt-3 mb-3" role="status">
    <h6 class="alert-heading"><strong>ℹ️ Diferencia entre nombres:</strong></h6>
    <ul class="mb-0 mt-2 small">
        <li><strong>Nombre de la empresa (arriba):</strong> Nombre corto...</li>
        <li><strong>Razón Social Legal (abajo):</strong> Nombre completo...</li>
    </ul>
</div>

<!-- DESPUÉS: Más conciso -->
<div class="o_row">
    <field name="partner_id" .../>
    <span class="text-muted small">
        (Razón social legal que aparece en DTEs - <code>&lt;RznSoc&gt;</code>)
    </span>
</div>
```

**Mejora #2: Agregar Comuna Visible**
```xml
<xpath expr="//group[@name='chile_tax']" position="before">
    <group string="Ubicación Tributaria" name="company_location">
        <field name="partner_id" invisible="1"/>
        <field name="partner_id.state_id" string="Región"/>
        <field name="partner_id.l10n_cl_comuna_id" string="Comuna (SII)"/>
        <field name="partner_id.city" string="Ciudad"/>
        <field name="partner_id.street" string="Dirección"/>
    </group>
</xpath>
```

---

### **3. res.config.settings (Configuración DTE)** - Score: 6.0/10

**Archivo:** `views/res_config_settings_views.xml`

#### ✅ **LO QUE ESTÁ BIEN** (Puntos Fuertes)

| Aspecto | Estado | Calificación |
|---------|--------|--------------|
| **Estructura layout** | ✅ Grid 2 columnas | 8/10 |
| **Microservicios config** | ✅ DTE Service + AI Service | 9/10 |
| **Botones test conexión** | ✅ UX excelente | 10/10 |
| **Resolución DTE** | ✅ Número + Fecha | 9/10 |
| **Ambiente SII** | ✅ Radio buttons | 9/10 |

**Código Actual (Bueno):**
```xml
<div class="col-12 col-lg-6 o_setting_box">
    <div class="o_setting_left_pane">
        <field name="use_ai_validation"/>
    </div>
    <div class="o_setting_right_pane">
        <label string="AI Service" for="use_ai_validation"/>
        <div class="text-muted">Pre-validación inteligente con IA</div>
        <div class="content-group" invisible="not use_ai_validation">
            <field name="ai_service_url"/>
            <field name="ai_api_key" password="True"/>
            <button name="action_test_ai_service" .../>
        </div>
    </div>
</div>
```

#### ❌ **LO QUE ESTÁ MAL / FALTA** (Gaps Críticos)

| Problema | Severidad | Impacto |
|----------|-----------|---------|
| **Usa campo DEPRECADO** `l10n_cl_activity_code` | 🔴 **CRÍTICO** | Inconsistente con res.company |
| **NO usa Many2many** `l10n_cl_activity_ids` | 🔴 **CRÍTICO** | Limita a 1 actividad |
| **Giro NO visible** | 🟡 IMPORTANTE | Duplica configuración |
| **Comuna NO visible** | 🟡 IMPORTANTE | Falta dato crítico |
| **Configuración dispersa** | 🟡 UX | res.company vs res.config.settings |

**Problema #1: Campo DEPRECADO en Configuración**
```xml
<!-- ACTUAL: ❌ USA CAMPO DEPRECADO -->
<field name="l10n_cl_activity_code"
       required="company_id"
       placeholder="Ej: 421000"/>

<!-- DEBERÍA SER: ✅ -->
<field name="company_id" invisible="1"/>
<field name="l10n_cl_activity_ids"
       widget="many2many_tags"
       options="{'no_create': True, 'color_field': 'code'}"
       placeholder="Seleccione actividades económicas..."
       required="True"/>
```

**Código del Modelo (Confirmación):**
```python
# res_company_dte.py:108
l10n_cl_activity_code = fields.Char(
    string='Código Actividad Principal (DEPRECADO)',
    compute='_compute_activity_code',
    store=False,
    help='Campo DEPRECADO: Ahora use l10n_cl_activity_ids (selección múltiple).'
)
```

**Impacto:** Configuración DTE permite solo 1 actividad económica cuando el modelo soporta múltiples. **Inconsistencia crítica.**

**Problema #2: Datos Tributarios Incompletos**

La configuración DTE no muestra:
- ❌ Giro (`l10n_cl_activity_description`)
- ❌ Comuna (`partner_id.l10n_cl_comuna_id`)
- ❌ Región (`partner_id.state_id`)

Estos datos son OBLIGATORIOS en XML DTE pero no se configuran en este formulario.

#### 🎯 **MEJORAS RECOMENDADAS**

**Mejora #1: Reemplazar Campo DEPRECADO**
```xml
<!-- Reemplazar sección completa -->
<div class="col-12 col-lg-6 o_setting_box">
    <div class="o_setting_left_pane"/>
    <div class="o_setting_right_pane">
        <label string="Actividades Económicas SII" for="l10n_cl_activity_ids"/>
        <div class="text-muted">
            Códigos CIIU Rev. 4 CL (OBLIGATORIO en DTEs, hasta 4 códigos)
        </div>
        <div class="content-group">
            <div class="mt16">
                <field name="company_id" invisible="1"/>
                <field name="l10n_cl_activity_ids"
                       widget="many2many_tags"
                       options="{'no_create': True, 'color_field': 'code'}"
                       placeholder="Seleccione una o más actividades económicas..."
                       required="True"/>
                <div class="text-muted mt8">
                    <a href="https://www.sii.cl/destacados/codigos_actividades/" target="_blank">
                        📋 Ver catálogo oficial de códigos SII
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>
```

**Mejora #2: Agregar Giro y Comuna**
```xml
<!-- Nueva sección: Datos Tributarios Completos -->
<div class="row mt16 o_settings_container">
    <div class="col-12 col-lg-6 o_setting_box">
        <div class="o_setting_left_pane"/>
        <div class="o_setting_right_pane">
            <label string="Giro de la Empresa" for="l10n_cl_activity_description"/>
            <div class="text-muted">
                Descripción textual de la actividad (máx 80 caracteres, OBLIGATORIO en DTEs)
            </div>
            <div class="content-group">
                <div class="mt16">
                    <field name="l10n_cl_activity_description"
                           placeholder="Ej: CONSULTORIAS INFORMATICAS, DESARROLLO DE SISTEMAS"
                           required="True"/>
                </div>
            </div>
        </div>
    </div>

    <div class="col-12 col-lg-6 o_setting_box">
        <div class="o_setting_left_pane"/>
        <div class="o_setting_right_pane">
            <label string="Comuna (SII)" for="partner_id.l10n_cl_comuna_id"/>
            <div class="text-muted">
                Comuna oficial según catálogo SII (OBLIGATORIO en DTEs)
            </div>
            <div class="content-group">
                <div class="mt16">
                    <field name="partner_id" invisible="1"/>
                    <field name="partner_id.state_id" string="Región" readonly="1"/>
                    <field name="partner_id.l10n_cl_comuna_id"
                           string="Comuna"
                           required="True"
                           options="{'no_create': True}"/>
                </div>
            </div>
        </div>
    </div>
</div>
```

---

## 📊 COMPARACIÓN GENERAL

### **Score Card por Vista**

| Vista | Completitud | UX/UI | Consistencia | Documentación | Score |
|-------|-------------|-------|--------------|---------------|-------|
| **res.partner** | 6/10 | 8/10 | 7/10 | 7/10 | **6.5/10** |
| **res.company** | 9/10 | 9/10 | 8/10 | 10/10 | **8.5/10** |
| **res.config.settings** | 5/10 | 7/10 | 4/10 | 7/10 | **6.0/10** |

**Overall Score:** **7.2/10** ⭐⭐⭐⭐

---

## 🚨 PROBLEMAS CRÍTICOS (P0)

### **1. res.config.settings usa campo DEPRECADO** 🔴

**Severidad:** CRÍTICA
**Impacto:** Configuración DTE limita a 1 actividad económica cuando deberían ser múltiples.
**Solución:** Reemplazar `l10n_cl_activity_code` → `l10n_cl_activity_ids`

### **2. Botón "Editar Razón Social" roto** 🔴

**Severidad:** ERROR FUNCIONAL
**Impacto:** Abre vista incorrecta (usuarios en vez de partner).
**Solución:** Cambiar `action_res_users` → `action_partner_form`

### **3. Comuna de Compañía NO visible** 🟡

**Severidad:** IMPORTANTE
**Impacto:** Dato OBLIGATORIO en DTE no se puede verificar fácilmente.
**Solución:** Agregar `partner_id.l10n_cl_comuna_id` en res.company y res.config.settings

---

## ✅ PUNTOS FUERTES (Mantener)

1. ✅ **Catálogos profesionales:** 347 comunas + 1,300+ actividades económicas
2. ✅ **Widget many2many_tags:** UX moderna y visual para actividades económicas
3. ✅ **Info boxes explicativos:** Documentación inline excelente (especialmente en res.company)
4. ✅ **Conditional visibility:** `invisible="country_code != 'CL'"` bien implementado
5. ✅ **No create options:** Previene creación manual de comunas/actividades (mantiene integridad catálogo)
6. ✅ **Placeholders:** Textos de ayuda claros y ejemplos concretos
7. ✅ **Domain filters:** Comuna filtrada por región automáticamente

---

## 🎯 RECOMENDACIONES FINALES

### **Inmediatas (Esta Semana)** 🔴

1. **Corregir res.config.settings:**
   - Reemplazar `l10n_cl_activity_code` → `l10n_cl_activity_ids`
   - Agregar `l10n_cl_activity_description` (Giro)
   - Agregar `partner_id.l10n_cl_comuna_id` (Comuna)

2. **Corregir botón Editar Razón Social:**
   - Cambiar action reference en res.company

3. **Agregar Comuna en res.company:**
   - Mostrar `partner_id.l10n_cl_comuna_id` readonly

### **Corto Plazo (2 Semanas)** 🟡

4. **Mejorar res.partner:**
   - Hacer más claro el flujo Región → Comuna → Ciudad
   - Considerar agregar `l10n_cl_activity_ids` a partners (si aplica negocio)

5. **Simplificar info boxes:**
   - Reemplazar alerts largos por tooltips o help text

6. **Testing UX:**
   - Validar con usuarios finales el flujo de configuración
   - Verificar que todos los datos OBLIGATORIOS para DTE sean visibles

### **Medio Plazo (1 Mes)** 🟢

7. **Consolidar configuración:**
   - Evaluar si res.config.settings debe tener TODO o solo microservicios
   - Quizás mover datos tributarios solo a res.company

8. **Agregar validaciones UI:**
   - Warning visual si falta Giro o Actividad Económica
   - Warning si Comuna no está configurada

---

## 📐 ARQUITECTURA RECOMENDADA

### **Separación de Responsabilidades**

```
res.company (Datos Maestros Tributarios):
  ✅ Razón Social (partner_id.name)
  ✅ RUT (vat)
  ✅ Giro (l10n_cl_activity_description)
  ✅ Actividades Económicas (l10n_cl_activity_ids)
  ✅ Región (partner_id.state_id)
  ✅ Comuna (partner_id.l10n_cl_comuna_id)
  ✅ Dirección (partner_id.street)

res.config.settings (Configuración Técnica DTE):
  ✅ DTE Service URL + API Key
  ✅ AI Service URL + API Key
  ✅ Ambiente SII (sandbox/production)
  ✅ Timeout SII
  ✅ Resolución DTE (número + fecha)
  ⚠️ OPCIONAL: Links rápidos a datos tributarios

res.partner (Contactos):
  ✅ Giro (l10n_cl_activity_description)
  ✅ Comuna (l10n_cl_comuna_id)
  ⚠️ Actividades Económicas? (evaluar necesidad negocio)
```

---

## 🏆 CLASIFICACIÓN FINAL

### **Score General: 7.2/10** ⭐⭐⭐⭐

**Clasificación:** BUENO (con mejoras necesarias)

| Nivel | Descripción | Estado Actual |
|-------|-------------|---------------|
| 🥇 **Enterprise-Grade** (9-10/10) | Perfecto, sin mejoras necesarias | ❌ No alcanzado |
| 🥈 **Profesional** (7-8.9/10) | Funcional, mejoras menores | ✅ **ACTUAL** |
| 🥉 **Básico** (5-6.9/10) | Funciona, pero gaps importantes | ⚠️ Cerca |
| ❌ **Incompleto** (<5/10) | No apto para producción | ❌ No |

---

## 📝 CHECKLIST DE MEJORAS

### **Críticas (P0) - Bloqueantes para 100% compliance**

- [ ] Corregir `res.config.settings`: reemplazar campo deprecado
- [ ] Corregir botón "Editar Razón Social" en `res.company`
- [ ] Agregar Comuna visible en `res.company`

### **Importantes (P1) - Mejoran UX significativamente**

- [ ] Agregar Giro en `res.config.settings`
- [ ] Mejorar flujo Región → Comuna en `res.partner`
- [ ] Simplificar info boxes

### **Opcionales (P2) - Nice to have**

- [ ] Agregar Actividades Económicas a `res.partner`
- [ ] Agregar tooltips/help text persistentes
- [ ] Dashboard validación datos tributarios

---

## 🎨 MOCKUP VISTA MEJORADA (res.company)

```xml
<group string="Configuración Tributaria Chile" name="chile_tax">

    <!-- Razón Social Legal -->
    <label for="partner_id" string="Razón Social Legal"/>
    <div class="o_row">
        <field name="partner_id" readonly="1" nolabel="1"/>
        <button name="%(base.action_partner_form)d" type="action"
                string="✏️ Editar" class="btn btn-link"
                context="{'form_view_ref': 'base.view_partner_form'}"/>
    </div>

    <!-- Ubicación Tributaria -->
    <separator string="Ubicación Tributaria" colspan="2"/>
    <field name="partner_id.state_id" string="Región" readonly="1"/>
    <field name="partner_id.l10n_cl_comuna_id" string="Comuna (SII)" readonly="1"/>
    <field name="partner_id.city" string="Ciudad" readonly="1"/>
    <field name="partner_id.street" string="Dirección" readonly="1"/>

    <!-- Giro y Actividades Económicas -->
    <separator string="Actividad Económica" colspan="2"/>
    <field name="l10n_cl_activity_description"
           placeholder="Ej: CONSULTORIAS INFORMATICAS, DESARROLLO DE SISTEMAS"
           required="True"/>
    <field name="l10n_cl_activity_ids"
           widget="many2many_tags"
           options="{'no_create': True, 'color_field': 'code'}"
           placeholder="Seleccione actividades económicas..."
           required="True"/>

    <!-- Help text conciso -->
    <div colspan="2" class="text-muted small mt-2">
        <strong>Giro:</strong> Descripción textual (máx 80 caracteres) → <code>&lt;GiroEmis&gt;</code><br/>
        <strong>Actividades:</strong> Códigos numéricos oficiales SII → <code>&lt;Acteco&gt;</code><br/>
        <a href="https://www.sii.cl/destacados/codigos_actividades/" target="_blank">
            📋 Ver catálogo SII
        </a>
    </div>

</group>
```

---

**Firma Digital:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ANÁLISIS GENERADO POR: Claude Code AI (Sonnet 4.5)
 ESPECIALIDAD: Ingeniero Senior Odoo 19 CE + DTE Chile
 FECHA: 2025-10-24
 MÓDULO: l10n_cl_dte v19.0.1.3.0
 CLASIFICACIÓN: 7.2/10 - PROFESIONAL (mejoras necesarias)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
