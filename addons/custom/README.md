# Módulos Personalizados

Este directorio contiene los módulos personalizados desarrollados específicamente para este proyecto.

## 📁 Estructura

```
custom/
├── payroll_cl/                    # Gestión de nóminas chilena
│   ├── __init__.py
│   ├── __manifest__.py
│   ├── models/
│   ├── views/
│   ├── reports/
│   └── security/
├── edi_cl_custom/                 # Extensiones de facturación electrónica
├── reports_cl/                    # Reportes personalizados
└── README.md
```

## 🆕 Crear Nuevo Módulo

### Paso 1: Crear Estructura

```bash
mkdir -p addons/custom/nombre_modulo/{models,views,security,reports,data}
cd addons/custom/nombre_modulo
```

### Paso 2: Crear __init__.py

**archivo:** `addons/custom/nombre_modulo/__init__.py`

```python
# -*- coding: utf-8 -*-
from . import models
```

### Paso 3: Crear __manifest__.py

**archivo:** `addons/custom/nombre_modulo/__manifest__.py`

```python
# -*- coding: utf-8 -*-
{
    'name': 'Nombre del Módulo',
    'version': '19.0.1.0.0',
    'category': 'Personalizaciones',
    'summary': 'Descripción breve del módulo',
    'author': 'Tu Nombre/Empresa',
    'license': 'AGPL-3',
    'depends': [
        'base',
        'account',
        'l10n_cl',  # Si usa localización chilena
    ],
    'data': [
        'security/ir.model.access.csv',
        'views/views.xml',
    ],
    'installable': True,
    'auto_install': False,
    'images': ['static/description/icon.png'],
}
```

### Paso 4: Crear Modelos

**archivo:** `addons/custom/nombre_modulo/models/__init__.py`

```python
from . import modelo_nombre
```

**archivo:** `addons/custom/nombre_modulo/models/modelo_nombre.py`

```python
# -*- coding: utf-8 -*-
from odoo import models, fields, api

class MiModelo(models.Model):
    _name = 'nombre_modulo.mi_modelo'
    _description = 'Descripción del modelo'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    
    name = fields.Char(string='Nombre', required=True)
```

### Paso 5: Crear Vistas

**archivo:** `addons/custom/nombre_modulo/views/views.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data>
        <!-- Actions -->
        <record id="action_mi_modelo" model="ir.actions.act_window">
            <field name="name">Mi Modelo</field>
            <field name="res_model">nombre_modulo.mi_modelo</field>
            <field name="view_mode">tree,form</field>
        </record>

        <!-- Menu Items -->
        <menuitem id="menu_mi_modelo" name="Mi Modelo" action="action_mi_modelo" parent="account.menu_finance" sequence="10" />
    </data>
</odoo>
```

### Paso 6: Configurar Acceso

**archivo:** `addons/custom/nombre_modulo/security/ir.model.access.csv`

```csv
id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink
access_mi_modelo_user,mi_modelo_user,model_nombre_modulo_mi_modelo,base.group_user,1,1,1,0
access_mi_modelo_admin,mi_modelo_admin,model_nombre_modulo_mi_modelo,base.group_system,1,1,1,1
```

## 📦 Módulos en Desarrollo

### payroll_cl - Gestión de Nóminas Chilena

**Estado:** En planificación

**Características Previstas:**
- Cálculo automático de sueldos
- Cálculos de descuentos (AFP, Salud, Impuesto)
- Generación de documentos de pago
- Reportes de nómina
- Integración con contabilidad

**Dependencias:**
- hr
- hr_payroll
- l10n_cl

**Responsable:** Equipo de Desarrollo

---

### edi_cl_custom - Extensiones de Facturación Electrónica

**Estado:** En planificación

**Características Previstas:**
- Validaciones adicionales de DTE
- Integraciones con sistemas externos
- Reportes de DTE personalizados
- Webhooks para actualizaciones

**Dependencias:**
- l10n_cl_edi
- web

**Responsable:** Equipo de Desarrollo

---

### reports_cl - Reportes Personalizados

**Estado:** En planificación

**Características Previstas:**
- Reportes financieros personalizados
- Reportes de análisis de ventas
- Reportes de gestión
- Dashboards

**Dependencias:**
- account_reports
- web_unseen

**Responsable:** Equipo de Desarrollo

---

## 🔄 Instalación de Módulo Personalizado

```bash
# Hacer scripts ejecutables
chmod +x scripts/*.sh

# Opción 1: Interfaz web
1. Apps → Actualizar lista de aplicaciones
2. Buscar el módulo
3. Click en "Instalar"

# Opción 2: Línea de comandos
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    --addons-path=/opt/odoo/addons,/opt/odoo/server/addons \
    --init=nombre_modulo \
    --stop-after-init

# Opción 3: Actualizar si está instalado
docker exec odoo19_app odoo \
    -c /etc/odoo/odoo.conf \
    -d odoo \
    -u nombre_modulo \
    --stop-after-init
```

## 📚 Convenciones y Mejores Prácticas

### Nombres
- Módulo: `snake_case` (ej: `payroll_cl`)
- Modelo: `nombre_modulo.modelo_nombre` (ej: `payroll_cl.employee_salary`)
- Campo: `snake_case` (ej: `fecha_pago`)
- Método: `snake_case` (ej: `calcular_neto`)

### Estructura
- Mantener archivos organizados por funcionalidad
- Usar `models/`, `views/`, `security/`, `reports/`
- Documentar código con docstrings

### Testing
- Crear tests en `tests/` si es necesario
- Ejecutar tests antes de commit
- Mantener cobertura >80%

## 🔗 Referencias

- [Documentación Odoo - Development](https://www.odoo.com/documentation/19.0/developer/)
- [Módulos Comunitarios Chile](https://github.com/odoo-chile)
- [Mejores Prácticas Odoo](https://github.com/OCA/server-tools)

## 📋 Checklist para Nuevo Módulo

- [ ] Crear estructura de directorios
- [ ] Implementar `__manifest__.py`
- [ ] Crear modelos en `models/`
- [ ] Crear vistas XML en `views/`
- [ ] Configurar acceso en `security/`
- [ ] Documentar en este README
- [ ] Crear tests
- [ ] Probar instalación
- [ ] Commit a git

## 📞 Contacto

Para preguntas sobre desarrollo de módulos personalizados, contacta al equipo de desarrollo.

---

**Última actualización**: 2025-10-21
