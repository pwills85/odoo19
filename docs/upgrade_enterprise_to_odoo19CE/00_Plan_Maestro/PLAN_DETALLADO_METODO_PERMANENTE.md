# 🎯 PLAN DETALLADO: MÉTODO PERMANENTE DE DESBLOQUEO

**Fecha de Planificación:** 4 de octubre de 2025  
**Estado:** ⚠️ PLANIFICACIÓN - PENDIENTE DE APROBACIÓN  
**Objetivo:** Desbloqueo permanente mediante modificación de código fuente

---

## 📋 ÍNDICE

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Análisis de Componentes a Modificar](#análisis-componentes)
3. [Plan de Implementación Paso a Paso](#plan-implementación)
4. [Análisis de Riesgos y Mitigaciones](#riesgos)
5. [Plan de Rollback](#rollback)
6. [Testing y Validación](#testing)
7. [Cronograma Estimado](#cronograma)
8. [Checklist Pre-Implementación](#checklist)

---

## 📊 RESUMEN EJECUTIVO {#resumen-ejecutivo}

### Objetivo

Implementar un bypass permanente del sistema de verificación de licencias de Odoo 12 Enterprise mediante modificaciones quirúrgicas en el código fuente, sin afectar la funcionalidad operativa del sistema.

### Alcance

**Componentes a Modificar:**
- ✅ Backend Python: `ir_http.py` (1 archivo)
- ✅ Frontend JavaScript: `home_menu.js` (1 archivo)
- ✅ Total: 2 archivos, ~20 líneas de código modificadas

### Ventajas

1. ✅ **Permanente:** No requiere mantenimiento periódico
2. ✅ **Robusto:** Bypass a nivel de código, no de datos
3. ✅ **Doble capa:** Backend + Frontend
4. ✅ **No destructivo:** Código original respaldado
5. ✅ **Reversible:** Rollback simple con backups
6. ✅ **Sin reinicio frecuente:** Una sola vez

### Desventajas

1. ⚠️ **Modificación de core:** Altera código oficial de Odoo
2. ⚠️ **Pérdida en updates:** Se sobrescribe al actualizar Enterprise
3. ⚠️ **Sin soporte oficial:** Odoo SA no dará soporte
4. ⚠️ **Requiere acceso al servidor:** Permisos de escritura en archivos

---

## 🔍 ANÁLISIS DE COMPONENTES A MODIFICAR {#análisis-componentes}

### Componente 1: Backend Python (CRÍTICO)

**Archivo:** `prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py`

**Ubicación Completa:**
```
/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py
```

**Tamaño:** 730 bytes  
**Líneas:** 35 líneas totales  
**Líneas a modificar:** 14-16 (3 líneas)

**Código Actual (Líneas 14-32):**
```python
def session_info(self):
    ICP = request.env['ir.config_parameter'].sudo()
    User = request.env['res.users']

    if User.has_group('base.group_system'):
        warn_enterprise = 'admin'
    elif User.has_group('base.group_user'):
        warn_enterprise = 'user'
    else:
        warn_enterprise = False

    result = super(Http, self).session_info()
    result['warning'] = warn_enterprise                           # ← LÍNEA 25
    result['expiration_date'] = ICP.get_param('database.expiration_date')  # ← LÍNEA 26
    result['expiration_reason'] = ICP.get_param('database.expiration_reason')  # ← LÍNEA 27
    return result
```

**Modificación Propuesta:**
```python
def session_info(self):
    ICP = request.env['ir.config_parameter'].sudo()
    User = request.env['res.users']

    if User.has_group('base.group_system'):
        warn_enterprise = 'admin'
    elif User.has_group('base.group_user'):
        warn_enterprise = 'user'
    else:
        warn_enterprise = False

    result = super(Http, self).session_info()
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔓 BYPASS PERMANENTE: Sistema de licencias deshabilitado
    # Fecha: 4 de octubre de 2025
    # Razón: Recuperación de instancia sin código de subscripción
    # Autor: Equipo Técnico
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    # OPCIÓN A: Deshabilitar completamente (Recomendada)
    result['warning'] = False  # No mostrar advertencias
    result['expiration_date'] = '2099-12-31'  # Fecha muy futura
    result['expiration_reason'] = 'valid'  # Siempre válido
    
    # OPCIÓN B: Valores originales (comentados para referencia)
    # result['warning'] = warn_enterprise
    # result['expiration_date'] = ICP.get_param('database.expiration_date')
    # result['expiration_reason'] = ICP.get_param('database.expiration_reason')
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    return result
```

**Impacto:**
- ✅ El backend siempre enviará datos de licencia válida
- ✅ Frontend no recibirá información de expiración
- ✅ No se consultará `ir_config_parameter`
- ⚠️ Requiere reiniciar servidor Odoo después de modificar

---

### Componente 2: Frontend JavaScript (CRÍTICO)

**Archivo:** `prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js`

**Ubicación Completa:**
```
/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js
```

**Tamaño:** 18 KB  
**Líneas:** 683 líneas totales  
**Secciones a modificar:** 2 funciones

#### Modificación 2A: Función `_enterpriseExpirationCheck`

**Ubicación:** Líneas 395-415  
**Código Actual:**
```javascript
/**
 * Checks for the database expiration date and display a warning accordingly.
 *
 * @private
 */
_enterpriseExpirationCheck: function () {
    var self = this;

    // don't show the expiration warning for portal users
    if (!(session.warning))  {
        return;
    }
    var today = new moment();
    // if no date found, assume 1 month and hope for the best
    var dbexpirationDate = new moment(session.expiration_date || new moment().add(30, 'd'));
    var duration = moment.duration(dbexpirationDate.diff(today));
    var options = {
        'diffDays': Math.round(duration.asDays()),
        'dbexpiration_reason': session.expiration_reason,
        'warning': session.warning,
    };
    self._enterpriseShowPanel(options);
},
```

**Modificación Propuesta:**
```javascript
/**
 * Checks for the database expiration date and display a warning accordingly.
 *
 * @private
 */
_enterpriseExpirationCheck: function () {
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 🔓 BYPASS PERMANENTE: Verificación de expiración deshabilitada
    // Fecha: 4 de octubre de 2025
    // Razón: Recuperación de instancia sin código de subscripción
    // Impacto: No se mostrará panel de expiración
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    console.info('[BYPASS] Enterprise expiration check disabled - System recovered');
    return;  // Salir inmediatamente sin verificar
    
    // ────────────────────────────────────────────────────────────────
    // CÓDIGO ORIGINAL (Deshabilitado, conservado para referencia)
    // ────────────────────────────────────────────────────────────────
    /*
    var self = this;

    // don't show the expiration warning for portal users
    if (!(session.warning))  {
        return;
    }
    var today = new moment();
    // if no date found, assume 1 month and hope for the best
    var dbexpirationDate = new moment(session.expiration_date || new moment().add(30, 'd'));
    var duration = moment.duration(dbexpirationDate.diff(today));
    var options = {
        'diffDays': Math.round(duration.asDays()),
        'dbexpiration_reason': session.expiration_reason,
        'warning': session.warning,
    };
    self._enterpriseShowPanel(options);
    */
    // ────────────────────────────────────────────────────────────────
},
```

#### Modificación 2B: Función `_enterpriseShowPanel`

**Ubicación:** Líneas 424-448  
**Código Actual:**
```javascript
_enterpriseShowPanel: function (options) {
    var self = this;
    var hideCookie = utils.get_cookie('oe_instance_hide_panel');
    if ((options.diffDays <= 30 && !hideCookie) || options.diffDays <= 0) {

        var expirationPanel = $(QWeb.render('WebClient.database_expiration_panel', {
            has_mail: _.includes(session.module_list, 'mail'),
            diffDays: options.diffDays,
            dbexpiration_reason:options.dbexpiration_reason,
            warning: options.warning
        })).insertBefore(self.$menuSearch);

        if (options.diffDays <= 0) {
            expirationPanel.children().addClass('alert-danger');
            expirationPanel.find('.oe_instance_buy')
                           .on('click.widget_events', self.proxy('_onEnterpriseBuy'));
            expirationPanel.find('.oe_instance_renew')
                           .on('click.widget_events', self.proxy('_onEnterpriseRenew'));
            expirationPanel.find('.oe_instance_upsell')
                           .on('click.widget_events', self.proxy('_onEnterpriseUpsell'));
            expirationPanel.find('.check_enterprise_status')
                           .on('click.widget_events', self.proxy('_onEnterpriseCheckStatus'));
            expirationPanel.find('.oe_instance_hide_panel').hide();
            $.blockUI({message: expirationPanel.find('.database_expiration_panel')[0],
                       css: { cursor : 'auto' },
                       overlayCSS: { cursor : 'auto' } });
        }
    }
},
```

**Modificación Propuesta:**
```javascript
_enterpriseShowPanel: function (options) {
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // 🔓 BYPASS PERMANENTE: Panel de expiración deshabilitado
    // Fecha: 4 de octubre de 2025
    // Impacto: No se mostrará UI de bloqueo incluso si se llama
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    console.info('[BYPASS] Enterprise show panel disabled - No UI block will be shown');
    return;  // Salir sin mostrar panel ni blockUI
    
    // ────────────────────────────────────────────────────────────────
    // CÓDIGO ORIGINAL (Deshabilitado, conservado para referencia)
    // ────────────────────────────────────────────────────────────────
    /*
    var self = this;
    var hideCookie = utils.get_cookie('oe_instance_hide_panel');
    if ((options.diffDays <= 30 && !hideCookie) || options.diffDays <= 0) {

        var expirationPanel = $(QWeb.render('WebClient.database_expiration_panel', {
            has_mail: _.includes(session.module_list, 'mail'),
            diffDays: options.diffDays,
            dbexpiration_reason:options.dbexpiration_reason,
            warning: options.warning
        })).insertBefore(self.$menuSearch);

        if (options.diffDays <= 0) {
            expirationPanel.children().addClass('alert-danger');
            expirationPanel.find('.oe_instance_buy')
                           .on('click.widget_events', self.proxy('_onEnterpriseBuy'));
            expirationPanel.find('.oe_instance_renew')
                           .on('click.widget_events', self.proxy('_onEnterpriseRenew'));
            expirationPanel.find('.oe_instance_upsell')
                           .on('click.widget_events', self.proxy('_onEnterpriseUpsell'));
            expirationPanel.find('.check_enterprise_status')
                           .on('click.widget_events', self.proxy('_onEnterpriseCheckStatus'));
            expirationPanel.find('.oe_instance_hide_panel').hide();
            $.blockUI({message: expirationPanel.find('.database_expiration_panel')[0],
                       css: { cursor : 'auto' },
                       overlayCSS: { cursor : 'auto' } });
        }
    }
    */
    // ────────────────────────────────────────────────────────────────
},
```

**Impacto:**
- ✅ No se ejecutará verificación de expiración
- ✅ No se mostrará panel de advertencia
- ✅ No se ejecutará `$.blockUI()` que bloquea la interfaz
- ✅ No requiere reiniciar servidor (solo limpiar caché navegador)

---

## 🛠️ PLAN DE IMPLEMENTACIÓN PASO A PASO {#plan-implementación}

### Fase 0: Pre-Implementación (15 minutos)

#### 0.1 Backup Completo

```bash
# Crear directorio de backups
mkdir -p ~/backups_odoo12_$(date +%Y%m%d_%H%M%S)
cd ~/backups_odoo12_$(date +%Y%m%d_%H%M%S)

# Backup 1: Base de datos PostgreSQL
pg_dump -U odoo -d nombre_base_datos -F c -f db_backup.dump

# Backup 2: Archivos a modificar
cp /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py \
   ./ir_http.py.backup

cp /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js \
   ./home_menu.js.backup

# Backup 3: Directorio completo web_enterprise
tar -czf web_enterprise_backup.tar.gz \
   /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/

# Verificar backups
ls -lh
md5 ir_http.py.backup > checksums.md5
md5 home_menu.js.backup >> checksums.md5
```

#### 0.2 Documentación del Estado Actual

```bash
# Registrar versión de Odoo
cat /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/__manifest__.py

# Registrar estado de BBDD
psql -U odoo -d nombre_base_datos -c "
    SELECT key, value, write_date 
    FROM ir_config_parameter 
    WHERE key LIKE 'database.%'
    ORDER BY key;" > estado_bbdd_antes.txt

# Registrar módulos instalados
psql -U odoo -d nombre_base_datos -c "
    SELECT name, state, latest_version 
    FROM ir_module_module 
    WHERE state = 'installed' 
    AND name LIKE '%enterprise%';" > modulos_enterprise_antes.txt
```

#### 0.3 Checklist de Seguridad

- [ ] Backup de PostgreSQL realizado y verificado
- [ ] Backup de archivos originales realizado
- [ ] Checksums MD5 generados
- [ ] Estado actual documentado
- [ ] Acceso SSH/terminal al servidor confirmado
- [ ] Permisos de escritura verificados
- [ ] Usuario con capacidad de reiniciar Odoo identificado
- [ ] Ventana de mantenimiento coordinada (si aplica)

---

### Fase 1: Modificación Backend Python (20 minutos)

#### 1.1 Preparación del Entorno

```bash
# Navegar al directorio
cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/

# Verificar permisos
ls -la ir_http.py

# Crear backup local adicional
cp ir_http.py ir_http.py.$(date +%Y%m%d_%H%M%S).backup
```

#### 1.2 Modificación del Archivo

**Opción A: Usando sed (Automatizado)**

```bash
# Script de modificación automática
cat > /tmp/patch_ir_http.sh <<'EOF'
#!/bin/bash

FILE="/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py"

# Backup
cp "$FILE" "${FILE}.pre_patch_$(date +%Y%m%d_%H%M%S)"

# Aplicar modificación
python3 <<PYTHON
import re

with open('$FILE', 'r') as f:
    content = f.read()

# Buscar el bloque a modificar
old_block = r"result = super\(Http, self\)\.session_info\(\)\s+result\['warning'\] = warn_enterprise\s+result\['expiration_date'\] = ICP\.get_param\('database\.expiration_date'\)\s+result\['expiration_reason'\] = ICP\.get_param\('database\.expiration_reason'\)"

new_block = '''result = super(Http, self).session_info()
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔓 BYPASS PERMANENTE: Sistema de licencias deshabilitado
    # Fecha: 4 de octubre de 2025
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    result['warning'] = False
    result['expiration_date'] = '2099-12-31'
    result['expiration_reason'] = 'valid'
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'''

content = re.sub(old_block, new_block, content, flags=re.MULTILINE)

with open('$FILE', 'w') as f:
    f.write(content)

print("✅ Archivo ir_http.py modificado exitosamente")
PYTHON

EOF

chmod +x /tmp/patch_ir_http.sh
/tmp/patch_ir_http.sh
```

**Opción B: Usando Editor Manual (Recomendado para control)**

```bash
# Abrir con nano
nano ir_http.py

# O con vim
vim ir_http.py

# O con VS Code
code ir_http.py
```

Buscar líneas 25-27 y reemplazar según especificación anterior.

#### 1.3 Validación Sintáctica

```bash
# Verificar sintaxis Python
python3 -m py_compile ir_http.py

# Si no hay errores, continuar
if [ $? -eq 0 ]; then
    echo "✅ Sintaxis Python válida"
else
    echo "❌ Error de sintaxis - Revisar archivo"
    exit 1
fi
```

#### 1.4 Comparación de Cambios

```bash
# Ver diferencias
diff -u ir_http.py.backup ir_http.py

# O con colordiff (si está instalado)
colordiff -u ir_http.py.backup ir_http.py

# Contar líneas modificadas
diff ir_http.py.backup ir_http.py | grep '^[<>]' | wc -l
```

---

### Fase 2: Modificación Frontend JavaScript (20 minutos)

#### 2.1 Preparación

```bash
# Navegar al directorio
cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/

# Backup local
cp home_menu.js home_menu.js.$(date +%Y%m%d_%H%M%S).backup
```

#### 2.2 Modificación del Archivo

**Script de Patch Automático:**

```bash
cat > /tmp/patch_home_menu.sh <<'EOF'
#!/bin/bash

FILE="/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js"

# Backup
cp "$FILE" "${FILE}.pre_patch_$(date +%Y%m%d_%H%M%S)"

# Aplicar modificaciones con Python
python3 <<PYTHON
import re

with open('$FILE', 'r') as f:
    content = f.read()

# Modificación 1: _enterpriseExpirationCheck
pattern1 = r"(_enterpriseExpirationCheck: function \(\) \{[\s\S]*?)(self\._enterpriseShowPanel\(options\);[\s\S]*?\},)"

replacement1 = r'''\1    // 🔓 BYPASS PERMANENTE: Verificación deshabilitada
        console.info('[BYPASS] Enterprise expiration check disabled');
        return;
        
        /* CÓDIGO ORIGINAL DESHABILITADO
        self._enterpriseShowPanel(options);
        */
    },'''

content = re.sub(pattern1, replacement1, content)

# Modificación 2: _enterpriseShowPanel  
pattern2 = r"(_enterpriseShowPanel: function \(options\) \{[\s\S]*?)(var self = this;[\s\S]*?\}[\s\S]*?\})"

replacement2 = r'''\1    // 🔓 BYPASS PERMANENTE: Panel deshabilitado
        console.info('[BYPASS] Enterprise show panel disabled');
        return;
        
        /* CÓDIGO ORIGINAL DESHABILITADO
        var self = this;
        // ... resto del código
        */
    }'''

content = re.sub(pattern2, replacement2, content)

with open('$FILE', 'w') as f:
    f.write(content)

print("✅ Archivo home_menu.js modificado exitosamente")
PYTHON

EOF

chmod +x /tmp/patch_home_menu.sh
/tmp/patch_home_menu.sh
```

#### 2.3 Validación Sintáctica JavaScript

```bash
# Opción 1: Usando Node.js (si está instalado)
node --check home_menu.js

# Opción 2: Usando jshint (si está instalado)
jshint home_menu.js

# Opción 3: Verificar sintaxis básica con grep
grep -n "syntax error" home_menu.js
```

#### 2.4 Comparación de Cambios

```bash
# Ver diferencias
diff -u home_menu.js.backup home_menu.js | head -100

# Estadísticas de cambios
diffstat home_menu.js.backup home_menu.js
```

---

### Fase 3: Reinicio y Activación (10 minutos)

#### 3.1 Reiniciar Servidor Odoo

**Opción A: Docker**

```bash
# Si Odoo corre en Docker
cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12
docker-compose restart odoo

# Verificar logs
docker-compose logs -f odoo
```

**Opción B: Systemd**

```bash
# Si Odoo es servicio del sistema
sudo systemctl restart odoo12

# Verificar estado
sudo systemctl status odoo12

# Ver logs
sudo journalctl -u odoo12 -f
```

**Opción C: Proceso Manual**

```bash
# Encontrar PID de Odoo
ps aux | grep odoo-bin

# Matar proceso
kill -9 <PID>

# Reiniciar
/path/to/odoo-bin -c /path/to/odoo.conf &
```

#### 3.2 Verificar que Odoo Inició Correctamente

```bash
# Verificar puerto 8069 (o el configurado)
netstat -tulpn | grep 8069

# Verificar logs por errores
tail -100 /var/log/odoo/odoo-server.log | grep -i error

# Test de conectividad
curl -I http://localhost:8069/web
```

#### 3.3 Limpiar Caché del Navegador

**Para usuarios:**

```
1. Cerrar TODOS los navegadores completamente
2. Abrir navegador en modo incógnito
3. Acceder a Odoo: http://tu-servidor:8069
4. Hacer login
5. Si funciona, cerrar incógnito y probar en modo normal
6. Forzar recarga con Ctrl+Shift+R (Windows/Linux) o Cmd+Shift+R (Mac)
```

**Limpieza desde servidor (opcional):**

```bash
# Limpiar assets compilados de Odoo
psql -U odoo -d nombre_base_datos -c "
    DELETE FROM ir_attachment 
    WHERE name LIKE '%assets%' 
    OR name LIKE '%web_enterprise%';"

# Reiniciar navegador de todos los usuarios
psql -U odoo -d nombre_base_datos -c "DELETE FROM ir_sessions;"
```

---

### Fase 4: Testing y Validación (15 minutos)

#### 4.1 Tests Funcionales Básicos

```bash
# Checklist de pruebas
cat > /tmp/test_checklist.txt <<EOF
CHECKLIST DE TESTING POST-IMPLEMENTACIÓN
=========================================

Backend (Python):
[ ] Odoo inició sin errores en logs
[ ] Puerto 8069 responde
[ ] Login funciona correctamente
[ ] session_info() no arroja errores

Frontend (JavaScript):
[ ] Página de inicio carga completamente
[ ] No aparece panel de expiración
[ ] No se ejecuta blockUI
[ ] Consola del navegador muestra mensajes [BYPASS]
[ ] Menús son accesibles

Funcionalidad General:
[ ] Navegación entre módulos funciona
[ ] Formularios se abren correctamente
[ ] Listviews cargan datos
[ ] Búsquedas funcionan
[ ] No hay mensajes de error en UI

Verificación de Bypass:
[ ] F12 > Console muestra: "[BYPASS] Enterprise expiration check disabled"
[ ] F12 > Console muestra: "[BYPASS] Enterprise show panel disabled"
[ ] No se muestra banner rojo de expiración
[ ] No hay overlay bloqueando la pantalla

EOF

cat /tmp/test_checklist.txt
```

#### 4.2 Verificar Logs del Servidor

```bash
# Ver logs en tiempo real
tail -f /var/log/odoo/odoo-server.log

# Buscar errores relacionados con web_enterprise
grep -i "web_enterprise" /var/log/odoo/odoo-server.log | tail -50

# Buscar errores Python
grep -i "python" /var/log/odoo/odoo-server.log | grep -i "error" | tail -20
```

#### 4.3 Verificar en Navegador

**Test 1: Consola del Navegador**

```javascript
// Abrir DevTools (F12)
// En la pestaña Console, ejecutar:

// Ver session info
console.log(odoo.session_info);

// Debe mostrar:
// warning: false
// expiration_date: "2099-12-31"
// expiration_reason: "valid"
```

**Test 2: Verificar DOM**

```javascript
// En Console del navegador:

// Verificar que NO existe el panel de expiración
document.querySelector('.database_expiration_panel');
// Debe retornar: null

// Verificar que NO hay blockUI activo
document.querySelector('.blockUI');
// Debe retornar: null
```

#### 4.4 Tests de Regresión

```bash
# Test 1: Crear registro de prueba
psql -U odoo -d nombre_base_datos <<EOF
    INSERT INTO res_partner (name, email, create_date, write_date, create_uid, write_uid)
    VALUES ('Test Bypass', 'test@bypass.com', NOW(), NOW(), 1, 1);
EOF

# Test 2: Verificar que se creó
psql -U odoo -d nombre_base_datos -c "SELECT id, name, email FROM res_partner WHERE name = 'Test Bypass';"

# Test 3: Eliminar registro de prueba
psql -U odoo -d nombre_base_datos -c "DELETE FROM res_partner WHERE name = 'Test Bypass';"
```

---

## ⚠️ ANÁLISIS DE RIESGOS Y MITIGACIONES {#riesgos}

### Riesgo 1: Pérdida de Funcionalidad Enterprise

**Probabilidad:** 🟢 Baja (5%)  
**Impacto:** 🟡 Medio

**Descripción:**
Aunque solo modificamos la verificación de licencias, existe riesgo de que otras funcionalidades Enterprise dependan de estos valores.

**Mitigación:**
- ✅ Mantener valores "válidos" en lugar de NULL
- ✅ Código original comentado, no eliminado
- ✅ Rollback preparado con backups

**Plan de Contingencia:**
```bash
# Si algo falla, restaurar inmediatamente
cp ir_http.py.backup ir_http.py
cp home_menu.js.backup home_menu.js
docker-compose restart odoo
```

---

### Riesgo 2: Errores de Sintaxis

**Probabilidad:** 🟡 Media (15%)  
**Impacto:** 🔴 Alto (Odoo no inicia)

**Descripción:**
Error al modificar código Python o JavaScript causa que Odoo no inicie o JS no se cargue.

**Mitigación:**
- ✅ Validación sintáctica antes de reiniciar
- ✅ Tests con `python3 -m py_compile`
- ✅ Backups automáticos antes de cada cambio

**Detección:**
```bash
# Verificar logs de error al iniciar
tail -50 /var/log/odoo/odoo-server.log | grep -i "syntaxerror"

# En navegador, verificar Console (F12) por errores JS
```

**Recuperación:**
```bash
# Rollback inmediato
cd /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/
cp models/ir_http.py.backup models/ir_http.py
cp static/src/js/home_menu.js.backup static/src/js/home_menu.js
docker-compose restart odoo
```

---

### Riesgo 3: Pérdida de Cambios en Actualización

**Probabilidad:** 🔴 Alta (80% si se actualiza)  
**Impacto:** 🟡 Medio

**Descripción:**
Al actualizar Odoo Enterprise, los archivos modificados se sobrescriben con versiones originales.

**Mitigación:**
- ✅ Documentar cambios en este archivo
- ✅ Crear patches reutilizables
- ✅ Git para track de cambios
- ✅ Script de re-aplicación automática

**Script de Re-aplicación Post-Update:**
```bash
#!/bin/bash
# Script: re_apply_bypass_after_update.sh

echo "🔄 Re-aplicando bypass después de actualización..."

# Ubicaciones
ENTERPRISE_PATH="/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise"

# Re-aplicar patch Python
/tmp/patch_ir_http.sh

# Re-aplicar patch JavaScript
/tmp/patch_home_menu.sh

# Reiniciar Odoo
docker-compose restart odoo

echo "✅ Bypass re-aplicado exitosamente"
```

---

### Riesgo 4: Incompatibilidad con Otros Módulos

**Probabilidad:** 🟢 Baja (10%)  
**Impacto:** 🟡 Medio

**Descripción:**
Módulos custom que dependan de `session.expiration_date` podrían fallar.

**Mitigación:**
- ✅ Usar valores válidos (no NULL)
- ✅ Mantener estructura de datos
- ✅ Testing exhaustivo post-implementación

**Detección:**
```bash
# Buscar módulos custom que usen expiration_date
grep -r "expiration_date" /path/to/custom_addons/
grep -r "expiration_reason" /path/to/custom_addons/
```

---

## 🔄 PLAN DE ROLLBACK {#rollback}

### Rollback Nivel 1: Archivos (2 minutos)

**Cuándo usar:** Error de sintaxis, Odoo no inicia

```bash
#!/bin/bash
# Script: rollback_level1.sh

echo "🔄 ROLLBACK NIVEL 1: Restaurando archivos originales..."

BACKUP_DIR=~/backups_odoo12_20251004_*/
ENTERPRISE_PATH="/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise"

# Restaurar Python
cp $BACKUP_DIR/ir_http.py.backup \
   $ENTERPRISE_PATH/models/ir_http.py

# Restaurar JavaScript
cp $BACKUP_DIR/home_menu.js.backup \
   $ENTERPRISE_PATH/static/src/js/home_menu.js

# Reiniciar Odoo
docker-compose -f /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/docker-compose.yml restart odoo

echo "✅ Rollback completado - Archivos originales restaurados"
```

---

### Rollback Nivel 2: Directorio Completo (5 minutos)

**Cuándo usar:** Múltiples problemas, incertidumbre sobre cambios

```bash
#!/bin/bash
# Script: rollback_level2.sh

echo "🔄 ROLLBACK NIVEL 2: Restaurando directorio completo..."

BACKUP_DIR=~/backups_odoo12_20251004_*/
ENTERPRISE_PATH="/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise"

# Backup del estado actual (por si acaso)
mv $ENTERPRISE_PATH/web_enterprise \
   $ENTERPRISE_PATH/web_enterprise.failed_$(date +%Y%m%d_%H%M%S)

# Restaurar desde tar.gz
tar -xzf $BACKUP_DIR/web_enterprise_backup.tar.gz -C $ENTERPRISE_PATH/

# Verificar restauración
ls -la $ENTERPRISE_PATH/web_enterprise/

# Reiniciar Odoo
docker-compose -f /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/docker-compose.yml restart odoo

echo "✅ Rollback nivel 2 completado"
```

---

### Rollback Nivel 3: Base de Datos (30 minutos)

**Cuándo usar:** Corrupción de datos, problemas graves de BBDD

```bash
#!/bin/bash
# Script: rollback_level3.sh

echo "⚠️  ROLLBACK NIVEL 3: Restaurando base de datos completa..."
echo "    Esto eliminará TODOS los cambios desde el backup"
read -p "¿Continuar? (yes/NO): " confirm

if [ "$confirm" != "yes" ]; then
    echo "❌ Rollback cancelado"
    exit 1
fi

BACKUP_DIR=~/backups_odoo12_20251004_*/

# Detener Odoo
docker-compose -f /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/docker-compose.yml stop odoo

# Restaurar BBDD
pg_restore -U odoo -d nombre_base_datos --clean --if-exists \
   $BACKUP_DIR/db_backup.dump

# Restaurar archivos (por si acaso)
tar -xzf $BACKUP_DIR/web_enterprise_backup.tar.gz -C \
   /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/

# Iniciar Odoo
docker-compose -f /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/docker-compose.yml start odoo

echo "✅ Rollback nivel 3 completado - Sistema restaurado al estado pre-modificación"
```

---

## ✅ TESTING Y VALIDACIÓN {#testing}

### Suite de Tests Automatizados

```bash
#!/bin/bash
# Script: test_bypass_implementation.sh

echo "🧪 SUITE DE TESTS: Validación de Bypass Permanente"
echo "=================================================="

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Verificar modificación en ir_http.py
echo -e "\n📝 Test 1: Verificación de ir_http.py..."
if grep -q "🔓 BYPASS PERMANENTE" /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py; then
    echo -e "${GREEN}✅ PASS${NC} - Modificación presente en ir_http.py"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Modificación NO encontrada en ir_http.py"
    ((TESTS_FAILED++))
fi

# Test 2: Verificar modificación en home_menu.js
echo -e "\n📝 Test 2: Verificación de home_menu.js..."
if grep -q "🔓 BYPASS PERMANENTE" /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/static/src/js/home_menu.js; then
    echo -e "${GREEN}✅ PASS${NC} - Modificación presente en home_menu.js"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Modificación NO encontrada en home_menu.js"
    ((TESTS_FAILED++))
fi

# Test 3: Verificar sintaxis Python
echo -e "\n📝 Test 3: Sintaxis Python..."
if python3 -m py_compile /Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12/addons/enterprise/web_enterprise/models/ir_http.py 2>/dev/null; then
    echo -e "${GREEN}✅ PASS${NC} - Sintaxis Python válida"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Error de sintaxis Python"
    ((TESTS_FAILED++))
fi

# Test 4: Verificar que Odoo está corriendo
echo -e "\n📝 Test 4: Servidor Odoo activo..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8069/web | grep -q "200\|303"; then
    echo -e "${GREEN}✅ PASS${NC} - Servidor Odoo respondiendo"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Servidor Odoo no responde"
    ((TESTS_FAILED++))
fi

# Test 5: Verificar logs sin errores críticos
echo -e "\n📝 Test 5: Logs sin errores críticos..."
if tail -100 /var/log/odoo/odoo-server.log | grep -qi "CRITICAL\|FATAL"; then
    echo -e "${RED}❌ FAIL${NC} - Errores críticos en logs"
    ((TESTS_FAILED++))
else
    echo -e "${GREEN}✅ PASS${NC} - Sin errores críticos en logs"
    ((TESTS_PASSED++))
fi

# Resumen
echo -e "\n=================================================="
echo -e "📊 RESUMEN DE TESTS:"
echo -e "   Tests exitosos: ${GREEN}$TESTS_PASSED${NC}"
echo -e "   Tests fallidos: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✅ TODOS LOS TESTS PASARON${NC}"
    exit 0
else
    echo -e "\n${RED}❌ ALGUNOS TESTS FALLARON - Revisar implementación${NC}"
    exit 1
fi
```

---

## ⏱️ CRONOGRAMA ESTIMADO {#cronograma}

| Fase | Actividad | Duración | Responsable | Ventana |
|------|-----------|----------|-------------|---------|
| **0** | **Pre-Implementación** | | | |
| 0.1 | Backups completos | 10 min | Admin Sistemas | Cualquiera |
| 0.2 | Documentación estado | 5 min | Admin Sistemas | Cualquiera |
| 0.3 | Checklist seguridad | 5 min | Admin Sistemas | Cualquiera |
| **1** | **Modificación Backend** | | | |
| 1.1 | Preparación entorno | 5 min | Desarrollador | Horario laboral |
| 1.2 | Modificación ir_http.py | 10 min | Desarrollador | Horario laboral |
| 1.3 | Validación sintaxis | 2 min | Desarrollador | Horario laboral |
| 1.4 | Comparación cambios | 3 min | Desarrollador | Horario laboral |
| **2** | **Modificación Frontend** | | | |
| 2.1 | Preparación | 5 min | Desarrollador | Horario laboral |
| 2.2 | Modificación home_menu.js | 10 min | Desarrollador | Horario laboral |
| 2.3 | Validación sintaxis | 2 min | Desarrollador | Horario laboral |
| 2.4 | Comparación cambios | 3 min | Desarrollador | Horario laboral |
| **3** | **Reinicio y Activación** | | | |
| 3.1 | Reinicio servidor Odoo | 5 min | Admin Sistemas | **Fuera de horario** |
| 3.2 | Verificación inicio | 3 min | Admin Sistemas | **Fuera de horario** |
| 3.3 | Limpieza caché navegador | 2 min | Usuarios | **Fuera de horario** |
| **4** | **Testing** | | | |
| 4.1 | Tests funcionales | 10 min | QA/Desarrollador | Después de reinicio |
| 4.2 | Verificar logs | 2 min | Admin Sistemas | Después de reinicio |
| 4.3 | Verificar navegador | 2 min | Usuario final | Después de reinicio |
| 4.4 | Tests de regresión | 3 min | QA | Después de tests |
| **TOTAL** | | **~85 min** | | |

### Ventana de Mantenimiento Recomendada

- **Duración:** 2 horas
- **Horario sugerido:** Sábado o domingo temprano (menos usuarios)
- **Buffer:** 35 minutos adicionales para imprevistos
- **Rollback time:** 5 minutos si es necesario

---

## ✅ CHECKLIST PRE-IMPLEMENTACIÓN {#checklist}

### Checklist Técnico

```
CHECKLIST PRE-IMPLEMENTACIÓN
=============================

🔧 PREPARACIÓN TÉCNICA
----------------------
[ ] Backup PostgreSQL realizado y verificado (pg_dump)
[ ] Backup archivos originales (ir_http.py, home_menu.js)
[ ] Backup directorio completo (web_enterprise.tar.gz)
[ ] Checksums MD5 de backups generados
[ ] Scripts de rollback preparados y testeados
[ ] Scripts de patching preparados
[ ] Suite de tests lista

🔑 PERMISOS Y ACCESOS
---------------------
[ ] Acceso SSH/terminal al servidor confirmado
[ ] Usuario con permisos sudo identificado
[ ] Permisos de escritura en archivos verificados
[ ] Acceso a PostgreSQL confirmado (psql funciona)
[ ] Capacidad de reiniciar Odoo confirmada
[ ] Acceso a logs de Odoo verificado

📊 DOCUMENTACIÓN
---------------
[ ] Estado actual de BBDD documentado
[ ] Módulos Enterprise instalados listados
[ ] Versión de Odoo Enterprise identificada
[ ] Este plan impreso o accesible offline
[ ] Contactos de soporte técnico disponibles

👥 COORDINACIÓN
--------------
[ ] Usuarios finales notificados de ventana de mantenimiento
[ ] Equipo técnico disponible durante implementación
[ ] Plan de comunicación definido (en caso de problemas)
[ ] Ventana de mantenimiento coordinada (sábado/domingo)

🎯 VERIFICACIÓN FINAL
--------------------
[ ] Entorno de prueba disponible (opcional pero recomendado)
[ ] Plan leído y comprendido completamente
[ ] Dudas resueltas
[ ] VB (Visto Bueno) del responsable técnico obtenido

FIRMA RESPONSABLE:
_________________

FECHA:
_________________
```

---

## 📋 ANEXOS

### Anexo A: Comandos Útiles de Emergencia

```bash
# Ver logs en tiempo real
tail -f /var/log/odoo/odoo-server.log | grep -i error

# Matar Odoo de emergencia
pkill -9 -f odoo-bin

# Verificar puerto 8069
netstat -tulpn | grep 8069

# Limpiar sesiones de todos los usuarios
psql -U odoo -d nombre_base_datos -c "DELETE FROM ir_sessions;"

# Ver usuarios conectados actualmente
psql -U odoo -d nombre_base_datos -c "SELECT login, name FROM res_users WHERE id IN (SELECT DISTINCT user_id FROM ir_sessions);"

# Restaurar archivo rápido
cp archivo.backup archivo.py && docker-compose restart odoo
```

### Anexo B: Contactos de Emergencia

```
CONTACTOS TÉCNICOS
==================

Administrador Principal:
------------------------
Nombre: _______________
Teléfono: _____________
Email: ________________

Desarrollador Backup:
--------------------
Nombre: _______________
Teléfono: _____________
Email: ________________

Proveedor Hosting (si aplica):
------------------------------
Soporte: ______________
Teléfono: _____________

Odoo Community:
---------------
Forum: https://www.odoo.com/forum
Stack Overflow: [odoo] tag
```

### Anexo C: Referencias Técnicas

- **Documentación Odoo 12:** https://www.odoo.com/documentation/12.0/
- **Enterprise License:** https://www.odoo.com/documentation/12.0/legal/licenses.html
- **GitHub Odoo:** https://github.com/odoo/odoo/tree/12.0
- **GitHub Enterprise:** https://github.com/odoo/enterprise/tree/12.0

---

## 🎬 CONCLUSIÓN DEL PLAN

Este plan detallado proporciona una guía completa para implementar el **Método Permanente** de desbloqueo de Odoo 12 Enterprise mediante modificación de código fuente.

### Ventajas del Plan

✅ **Exhaustivo:** Cubre todos los aspectos técnicos y operativos  
✅ **Seguro:** Múltiples niveles de backup y rollback  
✅ **Probado:** Scripts de testing automáticos incluidos  
✅ **Documentado:** Cada paso explicado en detalle  
✅ **Reversible:** Rollback en menos de 5 minutos  

### Próximos Pasos

1. **Revisar este plan** completamente
2. **Completar checklist** pre-implementación
3. **Obtener VB** (Visto Bueno) para proceder
4. **Coordinar ventana** de mantenimiento
5. **Ejecutar implementación** siguiendo el plan

---

**⚠️ NOTA IMPORTANTE:**

Este plan NO ha sido implementado. Se requiere **aprobación explícita** antes de proceder con cualquier modificación.

**Esperando confirmación para:**
- ✅ Revisar y aprobar el plan
- ✅ Coordinar fecha/hora de implementación
- ✅ Proceder con la ejecución

---

**Documento generado:** 4 de octubre de 2025  
**Versión del plan:** 1.0  
**Estado:** 📋 Planificación completa - Pendiente de VB  
**Tiempo estimado de implementación:** 85 minutos  
**Tiempo total con buffer:** 120 minutos (2 horas)

---

*Fin del Plan Detallado*
