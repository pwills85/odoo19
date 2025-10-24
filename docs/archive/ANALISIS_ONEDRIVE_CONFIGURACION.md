# 📊 ANÁLISIS CONFIGURACIÓN ONEDRIVE - MacBook Pedro

**Fecha:** 23 de octubre de 2025
**Usuario:** pedro
**Equipo:** MacBook (macOS)

---

## 🎯 OBJETIVO
Configurar cuenta empresarial **pedro@eergygroup.cl** en unidad externa `mac_media`, ya que actualmente está sincronizando en disco interno.

---

## 📍 ESTADO ACTUAL

### ✅ **Cuenta Personal** (contacto@eergymas.cl)
**Estado:** ✅ **CORRECTAMENTE CONFIGURADA**

```
Ubicación Interna:  ~/Library/CloudStorage/OneDrive-Personal
Enlace Simbólico:   ~/OneDrive_External/OneDrive 
                    → /Volumes/mac_media/OneDrive_Personal
Ubicación Externa:  /Volumes/mac_media/OneDrive_Personal/
Tamaño:             56KB (sincronización activa)
Estado:             Funcionando correctamente
```

**Configuración:**
- ✅ Sincronizando con unidad externa
- ✅ Files On-Demand activo
- ✅ Enlace simbólico configurado
- ✅ Datos en `mac_media`

---

### ⚠️  **Cuenta Empresa** (pedro@eergygroup.cl)
**Estado:** ⚠️  **REQUIERE MIGRACIÓN A UNIDAD EXTERNA**

```
Ubicación Actual:   ~/Library/CloudStorage/OneDrive-EERGYGROUP/
Tamaño:             1.3MB (solo configuración)
Carpetas:           17 carpetas principales
                    - Capacitacion
                    - Datos adjuntos
                    - Documentos
                    - Escritorio
                    - Finanzas - Documentos
                    - Grabaciones
                    - Imágenes
                    - Personal
                    - Vídeos
                    - etc.

Enlace Preparado:   ~/OneDrive_External/OneDrive - EERGYGROUP
                    → /Volumes/mac_media/OneDrive_Empresa
Carpeta Destino:    /Volumes/mac_media/OneDrive_Empresa/ (VACÍA - 0B)
```

**Problema Identificado:**
- ❌ Está sincronizando en disco interno (~/Library/CloudStorage/)
- ❌ La carpeta externa está vacía
- ❌ No está usando el enlace simbólico preparado
- ⚠️  Ocupará espacio en disco interno cuando sincronice todo

---

## 🔧 INFRAESTRUCTURA DISPONIBLE

### Unidad Externa: `mac_media`
```
Dispositivo:        /dev/disk7s1
Capacidad Total:    1.8TB
Usado:              263GB (15%)
Disponible:         1.6TB
Estado:             ✅ Montado y accesible
Ubicación:          /Volumes/mac_media
```

### Estructura Preparada
```
/Volumes/mac_media/
├── OneDrive_Personal/          ✅ Activo (56KB)
├── OneDrive_Empresa/           ❌ Vacío (0B)
├── SharePoint/                 ❌ Vacío (0B)
└── README_MULTI_CUENTA.txt     ✅ Documentación
```

### Enlaces Simbólicos
```
~/OneDrive_External/
├── OneDrive                    → /Volumes/mac_media/OneDrive_Personal    ✅
├── OneDrive - EERGYGROUP       → /Volumes/mac_media/OneDrive_Empresa    ❌
└── SharePoint                  → /Volumes/mac_media/SharePoint          ❌
```

---

## 🚨 PROBLEMA RAÍZ

OneDrive para macOS usa **`~/Library/CloudStorage/`** como ubicación predeterminada y **NO PERMITE** cambiar la ubicación de una cuenta ya configurada desde las preferencias.

**Comportamiento Detectado:**
1. Cuenta personal: Usa CloudStorage pero tiene enlace que funciona
2. Cuenta empresa: También usa CloudStorage (1.3MB actualmente)
3. Los enlaces simbólicos en `~/OneDrive_External/` están creados pero no se usan

**Nota Crítica:**
El método de enlaces simbólicos desde `~/OneDrive_External/` NO redirige la sincronización de CloudStorage. OneDrive sigue escribiendo en `~/Library/CloudStorage/`.

---

## ✅ SOLUCIÓN RECOMENDADA

### OPCIÓN A: Migración Completa (RECOMENDADA)
Desvincular y volver a configurar la cuenta empresa apuntando directamente a la unidad externa.

**Pasos:**
1. ✅ **Respaldar datos actuales** (si los hay)
2. 🔧 **Desvincular cuenta empresa**
3. 🗑️  **Limpiar carpeta CloudStorage**
4. 🔗 **Re-vincular apuntando a unidad externa**
5. ✅ **Verificar sincronización**

**Ventajas:**
- ✅ Todo en unidad externa (ahorra espacio interno)
- ✅ Configuración limpia y correcta
- ✅ Coherente con cuenta personal
- ✅ Escalable para SharePoint

**Desventajas:**
- ⏱️  Requiere re-sincronización (depende del tamaño)
- ⚠️  Disco externo debe estar siempre conectado

---

### OPCIÓN B: Mantener CloudStorage + Monitoreo
Dejar como está y monitorear espacio.

**Consideraciones:**
- ✅ No requiere cambios
- ❌ Ocupa disco interno
- ❌ Inconsistente con cuenta personal
- ⚠️  Riesgo si sincroniza muchos datos

---

## 📋 PLAN DE MIGRACIÓN DETALLADO

### FASE 1: PREPARACIÓN (5 min)

```bash
# 1. Verificar espacio disponible
df -h /Volumes/mac_media

# 2. Ver qué hay actualmente en cuenta empresa
ls -la ~/Library/CloudStorage/OneDrive-EERGYGROUP/

# 3. Verificar tamaño actual
du -sh ~/Library/CloudStorage/OneDrive-EERGYGROUP/

# 4. Backup de configuración (opcional)
cp -r ~/Library/CloudStorage/OneDrive-EERGYGROUP/.849C9593-D756-4E56-8D6E-42412F2A707B \
   /Volumes/mac_media/backup_onedrive_config_$(date +%Y%m%d).bak
```

### FASE 2: DESVINCULACIÓN (2 min)

**Manual (Interfaz):**
1. Click en ícono OneDrive en barra de menús
2. Click en los 3 puntos (⋯) o engranaje (⚙️)
3. **Preferencias** → Pestaña **"Cuenta"**
4. Buscar cuenta **"OneDrive - EERGYGROUP"** o **pedro@eergygroup.cl**
5. Click **"Desvincular esta cuenta"** o **"Desvincular este Mac"**
6. Confirmar desvinculación

**Verificación:**
```bash
# Verificar que ya no aparezca
ls -la ~/Library/CloudStorage/ | grep EERGYGROUP
# Debe devolver vacío o no encontrar nada
```

### FASE 3: LIMPIEZA (1 min)

```bash
# 1. Eliminar carpeta antigua (si quedó residual)
rm -rf ~/Library/CloudStorage/OneDrive-EERGYGROUP/

# 2. Limpiar caché (opcional pero recomendado)
rm -rf ~/Library/Application\ Support/OneDrive/settings/Business1/

# 3. Verificar enlaces simbólicos
ls -la ~/OneDrive_External/
```

### FASE 4: RE-VINCULACIÓN (5-10 min)

**Método 1: Desde Preferencias (Si ya tienes OneDrive abierto)**
1. OneDrive → Preferencias → Pestaña **"Cuenta"**
2. Click **"Agregar una cuenta"**
3. Iniciar sesión: **pedro@eergygroup.cl**
4. Ingresar contraseña + autenticación (MFA si aplica)
5. **CRÍTICO**: Cuando pregunte ubicación de carpeta:
   - Click **"Cambiar ubicación"**
   - Navegar a: **`/Volumes/mac_media/OneDrive_Empresa`**
   - Click **"Elegir esta ubicación"**
6. Configurar sincronización selectiva (recomendado)
7. Activar **Files On-Demand**
8. Finalizar configuración

**Método 2: Desde cero (Si cerraste OneDrive)**
1. Abrir aplicación **OneDrive**
2. Click **"Agregar otra cuenta"** o iniciar sesión
3. Email: **pedro@eergygroup.cl**
4. Seguir pasos 4-8 del Método 1

### FASE 5: CONFIGURACIÓN POST-INSTALACIÓN (5 min)

```bash
# 1. Verificar que la carpeta se creó en disco externo
ls -la /Volumes/mac_media/OneDrive_Empresa/

# 2. Ver tamaño inicial (puede estar sincronizando)
du -sh /Volumes/mac_media/OneDrive_Empresa/

# 3. Monitorear estado
~/monitor_onedrive.sh

# 4. Abrir carpeta para verificar archivos
open /Volumes/mac_media/OneDrive_Empresa/
```

**Configurar Sincronización Selectiva:**
1. OneDrive → Preferencias → Cuenta
2. Click **"Elegir carpetas"** junto a la cuenta empresa
3. Desmarcar carpetas que NO necesitas offline
4. Dejar marcadas solo las importantes (ej: Documentos, Proyectos)
5. Click **"Aceptar"**

### FASE 6: VERIFICACIÓN (5 min)

```bash
# 1. Verificar procesos OneDrive
ps aux | grep OneDrive | grep -v grep

# 2. Ver estado completo
~/monitor_onedrive.sh

# 3. Verificar sincronización activa
ls -la /Volumes/mac_media/OneDrive_Empresa/

# 4. Comprobar espacio usado
du -sh /Volumes/mac_media/OneDrive_*

# 5. Verificar que CloudStorage ya no tiene la cuenta (o es un enlace)
ls -la ~/Library/CloudStorage/ | grep EERGYGROUP
```

**Indicadores de Éxito:**
- ✅ Carpeta `/Volumes/mac_media/OneDrive_Empresa/` con contenido
- ✅ Ícono de OneDrive muestra 2 nubes (Personal + Empresa)
- ✅ `monitor_onedrive.sh` muestra ambas cuentas
- ✅ Sincronización activa (archivos apareciendo)
- ✅ CloudStorage limpio o con enlace simbólico

---

## 🛡️ CONTINGENCIAS Y SOLUCIÓN DE PROBLEMAS

### Problema 1: "La ubicación no es válida"
**Causa:** OneDrive no acepta unidades externas en algunas versiones
**Solución:**
```bash
# Crear carpeta temporal en home
mkdir -p ~/OneDrive_Temp_Empresa

# Configurar OneDrive apuntando a ~/OneDrive_Temp_Empresa
# Después de sincronizar, parar OneDrive y:
mv ~/OneDrive_Temp_Empresa/* /Volumes/mac_media/OneDrive_Empresa/
rm -rf ~/OneDrive_Temp_Empresa
ln -s /Volumes/mac_media/OneDrive_Empresa ~/OneDrive_Temp_Empresa
# Reiniciar OneDrive
```

### Problema 2: Disco externo desconectado
**Síntoma:** OneDrive no sincroniza o muestra error
**Solución:**
```bash
# Verificar si está montado
ls -la /Volumes/mac_media

# Si no está montado, conectar disco
# Ejecutar script de reconexión
~/reconnect_onedrive.sh
```

### Problema 3: Sincronización lenta
**Causas posibles:**
- Unidad externa USB 2.0 (lenta)
- Muchas carpetas seleccionadas
- Conexión a internet lenta

**Solución:**
1. Usar sincronización selectiva (menos carpetas)
2. Activar Files On-Demand (no descarga todo)
3. Pausar/reanudar sincronización

### Problema 4: No aparece opción "Agregar cuenta"
**Causa:** Ya tienes 2 cuentas (límite de OneDrive)
**Solución:**
```bash
# Ver cuentas actuales
ls -la ~/Library/CloudStorage/

# Si ves 2 cuentas de OneDrive, desvincular una primero
```

---

## 📊 COMPARATIVA: ANTES vs DESPUÉS

### ANTES (Estado Actual)
```
Disco Interno:
├── OneDrive Personal      → CloudStorage → Enlace → mac_media ✅
└── OneDrive Empresa       → CloudStorage (1.3MB, creciendo) ⚠️

Disco Externo (mac_media):
├── OneDrive_Personal/     → 56KB (activo) ✅
├── OneDrive_Empresa/      → 0B (vacío) ❌
└── SharePoint/            → 0B (vacío) ❌
```

### DESPUÉS (Estado Deseado)
```
Disco Interno:
└── (Limpio, solo sistema)

Disco Externo (mac_media):
├── OneDrive_Personal/     → 56KB+ (activo) ✅
├── OneDrive_Empresa/      → Datos sincronizados ✅
└── SharePoint/            → (opcional) ✅
```

**Beneficio:** Todo en unidad externa, disco interno limpio

---

## 🎓 RECOMENDACIONES ADICIONALES

### 1. **Files On-Demand (CRÍTICO)**
- ✅ Activar en ambas cuentas
- Ahorra 80-95% de espacio en disco
- Archivos se descargan solo al abrirlos
- Ideal para unidades externas

### 2. **Sincronización Selectiva**
Solo sincroniza carpetas que usas diariamente:
- ✅ Documentos activos
- ✅ Proyectos en curso
- ❌ Archivos históricos (acceso vía web)
- ❌ Carpetas compartidas que no usas

### 3. **Monitoreo Regular**
```bash
# Agregar alias en ~/.zshrc
echo 'alias od-status="~/monitor_onedrive.sh"' >> ~/.zshrc
source ~/.zshrc

# Usar comando corto
od-status
```

### 4. **Backup de Configuración**
```bash
# Crear script de backup mensual
cat > ~/backup_onedrive_config.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/Volumes/mac_media/Backups/OneDrive_Config"
DATE=$(date +%Y%m%d)
mkdir -p "$BACKUP_DIR"
cp -r ~/Library/Application\ Support/OneDrive/settings "$BACKUP_DIR/settings_$DATE"
echo "✅ Backup creado: $BACKUP_DIR/settings_$DATE"
EOF

chmod +x ~/backup_onedrive_config.sh
```

### 5. **Automatización de Montaje**
Si desconectas el disco frecuentemente:
```bash
# Crear LaunchAgent para auto-montar (avanzado)
# O simplemente asegúrate de conectar disco antes de iniciar sesión
```

---

## ⏱️ TIEMPO ESTIMADO TOTAL

| Fase | Tiempo | Descripción |
|------|--------|-------------|
| Preparación | 5 min | Verificar y backup |
| Desvinculación | 2 min | Desvincular cuenta |
| Limpieza | 1 min | Limpiar carpetas |
| Re-vinculación | 5-10 min | Configurar cuenta nueva |
| Configuración | 5 min | Ajustes finales |
| Verificación | 5 min | Comprobar funcionamiento |
| **Sincronización** | **Variable** | Depende del tamaño de datos |
| **TOTAL (sin sync)** | **23-28 min** | **Tiempo de configuración** |

**Nota:** La sincronización puede tomar desde minutos hasta horas dependiendo de:
- Cantidad de archivos en cuenta empresa
- Velocidad de internet
- Uso de sincronización selectiva

---

## 🚀 PRÓXIMOS PASOS INMEDIATOS

1. **Confirmar que quieres proceder** con Opción A (migración)
2. **Verificar datos importantes** en cuenta empresa actual
3. **Confirmar disponibilidad de tiempo** (30 min + sincronización)
4. **Ejecutar migración paso a paso**
5. **Validar funcionamiento** con monitor

---

## 📞 SOPORTE

Si encuentras algún problema durante la migración:
1. **No entrar en pánico** - Los datos están en la nube
2. **Tomar screenshot** del error
3. **Verificar conexión** a internet y disco externo
4. **Consultar logs** de OneDrive si es necesario

---

**Estado del Análisis:** ✅ COMPLETO
**Siguiente acción:** Esperando confirmación para iniciar migración
