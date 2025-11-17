# 🚀 GUÍA: Configurar OneDrive Empresa en Disco Externo

**Cuenta:** pedro@eergygroup.cl  
**Objetivo:** Configurar sincronización en `/Volumes/mac_media/OneDrive_Empresa/`  
**Fecha:** 23 de octubre de 2025

---

## ⚠️ SITUACIÓN ACTUAL

```
✅ Cuenta Personal (contacto@eergymas.cl): Funcionando en disco externo
❌ Cuenta Empresa (pedro@eergygroup.cl): Vinculada en disco INTERNO (1.3MB)
```

**Necesitamos:** Desvincular la cuenta empresa y volverla a vincular apuntando al disco externo.

---

## 📋 PREPARACIÓN (HAZ ESTO PRIMERO)

### 1️⃣ Verificar que el disco externo está conectado

```bash
ls -la /Volumes/mac_media/
```

**Debe mostrar:** La carpeta `OneDrive_Empresa` (puede estar vacía, está bien)

### 2️⃣ Verificar carpeta destino

```bash
# Ver que existe
ls -la /Volumes/mac_media/OneDrive_Empresa/

# Limpiarla si tiene contenido antiguo (OPCIONAL)
# rm -rf /Volumes/mac_media/OneDrive_Empresa/*
# rm -rf /Volumes/mac_media/OneDrive_Empresa/.*
```

### 3️⃣ Tener a mano tus credenciales
- ✅ Email: **pedro@eergygroup.cl**
- ✅ Contraseña de la cuenta
- ✅ Autenticación MFA (si la tienes configurada)

---

## 🔧 PASO A PASO: CONFIGURACIÓN DESDE LA APP

### PASO 1: Abrir Preferencias de OneDrive

1. **Click** en el ícono de **OneDrive** en la barra de menús (arriba a la derecha)
   - Verás un ícono de nube ☁️
   
2. **Click** en los **tres puntos** (⋯) o el **engranaje** (⚙️)
   
3. Seleccionar **"Preferencias"** o **"Preferences"**

---

### PASO 2: Desvincular Cuenta Empresa

1. En la ventana de Preferencias, ir a la pestaña **"Cuenta"** (Account)

2. Buscar la cuenta **"OneDrive - EERGYGROUP"** o **pedro@eergygroup.cl**
   - Deberías ver dos cuentas listadas:
     - ✅ OneDrive Personal (contacto@eergymas.cl) - **NO TOCAR**
     - ❌ OneDrive - EERGYGROUP (pedro@eergygroup.cl) - **ESTA SÍ**

3. **Seleccionar** la cuenta empresa (pedro@eergygroup.cl)

4. **Click** en el botón **"Desvincular esta cuenta"** o **"Unlink this account"**
   
   ⚠️ **IMPORTANTE:** 
   - Solo desvincular la cuenta **EMPRESA**
   - **NO** desvincular la cuenta personal
   - Puede decir "Desvincular este Mac" - está bien

5. **Confirmar** cuando pregunte si estás seguro
   - Click en **"Desvincular cuenta"** o **"Unlink Account"**

6. **Esperar** unos segundos mientras se desvincula

---

### PASO 3: Agregar Cuenta Empresa (Nueva Configuración)

1. **En la misma ventana** de Preferencias → pestaña **"Cuenta"**

2. **Click** en el botón **"Agregar una cuenta"** o **"Add an account"**

3. Se abrirá una ventana de inicio de sesión:
   - **Email:** `pedro@eergygroup.cl`
   - **Click** en **"Iniciar sesión"** o **"Sign in"**

4. **Ingresar contraseña** de la cuenta empresa

5. **Completar autenticación** (MFA si aplica)
   - Puede pedir código de teléfono
   - O aprobación en app Microsoft Authenticator

---

### PASO 4: ⭐ CONFIGURAR UBICACIÓN (EL MÁS IMPORTANTE)

1. Después de autenticar, verás una pantalla que dice:
   - **"Esta es tu carpeta de OneDrive"** o
   - **"This is your OneDrive folder"**
   
2. **Mostrará una ruta por defecto** como:
   ```
   /Users/pedro/OneDrive - EERGYGROUP
   ```

3. **🔴 NO ACEPTAR** esta ruta. En su lugar:
   - **Click** en el botón **"Cambiar ubicación"** o **"Change location"**
   - (Puede estar abajo a la izquierda o al lado de la ruta)

4. Se abrirá un **selector de carpeta**:
   - En la barra lateral izquierda, buscar y hacer click en **"mac_media"**
   - O navegar manualmente a: **`/Volumes/mac_media/`**
   
5. **Dentro de `/Volumes/mac_media/`**, seleccionar la carpeta:
   ```
   OneDrive_Empresa
   ```

6. **Click** en **"Elegir esta ubicación"** o **"Choose this location"**

7. Puede mostrar un mensaje diciendo:
   > "La carpeta ya existe. ¿Usar esta ubicación?"
   
   - **Click** en **"Usar esta ubicación"** o **"Use this location"**

8. La ruta ahora debería mostrar:
   ```
   /Volumes/mac_media/OneDrive_Empresa
   ```

9. **Click** en **"Siguiente"** o **"Next"**

---

### PASO 5: Configurar Sincronización

1. Verás una pantalla **"Sincronizar archivos desde tu OneDrive"**

2. **Opciones:**
   
   **Opción A - Sincronizar TODO (no recomendado):**
   - Dejar todas las carpetas marcadas
   - Click **"Siguiente"**
   - ⚠️ Descargará TODOS los archivos
   
   **Opción B - Sincronización SELECTIVA (RECOMENDADO):**
   - **Desmarcar carpetas** que NO necesitas offline
   - Dejar marcadas SOLO las importantes:
     - ✅ Documentos
     - ✅ Proyectos activos
     - ❌ Archivos históricos
     - ❌ Carpetas grandes que no usas
   - Click **"Siguiente"**
   - ✅ Ahorra espacio y tiempo

3. **Click** en **"Siguiente"** o **"Next"**

---

### PASO 6: Activar Files On-Demand (RECOMENDADO)

1. Si aparece una pantalla sobre **"Files On-Demand"**:
   - **Activar** o **Enable**
   - ✅ Esto permite ver archivos sin descargarlos
   - ✅ Se descargan solo cuando los abres
   - ✅ Ahorra MUCHO espacio

2. **Click** en **"Siguiente"** o **"Next"**

---

### PASO 7: Finalizar Configuración

1. Última pantalla: **"¡Todo listo!"** o **"All set!"**

2. **Click** en:
   - **"Abrir mi carpeta de OneDrive"** o
   - **"Open my OneDrive folder"** o
   - **"Finish"** / **"Finalizar"**

3. Se abrirá la carpeta en Finder:
   ```
   /Volumes/mac_media/OneDrive_Empresa/
   ```

4. Verás que empieza a sincronizar (puede tomar tiempo dependiendo del tamaño)

---

## ✅ VERIFICACIÓN: Confirmar que funcionó

### Verificación 1: Ver la carpeta en disco externo

```bash
# Abrir la carpeta
open /Volumes/mac_media/OneDrive_Empresa/

# Ver contenido (debe aparecer gradualmente)
ls -la /Volumes/mac_media/OneDrive_Empresa/
```

**Debe mostrar:** Carpetas y archivos de tu OneDrive empresa (pueden tener iconitos de nube)

### Verificación 2: Comprobar tamaño

```bash
# Ver espacio usado
du -sh /Volumes/mac_media/OneDrive_Empresa/

# Monitorear estado completo
~/monitor_onedrive.sh
```

**Debe mostrar:** Tamaño creciendo conforme sincroniza

### Verificación 3: Verificar que NO está en disco interno

```bash
# Buscar si quedó algo en CloudStorage
ls -la ~/Library/CloudStorage/ | grep -i eergygroup
```

**Debe mostrar:** 
- Nada, O
- Un enlace simbólico que apunta a `/Volumes/mac_media/OneDrive_Empresa/`

### Verificación 4: Ver íconos en barra de menús

1. **Click** en el ícono de OneDrive (barra superior)
2. Debe mostrar **DOS nubes**:
   - ☁️ OneDrive - Personal
   - ☁️ OneDrive - EERGYGROUP

### Verificación 5: Estado de sincronización

```bash
# Ver procesos corriendo
ps aux | grep OneDrive | grep -v grep

# Debe mostrar 2 procesos activos
```

---

## 🎯 INDICADORES DE ÉXITO

✅ **Carpeta en disco externo tiene contenido:**
```bash
ls /Volumes/mac_media/OneDrive_Empresa/
# Muestra: Documentos, Escritorio, Finanzas, etc.
```

✅ **Disco interno NO tiene la cuenta (o solo enlace):**
```bash
ls ~/Library/CloudStorage/ | grep -i eergygroup
# Vacío o muestra enlace simbólico
```

✅ **Monitor muestra ambas cuentas:**
```bash
~/monitor_onedrive.sh
# Muestra Personal + Empresa en mac_media
```

✅ **Íconos de OneDrive muestran 2 nubes** en barra de menús

✅ **Archivos se abren correctamente** desde la carpeta

---

## 🛑 SOLUCIÓN DE PROBLEMAS

### Problema 1: No aparece botón "Cambiar ubicación"

**Posible causa:** Versión antigua de OneDrive

**Solución:**
1. Cancelar configuración
2. Actualizar OneDrive:
   ```bash
   # Verificar versión actual
   /Applications/OneDrive.app/Contents/MacOS/OneDrive --version
   ```
3. Descargar última versión: https://onedrive.live.com/about/download/
4. Reinstalar e intentar de nuevo

---

### Problema 2: No acepta la ubicación en disco externo

**Error:** "La ubicación no es válida" o similar

**Solución alternativa:**
1. Cancelar y cerrar OneDrive
2. Crear enlace simbólico temporal:
   ```bash
   # Crear carpeta temporal en home
   mkdir -p ~/OneDrive_Empresa_Temp
   
   # Crear enlace desde esa carpeta al disco externo
   ln -s /Volumes/mac_media/OneDrive_Empresa ~/OneDrive_Empresa_Link
   ```
3. Configurar OneDrive apuntando a `~/OneDrive_Empresa_Link`
4. OneDrive seguirá el enlace al disco externo

---

### Problema 3: Disco externo no aparece en el selector

**Causa:** No está montado o no tiene permisos

**Solución:**
```bash
# Verificar que está montado
ls -la /Volumes/

# Dar permisos completos a la carpeta
sudo chmod -R 755 /Volumes/mac_media/OneDrive_Empresa/
sudo chown -R pedro:staff /Volumes/mac_media/OneDrive_Empresa/

# Reiniciar Finder
killall Finder
```

---

### Problema 4: Sincronización muy lenta

**Causas posibles:**
- Muchos archivos
- Conexión lenta
- Unidad externa lenta (USB 2.0)

**Soluciones:**
1. **Pausar y reanudar:**
   - OneDrive → Pausar sincronización → Reanudar
   
2. **Sincronización selectiva:**
   - OneDrive → Preferencias → Cuenta
   - "Elegir carpetas" → Desmarcar carpetas grandes

3. **Usar Files On-Demand:**
   - No descarga archivos hasta que los abras
   - OneDrive → Preferencias → Sincronización
   - Activar "Files On-Demand"

---

### Problema 5: Ya tengo 2 cuentas y no puedo agregar más

**Causa:** OneDrive permite máximo 1 personal + 1 empresa

**Verificar:**
```bash
ls -la ~/Library/CloudStorage/
```

**Si ves 2 cuentas de OneDrive:**
- Primero desvincular una
- Luego agregar la nueva

---

## 📊 DESPUÉS DE CONFIGURAR

### Configuración recomendada (OPCIONAL)

#### 1. Activar inicio automático
1. OneDrive → Preferencias → General
2. ✅ Marcar "Iniciar OneDrive automáticamente al iniciar sesión"

#### 2. Notificaciones
1. OneDrive → Preferencias → General
2. Configurar notificaciones según preferencia

#### 3. Sincronización selectiva (ajustar después)
1. OneDrive → Preferencias → Cuenta
2. Click "Elegir carpetas" junto a cuenta empresa
3. Ajustar qué carpetas mantener sincronizadas

#### 4. Files On-Demand (verificar)
1. OneDrive → Preferencias → Configuración
2. ✅ "Files On-Demand" debe estar activado

---

## 🔍 COMANDOS DE MONITOREO

```bash
# Ver estado completo
~/monitor_onedrive.sh

# Ver contenido de cuenta empresa
ls -la /Volumes/mac_media/OneDrive_Empresa/

# Ver tamaño usado
du -sh /Volumes/mac_media/OneDrive_Empresa/

# Ver espacio disponible en disco
df -h /Volumes/mac_media

# Ver procesos OneDrive
ps aux | grep OneDrive | grep -v grep

# Abrir carpeta en Finder
open /Volumes/mac_media/OneDrive_Empresa/
```

---

## ⏱️ TIEMPO ESTIMADO

| Paso | Tiempo |
|------|--------|
| Preparación | 2 min |
| Desvincular cuenta | 1 min |
| Agregar cuenta | 2 min |
| Configurar ubicación | 2 min |
| Configurar sincronización | 3 min |
| Verificación | 2 min |
| **TOTAL** | **12 minutos** |
| **Sincronización** | **Variable** (puede ser horas si hay muchos datos) |

---

## 📝 NOTAS IMPORTANTES

⚠️ **Disco externo DEBE estar siempre conectado** para que OneDrive funcione

⚠️ **NO desconectar** el disco mientras OneDrive está sincronizando

⚠️ **NO eliminar** la carpeta `/Volumes/mac_media/OneDrive_Empresa/` manualmente

✅ **Puedes pausar** la sincronización desde el menú de OneDrive si necesitas

✅ **Files On-Demand** te permite ver archivos sin descargarlos (recomendado)

✅ **Sincronización selectiva** ahorra espacio y tiempo

---

## 🚀 ¿LISTO PARA EMPEZAR?

**Checklist antes de comenzar:**
- [ ] Disco externo `mac_media` conectado
- [ ] Tengo credenciales de pedro@eergygroup.cl
- [ ] Tengo 15-20 minutos disponibles
- [ ] OneDrive está corriendo (ícono en barra de menús)
- [ ] He leído los pasos 1-7

**Cuando estés listo:**
1. Abre OneDrive → Preferencias
2. Sigue los pasos de la sección "PASO A PASO"
3. Usa los comandos de verificación al terminar

---

**¿Dudas?** Revisa la sección "SOLUCIÓN DE PROBLEMAS" antes de preguntar.

**Estado:** ✅ Listo para configurar
