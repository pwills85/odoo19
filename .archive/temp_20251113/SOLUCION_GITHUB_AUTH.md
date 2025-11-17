# 🔐 SOLUCIÓN: Autenticación GitHub que se pierde al reiniciar

**Problema detectado:** Docker Desktop y Cursor pierden autenticación con GitHub en cada sesión.

**Causa raíz:**
1. Email inválido en Git: `tu.email@ejemplo.com` ❌
2. Sin Personal Access Token (PAT) guardado en macOS Keychain ❌
3. Docker sin configuración para GitHub Container Registry ❌

---

## ⚡ Solución Rápida (Recomendada)

### ⚠️ ACLARACIÓN IMPORTANTE: Token vs Password

**Cuando GitHub/Git pide "Password", en realidad pide tu Personal Access Token (PAT):**

```bash
Username: pwills85
Password: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  # ← TOKEN, NO tu contraseña de login
```

GitHub **eliminó la autenticación por contraseña** en agosto 2021. Ahora solo acepta:
- ✅ **Personal Access Token (PAT)** - Este método
- ✅ **SSH con llaves públicas/privadas**
- ✅ **GitHub CLI (gh)**

**📖 Lee más:** `.github/agents/knowledge/github_token_vs_password.md`

---

### Ejecuta el script automático (Versión 2.0):

```bash
cd /Users/pedro/Documents/odoo19
./scripts/setup_github_auth_v2.sh  # ← Versión mejorada con explicaciones claras
```

**Este script te guiará paso a paso y configurará:**
- ✅ Git con email correcto
- ✅ Credential helper de macOS (persistente)
- ✅ Personal Access Token guardado en Keychain
- ✅ Docker Desktop para GitHub
- ✅ Cursor para autenticación con GitHub

---

## 📝 Pasos que realizará el script

### 1️⃣ Actualizar Git Config
```bash
git config --global user.email "tu-email-real@github.com"
git config --global credential.helper osxkeychain
```

### 2️⃣ Crear Personal Access Token (PAT)

**Ir a:** https://github.com/settings/tokens

**Configuración del token:**
- **Note**: `Docker Desktop + Cursor Authentication`
- **Expiration**: `No expiration` (o `90 days`)
- **Scopes necesarios**:
  - ✅ `repo` - Control total de repositorios privados
  - ✅ `workflow` - Actualizar workflows de GitHub Actions
  - ✅ `write:packages` - Subir paquetes a GitHub Package Registry
  - ✅ `delete:packages` - Eliminar paquetes
  - ✅ `read:org` - Leer membresía de organizaciones

**⚠️ IMPORTANTE:** Copia el token inmediatamente (solo se muestra una vez)

### 3️⃣ Guardar Token en macOS Keychain

El script guardará tu token de forma segura y permanente en el Keychain de macOS.

### 4️⃣ Configurar Docker Desktop

Actualizará `~/.docker/config.json` con autenticación para:
- `ghcr.io` (GitHub Container Registry)
- `docker.pkg.github.com` (GitHub Packages)

### 5️⃣ Verificar Configuración

El script probará automáticamente la autenticación con:
- Git (clonar/fetch repositorios)
- Docker (login a GitHub Container Registry)

---

## 🧪 Verificación Manual

### Test 1: Git funciona sin pedir credenciales
```bash
cd /Users/pedro/Documents/odoo19
git fetch
# No debe pedir username/password
```

### Test 2: Docker puede acceder a GitHub Container Registry
```bash
docker login ghcr.io -u pwills85
# Debe mostrar: Login Succeeded
```

### Test 3: Cursor no muestra el mensaje de "Sign in to GitHub"
1. Abre Cursor
2. Ve a la barra lateral de Docker
3. ✅ No debe aparecer el mensaje de autenticación

---

## 🔄 Reiniciar Servicios (Después de ejecutar el script)

### Docker Desktop
```bash
# Desde menú: Docker Desktop → Restart
# O desde terminal:
killall "Docker Desktop" && open -a "Docker Desktop"
```

### Cursor
```bash
# Cmd+Q para cerrar
# Abrir nuevamente desde Applications
```

---

## ⚠️ Si el Problema Persiste

### 1. Verificar que el token no haya expirado
```bash
# Ir a: https://github.com/settings/tokens
# Verificar que el token esté activo (verde)
```

### 2. Limpiar credenciales y reconfigurar
```bash
# Borrar credenciales antiguas
echo "url=https://github.com" | git credential-osxkeychain erase

# Volver a ejecutar el script
./scripts/setup_github_auth.sh
```

### 3. Verificar configuración de Git
```bash
git config --global --list | grep -E "(user|credential|github)"
```

**Salida esperada:**
```
user.name=Pedro Troncoso Willz
user.email=tu-email-real@ejemplo.com
credential.helper=osxkeychain
credential.https://github.com.helper=osxkeychain
```

---

## 📚 Documentación Completa

Para más detalles y troubleshooting avanzado:
- **Guía completa:** `.github/agents/knowledge/github_auth_troubleshooting.md`
- **Script de configuración:** `scripts/setup_github_auth.sh`

---

## 🎯 Checklist Final

Después de ejecutar el script, verifica:

- [x] Cursor configurado automáticamente ✅
- [ ] Email real en Git (NO `tu.email@ejemplo.com`)
- [ ] Personal Access Token creado en GitHub
- [ ] Token guardado en macOS Keychain
- [ ] Docker Desktop reiniciado
- [ ] Cursor reiniciado
- [ ] Test de Git exitoso (sin pedir credenciales)
- [ ] Test de Docker exitoso (login a ghcr.io)
- [ ] Mensaje de "Sign in to GitHub" ya NO aparece

---

## 🚨 Seguridad

**✅ Lo que SÍ debes hacer:**
- Guardar el token en macOS Keychain (el script lo hace automáticamente)
- Renovar el token cada 90 días (recomendado)
- Revocar tokens antiguos si creas uno nuevo

**❌ Lo que NUNCA debes hacer:**
- Compartir tu Personal Access Token con nadie
- Commitear archivos con tokens (están en .gitignore)
- Usar la misma contraseña de GitHub como token

---

**Ejecuta el script ahora:**

```bash
cd /Users/pedro/Documents/odoo19
./scripts/setup_github_auth.sh
```

**Tiempo estimado:** 5-10 minutos (incluye crear el token en GitHub)

---

**Autor:** Sistema de Migración Odoo19  
**Fecha:** 2025-11-13  
**Proyecto:** Odoo19 CE Chilean Localization

