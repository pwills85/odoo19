# 🔐 Guía de Autenticación GitHub - Troubleshooting

**Fecha:** 2025-11-13  
**Proyecto:** Odoo19 Chilean Localization  
**Problema:** "Sign in to GitHub to access your repositories" aparece en cada sesión

---

## 🎯 Resumen del Problema

Docker Desktop y Cursor pierden la autenticación con GitHub al reiniciar sesión porque:

1. **Email inválido en Git**: Configurado como `tu.email@ejemplo.com` (placeholder)
2. **Sin Personal Access Token (PAT)**: No hay token guardado en macOS Keychain
3. **Docker sin configuración de GitHub**: No hay credenciales para `ghcr.io` o `docker.pkg.github.com`
4. **Cursor sin configuración de GitHub**: Falta `github.gitAuthentication: true`

---

## ✅ Solución Implementada

### Archivos Modificados

| Archivo | Cambio | Estado |
|---------|--------|--------|
| `~/.gitconfig` | ❌ Requiere email real | ⚠️ PENDIENTE |
| `~/Library/Application Support/Cursor/User/settings.json` | ✅ Configuración de GitHub añadida | ✅ COMPLETADO |
| `~/.docker/config.json` | ✅ Preparado para auth de GitHub | ✅ COMPLETADO |
| `scripts/setup_github_auth.sh` | ✅ Script de configuración creado | ✅ COMPLETADO |

### Script de Configuración Automática

**Ubicación:** `/Users/pedro/Documents/odoo19/scripts/setup_github_auth.sh`

**Uso:**

```bash
cd /Users/pedro/Documents/odoo19
./scripts/setup_github_auth.sh
```

**Este script:**
1. ✅ Verifica y corrige configuración de Git
2. ✅ Configura credential helper de macOS (`osxkeychain`)
3. ✅ Te guía para crear un Personal Access Token (PAT)
4. ✅ Guarda el PAT en macOS Keychain (persistente)
5. ✅ Configura Docker Desktop para GitHub Container Registry
6. ✅ Prueba la autenticación

---

## 📋 Pasos Manuales (Si prefieres hacerlo paso a paso)

### Paso 1: Crear Personal Access Token (PAT)

1. Ve a: https://github.com/settings/tokens
2. Click en **"Generate new token"** → **"Generate new token (classic)"**
3. Configura:
   - **Note**: `Docker Desktop + Cursor Authentication`
   - **Expiration**: `No expiration` (o `90 days`)
   - **Scopes**:
     - ✅ `repo` (Full control of private repositories)
     - ✅ `workflow` (Update GitHub Action workflows)
     - ✅ `write:packages` (Upload packages to GitHub Package Registry)
     - ✅ `delete:packages` (Delete packages from GitHub Package Registry)
     - ✅ `read:org` (Read org and team membership)
4. Click **"Generate token"**
5. **⚠️ COPIA EL TOKEN** (solo se muestra una vez)

### Paso 2: Actualizar Git Config

```bash
# Actualizar email (REEMPLAZA con tu email real de GitHub)
git config --global user.email "tu-email-real@ejemplo.com"

# Configurar credential helper para GitHub
git config --global credential.helper osxkeychain
git config --global credential.https://github.com.helper osxkeychain

# Verificar configuración
git config --global --list
```

### Paso 3: Guardar Token en macOS Keychain

```bash
# Borrar credenciales antiguas (si existen)
echo "url=https://github.com" | git credential-osxkeychain erase

# Probar autenticación (te pedirá username y password)
cd /Users/pedro/Documents/odoo19
git fetch
```

**Cuando te pida credenciales:**
- **Username**: `pwills85`
- **Password**: `<TU_PAT>` (el token que generaste)

El sistema macOS guardará esto automáticamente.

### Paso 4: Configurar Docker Desktop

```bash
# Crear auth string (base64 de username:token)
echo -n "pwills85:<TU_PAT>" | base64

# Editar ~/.docker/config.json y añadir:
{
  "auths": {
    "ghcr.io": {
      "auth": "<RESULTADO_BASE64>"
    },
    "docker.pkg.github.com": {
      "auth": "<RESULTADO_BASE64>"
    }
  }
}
```

O usar el script que lo hace automáticamente.

### Paso 5: Reiniciar Servicios

```bash
# Reiniciar Docker Desktop
# Desde menú: Docker Desktop → Restart

# Reiniciar Cursor
# Cmd+Q → Abrir nuevamente
```

---

## 🧪 Verificación de Configuración

### Test 1: Git Authentication

```bash
cd /Users/pedro/Documents/odoo19
git ls-remote https://github.com/pwills85/odoo19.git
```

**Resultado esperado:** Lista de referencias sin pedir credenciales

### Test 2: Docker GitHub Container Registry

```bash
docker login ghcr.io -u pwills85
```

**Resultado esperado:** Login Succeeded

### Test 3: Cursor + GitHub Actions

1. Abre Cursor
2. Ve a la barra lateral de Docker
3. **NO debe aparecer**: "Sign in to GitHub to access your repositories"

---

## 🔧 Troubleshooting Avanzado

### Problema: Git sigue pidiendo credenciales

**Solución:**

```bash
# Verificar helper configurado
git config --global credential.helper
# Debe mostrar: osxkeychain

# Si no funciona, limpiar y reconfigurar
git credential-osxkeychain erase << EOF
protocol=https
host=github.com
EOF

# Volver a probar
git fetch
```

### Problema: Docker no puede acceder a ghcr.io

**Solución:**

```bash
# Verificar autenticación actual
cat ~/.docker/config.json | jq .auths

# Si no hay entrada para ghcr.io, ejecutar:
./scripts/setup_github_auth.sh
```

### Problema: Token expirado

**Síntomas:**
- Git devuelve: `fatal: Authentication failed`
- Docker: `unauthorized: authentication required`

**Solución:**
1. Ve a: https://github.com/settings/tokens
2. Revoca el token antiguo
3. Crea un nuevo token con los mismos permisos
4. Ejecuta nuevamente: `./scripts/setup_github_auth.sh`

---

## 📚 Referencias Oficiales

| Recurso | URL |
|---------|-----|
| GitHub PAT Documentation | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens |
| Git Credential Storage | https://git-scm.com/docs/git-credential-store |
| Docker Login | https://docs.docker.com/reference/cli/docker/login/ |
| GitHub Container Registry | https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry |

---

## ⚠️ Seguridad

### ✅ Buenas Prácticas

1. **NUNCA** compartas tu Personal Access Token
2. **NUNCA** commitees archivos con tokens:
   - `~/.docker/config.json` (está en `.gitignore`)
   - `~/.gitconfig` (fuera del proyecto)
3. **USA** tokens con permisos mínimos necesarios
4. **RENUEVA** tokens cada 90 días (recomendado)
5. **REVOCA** tokens inmediatamente si se comprometen

### ❌ Qué NO hacer

- ❌ Compartir tu PAT por Slack/Email/Chat
- ❌ Usar la misma contraseña de GitHub como token
- ❌ Dar permisos `admin:org` si no son necesarios
- ❌ Crear tokens sin fecha de expiración (para producción)

---

## 🎯 Checklist de Configuración Completa

Usa este checklist para verificar que todo está configurado correctamente:

- [ ] Email real configurado en Git (`git config --global user.email`)
- [ ] Credential helper configurado (`git config --global credential.helper osxkeychain`)
- [ ] Personal Access Token (PAT) creado en GitHub
- [ ] PAT guardado en macOS Keychain (probado con `git fetch`)
- [ ] Docker configurado con auth de GitHub (`~/.docker/config.json`)
- [ ] Cursor configurado con `github.gitAuthentication: true`
- [ ] Docker Desktop reiniciado
- [ ] Cursor reiniciado
- [ ] Test de Git exitoso (`git ls-remote`)
- [ ] Test de Docker exitoso (`docker login ghcr.io`)
- [ ] No aparece "Sign in to GitHub" en Cursor

---

## 🚀 Próximos Pasos (Después de Configurar)

Una vez resuelto el problema de autenticación:

1. **Verificar GitHub Actions**: Los workflows ahora deberían funcionar sin pedir credenciales
2. **Pull de imágenes privadas**: Si tienes imágenes en `ghcr.io/pwills85/*`, Docker puede accederlas
3. **Push a GitHub**: Commits y push funcionarán sin pedir usuario/contraseña

---

**Última actualización:** 2025-11-13  
**Autor:** Sistema de Migración Odoo19  
**Contacto:** Pedro Troncoso Willz (@pwills85)

---

**Nota:** Este documento es parte del sistema de conocimiento del proyecto Odoo19 CE Chilean Localization. Se actualiza automáticamente cuando se detectan problemas de configuración.

