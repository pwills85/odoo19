# 🔐 GitHub: Token vs Password - Explicación Completa

**Fecha:** 2025-11-13  
**Tema:** Autenticación GitHub - Aclaración sobre "Password" = "Token"

---

## ❌ Cambio Crítico: GitHub eliminó autenticación por contraseña (2021)

**Desde agosto 2021**, GitHub **YA NO PERMITE** usar tu contraseña de login para operaciones Git:

```bash
# ❌ ESTO YA NO FUNCIONA:
git clone https://github.com/pwills85/odoo19.git
Username: pwills85
Password: tu_contraseña_de_login_github  # ❌ ERROR: Authentication failed
```

**Error que verás:**
```
remote: Support for password authentication was removed on August 13, 2021.
remote: Please use a personal access token instead.
fatal: Authentication failed for 'https://github.com/pwills85/odoo19.git/'
```

---

## ✅ Métodos de Autenticación Válidos (2024-2025)

| Método | Seguridad | Facilidad | Expira | Uso Recomendado |
|--------|-----------|-----------|--------|-----------------|
| **HTTPS + Token** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Sí* | Docker, CI/CD, Cursor |
| **SSH + Llaves** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | No | Desarrollo local |
| **GitHub CLI** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Sí* | Simplicidad |

*_Se puede configurar sin expiración (no recomendado para producción)_

---

## 🎯 Método 1: HTTPS + Personal Access Token (PAT)

### ¿Qué es un Personal Access Token?

Un **Personal Access Token (PAT)** es una **clave de acceso** que reemplaza tu contraseña de GitHub.

**Características:**
- ✅ Más seguro que contraseñas (permisos granulares)
- ✅ Revocable en cualquier momento
- ✅ Expirable (puedes configurar duración)
- ✅ Trazable (GitHub registra qué token hizo qué)

### Formato del Token

```bash
# Tokens clásicos (Classic PAT):
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Ejemplo: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234

# Tokens fine-grained (Fine-grained PAT) - Más nuevos, más seguros:
github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Ejemplo: github_pat_11A23BC4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5
```

### Cómo Funciona en la Práctica

**Cuando Git te pide credenciales:**

```bash
git clone https://github.com/pwills85/odoo19.git
```

**Git solicita:**
```
Username: pwills85
Password: <AQUÍ_PEGAS_TU_TOKEN>  # ⚠️ NO tu contraseña, sino el TOKEN
```

**⚠️ IMPORTANTE:** Aunque dice "Password", GitHub espera **el TOKEN**, no tu contraseña de login.

### Ejemplo Completo

```bash
# 1. Clonar repositorio
git clone https://github.com/pwills85/odoo19.git

# Git te pide:
Username for 'https://github.com': pwills85
Password for 'https://pwills85@github.com': ghp_1234567890abcdefghijklmnopqrstuvwxyz1234
                                            ↑
                                    AQUÍ PEGAS TU TOKEN

# 2. macOS Keychain guarda el token automáticamente
# NUNCA MÁS te volverá a pedir credenciales

# 3. Operaciones futuras funcionan sin pedir nada
git pull
git push
git fetch
# ✅ Todo funciona automáticamente
```

---

## 🔧 Configuración Persistente con macOS Keychain

### ¿Por qué usar macOS Keychain?

**macOS Keychain** es el gestor de contraseñas nativo de macOS. Almacena tus credenciales de forma:
- ✅ **Cifrada** (protegida por el sistema operativo)
- ✅ **Persistente** (sobrevive a reinicios)
- ✅ **Segura** (requiere desbloquear tu Mac para acceder)

### Configuración Automática

```bash
# Configurar Git para usar macOS Keychain
git config --global credential.helper osxkeychain
git config --global credential.https://github.com.helper osxkeychain

# Probar autenticación (te pedirá credenciales UNA VEZ)
git clone https://github.com/pwills85/odoo19.git

# Ingresa:
# Username: pwills85
# Password: <TU_TOKEN>

# ✅ El token se guarda automáticamente en Keychain
```

### Verificar que el Token está Guardado

```bash
# Consultar Keychain por credenciales de GitHub
git credential-osxkeychain get << EOF
protocol=https
host=github.com
EOF

# Salida esperada:
protocol=https
host=github.com
username=pwills85
password=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Borrar Credenciales (si necesitas reconfigurar)

```bash
# Borrar token guardado
echo "url=https://github.com" | git credential-osxkeychain erase

# Ahora Git te pedirá credenciales nuevamente
git fetch
```

---

## 🐳 Docker + GitHub Container Registry

### ¿Por qué Docker necesita autenticación con GitHub?

Docker necesita autenticación cuando:
1. **Pulls de imágenes privadas**: `docker pull ghcr.io/pwills85/mi-imagen:latest`
2. **Pushes a GitHub Container Registry**: `docker push ghcr.io/pwills85/mi-imagen:latest`
3. **GitHub Actions workflows**: CI/CD que usa Docker con GitHub

### Autenticación de Docker con Token

```bash
# Método 1: Login interactivo (te pide el token)
docker login ghcr.io -u pwills85
Password: <TU_TOKEN>  # ⚠️ Pegar TOKEN, no contraseña

# Método 2: Login no interactivo (desde variable)
echo $GITHUB_PAT | docker login ghcr.io -u pwills85 --password-stdin

# Método 3: Configurar ~/.docker/config.json (el script lo hace automáticamente)
```

### Configuración Persistente en Docker

**Archivo:** `~/.docker/config.json`

```json
{
  "auths": {
    "ghcr.io": {
      "auth": "cHdpbGxzODU6Z2hwXzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ="
    },
    "docker.pkg.github.com": {
      "auth": "cHdpbGxzODU6Z2hwXzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ="
    }
  }
}
```

**⚠️ NOTA:** El campo `"auth"` es **base64(username:token)**, NO el token directo.

**Generar auth string:**

```bash
# Generar string de autenticación
echo -n "pwills85:ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | base64

# Salida (ejemplo):
# cHdpbGxzODU6Z2hwXzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ=
```

---

## 🔑 Crear Personal Access Token en GitHub

### Paso a Paso (Classic Token)

1. **Ve a:** https://github.com/settings/tokens

2. **Click en:** "Generate new token" → "Generate new token (classic)"

3. **Configura:**

   **Note (descripción):**
   ```
   Docker Desktop + Cursor + Git Authentication
   ```

   **Expiration:**
   - `No expiration` (token no expira - menos seguro pero más conveniente)
   - `90 days` (más seguro - requiere renovación)
   - `1 year` (balance entre seguridad y conveniencia)

   **Select scopes (permisos):**
   - ✅ `repo` - Full control of private repositories
   - ✅ `workflow` - Update GitHub Action workflows
   - ✅ `write:packages` - Upload packages to GitHub Package Registry
   - ✅ `delete:packages` - Delete packages from GitHub Package Registry
   - ✅ `read:org` - Read org and team membership
   - ✅ `read:user` - Read user profile data

4. **Click:** "Generate token"

5. **⚠️ COPIA EL TOKEN INMEDIATAMENTE:**
   ```
   ghp_1234567890abcdefghijklmnopqrstuvwxyz1234
   ```

   **Solo se muestra UNA VEZ**. Si lo pierdes, debes crear uno nuevo.

### Scopes Explicados

| Scope | Qué Permite | Necesario Para |
|-------|-------------|----------------|
| `repo` | Acceso completo a repositorios privados | Git clone/push/pull |
| `workflow` | Actualizar GitHub Actions workflows | CI/CD pipelines |
| `write:packages` | Subir paquetes/imágenes Docker | Docker push a ghcr.io |
| `delete:packages` | Eliminar paquetes/imágenes | Limpieza de imágenes |
| `read:org` | Leer organizaciones | Repos de organizaciones |

---

## 🎯 Método 2: SSH (Alternativa Recomendada)

### ¿Cuándo usar SSH en lugar de HTTPS + Token?

**Ventajas de SSH:**
- ✅ **Más seguro**: Criptografía asimétrica (llave pública/privada)
- ✅ **No expira**: No necesitas renovar tokens
- ✅ **Más rápido**: No requiere autenticación en cada operación
- ✅ **Sin contraseñas**: Usa tu llave privada cifrada

**Desventajas de SSH:**
- ⚠️ Configuración inicial más compleja
- ⚠️ Docker no puede usar SSH directamente (solo Git)
- ⚠️ Requiere configurar llave en cada dispositivo

### Configuración SSH

```bash
# 1. Generar par de llaves SSH
ssh-keygen -t ed25519 -C "tu-email@ejemplo.com"

# Salida:
# Generating public/private ed25519 key pair.
# Enter file in which to save the key (/Users/pedro/.ssh/id_ed25519): [Enter]
# Enter passphrase (empty for no passphrase): [Enter una contraseña segura]

# 2. Copiar llave pública
cat ~/.ssh/id_ed25519.pub
# Salida:
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGx... tu-email@ejemplo.com

# 3. Añadir llave a GitHub
# Ve a: https://github.com/settings/keys
# Click: "New SSH key"
# Title: "MacBook Pro - Odoo19 Dev"
# Key: <PEGA LA LLAVE PÚBLICA>

# 4. Probar conexión
ssh -T git@github.com
# Salida esperada:
# Hi pwills85! You've successfully authenticated, but GitHub does not provide shell access.

# 5. Cambiar URL del repositorio a SSH
cd /Users/pedro/Documents/odoo19
git remote set-url origin git@github.com:pwills85/odoo19.git

# 6. Ahora Git usa SSH (NUNCA pide credenciales)
git pull
git push
# ✅ Todo funciona automáticamente
```

### Comparación HTTPS vs SSH

| Característica | HTTPS + Token | SSH |
|----------------|---------------|-----|
| **Seguridad** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Configuración inicial** | ⭐⭐⭐⭐⭐ Fácil | ⭐⭐⭐ Media |
| **Uso con Docker** | ✅ Sí | ❌ No |
| **Uso con CI/CD** | ✅ Sí | ⚠️ Complejo |
| **Expira** | Sí (configurable) | No |
| **Requiere renovación** | Sí (si expira) | No |
| **Funciona detrás de firewalls** | ✅ Siempre (puerto 443) | ⚠️ A veces (puerto 22 puede estar bloqueado) |

**Recomendación:**
- **HTTPS + Token**: Para proyectos con Docker, CI/CD, o múltiples desarrolladores
- **SSH**: Para desarrollo local personal y repositorios Git puros

---

## 🚀 Método 3: GitHub CLI (gh)

### ¿Qué es GitHub CLI?

**GitHub CLI** (`gh`) es la herramienta oficial de GitHub para línea de comandos.

**Ventajas:**
- ✅ **Login por navegador**: No necesitas copiar/pegar tokens
- ✅ **Gestión automática**: Crea y renueva tokens automáticamente
- ✅ **Integración completa**: Git, GitHub Actions, Issues, PRs, etc.

### Instalación y Configuración

```bash
# 1. Instalar GitHub CLI
brew install gh

# 2. Login interactivo
gh auth login

# Sigue el asistente:
# ? What account do you want to log into? GitHub.com
# ? What is your preferred protocol for Git operations? HTTPS
# ? Authenticate Git with your GitHub credentials? Yes
# ? How would you like to authenticate GitHub CLI? Login with a web browser

# 3. Se abrirá tu navegador
# Ingresa el código que te muestra en terminal
# Autoriza la aplicación

# 4. Configurar Git automáticamente
gh auth setup-git

# ✅ Listo! Git ya está configurado
```

### Uso de GitHub CLI

```bash
# Verificar autenticación
gh auth status

# Salida esperada:
# github.com
#   ✓ Logged in to github.com as pwills85 (oauth_token)
#   ✓ Git operations for github.com configured to use https protocol.
#   ✓ Token: *******************

# Refresh token (si expira)
gh auth refresh

# Logout
gh auth logout
```

---

## 🔍 Troubleshooting Común

### Problema 1: "Authentication failed" al hacer git push

**Causa:** Token expirado, revocado, o sin permisos

**Solución:**

```bash
# 1. Borrar credenciales antiguas
echo "url=https://github.com" | git credential-osxkeychain erase

# 2. Verificar token en GitHub
# Ve a: https://github.com/settings/tokens
# Verifica que el token esté activo (verde, no gris)

# 3. Si expiró, crear nuevo token
# Sigue los pasos en "Crear Personal Access Token"

# 4. Probar nuevamente
git fetch
# Te pedirá credenciales: Username + NUEVO_TOKEN
```

### Problema 2: Docker no puede acceder a ghcr.io

**Causa:** Docker no tiene configuración de autenticación para GitHub

**Solución:**

```bash
# Logout de Docker (limpiar)
docker logout ghcr.io

# Login nuevamente con token
docker login ghcr.io -u pwills85
Password: <TU_TOKEN>

# Verificar
docker pull ghcr.io/pwills85/tu-imagen:latest
```

### Problema 3: Cursor sigue pidiendo login

**Causa:** Cursor no tiene configuración de GitHub en `settings.json`

**Solución:**

Editar: `~/Library/Application Support/Cursor/User/settings.json`

```json
{
  "github.gitAuthentication": true,
  "git.terminalAuthentication": true,
  "git.rememberCredentials": true
}
```

Luego reiniciar Cursor: `Cmd+Q` → Abrir nuevamente

---

## 📚 Referencias Oficiales

| Recurso | URL |
|---------|-----|
| **GitHub PAT Documentation** | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens |
| **GitHub CLI Documentation** | https://cli.github.com/manual/ |
| **Git Credential Storage** | https://git-scm.com/docs/git-credential-store |
| **Docker Login** | https://docs.docker.com/reference/cli/docker/login/ |
| **GitHub Container Registry** | https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry |
| **SSH Key Generation** | https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent |

---

## 🎯 Resumen Ejecutivo

### ¿Qué es "Password" en GitHub?

**Cuando GitHub pide "Password", en realidad pide tu Personal Access Token (PAT):**

```bash
Username: pwills85
Password: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  # ← TOKEN, NO contraseña
```

### ¿Por qué GitHub cambió esto?

1. **Seguridad**: Tokens tienen permisos granulares (contraseñas son todo-o-nada)
2. **Revocación**: Puedes revocar un token sin cambiar tu contraseña
3. **Trazabilidad**: GitHub registra qué token hizo qué acción
4. **Expiración**: Tokens pueden expirar automáticamente

### ¿Cómo guardar el token de forma persistente?

**En macOS:**
```bash
git config --global credential.helper osxkeychain
```

**En Linux:**
```bash
git config --global credential.helper store
# O mejor (con cache de 1 año):
git config --global credential.helper 'cache --timeout=31536000'
```

**En Windows:**
```bash
git config --global credential.helper wincred
```

---

**Última actualización:** 2025-11-13  
**Autor:** Sistema de Migración Odoo19  
**Contacto:** Pedro Troncoso Willz (@pwills85)

