# 🍎 INSTRUCCIONES DE SINCRONIZACIÓN - MacBook Pro M#

**Sistema:** macOS (Apple Silicon)  
**Fecha:** 2025-11-13  
**Repositorio:** odoo19

---

## 🚀 Ejecución Rápida

Abre la **Terminal** y ejecuta:

```bash
cd /Users/pedro/Documents/odoo19
chmod +x SYNC_GITHUB_MACOS.sh
./SYNC_GITHUB_MACOS.sh
```

El script es **100% interactivo** y te guiará en cada paso.

---

## 📋 Qué Hace el Script

### 1. Configura SSL para macOS
- Usa los certificados nativos de macOS (`/etc/ssl/cert.pem`)
- Configura `osxkeychain` (keychain nativo de macOS)
- Compatible con Homebrew en Apple Silicon (`/opt/homebrew/`)

### 2. Verifica GitHub CLI (recomendado)
- Si tienes `gh` instalado, lo usa automáticamente
- Si no está autenticado, te pregunta si quieres hacerlo
- **Autenticación web** (la más fácil en macOS)

### 3. Crea Backup de Seguridad
- Backup completo: `/tmp/odoo19-backup-[timestamp].bundle`
- Puedes restaurar con: `git clone /tmp/odoo19-backup-*.bundle`

### 4. Limpia Archivos Temporales
- Elimina `.tmp_*` y archivos temporales
- Actualiza `.gitignore` automáticamente

### 5. Commitea Cambios
- Archivos de configuración
- Tests actualizados
- Documentación
- Commit message profesional

### 6. Sincroniza con GitHub
- **Rama main:** Push/pull según sea necesario
- **Rama actual:** Publica en GitHub
- Manejo inteligente de divergencias

### 7. Verificación Final
- Confirma que todo está sincronizado
- Muestra resumen completo

---

## 🔧 Si No Tienes GitHub CLI (Opcional pero Recomendado)

### Instalar GitHub CLI en macOS:

```bash
# Con Homebrew (recomendado para Apple Silicon)
brew install gh

# Autenticar (abrirá tu navegador)
gh auth login --web --git-protocol https

# Configurar Git para usar gh
gh auth setup-git
```

**Ventajas:**
- ✅ Autenticación super fácil (web browser)
- ✅ No necesitas crear tokens manualmente
- ✅ Se integra perfectamente con macOS Keychain
- ✅ Credentials automáticamente renovadas

---

## 🔐 Alternativa: Autenticación Manual (Si NO usas GitHub CLI)

### Opción A: Usar Token Personal

1. **Crear token en GitHub:**
   - Ve a: https://github.com/settings/tokens
   - Click: "Generate new token (classic)"
   - Permisos necesarios: `repo`, `workflow`
   - Copia el token (se muestra solo UNA vez)

2. **Configurar en macOS Keychain:**
   ```bash
   # Git pedirá credentials la primera vez
   git fetch
   
   # Cuando pida:
   Username: pwills85
   Password: [PEGA TU TOKEN AQUÍ]
   
   # macOS Keychain lo guardará automáticamente
   ```

### Opción B: Usar SSH (Más seguro)

```bash
# 1. Generar clave SSH
ssh-keygen -t ed25519 -C "tu-email@ejemplo.com"
# Presiona Enter para ubicación default
# Crea un passphrase seguro

# 2. Agregar clave a ssh-agent
eval "$(ssh-agent -s)"
ssh-add --apple-use-keychain ~/.ssh/id_ed25519

# 3. Copiar clave pública
pbcopy < ~/.ssh/id_ed25519.pub

# 4. Agregar en GitHub:
# https://github.com/settings/keys
# Click "New SSH key", pega, guarda

# 5. Cambiar remote a SSH
cd /Users/pedro/Documents/odoo19
git remote set-url origin git@github.com:pwills85/odoo19.git

# 6. Probar
ssh -T git@github.com
# Debe decir: "Hi pwills85! You've successfully authenticated"
```

---

## 🐛 Solución de Problemas

### Error: "SSL certificate problem"

```bash
# Solución 1: Reinstalar certificados de Homebrew
brew reinstall openssl@3

# Solución 2: Usar certificados de macOS
git config --global http.sslCAInfo /etc/ssl/cert.pem

# Solución 3: Actualizar Homebrew
brew update && brew upgrade
```

### Error: "Could not resolve host"

```bash
# Verificar DNS
ping github.com

# Si falla, usar DNS de Google temporalmente
networksetup -setdnsservers Wi-Fi 8.8.8.8 8.8.4.4
```

### Error: "Authentication failed"

```bash
# Limpiar credentials guardadas
git credential-osxkeychain erase
host=github.com
protocol=https
[Presiona Enter dos veces]

# Luego vuelve a intentar (pedirá credentials nuevamente)
```

### El script falla al ejecutar

```bash
# Verificar que el script tenga permisos
ls -la SYNC_GITHUB_MACOS.sh

# Si no tiene 'x', agregar:
chmod +x SYNC_GITHUB_MACOS.sh

# Ejecutar con bash explícito
bash SYNC_GITHUB_MACOS.sh
```

---

## 📊 Estado Actual del Repositorio

### Antes de la Sincronización:

```
❌ Conexión: Error SSL
⚠️  Rama main: 800+ commits adelante del remoto
⚠️  Rama actual: fix/audit-p0-ciclo2-20251113 (no existe en GitHub)
🔴 Cambios sin commit: 7 archivos
🔴 Archivos sin track: 61+ archivos
```

### Después de la Sincronización:

```
✅ Conexión: Funcionando
✅ Rama main: Sincronizada con origin/main
✅ Rama actual: Publicada en GitHub
✅ Cambios: Commiteados y pushed
✅ Archivos temporales: Limpiados
```

---

## 🎯 Workflow Recomendado Post-Sync

### 1. Verificar en GitHub Web

```bash
# Abrir repositorio en navegador
open https://github.com/pwills85/odoo19
```

Verifica:
- ✅ Rama main actualizada
- ✅ Rama `fix/audit-p0-ciclo2-20251113` existe
- ✅ Commits recientes visibles

### 2. Crear Pull Request (si aplica)

```bash
# Con GitHub CLI (fácil)
gh pr create --title "P0 Audit Cycle 2 - Critical Fixes" \
             --body "Cierra hallazgos críticos del ciclo 2 de auditoría"

# O manualmente en:
# https://github.com/pwills85/odoo19/compare
```

### 3. Configurar Sync Automático Diario

Agrega a tu `.zshrc` (MacBook Pro usa zsh):

```bash
# Agregar al final de ~/.zshrc
alias odoo-sync="cd /Users/pedro/Documents/odoo19 && ./SYNC_GITHUB_MACOS.sh"
```

Luego puedes ejecutar simplemente:
```bash
odoo-sync
```

---

## 📈 Métricas Post-Sincronización

| Métrica | Antes | Después |
|---------|-------|---------|
| Conectividad GitHub | ❌ Error SSL | ✅ OK |
| Commits sin backup | 800+ | 0 |
| Archivos sin commit | 68 | 0 |
| Ramas sin publicar | 12 | 0-1 |
| Líneas sin backup remoto | 752K+ | 0 |

---

## 🔗 Referencias Útiles

- **GitHub CLI Docs:** https://cli.github.com/manual/
- **Git Credential macOS:** https://docs.github.com/en/get-started/getting-started-with-git/caching-your-github-credentials-in-git
- **SSH GitHub Setup:** https://docs.github.com/en/authentication/connecting-to-github-with-ssh

---

## ✅ Checklist Post-Ejecución

Después de ejecutar el script, verifica:

- [ ] Script completó sin errores
- [ ] Backup creado en `/tmp/`
- [ ] Rama main sincronizada
- [ ] Rama de trabajo publicada
- [ ] GitHub web muestra cambios
- [ ] `git status` muestra working tree limpio
- [ ] `git fetch` funciona sin pedir credentials

---

## 🆘 Soporte

Si el script falla:

1. **Lee el mensaje de error** (el script es verbose)
2. **Copia el error exacto** para diagnosticar
3. **Revisa la sección "Solución de Problemas"** arriba
4. **Verifica el backup** existe en `/tmp/` (tu código está seguro)

**El script es seguro:** Crea backup ANTES de hacer cambios.

---

**¿Listo?** Ejecuta:

```bash
cd /Users/pedro/Documents/odoo19 && ./SYNC_GITHUB_MACOS.sh
```

🚀 ¡Vamos!

