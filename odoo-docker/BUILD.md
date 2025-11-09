# 🏗️ Guía de Construcción - Odoo Docker Images

**Versión:** 19.0.1.0.0  
**Fecha:** 2025-10-24

---

## 📋 Tabla de Contenidos

1. [Requisitos Previos](#requisitos-previos)
2. [Build Rápido](#build-rápido)
3. [Build Manual](#build-manual)
4. [Build Stages](#build-stages)
5. [Verificación](#verificación)
6. [Troubleshooting](#troubleshooting)
7. [Optimización](#optimización)

---

## 🎯 Requisitos Previos

### Software Requerido

```bash
# Docker
docker --version  # >= 20.10.0

# Docker Compose
docker-compose --version  # >= 2.0.0

# Espacio en disco
df -h  # Mínimo 10GB libres
```

### Limpieza Previa (Opcional)

```bash
# Limpiar cache Docker
docker system prune -af --volumes

# Resultado esperado: ~14GB liberados
```

---

## 🚀 Build Rápido

### Opción 1: Script Automatizado (Recomendado)

```bash
cd /Users/pedro/Documents/odoo19/odoo-docker
./scripts/build.sh
```

**Tiempo:** 15-20 minutos (primera vez), 5-10 minutos (con cache)

**Resultado:**
```
✓ Base image built
✓ Chile image built
✓ Development image built

🎉 Build complete!

Images created:
  ✓ eergygroup/odoo19:base
  ✓ eergygroup/odoo19:base-19.0.1.0.0
  ✓ eergygroup/odoo19:chile
  ✓ eergygroup/odoo19:chile-19.0.1.0.0
  ✓ eergygroup/odoo19:latest
  ✓ eergygroup/odoo19:chile-dev
  ✓ eergygroup/odoo19:chile-19.0.1.0.0-dev
```

---

### Opción 2: Docker Compose

```bash
cd /Users/pedro/Documents/odoo19
docker-compose build odoo
```

**Resultado:** Solo imagen `chile` (producción)

---

## 🔧 Build Manual

### Build Stage Específico

#### Stage 1: Base (Oficial Odoo)

```bash
cd odoo-docker

docker build \
  --target base \
  --tag eergygroup/odoo19:base \
  --tag eergygroup/odoo19:base-19.0.1.0.0 \
  .
```

**Características:**
- Ubuntu Noble
- Odoo 19.0.20251021
- Scripts oficiales sin modificar
- Tamaño: 2.16GB

---

#### Stage 2: Chile (Producción)

```bash
docker build \
  --target chile \
  --tag eergygroup/odoo19:chile \
  --tag eergygroup/odoo19:chile-19.0.1.0.0 \
  --tag eergygroup/odoo19:latest \
  .
```

**Características:**
- Base + 25 deps Python
- Base + 12 deps sistema
- Configuración optimizada Chile
- Tamaño: 3.09GB

---

#### Stage 3: Development

```bash
docker build \
  --target development \
  --tag eergygroup/odoo19:chile-dev \
  --tag eergygroup/odoo19:chile-19.0.1.0.0-dev \
  .
```

**Características:**
- Chile + herramientas testing
- Chile + linting y formateo
- Chile + debugging
- Tamaño: 3.11GB

---

## 📊 Build Stages Detallado

### Flujo de Build

```
┌─────────────────────────────────────┐
│ STAGE 1: BASE                       │
│ (Oficial Odoo S.A.)                 │
├─────────────────────────────────────┤
│ • Ubuntu Noble                      │
│ • Odoo 19.0.20251021                │
│ • entrypoint.sh (oficial)           │
│ • wait-for-psql.py (oficial)        │
│ • Dependencias base Odoo            │
└─────────────────────────────────────┘
              ↓ hereda
┌─────────────────────────────────────┐
│ STAGE 2: CHILE                      │
│ (Customización EERGYGROUP)          │
├─────────────────────────────────────┤
│ • Base + Deps sistema (12)          │
│ • Base + Deps Python (25)           │
│ • l10n_cl_dte: 6/6 deps             │
│ • l10n_cl_financial_reports: 6/6    │
│ • l10n_cl_hr_payroll: 1/1           │
│ • Config optimizada Chile           │
└─────────────────────────────────────┘
              ↓ hereda
┌─────────────────────────────────────┐
│ STAGE 3: DEVELOPMENT                │
│ (Herramientas Dev)                  │
├─────────────────────────────────────┤
│ • Chile + pytest, pytest-cov        │
│ • Chile + black, flake8, pylint     │
│ • Chile + ipython, ipdb             │
└─────────────────────────────────────┘
```

---

### Layers por Stage

#### Stage 1: Base (9 layers)
```dockerfile
1. FROM ubuntu:noble
2. RUN apt-get update && install deps base
3. RUN install postgresql-client
4. RUN npm install -g rtlcss
5. RUN curl odoo.deb && install
6. COPY entrypoint.sh
7. COPY wait-for-psql.py
8. COPY odoo.conf
9. RUN chown & chmod & mkdir
```

#### Stage 2: Chile (+6 layers)
```dockerfile
10. RUN apt-get install deps sistema Chile
11. RUN apt-get install deps firma digital
12. COPY requirements-chile.txt
13. RUN pip install requirements-chile.txt
14. COPY odoo.conf Chile
15. RUN chown odoo.conf
```

#### Stage 3: Development (+1 layer)
```dockerfile
16. RUN pip install dev tools
```

---

## ✅ Verificación

### 1. Verificar Imágenes Creadas

```bash
docker images | grep eergygroup/odoo19
```

**Esperado:**
```
eergygroup/odoo19   chile-19.0.1.0.0-dev   ...   3.11GB
eergygroup/odoo19   chile-dev              ...   3.11GB
eergygroup/odoo19   chile                  ...   3.09GB
eergygroup/odoo19   chile-19.0.1.0.0       ...   3.09GB
eergygroup/odoo19   latest                 ...   3.09GB
eergygroup/odoo19   base                   ...   2.16GB
eergygroup/odoo19   base-19.0.1.0.0        ...   2.16GB
```

---

### 2. Verificar Versión Odoo

```bash
docker run --rm eergygroup/odoo19:chile odoo --version
```

**Esperado:**
```
Odoo Server 19.0-20251021
```

---

### 3. Verificar Dependencias Python

```bash
docker run --rm eergygroup/odoo19:chile python3 -c "
import lxml; print('✓ lxml:', lxml.__version__)
import zeep; print('✓ zeep:', zeep.__version__)
import pika; print('✓ pika:', pika.__version__)
import xlsxwriter; print('✓ xlsxwriter:', xlsxwriter.__version__)
import numpy; print('✓ numpy:', numpy.__version__)
import sklearn; print('✓ scikit-learn:', sklearn.__version__)
import jwt; print('✓ PyJWT:', jwt.__version__)
"
```

**Esperado:**
```
✓ lxml: 5.2.1
✓ zeep: 4.2.1
✓ pika: 1.3.2
✓ xlsxwriter: 3.1.9
✓ numpy: 2.3.4
✓ scikit-learn: 1.7.2
✓ PyJWT: 2.10.1
```

---

### 4. Verificar Scripts Oficiales

```bash
docker run --rm eergygroup/odoo19:chile ls -la /entrypoint.sh /usr/local/bin/wait-for-psql.py
```

**Esperado:**
```
-rwxr-xr-x 1 root root 1297 ... /entrypoint.sh
-rwxr-xr-x 1 root root  991 ... /usr/local/bin/wait-for-psql.py
```

---

### 5. Test de Arranque

```bash
docker run --rm \
  -e HOST=localhost \
  -e PORT=5432 \
  -e USER=odoo \
  -e PASSWORD=odoo \
  eergygroup/odoo19:chile \
  odoo --version
```

---

## 🔧 Troubleshooting

### Error: "PyPDF2 conflict"

**Síntoma:**
```
ERROR: Cannot uninstall PyPDF2 2.12.1, RECORD file not found
```

**Solución:**
PyPDF2 ya está incluido en Odoo base. Comentar en `requirements.txt`:
```python
# PyPDF2>=3.0.0  # Ya incluido en Odoo base
```

---

### Error: "Permission denied /var/lib/odoo/sessions"

**Síntoma:**
```
PermissionError: [Errno 13] Permission denied: '/var/lib/odoo/sessions'
```

**Solución:**
Verificar que el Dockerfile incluya:
```dockerfile
RUN mkdir -p /var/lib/odoo/sessions \
    && chown -R odoo:odoo /var/lib/odoo
```

---

### Error: "No space left on device"

**Síntoma:**
```
ERROR: failed to build: no space left on device
```

**Solución:**
```bash
# Limpiar cache Docker
docker system prune -af --volumes

# Verificar espacio
df -h
```

---

### Build Muy Lento

**Causas:**
1. Primera vez (sin cache)
2. Internet lento
3. Recursos limitados

**Soluciones:**
```bash
# 1. Usar cache de build anterior
docker build --cache-from eergygroup/odoo19:chile ...

# 2. Aumentar recursos Docker
# Docker Desktop → Settings → Resources → Memory: 4GB+

# 3. Build en paralelo (si tienes múltiples CPUs)
docker build --build-arg BUILDKIT_INLINE_CACHE=1 ...
```

---

## ⚡ Optimización

### 1. Usar BuildKit

```bash
export DOCKER_BUILDKIT=1
docker build ...
```

**Beneficios:**
- Build 50% más rápido
- Mejor cache
- Builds paralelos

---

### 2. Cache de Layers

```bash
# Build con cache explícito
docker build \
  --cache-from eergygroup/odoo19:base \
  --cache-from eergygroup/odoo19:chile \
  --target chile \
  -t eergygroup/odoo19:chile \
  .
```

---

### 3. Multi-Platform Build

```bash
# Build para múltiples arquitecturas
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --target chile \
  -t eergygroup/odoo19:chile \
  --push \
  .
```

---

## 📊 Métricas de Build

### Tiempos Típicos

| Stage | Primera Vez | Con Cache |
|-------|-------------|-----------|
| **base** | 8-10 min | 1-2 min |
| **chile** | 5-7 min | 2-3 min |
| **development** | 2-3 min | 30 seg |
| **TOTAL** | 15-20 min | 5-10 min |

### Tamaños

| Stage | Tamaño | Incremento |
|-------|--------|------------|
| **base** | 2.16GB | - |
| **chile** | 3.09GB | +930MB |
| **development** | 3.11GB | +20MB |

---

## 📝 Checklist de Build

### Pre-Build
- [ ] Docker instalado y corriendo
- [ ] Espacio en disco suficiente (>10GB)
- [ ] Archivos en `odoo-docker/` presentes
- [ ] `requirements.txt` actualizado

### Build
- [ ] Build ejecutado sin errores
- [ ] 7 imágenes creadas
- [ ] Tags correctos aplicados

### Post-Build
- [ ] Versión Odoo verificada
- [ ] Dependencias Python verificadas
- [ ] Scripts oficiales presentes
- [ ] Test de arranque exitoso

---

## 🔗 Referencias

- [Dockerfile](./Dockerfile)
- [README.md](./README.md)
- [CHANGELOG.md](./CHANGELOG.md)
- [Build Script](./scripts/build.sh)

---

**Última actualización:** 2025-10-24  
**Mantenido por:** EERGYGROUP
