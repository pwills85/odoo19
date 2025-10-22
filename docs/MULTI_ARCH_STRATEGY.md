# 🏗️ Estrategia Multi-Arquitectura: M3 (Desarrollo) vs AMD64 (Producción)

**Fecha:** 2025-10-21  
**Versión:** 1.0  
**Estado:** Documentación de Estrategia

---

## Objetivo

Definir una estrategia clara para construir y desplegar `eergygroup/odoo19:v1` en dos arquitecturas diferentes:
- **Desarrollo:** MacBook Pro M3 (ARM64 - Apple Silicon)
- **Producción:** Servidor AMD64 (Intel/AMD x86_64)

---

## Parte 1: Arquitecturas en Juego

### Tu MacBook Pro M3 (Desarrollo)

| Característica | Valor |
|---|---|
| **Procesador** | Apple M3 Pro |
| **Arquitectura** | ARM64 (Apple Silicon) |
| **Núcleos** | 12 (8 performance + 4 efficiency) |
| **Docker Arch** | linux/arm64 |
| **Emulación x86** | NO (nativa) |
| **Rendimiento** | ⚡ Excelente |

```bash
# Verificar en tu MacBook
uname -m                    → arm64 ✅
docker version --format ... → Arch: arm64 ✅
```

### Servidor Producción Típico (AMD64)

| Característica | Valor |
|---|---|
| **Procesador** | Intel Xeon / AMD Xeon |
| **Arquitectura** | AMD64 (x86_64) |
| **Ejemplos** | AWS EC2, Google Cloud, Azure, DigitalOcean |
| **Docker Arch** | linux/amd64 |
| **Emulación ARM** | NO (nativa) |
| **Rendimiento** | ⚡ Excelente |

---

## Parte 2: El Problema

### Si builds SOLO para ARM64 (tu M3):
```
✅ Funciona perfecto en MacBook M3
❌ FALLA en servidor AMD64 de producción
   - Arquitectura incompatible
   - Librerías compiladas para ARM
   - Error: "exec format error" o "killed"
```

### Si builds SOLO para AMD64:
```
❌ NO funciona en MacBook M3
   - Requeriría emulación QEMU = MUY LENTO
   - Desarrollo sería insoportable
✅ Funciona en servidor de producción
```

### Solución: TWO BUILDS

```
✅ eergygroup/odoo19:v1 (linux/arm64) → Desarrollo
✅ eergygroup/odoo19:v1-amd64 (linux/amd64) → Producción
```

---

## Parte 3: Nuestra Ventaja

### El Dockerfile es Multi-Arquitectura

Usamos `ubuntu:noble` que soporta ambas:

```dockerfile
FROM ubuntu:noble  # ✅ Funciona en ARM64 y AMD64
```

**Soporte del ecosistema:**
- ✅ ubuntu:noble: linux/arm64, linux/amd64, linux/arm/v7, linux/s390x
- ✅ postgres:13.15-alpine3.20: ✅ ARM64 ✅ AMD64
- ✅ redis:7-alpine: ✅ ARM64 ✅ AMD64
- ✅ Nuestras librerías Python: ✅ ARM64 ✅ AMD64

**Conclusión:** El mismo Dockerfile compila perfectamente en ambas arquitecturas.

---

## Parte 4: Estrategia Recomendada

### Fase 1: DESARROLLO (Tu MacBook - HOY)

```bash
$ cd /Users/pedro/Documents/odoo19
$ chmod +x scripts/*.sh
$ ./scripts/build.sh

# Resultado:
# ✅ eergygroup/odoo19:v1 (linux/arm64)
# ✅ Tamaño: ~2.5 GB
# ✅ Desarrollo funciona perfectamente
```

**Verificar:**
```bash
docker images | grep odoo19
# eergygroup/odoo19  v1  <ID>  ~2.5GB  linux/arm64 ✅
```

**Usar:**
```bash
docker-compose up -d
# Acceder: http://localhost:8069
# Usuario: admin
# Contraseña: admin
```

### Fase 2: PREPARACIÓN PRODUCCIÓN (Próximamente)

Cuando necesites versión para servidor AMD64:

```bash
# Opción A: Build local de AMD64 (requiere emulación - lento)
docker buildx build --platform linux/amd64 \
  -t eergygroup/odoo19:v1-amd64 .

# Opción B: Build en CI/CD (recomendado)
# Usar GitHub Actions, GitLab CI, etc. para buildear en AMD64
```

**Resultado:**
```bash
docker images
# eergygroup/odoo19        v1           <ID>  2.5GB  linux/arm64
# eergygroup/odoo19        v1-amd64     <ID>  2.5GB  linux/amd64
```

### Fase 3: PRODUCCIÓN (Servidor AMD64)

En tu servidor de producción:

```bash
# Pull imagen AMD64
docker pull eergygroup/odoo19:v1-amd64

# Usar en docker-compose
services:
  odoo:
    image: eergygroup/odoo19:v1-amd64  # ✅ AMD64
```

---

## Parte 5: Comparativa de Opciones

| Opción | Complejidad | Desarrollo (M3) | Producción (AMD64) | Recomendación |
|--------|-------------|---|---|---|
| **Solo ARM64** | ⭐ | ✅ | ❌ | NO |
| **Solo AMD64** | ⭐ | ⚠️ Emulado (lento) | ✅ | NO |
| **Dos tags (v1, v1-amd64)** | ⭐⭐ | ✅ | ✅ | ✅ **SÍ** |
| **Manifest multi-arch** | ⭐⭐⭐ | ✅ | ✅ | ✅ **Profesional** |

### Recomendación para tu proyecto: OPCIÓN 3 (Dos tags)

Razones:
- Simple de implementar
- Desarrollo rápido (no emulación)
- Producción nativa (no emulación)
- Fácil de mantener
- Escalable

---

## Parte 6: Comandos Específicos

### HOY - Build para tu MacBook (ARM64)

```bash
$ cd /Users/pedro/Documents/odoo19
$ ./scripts/build.sh

# Esto ejecuta:
docker build -t eergygroup/odoo19:v1 .
```

### PRÓXIMAMENTE - Build para Producción (AMD64)

**Opción A: Local (con emulación QEMU - MÁS LENTO)**
```bash
# Requiere tener buildx instalado
docker buildx install

# Build para AMD64
docker buildx build \
  --platform linux/amd64 \
  -t eergygroup/odoo19:v1-amd64 \
  --load .
```

**Opción B: CI/CD Pipeline (RECOMENDADO - RÁPIDO)**

Crear `.github/workflows/build-prod.yml`:
```yaml
name: Build Production Image (AMD64)
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: docker/setup-buildx-action@v1
      - uses: docker/build-push-action@v3
        with:
          platforms: linux/amd64
          tags: eergygroup/odoo19:v1-amd64
          push: true  # Push a Docker Hub
```

---

## Parte 7: Tamaños Estimados

| Imagen | Arquitectura | Tamaño | Optimización |
|--------|---|---|---|
| eergygroup/odoo19:v1 | linux/arm64 | ~2.5 GB | ✅ Alpine donde posible |
| eergygroup/odoo19:v1-amd64 | linux/amd64 | ~2.5 GB | ✅ Mismo tamaño (ubuntu:noble) |

---

## Parte 8: Validación en Producción

### Antes de desplegar en producción AMD64:

```bash
# 1. Verificar arquitectura de imagen
docker inspect eergygroup/odoo19:v1-amd64 --format='{{.Architecture}}'
# Resultado: amd64 ✅

# 2. Probar en servidor AMD64 (o VM local)
docker run -it eergygroup/odoo19:v1-amd64 /bin/bash

# 3. Verificar librerías críticas
python3 -c "import pyOpenSSL; import zeep; import lxml"
# Sin errores = ✅

# 4. Validar conectividad
docker-compose -f docker-compose.prod.yml up --dry-run

# 5. Deploy
docker-compose -f docker-compose.prod.yml up -d
```

---

## Parte 9: Resumen de Architechturas

### Linux Arm64 (apple Silicon)
- MacBook M1/M2/M3/M4
- AWS Graviton
- Otros ARM64

### Linux Amd64 (Intel/AMD x86)
- La mayoría de servidores en cloud
- On-premises típicos
- Máquinas virtuales

### Nuestra solución
- Dockerfile genérico: funciona en AMBAS
- Build específico por arquitectura
- Dos imágenes Docker diferentes
- Mismo código fuente

---

## Parte 10: Checklist de Implementación

### FASE 1 - DESARROLLO (AHORA)
- [ ] Ejecutar `./scripts/build.sh` en MacBook M3
- [ ] Verificar: `docker images | grep odoo19`
- [ ] Ejecutar: `docker-compose up -d`
- [ ] Acceder: http://localhost:8069
- [ ] Desarrollo del módulo l10n_cl_dte

### FASE 2 - PREPARACIÓN PRODUCCIÓN
- [ ] Crear imagen AMD64 (buildx o CI/CD)
- [ ] Tagear como `v1-amd64`
- [ ] Testear en servidor AMD64 o VM
- [ ] Crear docker-compose.prod.yml
- [ ] Documentar en README.md

### FASE 3 - PRODUCCIÓN
- [ ] Push de imagen AMD64 a Docker Hub (opcional)
- [ ] Deploy en servidor producción AMD64
- [ ] Verificar con `docker ps`
- [ ] Testing de funcionalidad
- [ ] Monitoreo

---

## Conclusión

**Tu estrategia es correcta:**

```
✅ Desarrollo en MacBook M3:     eergygroup/odoo19:v1 (ARM64)
✅ Producción en servidor AMD64: eergygroup/odoo19:v1-amd64 (AMD64)
```

Ambas imágenes usan el **mismo Dockerfile**, lo que garantiza:
- Código idéntico entre dev y prod
- Fácil mantenimiento
- Comportamiento predecible
- Escalabilidad

El tamaño será similar (~2.5 GB) porque ubuntu:noble es eficiente en ambas arquitecturas.

---

**Próximo paso:** Ejecutar `./scripts/build.sh` en tu MacBook M3
