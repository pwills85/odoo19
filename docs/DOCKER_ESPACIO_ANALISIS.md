# 🚨 ANÁLISIS: PROBLEMA DE ESPACIO DOCKER

**Fecha:** 2025-10-22  
**Sistema:** MacBook Pro M3  
**Problema:** Docker consumiendo demasiado espacio

---

## 📊 ESTADO ACTUAL

### **Uso Total Docker:**

```
TYPE            TOTAL     ACTIVE    SIZE      RECLAIMABLE
Images          18        9         18.21GB   7.914GB (43%)
Containers      11        6         505.6kB   498.3kB (98%)
Local Volumes   16        14        18.81GB   13.65GB (72%)
Build Cache     50        0         152.6kB   152.6kB (100%)
────────────────────────────────────────────────────────────
TOTAL DOCKER:                       37.02GB
```

### **Disco MacBook:**

```
Filesystem: /dev/disk3s5
Size:       460 GB
Used:       400 GB (91% LLENO) ⚠️
Available:  41 GB
```

---

## 🔍 ANÁLISIS DETALLADO

### **1. IMÁGENES DOCKER (18.21 GB)**

| Imagen | Tag | Tamaño | Estado | Acción |
|--------|-----|--------|--------|--------|
| **Ollama** | latest | **4.93 GB** | ⚠️ ACTIVO | **PROBLEMA** |
| eergygroup/odoo19 | v1 | 2.82 GB | Activo | Mantener |
| `<none>` | - | 2.82 GB | ❌ Huérfana | **ELIMINAR** |
| odoo19-ai-service | latest | 1.83 GB | Activo | Mantener |
| `<none>` | - | 1.74 GB | ❌ Huérfana | **ELIMINAR** |
| pedrowills/odoo12 | v15.4 | 1.55 GB | Activo | Revisar |
| pedrowills/odoo11 | v9.5.3 | 1.42 GB | Activo | Revisar |
| pedrowills/odoo11 | v9.5.3-dev | 1.42 GB | Duplicado | **ELIMINAR** |
| odoo19-dte-service | latest | 522 MB | Activo | Mantener |
| `<none>` | - | 521 MB × 6 | ❌ Huérfanas | **ELIMINAR** |
| prod_odoo-11_ai | latest | 354 MB | Activo | Revisar |
| postgres | 13.15 | 245 MB | Activo | Mantener |
| rabbitmq | 3.12 | 176 MB | Activo | Mantener |
| redis | 7-alpine | 41.7 MB | Activo | Mantener |

**Imágenes huérfanas:** ~7.9 GB (43% recuperable)

---

### **2. VOLÚMENES (18.81 GB)**

| Volumen | Tamaño | Proyecto | Acción |
|---------|--------|----------|--------|
| **buildx_buildkit_odoo-builder0_state** | **13.65 GB** | Build cache | **ELIMINAR** |
| prod_odoo-11_data_db | 3.95 GB | Odoo 11 prod | Revisar |
| prod_odoo-11_data_web | 1.16 GB | Odoo 11 prod | Revisar |
| prod_odoo-12_data_db | 41.3 MB | Odoo 12 prod | Revisar |
| odoo19_rabbitmq_data | 250 KB | Odoo 19 | Mantener |
| prod_odoo-11_redis_data | 199 KB | Odoo 11 | Mantener |
| odoo19_ollama_data | 468 B | Odoo 19 | Mantener |
| odoo19_ai_* | 0 B × 3 | Odoo 19 | Mantener |

**Build cache:** 13.65 GB (72% recuperable) ⚠️

---

### **3. BUILD CACHE (152.6 KB)**

Build cache activo es mínimo, pero el volumen `buildx_buildkit_odoo-builder0_state` tiene **13.65 GB**.

---

## 🎯 PROBLEMAS IDENTIFICADOS

### **CRÍTICO:**

1. ⚠️ **Ollama: 4.93 GB** - Imagen MUY pesada
2. ⚠️ **Build cache: 13.65 GB** - Cache de builds antiguos
3. ⚠️ **Imágenes huérfanas: 7.9 GB** - Imágenes sin usar

### **IMPORTANTE:**

4. ⚠️ **Odoo 11/12 prod: 5.1 GB** - Proyectos antiguos en producción
5. ⚠️ **Imágenes duplicadas** - pedrowills/odoo11 v9.5.3 y v9.5.3-dev

---

## 💡 SOLUCIONES PROPUESTAS

### **SOLUCIÓN 1: LIMPIEZA INMEDIATA (Recupera ~21 GB)**

#### **A. Eliminar imágenes huérfanas (7.9 GB)**

```bash
# Eliminar imágenes sin tag
docker image prune -a -f
```

**Recupera:** 7.9 GB

---

#### **B. Eliminar build cache (13.65 GB)**

```bash
# Eliminar volumen de build cache
docker volume rm buildx_buildkit_odoo-builder0_state

# Limpiar build cache general
docker builder prune -a -f
```

**Recupera:** 13.65 GB

---

#### **C. Eliminar contenedores parados (498 KB)**

```bash
# Eliminar contenedores no activos
docker container prune -f
```

**Recupera:** 498 KB (mínimo)

---

**Total recuperado:** ~21.5 GB  
**Espacio disponible después:** 62.5 GB

---

### **SOLUCIÓN 2: OPTIMIZAR OLLAMA (Recupera 4 GB)**

#### **Problema:** Ollama imagen completa es 4.93 GB

**Opciones:**

#### **Opción A: Eliminar Ollama (Recomendado según análisis costos)**

```bash
# Detener y eliminar Ollama
docker-compose stop ollama
docker-compose rm -f ollama
docker rmi ollama/ollama:latest
docker volume rm odoo19_ollama_data
```

**Razón:**
- Según análisis de costos: Claude Haiku/Sonnet es mejor
- Costo: $14.69/mes (insignificante)
- Sin mantenimiento
- Mejor calidad

**Recupera:** 4.93 GB

---

#### **Opción B: Usar Ollama con modelo pequeño**

```bash
# Usar modelo más pequeño
# En vez de llama2 (4 GB), usar:
# - tinyllama (637 MB)
# - phi (1.6 GB)
# - mistral (4.1 GB)

# Modificar docker-compose.yml o config.py:
ollama_model: str = "tinyllama"  # En vez de "llama2"
```

**Recupera:** ~3 GB (depende del modelo)

---

### **SOLUCIÓN 3: REVISAR PROYECTOS ANTIGUOS (Recupera 5-6 GB)**

#### **Odoo 11 y Odoo 12 en producción:**

```
prod_odoo-11_eergygroup: 5.1 GB
prod_odoo-12-GR: 41.3 MB
```

**Preguntas:**
1. ¿Estos proyectos siguen activos?
2. ¿Se pueden mover a otro servidor?
3. ¿Se pueden hacer backups y eliminar?

**Si no son necesarios:**

```bash
# Backup primero
docker-compose -f <ruta-proyecto> exec db pg_dump > backup.sql

# Detener y eliminar
docker-compose -f <ruta-proyecto> down -v
```

**Recupera:** 5-6 GB

---

## 🚀 PLAN DE ACCIÓN RECOMENDADO

### **FASE 1: LIMPIEZA INMEDIATA (5 min)**

```bash
# 1. Eliminar imágenes huérfanas
docker image prune -a -f

# 2. Eliminar build cache
docker builder prune -a -f

# 3. Eliminar contenedores parados
docker container prune -f

# 4. Eliminar volúmenes sin usar
docker volume prune -f
```

**Recupera:** ~21 GB  
**Riesgo:** Bajo (solo elimina recursos no usados)

---

### **FASE 2: ELIMINAR OLLAMA (2 min)**

```bash
# Modificar docker-compose.yml
# Comentar sección ollama (líneas 162-173)

# Detener y eliminar
cd /Users/pedro/Documents/odoo19
docker-compose stop ollama
docker-compose rm -f ollama
docker rmi ollama/ollama:latest
docker volume rm odoo19_ollama_data

# Modificar ai-service/config.py
# Comentar configuración Ollama
```

**Recupera:** 4.93 GB  
**Riesgo:** Bajo (según análisis, Claude es mejor opción)

---

### **FASE 3: REVISAR PROYECTOS ANTIGUOS (Opcional)**

```bash
# Evaluar si Odoo 11/12 siguen necesarios
# Si no: hacer backup y eliminar
```

**Recupera:** 5-6 GB  
**Riesgo:** Medio (requiere validar con equipo)

---

## 📊 RESULTADO ESPERADO

| Acción | Espacio Recuperado | Espacio Disponible |
|--------|-------------------|-------------------|
| **Estado actual** | - | 41 GB (91% usado) |
| Limpieza inmediata | +21 GB | 62 GB (87% usado) |
| Eliminar Ollama | +5 GB | 67 GB (85% usado) |
| Proyectos antiguos | +5 GB | 72 GB (84% usado) |

---

## ✅ COMANDOS PARA EJECUTAR AHORA

### **Script de limpieza completo:**

```bash
#!/bin/bash
#═══════════════════════════════════════════════════════════════
# Script: Limpieza Docker - MacBook Pro M3
# Propósito: Recuperar espacio en disco
#═══════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════"
echo "🧹 LIMPIEZA DOCKER - RECUPERACIÓN DE ESPACIO"
echo "════════════════════════════════════════════════════════════"
echo ""

# Mostrar estado actual
echo "📊 Estado actual:"
docker system df
echo ""

# 1. Eliminar imágenes huérfanas
echo "🗑️  Eliminando imágenes huérfanas..."
docker image prune -a -f
echo ""

# 2. Eliminar build cache
echo "🗑️  Eliminando build cache..."
docker builder prune -a -f
echo ""

# 3. Eliminar contenedores parados
echo "🗑️  Eliminando contenedores parados..."
docker container prune -f
echo ""

# 4. Eliminar volúmenes sin usar
echo "🗑️  Eliminando volúmenes sin usar..."
docker volume prune -f
echo ""

# 5. Eliminar redes sin usar
echo "🗑️  Eliminando redes sin usar..."
docker network prune -f
echo ""

# Mostrar estado final
echo "════════════════════════════════════════════════════════════"
echo "✅ LIMPIEZA COMPLETADA"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "📊 Estado final:"
docker system df
echo ""

# Mostrar espacio en disco
echo "💾 Espacio en disco:"
df -h ~/Library/Containers/com.docker.docker/Data/vms/0/data
echo ""
```

---

## 🎯 RECOMENDACIÓN FINAL

### **Ejecutar AHORA:**

1. ✅ **Limpieza inmediata** (recupera 21 GB)
   - Sin riesgo
   - 5 minutos
   - Ejecutar script arriba

2. ✅ **Eliminar Ollama** (recupera 5 GB)
   - Bajo riesgo
   - Claude es mejor opción (según análisis)
   - 2 minutos

### **Evaluar después:**

3. ⚠️ **Proyectos Odoo 11/12**
   - Validar con equipo
   - Hacer backups primero
   - Potencial: 5-6 GB

---

## 💡 PREVENCIÓN FUTURA

### **Configurar límites Docker Desktop:**

1. Abrir Docker Desktop
2. Settings → Resources → Advanced
3. Configurar:
   - **Disk image size:** 100 GB (en vez de ilimitado)
   - **Memory:** 8 GB
   - **CPUs:** 4

### **Limpieza periódica:**

```bash
# Agregar a crontab (cada semana)
0 2 * * 0 docker system prune -a -f
```

---

## 🚨 ADVERTENCIAS

### **NO ejecutar sin revisar:**

```bash
# ❌ NO ejecutar esto sin backup:
docker system prune -a --volumes -f

# Esto elimina TODO (imágenes, volúmenes, contenedores)
```

### **Hacer backup antes de eliminar proyectos:**

```bash
# ✅ Siempre hacer backup primero:
docker-compose exec db pg_dump -U odoo odoo > backup_$(date +%Y%m%d).sql
```

---

**¿Procedo a crear el script de limpieza y ejecutarlo?** 🚀
