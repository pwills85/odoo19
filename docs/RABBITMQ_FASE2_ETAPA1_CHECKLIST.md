# ✅ RABBITMQ FASE 2 - ETAPA 1: PREPARACIÓN

**Duración:** 30 minutos  
**Estado:** 🟢 LISTO PARA EJECUTAR

---

## 📋 CHECKLIST DE EJECUCIÓN

### 1. Dependencias en Dockerfile ✅

**Archivos modificados:**
- ✅ `dte-service/requirements.txt` - Agregadas aio-pika y tenacity
- ✅ `dte-service/Dockerfile` - Instalación explícita

**Verificar:**
```bash
# Ver cambios en requirements.txt
cat dte-service/requirements.txt | grep -A2 "RABBITMQ"

# Ver cambios en Dockerfile
cat dte-service/Dockerfile | grep -A5 "RABBITMQ"
```

---

### 2. Rebuild Imagen Docker (15 min)

**Comando:**
```bash
cd /Users/pedro/Documents/odoo19

# Rebuild solo dte-service
docker-compose build dte-service

# Verificar que se instaló aio-pika
docker-compose run --rm dte-service python -c "import aio_pika; print(f'aio-pika {aio_pika.__version__} instalado')"
```

**Salida esperada:**
```
aio-pika 9.3.0 instalado
```

---

### 3. Crear Estructura de Directorios (5 min)

**Comandos:**
```bash
cd /Users/pedro/Documents/odoo19

# Crear directorios
mkdir -p config/rabbitmq
mkdir -p dte-service/messaging

# Crear archivos Python
touch dte-service/messaging/__init__.py
touch dte-service/messaging/models.py
touch dte-service/messaging/rabbitmq_client.py
touch dte-service/messaging/consumers.py

# Verificar estructura
tree config/rabbitmq dte-service/messaging
```

**Estructura esperada:**
```
config/rabbitmq/
└── (vacío por ahora)

dte-service/messaging/
├── __init__.py
├── models.py
├── rabbitmq_client.py
└── consumers.py
```

---

### 4. Verificación Final (5 min)

**Checklist:**
- [ ] aio-pika agregado a requirements.txt
- [ ] aio-pika agregado a Dockerfile
- [ ] Imagen dte-service rebuildeada
- [ ] aio-pika importa correctamente
- [ ] Directorios creados
- [ ] Archivos Python creados
- [ ] Commit realizado

**Comando de verificación completa:**
```bash
# 1. Verificar archivos existen
ls -la dte-service/messaging/

# 2. Verificar aio-pika en contenedor
docker-compose run --rm dte-service python -c "
import aio_pika
import tenacity
print(f'✅ aio-pika {aio_pika.__version__}')
print(f'✅ tenacity {tenacity.__version__}')
"

# 3. Verificar estructura
tree -L 2 config/ dte-service/messaging/
```

---

## 🎯 RESULTADO ESPERADO

Al completar Etapa 1:
- ✅ Imagen Docker con aio-pika instalado
- ✅ Estructura de directorios creada
- ✅ Archivos Python base creados
- ✅ Listo para Etapa 2 (Configuración)

---

## 🚀 COMANDO RÁPIDO (TODO EN UNO)

```bash
cd /Users/pedro/Documents/odoo19

# 1. Rebuild imagen
echo "🔨 Rebuilding dte-service image..."
docker-compose build dte-service

# 2. Verificar aio-pika
echo "✅ Verificando aio-pika..."
docker-compose run --rm dte-service python -c "import aio_pika; print(f'aio-pika {aio_pika.__version__} OK')"

# 3. Crear estructura
echo "📁 Creando estructura..."
mkdir -p config/rabbitmq dte-service/messaging
touch dte-service/messaging/{__init__,models,rabbitmq_client,consumers}.py

# 4. Verificar
echo "🔍 Verificando estructura..."
ls -la dte-service/messaging/

echo "✅ Etapa 1 completada!"
```

---

## ⏭️ PRÓXIMO PASO

**Etapa 2: Configuración (1 hora)**
- Crear `config/rabbitmq/rabbitmq.conf`
- Crear `config/rabbitmq/definitions.json`
- Actualizar `docker-compose.yml`

---

**Creado:** 2025-10-21 22:45 UTC-03:00  
**Estado:** ✅ LISTO PARA EJECUTAR  
**Tiempo estimado:** 30 minutos
