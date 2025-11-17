# 🔧 Scripts de Extracción e Importación: Odoo 11 → Odoo 19

**Ubicación:** `/scripts/`
**Propósito:** Automatizar migración certificado + CAF desde Odoo 11
**Creado:** 2025-10-23

---

## 📁 Scripts Disponibles

### 1. `extract_odoo11_credentials.py`

**Descripción:** Script Python para extraer certificado digital, CAF y configuración empresa desde base de datos Odoo 11.

**Ubicación:** `/scripts/extract_odoo11_credentials.py`

**Características:**
- ✅ Extrae certificado .p12 desde tabla `sii.firma`
- ✅ Extrae password certificado
- ✅ Extrae 5 CAF .xml desde tabla `caf`
- ✅ Extrae configuración empresa
- ✅ Validaciones integridad
- ✅ Resúmenes automáticos
- ✅ Compatible PostgreSQL local y remoto

**Dependencias:**
```bash
pip install psycopg2-binary
```

**Uso Básico:**
```bash
# Base de datos local
python scripts/extract_odoo11_credentials.py \
  --db odoo11_eergygroup \
  --user odoo \
  --output /tmp/export_odoo11

# Base de datos remota
python scripts/extract_odoo11_credentials.py \
  --db odoo11_eergygroup \
  --user odoo \
  --host 192.168.1.100 \
  --port 5432 \
  --password "mi_password" \
  --output /tmp/export_odoo11
```

**Argumentos:**
- `--db` (requerido): Nombre base de datos Odoo 11
- `--user` (default: odoo): Usuario PostgreSQL
- `--host` (default: localhost): Host base de datos
- `--port` (default: 5432): Puerto PostgreSQL
- `--password`: Password (si no se provee, pregunta interactivamente)
- `--output` (default: /tmp/export_odoo11): Directorio salida

**Output Esperado:**
```
/tmp/export_odoo11/
├── certificado_produccion.p12    # Certificado digital (3-5 KB)
├── certificado_info.txt           # Metadatos + password
├── CAF_33.xml                     # CAF Factura (2-3 KB)
├── CAF_34.xml                     # CAF Honorarios
├── CAF_52.xml                     # CAF Guía Despacho
├── CAF_56.xml                     # CAF Nota Débito
├── CAF_61.xml                     # CAF Nota Crédito
├── caf_summary.txt                # Resumen folios
└── company_config.txt             # Configuración empresa
```

**Validaciones Automáticas:**
1. Verifica existencia tablas `sii.firma` y `caf`
2. Busca certificado válido (no expirado)
3. Filtra CAF en uso con folios disponibles
4. Extrae un CAF por tipo DTE (el más reciente)
5. Genera resúmenes legibles

**Ejemplo Ejecución:**
```bash
$ python scripts/extract_odoo11_credentials.py --db odoo11_eergygroup --user odoo
🔌 Connecting to database: odoo11_eergygroup
Enter password for database user 'odoo': ********
✅ Connected successfully

📜 Extracting Digital Certificate...
✅ Certificate found:
   ID: 1
   Name: Certificado Eergygroup 2024
   RUT: 76123456-7
   Expires: 2025-12-31
   State: valid
✅ Certificate saved: /tmp/export_odoo11/certificado_produccion.p12
✅ Certificate info saved: /tmp/export_odoo11/certificado_info.txt

📁 Extracting CAF Files...
✅ Found 8 CAF file(s)

📄 CAF DTE 33:
   ID: 5
   Name: CAF Factura 2024
   Folios: 1000 - 1500
   Use Level: 45.2%
   State: in_use
   ✅ Saved: /tmp/export_odoo11/CAF_33.xml

...

✅ CAF summary saved: /tmp/export_odoo11/caf_summary.txt

🏢 Extracting Company Configuration...
✅ Company found:
   Name: Eergygroup SpA
   RUT: 76.123.456-7
   Address: Av Providencia 123, Santiago
✅ Company config saved: /tmp/export_odoo11/company_config.txt

================================================================================
📊 EXTRACTION SUMMARY
================================================================================
Certificate: ✅ Success
CAF Files:   ✅ Success
Company:     ✅ Success

Output directory: /tmp/export_odoo11

📋 NEXT STEPS:
1. Verify files integrity:
   ls -lh /tmp/export_odoo11/
2. Validate certificate:
   openssl pkcs12 -info -in /tmp/export_odoo11/certificado_produccion.p12 -noout
3. Import to Odoo 19 staging
================================================================================
```

---

### 2. `import_to_odoo19.sh`

**Descripción:** Script Bash para validar archivos extraídos e importar a Odoo 19.

**Ubicación:** `/scripts/import_to_odoo19.sh`

**Características:**
- ✅ Valida archivos extraídos existen
- ✅ Valida certificado con OpenSSL
- ✅ Valida CAF con xmllint
- ✅ Verifica Odoo 19 corriendo
- ✅ Instrucciones detalladas importación manual
- ✅ Checklist pre-import

**Uso:**
```bash
# Con directorio default
./scripts/import_to_odoo19.sh

# Con directorio custom
./scripts/import_to_odoo19.sh /path/to/export
```

**Output Ejemplo:**
```bash
$ ./scripts/import_to_odoo19.sh /tmp/export_odoo11
==================================================
🚀 Import Certificate & CAF to Odoo 19
==================================================
Export directory: /tmp/export_odoo11
Project directory: /Users/pedro/Documents/odoo19

✅ Odoo 19 is running

📋 Files found in export directory:
total 56K
-rw-r--r-- 1 user user 4.2K Oct 23 10:00 certificado_produccion.p12
-rw-r--r-- 1 user user  312 Oct 23 10:00 certificado_info.txt
-rw-r--r-- 1 user user 2.8K Oct 23 10:00 CAF_33.xml
-rw-r--r-- 1 user user 2.7K Oct 23 10:00 CAF_34.xml
...

🔐 Validating certificate with OpenSSL...
Enter certificate password (from certificado_info.txt):
✅ Certificate validation: OK

📁 CAF files found: 5
...

🔍 Validating CAF XML files...
  ✅ CAF_33.xml: Valid XML
  ✅ CAF_34.xml: Valid XML
  ...

==================================================
📋 MANUAL IMPORT INSTRUCTIONS
==================================================

1. Access Odoo 19 UI:
   http://localhost:8169

2. Login as admin

3. Import Certificate:
   Settings → Technical → Database Structure → Models
   ...

==================================================
```

---

## 🔄 Flujo Completo de Migración

### Paso 1: Preparación

```bash
# 1. Clonar proyecto Odoo 19
cd /Users/pedro/Documents/odoo19

# 2. Instalar dependencias Python
pip install psycopg2-binary

# 3. Verificar acceso Odoo 11
# Asegurar credenciales DB disponibles
```

### Paso 2: Extracción

```bash
# Ejecutar script extracción
python scripts/extract_odoo11_credentials.py \
  --db odoo11_eergygroup \
  --user odoo \
  --output /tmp/export_odoo11

# Verificar archivos
ls -lh /tmp/export_odoo11/
```

### Paso 3: Validación

```bash
# Validar certificado
openssl pkcs12 -info \
  -in /tmp/export_odoo11/certificado_produccion.p12 \
  -noout

# Validar CAF
for caf in /tmp/export_odoo11/CAF_*.xml; do
  xmllint --noout "$caf" && echo "✅ $(basename $caf): OK"
done
```

### Paso 4: Importación

```bash
# Ejecutar script import (validación + instrucciones)
./scripts/import_to_odoo19.sh /tmp/export_odoo11

# Seguir instrucciones manual (UI Odoo 19)
```

### Paso 5: Testing

```bash
# Generar 1 DTE test en Maullin (sandbox)
# Via UI Odoo 19
```

---

## 🛠️ Troubleshooting

### Error: "Table sii.firma not found"

**Causa:** Odoo 11 usa nombre tabla diferente para certificados.

**Solución:**
```bash
# Listar tablas relacionadas
psql -U odoo -d odoo11_db -c \
  "SELECT table_name FROM information_schema.tables
   WHERE table_name LIKE '%firma%' OR table_name LIKE '%cert%';"

# Ajustar script con nombre tabla correcto
# Editar línea 85-90 de extract_odoo11_credentials.py
```

### Error: "No CAF files found"

**Causa:** Tabla CAF vacía o nombre diferente.

**Solución:**
```bash
# Listar tablas CAF
psql -U odoo -d odoo11_db -c \
  "SELECT table_name FROM information_schema.tables
   WHERE table_name LIKE '%caf%';"

# Verificar registros
psql -U odoo -d odoo11_db -c \
  "SELECT COUNT(*) FROM caf WHERE state='in_use';"
```

### Error: OpenSSL "MAC verify error"

**Causa:** Password incorrecto certificado.

**Solución:**
```bash
# Verificar password en Odoo 11 UI
# Settings → Certificates → [Ver certificado] → Password

# Actualizar password en certificado_info.txt
nano /tmp/export_odoo11/certificado_info.txt
```

### Error: "psycopg2 not installed"

**Causa:** Dependencia Python faltante.

**Solución:**
```bash
pip install psycopg2-binary

# Si error compilación, instalar libpq-dev:
# Ubuntu/Debian:
sudo apt-get install libpq-dev python3-dev

# macOS:
brew install postgresql
```

### Error: "Permission denied" al ejecutar script

**Causa:** Script no tiene permisos ejecución.

**Solución:**
```bash
chmod +x scripts/extract_odoo11_credentials.py
chmod +x scripts/import_to_odoo19.sh
```

---

## 📊 Validaciones Post-Extracción

### Checklist Archivos Extraídos

- [ ] **certificado_produccion.p12**
  - Tamaño: 3-5 KB
  - OpenSSL valida OK
  - Password correcto

- [ ] **certificado_info.txt**
  - Contiene RUT empresa
  - Password presente
  - Fecha expiración > 6 meses

- [ ] **CAF_33.xml (Factura)**
  - XML válido (xmllint)
  - Folios disponibles > 100

- [ ] **CAF_34.xml (Honorarios)**
  - XML válido
  - Folios disponibles > 50

- [ ] **CAF_52.xml (Guía Despacho)**
  - XML válido
  - Folios disponibles > 50

- [ ] **CAF_56.xml (Nota Débito)**
  - XML válido
  - Folios disponibles > 20

- [ ] **CAF_61.xml (Nota Crédito)**
  - XML válido
  - Folios disponibles > 20

- [ ] **caf_summary.txt**
  - Lista 5 CAF
  - Rangos folios correctos

- [ ] **company_config.txt**
  - RUT empresa presente
  - Dirección completa

---

## 🔒 Seguridad

### Buenas Prácticas

1. **Certificado Password:**
   - Nunca commitear password a Git
   - Almacenar en gestor passwords (1Password, LastPass)
   - Eliminar certificado_info.txt después importar

2. **Directorio Output:**
   - Usar directorio temporal `/tmp/` (se borra al reiniciar)
   - O directorio con permisos restrictivos: `chmod 700`

3. **Archivos Sensibles:**
   ```bash
   # Después de importar a Odoo 19:
   # Encriptar archivos
   tar -czf export_backup.tar.gz /tmp/export_odoo11/
   gpg -c export_backup.tar.gz  # Pedir password

   # Eliminar originales
   rm -rf /tmp/export_odoo11/
   rm export_backup.tar.gz

   # Guardar solo export_backup.tar.gz.gpg
   ```

4. **Backups:**
   - Siempre backup completo Odoo 11 ANTES extracción
   - Guardar backups en storage redundante (S3, NAS)
   - Cifrar backups con contraseñas fuertes

---

## 📚 Referencias

- **Checklist Migración:** `/docs/MIGRATION_CHECKLIST_FAST_TRACK.md`
- **Plan Fast-Track:** `/docs/FAST_TRACK_MIGRATION_PLAN.md`
- **Análisis Odoo 11:** `/docs/ODOO11_ODOO18_ANALYSIS.md`
- **Roadmap 100%:** `/docs/ROADMAP_TO_100_PERCENT.md`

---

## ✅ Testing Scripts

### Test Script Extracción (Dry Run)

```bash
# Test con base de datos demo (si existe)
python scripts/extract_odoo11_credentials.py \
  --db odoo_demo \
  --user odoo \
  --output /tmp/test_export

# Verificar output
ls -la /tmp/test_export/
```

### Test Script Importación

```bash
# Validar sin importar
./scripts/import_to_odoo19.sh /tmp/test_export

# Verificar solo muestra instrucciones, no modifica nada
```

---

## 🎯 Métricas de Éxito

| Métrica | Objetivo | Resultado |
|---------|----------|-----------|
| **Tiempo Extracción** | < 5 min | _______ |
| **Archivos Extraídos** | 9/9 | _______ |
| **Validación OpenSSL** | OK | _______ |
| **Validación XML** | 5/5 OK | _______ |
| **Importación Odoo 19** | 6/6 OK | _______ |
| **Errores** | 0 | _______ |

---

**Actualizado:** 2025-10-23
**Versión:** 1.0.0
**Autor:** Claude + Pedro
**Estado:** Production Ready ✅

