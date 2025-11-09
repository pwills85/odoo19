# Odoo 19 CLI Commands Reference

Referencia completa de comandos de línea de comandos para desarrollo, testing y gestión de bases de datos en Odoo 19 CE.

**Fecha:** 2025-10-22
**Versión Odoo:** 19.0-20251021
**Proyecto:** l10n_cl_dte (Chilean Electronic Invoicing)

---

## 📋 Índice

1. [Comandos Principales](#comandos-principales)
2. [Gestión de Bases de Datos](#gestión-de-bases-de-datos)
3. [Gestión de Módulos](#gestión-de-módulos)
4. [Testing y QA](#testing-y-qa)
5. [Comandos de Servidor](#comandos-de-servidor)
6. [Comandos Auxiliares](#comandos-auxiliares)
7. [Ejemplos Prácticos](#ejemplos-prácticos)
8. [Testing Patterns (l10n_cl)](#testing-patterns-l10n_cl)

---

## Comandos Principales

### Ver todos los comandos disponibles

```bash
docker-compose exec odoo odoo --help
```

**Comandos disponibles:**
- `cloc` - Contar líneas de código por módulo
- `db` - Crear, eliminar, dump, cargar bases de datos
- `deploy` - Desplegar módulo en instancia Odoo
- `genproxytoken` - Generar token de proxy
- `help` - Mostrar lista de comandos
- `i18n` - Importar, exportar, configurar idiomas
- `module` - Gestionar módulos, instalar demo data
- `neutralize` - Neutralizar BD de producción para testing
- `obfuscate` - Ofuscar datos en BD
- `populate` - Poblar BD con datos duplicados (testing/demo)
- `scaffold` - Generar esqueleto de módulo Odoo
- `server` - Iniciar servidor Odoo (comando por defecto)
- `shell` - Iniciar Odoo en shell interactivo
- `start` - Iniciar servidor rápido con opciones por defecto
- `upgrade_code` - Reescribir código fuente con scripts de upgrade

---

## Gestión de Bases de Datos

### Comando: `odoo db`

Gestión de bases de datos con soporte filestore.

#### Subcomandos disponibles

```bash
docker-compose exec odoo odoo db --help
```

**Subcomandos:**
- `init` - Crear e inicializar base de datos
- `load` - Cargar archivo dump
- `dump` - Crear dump con filestore
- `duplicate` - Duplicar base de datos incluyendo filestore
- `rename` - Renombrar base de datos incluyendo filestore
- `drop` - Eliminar base de datos incluyendo filestore

### 1. Crear nueva base de datos

```bash
# Sintaxis básica
docker-compose exec odoo odoo db init <database_name>

# Con opciones completas
docker-compose exec odoo odoo db init \
  --with-demo \
  --language es_CL \
  --username admin \
  --password admin123 \
  --country CL \
  odoo_test
```

**Opciones disponibles:**
- `--with-demo` - Instalar datos de demostración
- `--force` - Eliminar BD si ya existe
- `--language LANGUAGE` - Idioma por defecto (default: 'en_US')
- `--username USERNAME` - Usuario admin (default: 'admin')
- `--password PASSWORD` - Contraseña admin (default: 'admin')
- `--country COUNTRY` - País de la empresa principal

**Ejemplo para Chile:**
```bash
docker-compose exec odoo odoo db init \
  --language es_CL \
  --country CL \
  --username admin \
  --password eergygroup2024 \
  odoo_cl_test
```

### 2. Dump (Backup) de base de datos

```bash
# Dump con filestore
docker-compose exec odoo odoo db dump odoo > backup_odoo_$(date +%Y%m%d).dump

# Desde el host (sin exec)
docker-compose run --rm odoo odoo db dump odoo > backup_odoo_$(date +%Y%m%d).dump
```

### 3. Cargar dump

```bash
# Desde archivo dump
docker-compose exec odoo odoo db load odoo < backup_odoo_20251022.dump
```

### 4. Duplicar base de datos

```bash
# Duplicar BD completa (incluyendo filestore)
docker-compose exec odoo odoo db duplicate odoo odoo_copy
```

### 5. Renombrar base de datos

```bash
# Renombrar BD (incluyendo filestore)
docker-compose exec odoo odoo db rename odoo_old odoo_new
```

### 6. Eliminar base de datos

```bash
# Eliminar BD (incluyendo filestore)
docker-compose exec odoo odoo db drop odoo_test
```

---

## Gestión de Módulos

### Comando: `odoo module`

Gestionar instalación, actualización y desinstalación de módulos.

#### Subcomandos disponibles

```bash
docker-compose exec odoo odoo module --help
```

**Subcomandos:**
- `install` - Instalar módulos
- `upgrade` - Actualizar módulos
- `uninstall` - Desinstalar módulos
- `force-demo` - Instalar datos demo (forzar)

### 1. Instalar módulos

```bash
# Sintaxis básica
docker-compose exec odoo odoo module install \
  -d <database_name> \
  <module_name> [<module_name2> ...]

# Instalar l10n_cl_dte
docker-compose exec odoo odoo module install \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  l10n_cl_dte

# Instalar múltiples módulos
docker-compose exec odoo odoo module install \
  -d odoo \
  l10n_cl l10n_latam_base l10n_cl_dte

# Instalar módulos data (.zip)
docker-compose exec odoo odoo module install \
  -d odoo \
  /path/to/module.zip
```

**Opciones:**
- `-c CONFIG, --config CONFIG` - Archivo de configuración específico
- `-d DB_NAME, --database DB_NAME` - Nombre de base de datos

**Nota:** La BD debe existir y estar inicializada previamente con `db init`.

### 2. Actualizar módulos

```bash
# Actualizar un módulo
docker-compose exec odoo odoo module upgrade \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  l10n_cl_dte

# Actualizar múltiples módulos
docker-compose exec odoo odoo module upgrade \
  -d odoo \
  l10n_cl_dte account stock
```

### 3. Desinstalar módulos

```bash
# Desinstalar un módulo
docker-compose exec odoo odoo module uninstall \
  -d odoo \
  l10n_cl_dte
```

### 4. Forzar instalación de datos demo

```bash
# Forzar demo data en módulo
docker-compose exec odoo odoo module force-demo \
  -d odoo \
  l10n_cl_dte
```

---

## Testing y QA

### Opciones de Testing del servidor

Todas las opciones de testing se usan con el comando `odoo server`.

### 1. Ejecutar todos los tests

```bash
# Habilitar tests (implica --stop-after-init)
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-enable \
  --stop-after-init
```

### 2. Ejecutar tests por tags

```bash
# Sintaxis de filtro de tests
--test-tags=STRING

# Formato del filtro:
[-][tag][/module][:class][.method][[params]]
```

**Componentes del filtro:**
- `-` - Prefijo para excluir tests
- `tag` - Tag añadido con decorator @tagged
- `/module` - Nombre del módulo
- `:class` - Nombre de la clase de test
- `.method` - Nombre del método de test
- `[params]` - Parámetros para el método (opcional)

**Tags por defecto:**
- `standard` - Tests estándar (por defecto si no se especifica)
- `at_install` - Tests que corren al instalar
- `post_install` - Tests que corren después de instalar todos los módulos
- `*` - Todos los tags

### 3. Ejemplos de test-tags

```bash
# Tests estándar de un módulo específico
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags /l10n_cl_dte \
  --stop-after-init

# Tests de una clase específica
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags :TestRUTValidator \
  --stop-after-init

# Tests de un método específico
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags :TestRUTValidator.test_valid_rut \
  --stop-after-init

# Tests por tag personalizado
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags post_install_l10n \
  --stop-after-init

# Múltiples filtros (separados por coma)
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags :TestClass.test_func,/test_module,external \
  --stop-after-init

# Excluir tests específicos
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags /l10n_cl_dte,-:TestSlow \
  --stop-after-init

# Tests con parámetros
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags /web.test_js[mail] \
  --stop-after-init
```

### 4. Tests de un archivo específico

```bash
# Ejecutar test file (Python)
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-file=/mnt/extra-addons/localization/l10n_cl_dte/tests/test_rut_validator.py \
  --stop-after-init
```

### 5. Screenshots y Screencasts

```bash
# Guardar screenshots de tests
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-enable \
  --screenshots=/tmp/odoo_screenshots \
  --stop-after-init

# Guardar screencasts de tests
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-enable \
  --screencasts=/tmp/odoo_screencasts \
  --stop-after-init
```

**Ubicación por defecto:** `/tmp/odoo_tests/{db_name}/screenshots` o `screencasts`

---

## Comandos de Servidor

### Iniciar servidor con opciones específicas

```bash
# Ver todas las opciones del servidor
docker-compose exec odoo odoo server --help
```

### Opciones Comunes

#### 1. Instalación y actualización de módulos

```bash
# Instalar módulos (método antiguo, via server)
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  -i l10n_cl_dte \
  --stop-after-init

# Actualizar módulos
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  -u l10n_cl_dte \
  --stop-after-init

# Actualizar todos los módulos
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  -u all \
  --stop-after-init

# Reinstalar módulos
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --reinit=l10n_cl_dte \
  --stop-after-init
```

#### 2. Datos de demostración

```bash
# Instalar con demo data
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  -i l10n_cl_dte \
  --with-demo \
  --stop-after-init

# Sin demo data (default)
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  -i l10n_cl_dte \
  --without-demo \
  --stop-after-init
```

#### 3. Modo Desarrollador

```bash
# Dev mode con todas las features
docker-compose up odoo \
  --dev=all

# Dev mode específico
docker-compose up odoo \
  --dev=reload,qweb,xml

# Features disponibles:
# - access: log traceback de errores de acceso
# - qweb: log XML compilado con errores qweb
# - reload: reiniciar server al cambiar código fuente
# - replica: simular deployment con replica readonly
# - werkzeug: abrir debugger HTML en error HTTP
# - xml: leer vistas desde código fuente (no DB)
```

#### 4. Logging

```bash
# Log a archivo
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  --logfile=/var/log/odoo/odoo.log

# Log a syslog
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  --syslog

# Log handlers específicos
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  --log-handler=odoo.orm:DEBUG \
  --log-handler=werkzeug:CRITICAL

# Shortcuts
--log-web        # Shortcut para --log-handler=odoo.http:DEBUG
--log-sql        # Shortcut para --log-handler=odoo.sql_db:DEBUG

# Log level
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  --log-level=debug
```

**Niveles aceptados:** info, debug_rpc, warn, test, critical, runbot, debug_sql, error, debug, debug_rpc_answer, notset

#### 5. Database options

```bash
# Especificar database
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo,odoo_test

# Credenciales DB
docker-compose run --rm odoo odoo server \
  --db_host=db \
  --db_port=5432 \
  --db_user=odoo \
  --db_password=odoo

# Template personalizado
docker-compose run --rm odoo odoo server \
  --db-template=template_odoo

# Conexiones máximas
docker-compose run --rm odoo odoo server \
  --db_maxconn=64

# SSL mode
docker-compose run --rm odoo odoo server \
  --db_sslmode=require
```

---

## Comandos Auxiliares

### 1. Shell Interactivo

```bash
# Abrir shell de Odoo (Python)
docker-compose exec odoo odoo shell \
  -c /etc/odoo/odoo.conf \
  -d odoo
```

**Uso dentro del shell:**
```python
# Acceso a env
env['res.partner'].search([])

# Acceso a modelos
partners = env['res.partner'].search([('country_id.code', '=', 'CL')])
for p in partners:
    print(f"{p.name} - {p.vat}")

# Crear registros
company = env['res.company'].browse(1)
company.l10n_cl_activity_code = '421000'
env.cr.commit()  # IMPORTANTE: hacer commit

# Salir
exit()
```

### 2. Contar líneas de código

```bash
# Contar líneas por módulo
docker-compose exec odoo odoo cloc

# Ejemplo de output:
# Module: l10n_cl_dte
#   Python: 2,543 lines
#   XML: 876 lines
#   JS: 234 lines
```

### 3. Neutralizar base de datos

```bash
# Neutralizar BD de producción para testing
# (desactiva envío de emails, crons, etc.)
docker-compose exec odoo odoo neutralize \
  -d odoo_production_copy
```

### 4. Ofuscar datos

```bash
# Ofuscar datos sensibles en BD
docker-compose exec odoo odoo obfuscate \
  -d odoo_production_copy
```

### 5. Poblar base de datos

```bash
# Duplicar datos existentes para testing/demo
docker-compose exec odoo odoo populate \
  -d odoo_test
```

### 6. Scaffold (generar módulo)

```bash
# Crear esqueleto de módulo nuevo
docker-compose exec odoo odoo scaffold \
  my_custom_module \
  /mnt/extra-addons/custom/

# Estructura generada:
# my_custom_module/
#   __init__.py
#   __manifest__.py
#   controllers/
#   models/
#   security/
#   views/
```

### 7. i18n (Internacionalización)

```bash
# Cargar idioma
docker-compose exec odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --load-language=es_CL \
  --stop-after-init

# Sobrescribir términos existentes
docker-compose exec odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --load-language=es_CL \
  --i18n-overwrite \
  --stop-after-init
```

---

## Ejemplos Prácticos

### Workflow Completo: Nueva BD de Testing

```bash
# 1. Crear base de datos limpia para Chile
docker-compose exec odoo odoo db init \
  --language es_CL \
  --country CL \
  --username admin \
  --password admin123 \
  --force \
  odoo_cl_test

# 2. Instalar módulos base chilenos
docker-compose exec odoo odoo module install \
  -d odoo_cl_test \
  l10n_latam_base l10n_cl

# 3. Instalar módulo DTE
docker-compose exec odoo odoo module install \
  -d odoo_cl_test \
  l10n_cl_dte

# 4. Ejecutar tests del módulo
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo_cl_test \
  --test-tags /l10n_cl_dte \
  --stop-after-init

# 5. Hacer backup
docker-compose exec odoo odoo db dump odoo_cl_test > backup_cl_test_$(date +%Y%m%d).dump
```

### Workflow: Desarrollo y Testing Rápido

```bash
# 1. Detener Odoo
docker-compose stop odoo

# 2. Actualizar módulo con tests
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  -u l10n_cl_dte \
  --test-tags /l10n_cl_dte \
  --stop-after-init

# 3. Verificar logs (si hay errores)
docker-compose logs --tail=100 odoo | grep -E "ERROR|FAIL|PASS"

# 4. Reiniciar Odoo
docker-compose up -d odoo
```

### Workflow: Testing Específico

```bash
# Test solo validaciones RUT
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags :TestRUTValidator \
  --stop-after-init

# Test solo integraciones l10n_cl
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags :TestIntegrationL10nCl \
  --stop-after-init

# Test workflow completo DTE
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags :TestDTEWorkflow \
  --stop-after-init
```

### Workflow: Backup y Restore

```bash
# 1. Backup BD producción
docker-compose exec odoo odoo db dump odoo > backup_prod_$(date +%Y%m%d_%H%M).dump

# 2. Crear copia para testing
docker-compose exec odoo odoo db duplicate odoo odoo_test

# 3. Neutralizar BD test (desactivar emails, crons)
docker-compose exec odoo odoo neutralize -d odoo_test

# 4. Ofuscar datos sensibles
docker-compose exec odoo odoo obfuscate -d odoo_test

# 5. Ejecutar tests en BD neutralizada
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo_test \
  --test-enable \
  --stop-after-init

# 6. Limpiar BD test
docker-compose exec odoo odoo db drop odoo_test
```

---

## Testing Patterns (l10n_cl)

### Estructura de Test Class

Basado en `/docs/odoo19_official/03_localization/l10n_cl/tests/test_latam_document_type.py`

```python
from odoo.addons.account.tests.common import AccountTestInvoicingCommon
from odoo.tests import tagged, Form

@tagged('post_install_l10n', 'post_install', '-at_install')
class TestClDTE(AccountTestInvoicingCommon):

    @classmethod
    @AccountTestInvoicingCommon.setup_country('cl')
    def setUpClass(cls):
        super().setUpClass()

        # Setup país Chile
        country_cl = cls.env.ref('base.cl')
        rut_id_type = cls.env.ref('l10n_cl.it_RUT')

        # Crear partners de prueba
        cls.cl_partner_a = cls.env['res.partner'].create({
            'name': 'Chilean Partner A',
            'country_id': country_cl.id,
            'l10n_latam_identification_type_id': rut_id_type.id,
            'vat': '76201224-3',
            'l10n_cl_sii_taxpayer_type': '1',
        })

        # Crear journal para DTEs
        cls.purchase_journal = cls.env['account.journal'].create({
            'name': 'Vendor bills elec',
            'code': 'VBE',
            'company_id': cls.company_data['company'].id,
            'type': 'purchase',
            'l10n_latam_use_documents': True,
            'default_account_id': cls.company_data['default_journal_purchase'].default_account_id.id,
        })

    def test_document_type_validation(self):
        """Test validación de tipo de documento"""
        document_type_33 = self.env.ref('l10n_cl.dc_a_f_dte')

        # Crear factura con Form
        with Form(self.env['account.move'].with_context({'default_move_type': 'in_invoice'})) as invoice_form:
            invoice_form.journal_id = self.purchase_journal
            invoice_form.partner_id = self.cl_partner_a

            # Verificar que tipo de documento se setea correctamente
            self.assertEqual(invoice_form.l10n_latam_document_type_id.id, document_type_33.id)

            invoice_form.l10n_latam_document_number = '000001'

        invoice = invoice_form.save()

        # Assertions finales
        self.assertRecordValues(invoice, [{
            'partner_id': self.cl_partner_a.id,
            'l10n_latam_document_type_id': document_type_33.id,
        }])
```

### Decoradores de Testing

```python
# Tags estándar Odoo
@tagged('standard')              # Tag por defecto
@tagged('at_install')            # Ejecutar al instalar módulo
@tagged('post_install')          # Ejecutar después de instalar todos los módulos
@tagged('-at_install')           # NO ejecutar al instalar

# Tags personalizados l10n_cl
@tagged('post_install_l10n')     # Post-install específico para localización
@tagged('post_install', '-at_install')  # Solo post-install

# Múltiples tags
@tagged('post_install_l10n', 'post_install', '-at_install')
```

### Assertions Comunes

```python
# Verificar valores de registros
self.assertRecordValues(record, [{
    'field1': expected_value1,
    'field2': expected_value2,
}])

# Assertions básicos
self.assertEqual(actual, expected)
self.assertTrue(condition)
self.assertFalse(condition)
self.assertIn(member, container)
self.assertIsNone(value)
self.assertIsNotNone(value)

# Assertions de excepciones
with self.assertRaises(ValidationError):
    record.field = invalid_value
```

### Comando para ejecutar tests de l10n_cl

```bash
# Todos los tests post_install de l10n
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags post_install_l10n \
  --stop-after-init

# Solo tests de l10n_cl
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags /l10n_cl \
  --stop-after-init

# Clase específica
docker-compose run --rm odoo odoo server \
  -c /etc/odoo/odoo.conf \
  -d odoo \
  --test-tags :TestClLatamDocumentType \
  --stop-after-init
```

---

## Resumen de Comandos Esenciales

### Base de Datos

```bash
# Crear
odoo db init --language es_CL --country CL odoo_test

# Backup
odoo db dump odoo > backup.dump

# Restore
odoo db load odoo < backup.dump

# Duplicar
odoo db duplicate odoo odoo_copy

# Eliminar
odoo db drop odoo_test
```

### Módulos

```bash
# Instalar (nuevo método)
odoo module install -d odoo l10n_cl_dte

# Actualizar (nuevo método)
odoo module upgrade -d odoo l10n_cl_dte

# Instalar (método antiguo via server)
odoo server -c odoo.conf -d odoo -i l10n_cl_dte --stop-after-init

# Actualizar (método antiguo via server)
odoo server -c odoo.conf -d odoo -u l10n_cl_dte --stop-after-init
```

### Testing

```bash
# Todos los tests
odoo server -d odoo --test-enable --stop-after-init

# Tests por módulo
odoo server -d odoo --test-tags /l10n_cl_dte --stop-after-init

# Tests por clase
odoo server -d odoo --test-tags :TestRUTValidator --stop-after-init

# Tests por método
odoo server -d odoo --test-tags :TestRUTValidator.test_valid_rut --stop-after-init
```

### Shell

```bash
# Shell interactivo
odoo shell -c odoo.conf -d odoo
```

---

## Notas Importantes

### Docker Compose

Todos los comandos deben ejecutarse dentro del contenedor Docker:

```bash
# Ejecutar en contenedor corriendo
docker-compose exec odoo odoo <comando>

# Ejecutar en contenedor temporal (recomendado para operaciones largas)
docker-compose run --rm odoo odoo <comando>
```

### Stop After Init

**IMPORTANTE:** La opción `--stop-after-init` detiene el servidor después de completar la operación. Útil para:
- Instalaciones/actualizaciones de módulos
- Ejecución de tests
- Operaciones batch

**NO usar** `--stop-after-init` cuando se quiere dejar el servidor corriendo.

### Testing

Los tests se ejecutan en dos momentos:
1. **at_install**: Inmediatamente después de instalar cada módulo
2. **post_install**: Al final de la carga de todos los módulos

Filtrar por tags permite ejecutar solo los tests relevantes.

---

**Documentación generada:** 2025-10-22
**Proyecto:** Odoo 19 CE - Chilean Electronic Invoicing (l10n_cl_dte)
**Stack:** Docker Compose | PostgreSQL 15 | Odoo 19.0-20251021
