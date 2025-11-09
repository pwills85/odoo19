#!/bin/bash
################################################################################
#                                                                              #
#              🔓 SCRIPT DE DESBLOQUEO ODOO 12 ENTERPRISE (BASH)              #
#                                                                              #
#  Propósito: Desbloquear Odoo 12 Enterprise vencido via PostgreSQL          #
#  Requisitos: psql (cliente PostgreSQL)                                      #
#  Fecha: 4 de octubre de 2025                                                #
#                                                                              #
################################################################################

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==================== CONFIGURACIÓN ====================
# ⚠️ MODIFICAR ESTOS VALORES CON TUS DATOS REALES
# =======================================================

DB_HOST="localhost"
DB_PORT="5432"
DB_NAME="nombre_db_aqui"        # ⚠️ CAMBIAR: Nombre de tu base de datos
DB_USER="odoo"
DB_PASSWORD="tu_password"       # ⚠️ CAMBIAR: Password de PostgreSQL

# Configuración de extensión
EXTENSION_YEARS=10
NEW_REASON="demo"

# =======================================================

# Función para imprimir con colores
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Banner
print_banner() {
    echo ""
    echo "================================================================================"
    echo "║                     🔓 ODOO 12 ENTERPRISE - DESBLOQUEO                      ║"
    echo "================================================================================"
    echo ""
}

# Verificar que psql esté instalado
check_requirements() {
    if ! command -v psql &> /dev/null; then
        print_error "psql no está instalado"
        echo ""
        echo "Para instalar PostgreSQL client:"
        echo "  Ubuntu/Debian: sudo apt-get install postgresql-client"
        echo "  macOS: brew install postgresql"
        echo "  CentOS/RHEL: sudo yum install postgresql"
        exit 1
    fi
    
    if ! command -v bc &> /dev/null; then
        print_warning "bc no está instalado (opcional para cálculos)"
    fi
}

# Verificar configuración
check_config() {
    print_info "Verificando configuración..."
    
    if [ "$DB_NAME" = "nombre_db_aqui" ]; then
        print_error "Debes configurar el nombre de la base de datos"
        echo "Edita el archivo y modifica DB_NAME"
        exit 1
    fi
    
    if [ "$DB_PASSWORD" = "tu_password" ]; then
        print_error "Debes configurar el password de PostgreSQL"
        echo "Edita el archivo y modifica DB_PASSWORD"
        exit 1
    fi
    
    print_success "Configuración válida"
    echo ""
}

# Probar conexión a PostgreSQL
test_connection() {
    print_info "Probando conexión a PostgreSQL..."
    echo "   Host: $DB_HOST:$DB_PORT"
    echo "   Base de datos: $DB_NAME"
    echo "   Usuario: $DB_USER"
    echo ""
    
    export PGPASSWORD="$DB_PASSWORD"
    
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1; then
        print_success "Conexión exitosa"
        echo ""
        return 0
    else
        print_error "No se pudo conectar a PostgreSQL"
        echo ""
        echo "Verifica que:"
        echo "  - PostgreSQL esté corriendo"
        echo "  - Host, puerto, usuario y password sean correctos"
        echo "  - La base de datos exista"
        exit 1
    fi
}

# Mostrar estado actual
show_current_status() {
    print_info "Estado actual de la base de datos:"
    echo "────────────────────────────────────────────────────────────────"
    
    export PGPASSWORD="$DB_PASSWORD"
    
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "
        SELECT '   ' || key || ' = ' || COALESCE(value, 'NULL')
        FROM ir_config_parameter 
        WHERE key IN ('database.expiration_date', 
                      'database.expiration_reason',
                      'database.enterprise_code')
        ORDER BY key;
    "
    
    # Calcular días hasta expiración
    EXPIRATION_DATE=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "
        SELECT value FROM ir_config_parameter 
        WHERE key = 'database.expiration_date';
    " | xargs)
    
    if [ ! -z "$EXPIRATION_DATE" ]; then
        CURRENT_DATE=$(date +%Y-%m-%d)
        
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            EXP_SECONDS=$(date -jf "%Y-%m-%d" "$EXPIRATION_DATE" +%s 2>/dev/null || echo "0")
            NOW_SECONDS=$(date -jf "%Y-%m-%d" "$CURRENT_DATE" +%s)
        else
            # Linux
            EXP_SECONDS=$(date -d "$EXPIRATION_DATE" +%s 2>/dev/null || echo "0")
            NOW_SECONDS=$(date -d "$CURRENT_DATE" +%s)
        fi
        
        if [ "$EXP_SECONDS" != "0" ]; then
            DAYS_DIFF=$(( (EXP_SECONDS - NOW_SECONDS) / 86400 ))
            
            echo ""
            if [ $DAYS_DIFF -lt 0 ]; then
                print_warning "Base de datos VENCIDA hace $((-DAYS_DIFF)) días"
                print_error "Estado: BLOQUEADA"
            else
                print_success "Base de datos válida por $DAYS_DIFF días más"
            fi
        fi
    fi
    
    echo "────────────────────────────────────────────────────────────────"
    echo ""
}

# Aplicar desbloqueo
apply_unlock() {
    print_info "Aplicando desbloqueo..."
    
    # Calcular nueva fecha (10 años adelante)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        NEW_DATE=$(date -v +${EXTENSION_YEARS}y +%Y-%m-%d)
    else
        # Linux
        NEW_DATE=$(date -d "+${EXTENSION_YEARS} years" +%Y-%m-%d)
    fi
    
    echo "   Nueva fecha de expiración: $NEW_DATE"
    echo "   Nueva razón: $NEW_REASON"
    echo ""
    
    export PGPASSWORD="$DB_PASSWORD"
    
    # Ejecutar SQL de desbloqueo
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1 <<EOF
-- Actualizar fecha de expiración
UPDATE ir_config_parameter 
SET value = '$NEW_DATE', write_date = NOW()
WHERE key = 'database.expiration_date';

-- Si no existe, crear el parámetro
INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date)
SELECT 'database.expiration_date', '$NEW_DATE', 1, NOW(), 1, NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM ir_config_parameter WHERE key = 'database.expiration_date'
);

-- Actualizar razón
UPDATE ir_config_parameter 
SET value = '$NEW_REASON', write_date = NOW()
WHERE key = 'database.expiration_reason';

-- Si no existe, crear el parámetro
INSERT INTO ir_config_parameter (key, value, create_uid, create_date, write_uid, write_date)
SELECT 'database.expiration_reason', '$NEW_REASON', 1, NOW(), 1, NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM ir_config_parameter WHERE key = 'database.expiration_reason'
);

-- Limpiar sesiones activas
DELETE FROM ir_sessions;
EOF

    if [ $? -eq 0 ]; then
        print_success "¡Desbloqueo aplicado exitosamente!"
        echo "   La base de datos ahora es válida hasta: $NEW_DATE"
        echo ""
        return 0
    else
        print_error "Error al aplicar desbloqueo"
        return 1
    fi
}

# Verificar cambios
verify_unlock() {
    print_info "Verificando cambios..."
    echo "────────────────────────────────────────────────────────────────"
    
    export PGPASSWORD="$DB_PASSWORD"
    
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "
        SELECT '   ' || key || ' = ' || value
        FROM ir_config_parameter 
        WHERE key IN ('database.expiration_date', 'database.expiration_reason')
        ORDER BY key;
    "
    
    # Calcular días restantes
    EXPIRATION_DATE=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "
        SELECT value FROM ir_config_parameter 
        WHERE key = 'database.expiration_date';
    " | xargs)
    
    if [ ! -z "$EXPIRATION_DATE" ]; then
        CURRENT_DATE=$(date +%Y-%m-%d)
        
        if [[ "$OSTYPE" == "darwin"* ]]; then
            EXP_SECONDS=$(date -jf "%Y-%m-%d" "$EXPIRATION_DATE" +%s)
            NOW_SECONDS=$(date -jf "%Y-%m-%d" "$CURRENT_DATE" +%s)
        else
            EXP_SECONDS=$(date -d "$EXPIRATION_DATE" +%s)
            NOW_SECONDS=$(date -d "$CURRENT_DATE" +%s)
        fi
        
        DAYS_REMAINING=$(( (EXP_SECONDS - NOW_SECONDS) / 86400 ))
        
        echo ""
        print_success "Días restantes de validez: $DAYS_REMAINING"
    fi
    
    echo "────────────────────────────────────────────────────────────────"
    echo ""
}

# Mostrar instrucciones post-desbloqueo
show_instructions() {
    echo ""
    echo "================================================================================"
    echo "║                     ⚠️  INSTRUCCIONES IMPORTANTES                           ║"
    echo "================================================================================"
    echo ""
    echo "Para que los cambios tomen efecto:"
    echo ""
    echo "1. 🌐 CERRAR EL NAVEGADOR COMPLETAMENTE"
    echo "   - No solo la pestaña, sino todo el navegador"
    echo "   - Esto limpiará la caché de sesión"
    echo ""
    echo "2. 🔄 VOLVER A ABRIR EL NAVEGADOR"
    echo "   - Abrir nueva ventana del navegador"
    echo ""
    echo "3. 🔐 INGRESAR A ODOO"
    echo "   - Ir a la URL de tu instancia Odoo"
    echo "   - Hacer login normalmente"
    echo "   - La interfaz ya NO estará bloqueada"
    echo ""
    echo "4. ✅ VERIFICAR FUNCIONAMIENTO"
    echo "   - Navegar por diferentes menús"
    echo "   - Verificar que no aparezca mensaje de expiración"
    echo ""
    echo "NOTAS ADICIONALES:"
    echo "─────────────────"
    echo "• Los datos de tu base de datos están intactos"
    echo "• Solo se modificaron parámetros de configuración"
    echo "• Este desbloqueo es válido por $EXTENSION_YEARS años"
    echo "• Considera regularizar tu licencia de Odoo Enterprise"
    echo ""
    echo "SOLUCIÓN PERMANENTE:"
    echo "───────────────────"
    echo "→ Comprar subscripción Enterprise: https://www.odoo.com/pricing"
    echo "→ Migrar a Community Edition (gratis, sin Enterprise features)"
    echo "→ Migrar a Odoo 18 (versión más reciente)"
    echo ""
    echo "================================================================================"
    echo ""
}

# Función principal
main() {
    print_banner
    
    # Verificar requisitos
    check_requirements
    
    # Verificar configuración
    check_config
    
    # Advertencia
    print_warning "ADVERTENCIA:"
    echo "   Este script modificará la base de datos de Odoo"
    echo "   Se recomienda hacer un backup antes de continuar"
    echo ""
    
    # Solicitar confirmación
    read -p "¿Desea continuar con el desbloqueo? (S/n): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[SsYy]$ ]] && [[ ! -z $REPLY ]]; then
        print_error "Operación cancelada por el usuario"
        exit 0
    fi
    
    echo ""
    
    # Probar conexión
    test_connection
    
    # Mostrar estado actual
    show_current_status
    
    # Aplicar desbloqueo
    if apply_unlock; then
        # Verificar cambios
        verify_unlock
        
        # Mostrar instrucciones
        show_instructions
        
        print_success "¡Proceso completado exitosamente!"
        exit 0
    else
        print_error "El proceso falló"
        exit 1
    fi
}

# Trap para Ctrl+C
trap 'echo ""; print_error "Operación cancelada (Ctrl+C)"; exit 130' INT

# Ejecutar script
main "$@"
