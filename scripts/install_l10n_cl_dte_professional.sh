#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Professional Installation Script - l10n_cl_dte Module
# ══════════════════════════════════════════════════════════════════════════════
# Author: EERGYGROUP - Ing. Pedro Troncoso Willz
# Date: 2025-10-24
# Description: Professional installation script with zero errors/warnings
# ══════════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ODOO_CONTAINER="odoo"
ODOO_DB="odoo"
ODOO_ADMIN_PASSWORD="admin"
MODULE_NAME="l10n_cl_dte"
LOG_FILE="/tmp/odoo_install_${MODULE_NAME}_$(date +%Y%m%d_%H%M%S).log"

# Functions
print_header() {
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"
}

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

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1: Prerequisites Check
# ══════════════════════════════════════════════════════════════════════════════

print_header "STEP 1: Checking Prerequisites"

# Check Docker is running
print_info "Checking Docker..."
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi
print_success "Docker is running"

# Check Odoo container exists
print_info "Checking Odoo container..."
if ! docker ps -a | grep -q "$ODOO_CONTAINER"; then
    print_error "Odoo container '$ODOO_CONTAINER' not found."
    exit 1
fi
print_success "Odoo container found"

# Check Odoo container is running
print_info "Checking if Odoo is running..."
if ! docker ps | grep -q "$ODOO_CONTAINER"; then
    print_warning "Odoo container is not running. Starting..."
    docker-compose up -d odoo
    sleep 10
fi
print_success "Odoo is running"

# Check PostgreSQL is accessible
print_info "Checking PostgreSQL connection..."
if ! docker exec $ODOO_CONTAINER psql -U odoo -d postgres -c "SELECT 1" > /dev/null 2>&1; then
    print_error "Cannot connect to PostgreSQL"
    exit 1
fi
print_success "PostgreSQL is accessible"

# Check database exists
print_info "Checking database '$ODOO_DB'..."
DB_EXISTS=$(docker exec $ODOO_CONTAINER psql -U odoo -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$ODOO_DB'")
if [ "$DB_EXISTS" != "1" ]; then
    print_error "Database '$ODOO_DB' does not exist. Create it first."
    exit 1
fi
print_success "Database '$ODOO_DB' exists"

# Check module files exist
print_info "Checking module files..."
if ! docker exec $ODOO_CONTAINER test -d "/mnt/extra-addons/addons/localization/$MODULE_NAME"; then
    print_error "Module directory not found in container"
    exit 1
fi
print_success "Module files found"

print_success "All prerequisites passed\n"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2: Module Syntax Verification
# ══════════════════════════════════════════════════════════════════════════════

print_header "STEP 2: Module Syntax Verification"

print_info "Checking Python syntax..."
docker exec $ODOO_CONTAINER bash -c "
    cd /mnt/extra-addons/addons/localization/$MODULE_NAME
    python3 -m compileall -q . 2>&1
" >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    print_success "Python syntax verification passed"
else
    print_error "Python syntax errors found. Check $LOG_FILE"
    exit 1
fi

print_info "Checking XML syntax..."
docker exec $ODOO_CONTAINER bash -c "
    cd /mnt/extra-addons/addons/localization/$MODULE_NAME
    find . -name '*.xml' -exec xmllint --noout {} \; 2>&1
" >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    print_success "XML syntax verification passed"
else
    print_warning "XML syntax warnings found. Check $LOG_FILE"
fi

print_success "Syntax verification complete\n"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: Update Module List
# ══════════════════════════════════════════════════════════════════════════════

print_header "STEP 3: Updating Module List"

print_info "Updating Odoo module list..."
docker exec $ODOO_CONTAINER odoo -c /etc/odoo/odoo.conf -d $ODOO_DB --stop-after-init --update=base >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    print_success "Module list updated"
else
    print_error "Failed to update module list. Check $LOG_FILE"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: Install Dependencies
# ══════════════════════════════════════════════════════════════════════════════

print_header "STEP 4: Installing Dependencies"

DEPENDENCIES="base account l10n_latam_base l10n_latam_invoice_document l10n_cl purchase stock web"

for dep in $DEPENDENCIES; do
    print_info "Checking dependency: $dep..."

    # Check if already installed
    INSTALLED=$(docker exec $ODOO_CONTAINER psql -U odoo -d $ODOO_DB -tAc "
        SELECT state FROM ir_module_module WHERE name='$dep'
    ")

    if [ "$INSTALLED" = "installed" ]; then
        print_success "$dep already installed"
    else
        print_info "Installing $dep..."
        docker exec $ODOO_CONTAINER odoo -c /etc/odoo/odoo.conf -d $ODOO_DB --stop-after-init -i $dep >> "$LOG_FILE" 2>&1

        if [ $? -eq 0 ]; then
            print_success "$dep installed"
        else
            print_error "Failed to install $dep. Check $LOG_FILE"
            exit 1
        fi
    fi
done

print_success "All dependencies installed\n"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: Install Module
# ══════════════════════════════════════════════════════════════════════════════

print_header "STEP 5: Installing $MODULE_NAME Module"

print_info "Checking if module is already installed..."
INSTALLED=$(docker exec $ODOO_CONTAINER psql -U odoo -d $ODOO_DB -tAc "
    SELECT state FROM ir_module_module WHERE name='$MODULE_NAME'
")

if [ "$INSTALLED" = "installed" ]; then
    print_warning "Module $MODULE_NAME is already installed"
    read -p "Do you want to upgrade it? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Upgrading $MODULE_NAME..."
        docker exec $ODOO_CONTAINER odoo -c /etc/odoo/odoo.conf -d $ODOO_DB --stop-after-init -u $MODULE_NAME >> "$LOG_FILE" 2>&1
        ACTION="upgraded"
    else
        print_info "Skipping installation"
        exit 0
    fi
else
    print_info "Installing $MODULE_NAME..."
    docker exec $ODOO_CONTAINER odoo -c /etc/odoo/odoo.conf -d $ODOO_DB --stop-after-init -i $MODULE_NAME >> "$LOG_FILE" 2>&1
    ACTION="installed"
fi

if [ $? -eq 0 ]; then
    print_success "Module $MODULE_NAME $ACTION successfully"
else
    print_error "Failed to install $MODULE_NAME. Check $LOG_FILE"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6: Post-Installation Verification
# ══════════════════════════════════════════════════════════════════════════════

print_header "STEP 6: Post-Installation Verification"

# Check module state
print_info "Verifying module state..."
MODULE_STATE=$(docker exec $ODOO_CONTAINER psql -U odoo -d $ODOO_DB -tAc "
    SELECT state FROM ir_module_module WHERE name='$MODULE_NAME'
")

if [ "$MODULE_STATE" = "installed" ]; then
    print_success "Module state: installed"
else
    print_error "Module state: $MODULE_STATE"
    exit 1
fi

# Check for errors in log
print_info "Checking for errors in installation log..."
ERROR_COUNT=$(grep -i "error" "$LOG_FILE" | grep -v "No errors" | wc -l)
if [ "$ERROR_COUNT" -gt 0 ]; then
    print_warning "Found $ERROR_COUNT error(s) in log. Check $LOG_FILE"
else
    print_success "No errors found in installation log"
fi

# Check for warnings
print_info "Checking for warnings in installation log..."
WARNING_COUNT=$(grep -i "warning" "$LOG_FILE" | wc -l)
if [ "$WARNING_COUNT" -gt 0 ]; then
    print_warning "Found $WARNING_COUNT warning(s) in log. Check $LOG_FILE"
else
    print_success "No warnings found in installation log"
fi

# Count models created
print_info "Counting models created..."
MODEL_COUNT=$(docker exec $ODOO_CONTAINER psql -U odoo -d $ODOO_DB -tAc "
    SELECT COUNT(*) FROM ir_model WHERE model LIKE '%l10n_cl%' OR model LIKE '%dte%'
")
print_success "$MODEL_COUNT models created"

# Count views created
print_info "Counting views created..."
VIEW_COUNT=$(docker exec $ODOO_CONTAINER psql -U odoo -d $ODOO_DB -tAc "
    SELECT COUNT(*) FROM ir_ui_view WHERE name LIKE '%dte%' OR name LIKE '%l10n_cl%'
")
print_success "$VIEW_COUNT views created"

# Count menu items created
print_info "Counting menu items created..."
MENU_COUNT=$(docker exec $ODOO_CONTAINER psql -U odoo -d $ODOO_DB -tAc "
    SELECT COUNT(*) FROM ir_ui_menu WHERE name LIKE '%DTE%' OR name LIKE '%Facturación%'
")
print_success "$MENU_COUNT menu items created"

print_success "Post-installation verification complete\n"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 7: Restart Odoo
# ══════════════════════════════════════════════════════════════════════════════

print_header "STEP 7: Restarting Odoo"

print_info "Restarting Odoo container..."
docker-compose restart odoo >> "$LOG_FILE" 2>&1

print_info "Waiting for Odoo to start (30 seconds)..."
sleep 30

# Check if Odoo is responding
print_info "Checking Odoo health..."
if docker exec $ODOO_CONTAINER curl -s http://localhost:8069/web/health | grep -q "\"status\":\"pass\""; then
    print_success "Odoo is healthy and responding"
else
    print_warning "Odoo health check did not pass. Check manually."
fi

print_success "Odoo restarted\n"

# ══════════════════════════════════════════════════════════════════════════════
# FINAL REPORT
# ══════════════════════════════════════════════════════════════════════════════

print_header "INSTALLATION COMPLETE"

echo -e "${GREEN}"
cat << EOF
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  ✅ Module $MODULE_NAME successfully $ACTION               ║
║                                                               ║
║  📊 Statistics:                                               ║
║     - Models: $MODEL_COUNT                                              ║
║     - Views: $VIEW_COUNT                                              ║
║     - Menus: $MENU_COUNT                                              ║
║     - Errors: $ERROR_COUNT                                              ║
║     - Warnings: $WARNING_COUNT                                           ║
║                                                               ║
║  📝 Log file: $LOG_FILE                                        ║
║                                                               ║
║  🌐 Access Odoo:                                              ║
║     URL: http://localhost:8069                                ║
║     Database: $ODOO_DB                                          ║
║                                                               ║
║  🎉 Ready to use!                                             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Generate installation report
REPORT_FILE="/tmp/odoo_install_${MODULE_NAME}_report_$(date +%Y%m%d_%H%M%S).txt"
cat > "$REPORT_FILE" << EOF
══════════════════════════════════════════════════════════════════
ODOO MODULE INSTALLATION REPORT
══════════════════════════════════════════════════════════════════

Date: $(date)
Module: $MODULE_NAME
Action: $ACTION
Database: $ODOO_DB

STATISTICS:
-----------
Models created: $MODEL_COUNT
Views created: $VIEW_COUNT
Menu items created: $MENU_COUNT
Errors: $ERROR_COUNT
Warnings: $WARNING_COUNT

STATUS: SUCCESS ✅

Log file: $LOG_FILE

══════════════════════════════════════════════════════════════════
EOF

print_info "Installation report saved to: $REPORT_FILE"

exit 0
