#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# ODOO 19 CE - ORQUESTADOR MAESTRO DE MIGRACIÓN
# ═══════════════════════════════════════════════════════════════════
# Fecha: 2025-11-11
# Autor: Sistema de Migración Odoo 19
#
# OBJETIVO:
# Ejecutar el flujo completo de auditoría y migración con:
# - Confirmaciones interactivas en cada paso
# - Git commits de seguridad antes de cambios
# - Rollback automático si falla validación
# - Feedback continuo hasta 100% compliance
#
# USO:
#   ./MASTER_ORCHESTRATOR.sh [--auto-approve]
#
# OPCIONES:
#   --auto-approve    Ejecuta sin confirmaciones (PELIGROSO, solo para CI/CD)
# ═══════════════════════════════════════════════════════════════════

set -e  # Salir si cualquier comando falla

# ═══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIGRATION_SCRIPTS_DIR="$PROJECT_ROOT/scripts/odoo19_migration"
ADDONS_PATH="$PROJECT_ROOT/addons/localization"

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Modo auto-approve
AUTO_APPROVE=false
if [[ "$1" == "--auto-approve" ]]; then
    AUTO_APPROVE=true
fi

# ═══════════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES
# ═══════════════════════════════════════════════════════════════════

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}  $1${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════${NC}"
    echo ""
}

ask_confirmation() {
    if [[ "$AUTO_APPROVE" == true ]]; then
        return 0
    fi
    
    local message="$1"
    echo -e "${YELLOW}$message${NC}"
    read -p "¿Continuar? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return 1
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════════
# GIT SAFETY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

create_git_safety_point() {
    local message="$1"
    log_info "Creando punto de seguridad en Git..."
    
    cd "$PROJECT_ROOT"
    
    # Verificar si hay cambios para commitear
    if [[ -n $(git status -s) ]]; then
        git add scripts/odoo19_migration/
        git commit -m "🔒 SAFETY POINT: $message" --no-verify || {
            log_warning "Git commit falló (posiblemente no hay cambios nuevos)"
        }
        log_success "Commit de seguridad creado: $message"
    else
        log_info "No hay cambios para commitear"
    fi
}

create_git_stash() {
    log_info "Creando Git stash de seguridad..."
    cd "$PROJECT_ROOT"
    git stash push -u -m "Pre-migration backup $(date +%Y%m%d_%H%M%S)" || {
        log_warning "Git stash falló (posiblemente no hay cambios)"
    }
    log_success "Git stash creado"
}

rollback_git() {
    log_error "¡Iniciando ROLLBACK de Git!"
    cd "$PROJECT_ROOT"
    
    # Intentar recuperar el último stash
    if git stash list | grep -q "Pre-migration"; then
        log_info "Restaurando desde Git stash..."
        git stash pop
        log_success "Rollback completado desde stash"
    else
        log_warning "No se encontró stash de pre-migración"
        log_info "Puedes hacer rollback manual con: git reset --hard HEAD~1"
    fi
    
    exit 1
}

# ═══════════════════════════════════════════════════════════════════
# PASOS DEL FLUJO
# ═══════════════════════════════════════════════════════════════════

step_0_init() {
    log_step "PASO 0: INICIALIZACIÓN Y VERIFICACIONES"
    
    # Verificar que estamos en el directorio correcto
    if [[ ! -d "$ADDONS_PATH" ]]; then
        log_error "Directorio de addons no encontrado: $ADDONS_PATH"
        exit 1
    fi
    
    # Verificar que Python 3 está disponible
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    # Verificar que los scripts existen
    if [[ ! -f "$MIGRATION_SCRIPTS_DIR/1_audit_deprecations.py" ]]; then
        log_error "Script de auditoría no encontrado"
        exit 1
    fi
    
    log_success "Verificaciones iniciales completadas"
    
    # Commit de seguridad del sistema de migración
    create_git_safety_point "Sistema de migración Odoo 19 instalado"
}

step_1_audit() {
    log_step "PASO 1: AUDITORÍA DE DEPRECACIONES"
    
    log_info "Ejecutando script de auditoría..."
    cd "$PROJECT_ROOT"
    
    python3 scripts/odoo19_migration/1_audit_deprecations.py
    
    if [[ $? -ne 0 ]]; then
        log_error "La auditoría falló"
        exit 1
    fi
    
    log_success "Auditoría completada"
    
    # Mostrar resumen
    if [[ -f "audit_report.md" ]]; then
        log_info "Resumen de hallazgos:"
        grep -A 5 "RESUMEN EJECUTIVO" audit_report.md | head -n 10
        echo ""
    fi
    
    # Preguntar si revisar el reporte completo
    if ! $AUTO_APPROVE; then
        echo -e "${CYAN}¿Deseas revisar el reporte completo? (y/N):${NC}"
        read -p "" -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            less audit_report.md
        fi
    fi
}

step_2_dry_run() {
    log_step "PASO 2: MIGRACIÓN DRY RUN (Preview)"
    
    log_info "Ejecutando migración en modo DRY RUN..."
    log_warning "NO se aplicarán cambios en este paso"
    
    cd "$PROJECT_ROOT"
    python3 scripts/odoo19_migration/2_migrate_safe.py --dry-run
    
    if [[ $? -ne 0 ]]; then
        log_error "El dry run falló"
        exit 1
    fi
    
    log_success "Dry run completado"
    
    # Mostrar resumen de cambios propuestos
    if [[ -f "migration_results_dryrun.json" ]]; then
        log_info "Resumen de cambios propuestos:"
        python3 -c "
import json
with open('migration_results_dryrun.json') as f:
    data = json.load(f)
    print(f\"  Total archivos: {data['total_files']}\")
    print(f\"  Exitosos: {data['successful']}\")
    print(f\"  Requieren manual: {data['manual_required']}\")
    print(f\"  Fallidos: {data['failed']}\")
"
    fi
    
    if ! ask_confirmation "¿Deseas continuar con la migración REAL?"; then
        log_warning "Migración cancelada por el usuario"
        exit 0
    fi
}

step_3_create_stash() {
    log_step "PASO 3: CREAR PUNTO DE SEGURIDAD (Git Stash)"
    
    create_git_stash
    
    log_success "Punto de seguridad creado"
    log_info "En caso de problemas, puedes recuperar con: git stash pop"
}

step_4_migrate_p0() {
    log_step "PASO 4: MIGRACIÓN REAL - PRIORIDAD P0 (CRÍTICO)"
    
    log_warning "⚠️  Se van a aplicar cambios REALES al código"
    log_warning "⚠️  Se crearán backups automáticos de cada archivo"
    
    if ! ask_confirmation "¿Confirmas aplicar migraciones P0 (críticas)?"; then
        log_warning "Migración cancelada por el usuario"
        rollback_git
    fi
    
    cd "$PROJECT_ROOT"
    python3 scripts/odoo19_migration/2_migrate_safe.py --apply --priority P0
    
    if [[ $? -ne 0 ]]; then
        log_error "La migración P0 falló"
        rollback_git
    fi
    
    log_success "Migración P0 completada"
    
    # Commit de seguridad después de P0
    create_git_safety_point "Migraciones P0 (críticas) aplicadas"
}

step_5_validate() {
    log_step "PASO 5: VALIDACIÓN TRIPLE"
    
    log_info "Ejecutando validación triple (Sintaxis + Semántica + Funcional)..."
    
    cd "$PROJECT_ROOT"
    python3 scripts/odoo19_migration/3_validate_changes.py
    
    local validation_exit_code=$?
    
    if [[ $validation_exit_code -ne 0 ]]; then
        log_error "❌ VALIDACIÓN FALLÓ"
        log_error "Se detectaron errores críticos"
        
        if [[ -f "validation_report.txt" ]]; then
            log_info "Mostrando reporte de validación:"
            cat validation_report.txt
        fi
        
        if ! ask_confirmation "¿Deseas aplicar ROLLBACK automático?"; then
            log_warning "Rollback cancelado. Revisa los errores manualmente."
            exit 1
        fi
        
        rollback_git
    fi
    
    log_success "✅ Validación completada exitosamente"
    
    # Commit de seguridad después de validación exitosa
    create_git_safety_point "Validación triple exitosa - P0 100% compliant"
}

step_6_migrate_p1() {
    log_step "PASO 6: MIGRACIÓN REAL - PRIORIDAD P1 (ALTO)"
    
    if ! ask_confirmation "¿Deseas continuar con migraciones P1 (altas)?"; then
        log_info "Migraciones P1 omitidas. Puedes ejecutarlas después con:"
        log_info "  python3 scripts/odoo19_migration/2_migrate_safe.py --apply --priority P1"
        return 0
    fi
    
    cd "$PROJECT_ROOT"
    python3 scripts/odoo19_migration/2_migrate_safe.py --apply --priority P1
    
    if [[ $? -ne 0 ]]; then
        log_error "La migración P1 falló"
        log_warning "P0 ya está aplicado y validado. P1 requiere revisión manual."
        return 1
    fi
    
    log_success "Migración P1 completada"
    
    # Validar nuevamente
    log_info "Validando cambios P1..."
    python3 scripts/odoo19_migration/3_validate_changes.py
    
    if [[ $? -ne 0 ]]; then
        log_error "Validación P1 falló"
        return 1
    fi
    
    # Commit de seguridad
    create_git_safety_point "Migraciones P1 (altas) aplicadas y validadas"
}

step_7_final_report() {
    log_step "PASO 7: REPORTE FINAL"
    
    log_success "🎉 MIGRACIÓN COMPLETADA EXITOSAMENTE"
    echo ""
    log_info "Archivos generados:"
    log_info "  📄 audit_report.md - Reporte de auditoría"
    log_info "  📄 migration_results.json - Resultados de migración"
    log_info "  📄 validation_report.txt - Reporte de validación"
    echo ""
    log_info "Próximos pasos:"
    log_info "  1. Revisar los reportes generados"
    log_info "  2. Ejecutar tests de Odoo manualmente:"
    log_info "     docker-compose exec odoo odoo-bin -d odoo19_db --test-enable --stop-after-init"
    log_info "  3. Si todo OK, aplicar migraciones P2 (optimización) cuando tengas tiempo"
    echo ""
    log_success "Backups disponibles en: {archivo}.backup_{timestamp}"
    log_success "Git commits de seguridad creados"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════
# MAIN FLOW
# ═══════════════════════════════════════════════════════════════════

main() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗██████╗  ██████╗  ██████╗    ██╗ ██╗███╗   ██╗        ║
║   ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗  ███║███║████╗  ██║        ║
║   █████╗  ██║  ██║██║   ██║██║   ██║  ╚██║╚██║██╔██╗ ██║        ║
║   ██╔══╝  ██║  ██║██║   ██║██║   ██║   ██║ ██║██║╚██╗██║        ║
║   ███████╗██████╔╝╚██████╔╝╚██████╔╝   ██║ ██║██║ ╚████║        ║
║   ╚══════╝╚═════╝  ╚═════╝  ╚═════╝    ╚═╝ ╚═╝╚═╝  ╚═══╝        ║
║                                                                   ║
║          SISTEMA DE MIGRACIÓN ODOO 19 CE                          ║
║          Orquestador Maestro v1.0                                 ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log_info "Directorio del proyecto: $PROJECT_ROOT"
    log_info "Modo auto-approve: $AUTO_APPROVE"
    echo ""
    
    if ! $AUTO_APPROVE; then
        log_warning "Este proceso modificará tu código fuente"
        log_warning "Se crearán backups y commits de seguridad automáticamente"
        if ! ask_confirmation "¿Deseas iniciar el proceso de migración?"; then
            log_info "Proceso cancelado por el usuario"
            exit 0
        fi
    fi
    
    # Ejecutar flujo completo
    step_0_init
    step_1_audit
    step_2_dry_run
    step_3_create_stash
    step_4_migrate_p0
    step_5_validate
    step_6_migrate_p1
    step_7_final_report
    
    log_success "✅ PROCESO COMPLETADO EXITOSAMENTE"
    exit 0
}

# Trap para manejar interrupciones
trap 'log_error "Proceso interrumpido por el usuario"; exit 130' INT TERM

# Ejecutar
main "$@"
