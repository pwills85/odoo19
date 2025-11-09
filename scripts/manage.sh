#!/bin/bash

# Container Management Script for Odoo 19 CE
# Uso: ./scripts/manage.sh [start|stop|restart|status|logs|shell]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Commands
COMMAND="${1:-status}"

# Helper functions
print_header() {
    echo -e "${YELLOW}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

case "$COMMAND" in
    start)
        print_header "Starting Odoo 19 CE Services"
        echo ""
        docker-compose up -d
        sleep 3
        print_success "Services started"
        echo ""
        print_info "Odoo URL: http://localhost:8069"
        print_info "pgAdmin: http://localhost:5050"
        ;;

    stop)
        print_header "Stopping Odoo 19 CE Services"
        echo ""
        docker-compose down
        print_success "Services stopped"
        ;;

    restart)
        print_header "Restarting Odoo 19 CE Services"
        echo ""
        "$SCRIPT_DIR/manage.sh" stop
        sleep 2
        "$SCRIPT_DIR/manage.sh" start
        ;;

    status)
        print_header "Odoo 19 CE Services Status"
        echo ""
        docker-compose ps
        ;;

    logs)
        print_header "Odoo Container Logs"
        SERVICE="${2:-odoo}"
        docker-compose logs -f "$SERVICE"
        ;;

    shell)
        print_header "Odoo Container Shell"
        docker exec -it odoo19_app bash
        ;;

    db-shell)
        print_header "PostgreSQL Container Shell"
        docker exec -it odoo19_db psql -U odoo -d odoo
        ;;

    backup)
        print_header "Database Backup"
        BACKUP_DIR="$PROJECT_DIR/backups"
        mkdir -p "$BACKUP_DIR"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BACKUP_FILE="$BACKUP_DIR/odoo_backup_$TIMESTAMP.sql.gz"
        
        echo "Backing up database to: $BACKUP_FILE"
        docker exec odoo19_db pg_dump -U odoo odoo | gzip > "$BACKUP_FILE"
        print_success "Database backed up successfully"
        ;;

    restore)
        print_header "Database Restore"
        BACKUP_FILE="${2:-}"
        
        if [ -z "$BACKUP_FILE" ] || [ ! -f "$BACKUP_FILE" ]; then
            print_error "Backup file not found: $BACKUP_FILE"
            echo ""
            echo "Available backups:"
            ls -lh "$PROJECT_DIR/backups/" 2>/dev/null || echo "No backups found"
            exit 1
        fi
        
        echo "Restoring database from: $BACKUP_FILE"
        gunzip -c "$BACKUP_FILE" | docker exec -i odoo19_db psql -U odoo odoo
        print_success "Database restored successfully"
        ;;

    clean)
        print_header "Cleaning Containers and Volumes"
        echo ""
        read -p "Are you sure? This will delete all data. (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            docker-compose down -v
            print_success "Containers and volumes removed"
        else
            print_info "Cancelled"
        fi
        ;;

    help)
        cat << EOF
${YELLOW}Odoo 19 CE Container Management${NC}

${BLUE}Usage:${NC}
  ./scripts/manage.sh [command] [options]

${BLUE}Commands:${NC}
  start        Start all services
  stop         Stop all services
  restart      Restart all services
  status       Show services status
  logs         Show container logs (default: odoo)
  shell        Open bash shell in Odoo container
  db-shell     Open psql shell in database container
  backup       Create database backup
  restore      Restore database from backup
  clean        Remove containers and volumes
  help         Show this help message

${BLUE}Examples:${NC}
  ./scripts/manage.sh start
  ./scripts/manage.sh logs odoo
  ./scripts/manage.sh logs db
  ./scripts/manage.sh backup
  ./scripts/manage.sh restore backups/odoo_backup_20250101_120000.sql.gz

EOF
        ;;

    *)
        print_error "Unknown command: $COMMAND"
        echo ""
        ./scripts/manage.sh help
        exit 1
        ;;
esac
