#!/bin/bash
# Script para iniciar el dashboard de métricas de Copilot CLI
# Uso: ./scripts/start-metrics-dashboard.sh [--port 9090] [--background]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuración por defecto
PORT=9090
BACKGROUND=false
LOG_FILE="$HOME/.copilot/logs/dashboard.log"

# Parsear argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            PORT="$2"
            shift 2
            ;;
        --background)
            BACKGROUND=true
            shift
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        *)
            echo "Uso: $0 [--port PORT] [--background] [--log-file LOG_FILE]"
            exit 1
            ;;
    esac
done

# Crear directorio de logs
mkdir -p "$(dirname "$LOG_FILE")"

# Función para verificar dependencias
check_dependencies() {
    echo "🔍 Verificando dependencias..."

    # Verificar Python
    if ! command -v python3 &> /dev/null; then
        echo "❌ Python 3 no encontrado. Instale Python 3.8+"
        exit 1
    fi

    # Verificar pip
    if ! command -v pip3 &> /dev/null; then
        echo "❌ pip3 no encontrado. Instale pip para Python 3"
        exit 1
    fi

    # Instalar dependencias de Python si no están disponibles
    pip3 install flask chart.js psutil schedule 2>/dev/null || true

    echo "✅ Dependencias verificadas"
}

# Función para iniciar el dashboard
start_dashboard() {
    echo "🚀 Iniciando Copilot CLI Metrics Dashboard..."
    echo "   📊 URL: http://localhost:$PORT"
    echo "   📁 Logs: $LOG_FILE"
    echo "   💾 Base de datos: $HOME/.copilot/odoo19-knowledge.db"
    echo ""

    cd "$PROJECT_ROOT"

    if [ "$BACKGROUND" = true ]; then
        echo "🔄 Ejecutando en segundo plano..."
        nohup python3 scripts/metrics-dashboard/copilot-metrics-dashboard.py \
            --port "$PORT" >> "$LOG_FILE" 2>&1 &
        echo $! > /tmp/copilot-dashboard.pid
        echo "✅ Dashboard iniciado en segundo plano (PID: $(cat /tmp/copilot-dashboard.pid))"
        echo "   Para detener: kill $(cat /tmp/copilot-dashboard.pid)"
        echo "   Para ver logs: tail -f $LOG_FILE"
    else
        echo "🔄 Ejecutando en primer plano..."
        echo "   Presione Ctrl+C para detener"
        python3 scripts/metrics-dashboard/copilot-metrics-dashboard.py --port "$PORT"
    fi
}

# Función para verificar estado del dashboard
check_status() {
    if [ -f /tmp/copilot-dashboard.pid ]; then
        PID=$(cat /tmp/copilot-dashboard.pid)
        if kill -0 "$PID" 2>/dev/null; then
            echo "✅ Dashboard ejecutándose (PID: $PID)"
            echo "   📊 URL: http://localhost:$PORT"
            return 0
        else
            echo "❌ Dashboard no responde (PID obsoleto: $PID)"
            rm -f /tmp/copilot-dashboard.pid
            return 1
        fi
    else
        echo "❌ Dashboard no ejecutándose"
        return 1
    fi
}

# Función para detener el dashboard
stop_dashboard() {
    if [ -f /tmp/copilot-dashboard.pid ]; then
        PID=$(cat /tmp/copilot-dashboard.pid)
        echo "🛑 Deteniendo dashboard (PID: $PID)..."
        kill "$PID" 2>/dev/null || true
        sleep 2
        if kill -0 "$PID" 2>/dev/null; then
            echo "⚠️  Forzando terminación..."
            kill -9 "$PID" 2>/dev/null || true
        fi
        rm -f /tmp/copilot-dashboard.pid
        echo "✅ Dashboard detenido"
    else
        echo "❌ No se encontró PID del dashboard"
    fi
}

# Función para mostrar ayuda
show_help() {
    cat << EOF
🤖 Copilot CLI Metrics Dashboard

Uso: $0 [COMANDO] [OPCIONES]

Comandos:
    start       Iniciar el dashboard
    stop        Detener el dashboard
    status      Verificar estado del dashboard
    restart     Reiniciar el dashboard
    logs        Ver logs del dashboard

Opciones:
    --port PORT         Puerto del servidor (default: 9090)
    --background        Ejecutar en segundo plano
    --log-file FILE     Archivo de logs (default: ~/.copilot/logs/dashboard.log)

Ejemplos:
    $0 start                                    # Iniciar en primer plano
    $0 start --background                       # Iniciar en segundo plano
    $0 start --port 8080 --background           # Puerto personalizado
    $0 stop                                     # Detener dashboard
    $0 status                                   # Ver estado
    $0 logs                                     # Ver logs recientes

Dashboard URL: http://localhost:9090 (o puerto personalizado)
EOF
}

# Función principal
main() {
    case "${1:-start}" in
        start)
            shift
            check_dependencies
            if check_status 2>/dev/null; then
                echo "⚠️  Dashboard ya ejecutándose. Use 'restart' para reiniciar."
                exit 1
            fi
            start_dashboard "$@"
            ;;
        stop)
            stop_dashboard
            ;;
        status)
            check_status
            ;;
        restart)
            stop_dashboard
            sleep 2
            check_dependencies
            start_dashboard --background
            ;;
        logs)
            if [ -f "$LOG_FILE" ]; then
                tail -f "$LOG_FILE"
            else
                echo "❌ Archivo de logs no encontrado: $LOG_FILE"
                exit 1
            fi
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "❌ Comando desconocido: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Ejecutar función principal
main "$@"
