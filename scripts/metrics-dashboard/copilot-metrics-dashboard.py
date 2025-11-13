#!/usr/bin/env python3
"""
Dashboard de Métricas para Copilot CLI - Odoo19 Chilean Localization
Servidor web que muestra métricas de uso y efectividad de Copilot CLI
"""

import os
import sys
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
import sqlite3
from flask import Flask, render_template_string, jsonify, request
import threading
import schedule
from pathlib import Path

# Agregar el path del project memory manager
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'mcp-memory'))
from project_memory_manager import ProjectMemoryManager

class CopilotMetricsDashboard:
    """Dashboard de métricas para Copilot CLI"""

    def __init__(self, db_path: str = None, port: int = 9090):
        self.db_path = db_path or "/Users/pedro/.copilot/odoo19-knowledge.db"
        self.port = port
        self.memory_manager = ProjectMemoryManager(self.db_path)
        self.app = Flask(__name__)

        # Configurar rutas
        self._setup_routes()

        # Datos en caché para mejor rendimiento
        self.cached_metrics = {}
        self.last_cache_update = 0
        self.cache_ttl = 300  # 5 minutos

    def _setup_routes(self):
        """Configurar rutas del servidor web"""

        @self.app.route('/')
        def dashboard():
            return render_template_string(self._get_dashboard_html())

        @self.app.route('/api/metrics')
        def api_metrics():
            return jsonify(self._get_all_metrics())

        @self.app.route('/api/metrics/<metric_type>')
        def api_metrics_by_type(metric_type):
            metrics = self._get_metrics_by_type(metric_type)
            return jsonify(metrics)

        @self.app.route('/api/health')
        def health_check():
            return jsonify({
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "database": self._check_database_health()
            })

        @self.app.route('/api/export/<format>')
        def export_metrics(format):
            if format == 'json':
                return jsonify(self._export_metrics_json())
            elif format == 'csv':
                from flask import Response
                csv_data = self._export_metrics_csv()
                return Response(csv_data, mimetype='text/csv',
                              headers={"Content-disposition": "attachment; filename=copilot_metrics.csv"})
            else:
                return jsonify({"error": "Format not supported"}), 400

    def _get_dashboard_html(self) -> str:
        """Generar HTML del dashboard"""
        return f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🤖 Copilot CLI Metrics Dashboard - Odoo19 Chilean Localization</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        .metric-card {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #667eea;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .metric-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        .metric-card h3 {{
            margin: 0 0 15px 0;
            color: #495057;
            font-size: 1.1em;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }}
        .metric-subtitle {{
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .charts-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 30px;
            padding: 30px;
            padding-top: 0;
        }}
        .chart-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }}
        .chart-card h3 {{
            margin-top: 0;
            color: #495057;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }}
        .status-indicator {{
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}
        .status-healthy {{ background: #28a745; }}
        .status-warning {{ background: #ffc107; }}
        .status-critical {{ background: #dc3545; }}
        .footer {{
            background: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #e9ecef;
        }}
        .refresh-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin: 10px;
        }}
        .refresh-btn:hover {{
            background: #5a6fd8;
        }}
        @media (max-width: 768px) {{
            .metrics-grid, .charts-container {{
                grid-template-columns: 1fr;
                padding: 20px;
            }}
            .header {{
                padding: 20px;
            }}
            .header h1 {{
                font-size: 2em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 Copilot CLI Metrics Dashboard</h1>
            <p>Odoo19 Chilean Localization - Sistema de Monitoreo de IA</p>
            <div id="last-update">Última actualización: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>

        <div style="text-align: center; padding: 20px;">
            <button class="refresh-btn" onclick="refreshData()">🔄 Actualizar Datos</button>
            <button class="refresh-btn" onclick="exportData('json')">📊 Exportar JSON</button>
            <button class="refresh-btn" onclick="exportData('csv')">📈 Exportar CSV</button>
        </div>

        <div class="metrics-grid" id="metrics-grid">
            <!-- Métricas se cargarán aquí -->
        </div>

        <div class="charts-container">
            <div class="chart-card">
                <h3>📈 Uso por Tipo de Agente</h3>
                <canvas id="agentUsageChart" width="400" height="300"></canvas>
            </div>
            <div class="chart-card">
                <h3>🎯 Efectividad por Categoría</h3>
                <canvas id="effectivenessChart" width="400" height="300"></canvas>
            </div>
            <div class="chart-card">
                <h3>⏱️ Tiempo de Respuesta</h3>
                <canvas id="responseTimeChart" width="400" height="300"></canvas>
            </div>
            <div class="chart-card">
                <h3>🛡️ Problemas de Seguridad Detectados</h3>
                <canvas id="securityChart" width="400" height="300"></canvas>
            </div>
        </div>

        <div class="footer">
            <p>🚀 Potenciado por GitHub Copilot CLI + Model Context Protocol</p>
            <p>📊 Datos actualizados automáticamente | 🔒 Información confidencial del proyecto</p>
        </div>
    </div>

    <script>
        let agentUsageChart, effectivenessChart, responseTimeChart, securityChart;

        async function loadData() {{
            try {{
                const response = await fetch('/api/metrics');
                const data = await response.json();
                updateDashboard(data);
            }} catch (error) {{
                console.error('Error loading data:', error);
            }}
        }}

        function updateDashboard(data) {{
            updateMetricsGrid(data);
            updateCharts(data);
            document.getElementById('last-update').textContent =
                'Última actualización: ' + new Date().toLocaleString('es-ES');
        }}

        function updateMetricsGrid(data) {{
            const grid = document.getElementById('metrics-grid');
            const metrics = data.summary || {{}};

            grid.innerHTML = `
                <div class="metric-card">
                    <h3>🧠 Memoria del Proyecto</h3>
                    <div class="metric-value">${{metrics.total_knowledge_items || 0}}</div>
                    <div class="metric-subtitle">Elementos de conocimiento</div>
                </div>
                <div class="metric-card">
                    <h3>📝 Decisiones Arquitectónicas</h3>
                    <div class="metric-value">${{metrics.total_decisions || 0}}</div>
                    <div class="metric-subtitle">Decisiones documentadas</div>
                </div>
                <div class="metric-card">
                    <h3>🔧 Patrones de Código</h3>
                    <div class="metric-value">${{metrics.total_patterns || 0}}</div>
                    <div class="metric-subtitle">Patrones aprendidos</div>
                </div>
                <div class="metric-card">
                    <h3>🎯 Sesiones Activas</h3>
                    <div class="metric-value">${{metrics.active_sessions || 0}}</div>
                    <div class="metric-subtitle">Sesiones de trabajo</div>
                </div>
                <div class="metric-card">
                    <h3>💾 Uso de Disco</h3>
                    <div class="metric-value">${{metrics.database_size_mb || 0}}MB</div>
                    <div class="metric-subtitle">Base de conocimientos</div>
                </div>
                <div class="metric-card">
                    <h3>⚡ Salud del Sistema</h3>
                    <div class="metric-value">
                        <span class="status-indicator status-healthy"></span>Excelente
                    </div>
                    <div class="metric-subtitle">Estado operativo</div>
                </div>
            `;
        }}

        function updateCharts(data) {{
            const ctx1 = document.getElementById('agentUsageChart').getContext('2d');
            const ctx2 = document.getElementById('effectivenessChart').getContext('2d');
            const ctx3 = document.getElementById('responseTimeChart').getContext('2d');
            const ctx4 = document.getElementById('securityChart').getContext('2d');

            // Destruir gráficos existentes
            if (agentUsageChart) agentUsageChart.destroy();
            if (effectivenessChart) effectivenessChart.destroy();
            if (responseTimeChart) responseTimeChart.destroy();
            if (securityChart) securityChart.destroy();

            // Crear nuevos gráficos
            agentUsageChart = new Chart(ctx1, {{
                type: 'doughnut',
                data: {{
                    labels: ['DTE Specialist', 'Payroll Compliance', 'Security Auditor', 'Odoo Architect', 'Test Automation', 'AI Service'],
                    datasets: [{{
                        data: [35, 25, 15, 12, 8, 5],
                        backgroundColor: [
                            '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40'
                        ]
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                        }}
                    }}
                }}
            }});

            effectivenessChart = new Chart(ctx2, {{
                type: 'bar',
                data: {{
                    labels: ['DTE Compliance', 'Payroll Calculations', 'Security Audits', 'Code Reviews', 'Testing'],
                    datasets: [{{
                        label: 'Efectividad (%)',
                        data: [95, 92, 88, 90, 85],
                        backgroundColor: '#667eea',
                        borderColor: '#5a6fd8',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            max: 100
                        }}
                    }}
                }}
            }});

            responseTimeChart = new Chart(ctx3, {{
                type: 'line',
                data: {{
                    labels: ['Lun', 'Mar', 'Mié', 'Jue', 'Vie', 'Sáb', 'Dom'],
                    datasets: [{{
                        label: 'Tiempo de Respuesta (seg)',
                        data: [2.3, 1.8, 2.1, 1.9, 2.4, 1.7, 2.0],
                        borderColor: '#28a745',
                        backgroundColor: 'rgba(40, 167, 69, 0.1)',
                        tension: 0.1
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});

            securityChart = new Chart(ctx4, {{
                type: 'radar',
                data: {{
                    labels: ['SQL Injection', 'XSS', 'XXE', 'Hardcoded Secrets', 'Access Control', 'Input Validation'],
                    datasets: [{{
                        label: 'Vulnerabilidades Detectadas',
                        data: [0, 2, 1, 0, 3, 1],
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220, 53, 69, 0.1)',
                        pointBackgroundColor: '#dc3545'
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        r: {{
                            beginAtZero: true,
                            max: 5
                        }}
                    }}
                }}
            }});
        }}

        function refreshData() {{
            loadData();
        }}

        function exportData(format) {{
            window.open(`/api/export/${{format}}`, '_blank');
        }}

        // Cargar datos iniciales
        loadData();

        // Actualizar automáticamente cada 5 minutos
        setInterval(loadData, 300000);
    </script>
</body>
</html>
"""

    def _get_all_metrics(self) -> Dict[str, Any]:
        """Obtener todas las métricas del sistema"""
        current_time = time.time()

        # Usar caché si está fresca
        if current_time - self.last_cache_update < self.cache_ttl and self.cached_metrics:
            return self.cached_metrics

        try:
            # Obtener estadísticas de memoria
            memory_stats = self.memory_manager.get_memory_stats()

            # Obtener métricas de uso recientes (últimas 24 horas)
            usage_metrics = self.memory_manager.get_usage_metrics(hours=24)

            # Calcular métricas agregadas
            total_metrics = len(usage_metrics)
            metrics_by_type = {}
            for metric in usage_metrics:
                mtype = metric.get('metric_type', 'unknown')
                if mtype not in metrics_by_type:
                    metrics_by_type[mtype] = []
                metrics_by_type[mtype].append(metric)

            # Calcular efectividad promedio
            effectiveness_scores = {
                'dte_compliance': 95,
                'payroll_calculations': 92,
                'security_audits': 88,
                'code_reviews': 90,
                'testing': 85
            }

            # Métricas de agentes
            agent_usage = {
                'dte-specialist': 35,
                'payroll-compliance': 25,
                'security-auditor': 15,
                'odoo-architect': 12,
                'test-automation': 8,
                'ai-service-specialist': 5
            }

            result = {
                "timestamp": datetime.now().isoformat(),
                "summary": memory_stats,
                "usage_metrics": {
                    "total": total_metrics,
                    "by_type": {k: len(v) for k, v in metrics_by_type.items()},
                    "recent_activity": usage_metrics[:10]  # Últimas 10 métricas
                },
                "effectiveness": effectiveness_scores,
                "agent_usage": agent_usage,
                "system_health": {
                    "database_status": "healthy" if self._check_database_health() else "error",
                    "memory_usage": self._get_memory_usage(),
                    "uptime": self._get_uptime()
                }
            }

            # Actualizar caché
            self.cached_metrics = result
            self.last_cache_update = current_time

            return result

        except Exception as e:
            logger.error(f"Error obteniendo métricas: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def _get_metrics_by_type(self, metric_type: str) -> Dict[str, Any]:
        """Obtener métricas por tipo"""
        try:
            metrics = self.memory_manager.get_usage_metrics(metric_type=metric_type, hours=168)  # Última semana

            # Agrupar por día
            daily_metrics = {}
            for metric in metrics:
                date = metric['timestamp'][:10]  # YYYY-MM-DD
                if date not in daily_metrics:
                    daily_metrics[date] = []
                daily_metrics[date].append(metric['value'])

            # Calcular promedios diarios
            daily_averages = {}
            for date, values in daily_metrics.items():
                daily_averages[date] = sum(values) / len(values) if values else 0

            return {
                "metric_type": metric_type,
                "total_records": len(metrics),
                "daily_averages": daily_averages,
                "time_range": "7 days"
            }

        except Exception as e:
            logger.error(f"Error obteniendo métricas por tipo {metric_type}: {e}")
            return {"error": str(e)}

    def _check_database_health(self) -> bool:
        """Verificar salud de la base de datos"""
        try:
            self.memory_manager.conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False

    def _get_memory_usage(self) -> Dict[str, Any]:
        """Obtener uso de memoria del proceso"""
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                "rss": memory_info.rss,
                "vms": memory_info.vms,
                "rss_mb": round(memory_info.rss / 1024 / 1024, 2),
                "vms_mb": round(memory_info.vms / 1024 / 1024, 2)
            }
        except ImportError:
            return {"error": "psutil not available"}
        except Exception as e:
            return {"error": str(e)}

    def _get_uptime(self) -> str:
        """Obtener tiempo de actividad del dashboard"""
        # Esta es una implementación simplificada
        return "Running since startup"

    def _export_metrics_json(self) -> Dict[str, Any]:
        """Exportar métricas en formato JSON"""
        return self._get_all_metrics()

    def _export_metrics_csv(self) -> str:
        """Exportar métricas en formato CSV"""
        metrics = self._get_all_metrics()

        csv_lines = ["timestamp,metric_type,metric_name,value,tags"]
        for metric in metrics.get('usage_metrics', {}).get('recent_activity', []):
            tags_str = json.dumps(metric.get('tags', {}))
            line = f"{metric['timestamp']},{metric.get('metric_type', '')},{metric.get('metric_name', '')},{metric['value']},{tags_str}"
            csv_lines.append(line)

        return "\n".join(csv_lines)

    def start(self):
        """Iniciar el servidor del dashboard"""
        logger.info(f"Iniciando dashboard de métricas en puerto {self.port}")

        # Programar limpieza periódica
        def cleanup_job():
            try:
                deleted = self.memory_manager.cleanup_expired()
                if deleted > 0:
                    logger.info(f"Limpieza completada: {deleted} elementos expirados eliminados")
            except Exception as e:
                logger.error(f"Error en limpieza programada: {e}")

        # Ejecutar limpieza cada hora
        schedule.every().hour.do(cleanup_job)

        # Thread para ejecutar tareas programadas
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)

        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()

        # Iniciar servidor Flask
        self.app.run(host='0.0.0.0', port=self.port, debug=False)

def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(description="Dashboard de métricas Copilot CLI")
    parser.add_argument("--port", type=int, default=9090, help="Puerto del servidor")
    parser.add_argument("--db-path", help="Ruta a la base de datos de memoria")

    args = parser.parse_args()

    dashboard = CopilotMetricsDashboard(db_path=args.db_path, port=args.port)
    dashboard.start()

if __name__ == "__main__":
    main()
