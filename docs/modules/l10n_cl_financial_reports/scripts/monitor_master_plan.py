#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
"""
MONITOR DEL PLAN MAESTRO - SEGUIMIENTO EN TIEMPO REAL
Dashboard de control y validación del cierre de brechas
"""

import os
import sys
import json
import time
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

# Try to import rich for better terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️ Rich library not available. Install with: pip install rich")

class MasterPlanMonitor:
    """Monitor y dashboard del Plan Maestro de cierre de brechas"""

    def __init__(self):
        self.module_path = Path(__file__).parent.parent
        self.reports_path = self.module_path / 'reports'
        self.scripts_path = self.module_path / 'scripts'

        # Estado de las 12 brechas
        self.gaps = {
            # CRÍTICAS
            'security_sql': {'status': 'pending', 'priority': 'CRITICAL', 'progress': 0, 'target': 100},
            'wizard_dashboard': {'status': 'pending', 'priority': 'CRITICAL', 'progress': 0, 'target': 100},
            'sii_compliance': {'status': 'pending', 'priority': 'CRITICAL', 'progress': 55, 'target': 100},

            # ALTAS
            'f29_performance': {'status': 'pending', 'priority': 'HIGH', 'progress': 0, 'target': 100},
            'dashboard_performance': {'status': 'pending', 'priority': 'HIGH', 'progress': 0, 'target': 100},
            'cache_optimization': {'status': 'pending', 'priority': 'HIGH', 'progress': 75, 'target': 90},

            # MEDIAS
            'config_access': {'status': 'pending', 'priority': 'MEDIUM', 'progress': 60, 'target': 100},
            'states_warnings': {'status': 'pending', 'priority': 'MEDIUM', 'progress': 0, 'target': 100},
            'mobile_ux': {'status': 'pending', 'priority': 'MEDIUM', 'progress': 60, 'target': 90},

            # BAJAS
            'localization': {'status': 'pending', 'priority': 'LOW', 'progress': 70, 'target': 100},
            'documentation': {'status': 'pending', 'priority': 'LOW', 'progress': 30, 'target': 100},
            'test_coverage': {'status': 'pending', 'priority': 'LOW', 'progress': 70, 'target': 95},
        }

        # Fases del plan
        self.phases = {
            'phase1': {
                'name': 'CORRECCIONES CRÍTICAS',
                'duration': '0-24h',
                'status': 'not_started',
                'progress': 0,
                'gaps': ['security_sql', 'wizard_dashboard', 'sii_compliance']
            },
            'phase2': {
                'name': 'OPTIMIZACIONES ALTAS',
                'duration': '24-72h',
                'status': 'not_started',
                'progress': 0,
                'gaps': ['f29_performance', 'dashboard_performance', 'cache_optimization']
            },
            'phase3': {
                'name': 'CORRECCIONES MEDIAS',
                'duration': '3-7 días',
                'status': 'not_started',
                'progress': 0,
                'gaps': ['config_access', 'states_warnings', 'mobile_ux']
            },
            'phase4': {
                'name': 'MEJORAS BAJAS',
                'duration': '1-2 semanas',
                'status': 'not_started',
                'progress': 0,
                'gaps': ['localization', 'documentation', 'test_coverage']
            }
        }

        # Métricas globales
        self.metrics = {
            'overall_progress': 0,
            'critical_resolved': 0,
            'high_resolved': 0,
            'medium_resolved': 0,
            'low_resolved': 0,
            'estimated_completion': None,
            'start_time': datetime.now(),
            'elapsed_time': timedelta(0)
        }

    def check_phase_status(self, phase_id: str) -> Dict:
        """Verificar estado de una fase específica"""
        phase = self.phases[phase_id]

        # Check if phase script exists and has been run
        phase_script = self.scripts_path / f"{phase_id}_*.py"
        phase_scripts = list(self.scripts_path.glob(f"{phase_id}_*.py"))

        if phase_scripts:
            # Check for phase report
            phase_reports = list(self.reports_path.glob(f"{phase_id}_report_*.txt"))
            if phase_reports:
                # Get latest report
                latest_report = max(phase_reports, key=lambda p: p.stat().st_mtime)

                # Parse report for status
                with open(latest_report, 'r') as f:
                    content = f.read()

                if 'COMPLETADA EXITOSAMENTE' in content:
                    phase['status'] = 'completed'
                    phase['progress'] = 100
                elif 'COMPLETADA CON ERRORES' in content:
                    phase['status'] = 'partial'
                    phase['progress'] = 75
                else:
                    phase['status'] = 'in_progress'
                    phase['progress'] = 50
            else:
                phase['status'] = 'ready'
                phase['progress'] = 0

        # Update gap statuses based on phase
        if phase['status'] == 'completed':
            for gap_id in phase['gaps']:
                self.gaps[gap_id]['status'] = 'resolved'
                self.gaps[gap_id]['progress'] = self.gaps[gap_id]['target']

        return phase

    def calculate_overall_progress(self) -> float:
        """Calcular progreso general del plan"""
        total_gaps = len(self.gaps)
        resolved_gaps = sum(1 for gap in self.gaps.values() if gap['status'] == 'resolved')

        # Weight by priority
        weighted_progress = 0
        weights = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1.5, 'LOW': 1}
        total_weight = sum(weights[gap['priority']] for gap in self.gaps.values())

        for gap in self.gaps.values():
            weight = weights[gap['priority']]
            progress_ratio = gap['progress'] / gap['target']
            weighted_progress += (progress_ratio * weight)

        return (weighted_progress / total_weight) * 100

    def estimate_completion_time(self) -> datetime:
        """Estimar tiempo de finalización basado en progreso actual"""
        current_progress = self.calculate_overall_progress()
        elapsed_time = datetime.now() - self.metrics['start_time']

        if current_progress > 0:
            # Estimate based on current rate
            total_time = elapsed_time * (100 / current_progress)
            remaining_time = total_time - elapsed_time
            estimated_completion = datetime.now() + remaining_time
        else:
            # Use planned duration (2 weeks)
            estimated_completion = self.metrics['start_time'] + timedelta(weeks=2)

        return estimated_completion

    def get_priority_color(self, priority: str) -> str:
        """Get color for priority level"""
        colors = {
            'CRITICAL': 'red',
            'HIGH': 'yellow',
            'MEDIUM': 'cyan',
            'LOW': 'green'
        }
        return colors.get(priority, 'white')

    def get_status_symbol(self, status: str) -> str:
        """Get symbol for status"""
        symbols = {
            'resolved': '✅',
            'in_progress': '🔄',
            'partial': '⚠️',
            'pending': '⏳',
            'error': '❌'
        }
        return symbols.get(status, '❓')

    def display_dashboard(self):
        """Display dashboard using rich or plain text"""
        if RICH_AVAILABLE:
            self._display_rich_dashboard()
        else:
            self._display_plain_dashboard()

    def _display_rich_dashboard(self):
        """Display rich terminal dashboard"""
        # Create layout
        layout = Layout()

        # Header
        header = Panel(
            f"[bold cyan]PLAN MAESTRO - CIERRE DE BRECHAS[/bold cyan]\n"
            f"[yellow]account_financial_report v18.0.2.0.0[/yellow]\n"
            f"Started: {self.metrics['start_time'].strftime('%Y-%m-%d %H:%M')}",
            title="🎯 MONITOR DE EJECUCIÓN",
            border_style="cyan"
        )

        # Progress Overview
        overall_progress = self.calculate_overall_progress()
        progress_panel = Panel(
            f"[bold]Progreso General:[/bold] {overall_progress:.1f}%\n"
            f"{'█' * int(overall_progress/5)}{'░' * (20 - int(overall_progress/5))}\n\n"
            f"[red]Críticas:[/red] {self.count_by_priority_and_status('CRITICAL', 'resolved')}/3\n"
            f"[yellow]Altas:[/yellow] {self.count_by_priority_and_status('HIGH', 'resolved')}/3\n"
            f"[cyan]Medias:[/cyan] {self.count_by_priority_and_status('MEDIUM', 'resolved')}/3\n"
            f"[green]Bajas:[/green] {self.count_by_priority_and_status('LOW', 'resolved')}/3",
            title="📊 PROGRESO",
            border_style="green"
        )

        # Gaps Table
        gaps_table = Table(title="🔍 Estado de Brechas", show_header=True, header_style="bold magenta")
        gaps_table.add_column("ID", style="cyan", width=20)
        gaps_table.add_column("Prioridad", justify="center", width=10)
        gaps_table.add_column("Estado", justify="center", width=12)
        gaps_table.add_column("Progreso", justify="right", width=15)
        gaps_table.add_column("Target", justify="right", width=10)

        for gap_id, gap_data in self.gaps.items():
            color = self.get_priority_color(gap_data['priority'])
            status_symbol = self.get_status_symbol(gap_data['status'])

            gaps_table.add_row(
                gap_id,
                f"[{color}]{gap_data['priority']}[/{color}]",
                f"{status_symbol} {gap_data['status']}",
                f"{gap_data['progress']}%",
                f"{gap_data['target']}%"
            )

        # Phases Table
        phases_table = Table(title="📅 Fases de Ejecución", show_header=True, header_style="bold blue")
        phases_table.add_column("Fase", style="cyan", width=8)
        phases_table.add_column("Nombre", width=25)
        phases_table.add_column("Duración", width=15)
        phases_table.add_column("Estado", width=15)
        phases_table.add_column("Progreso", width=15)

        for phase_id, phase_data in self.phases.items():
            self.check_phase_status(phase_id)
            status_symbol = self.get_status_symbol(phase_data['status'])

            phases_table.add_row(
                phase_id.upper(),
                phase_data['name'],
                phase_data['duration'],
                f"{status_symbol} {phase_data['status']}",
                f"{phase_data['progress']}%"
            )

        # Display all
        console.clear()
        console.print(header)
        console.print(progress_panel)
        console.print(gaps_table)
        console.print(phases_table)

        # Estimated completion
        estimated = self.estimate_completion_time()
        console.print(Panel(
            f"[bold]Finalización Estimada:[/bold] {estimated.strftime('%Y-%m-%d %H:%M')}\n"
            f"[bold]Tiempo Restante:[/bold] {estimated - datetime.now()}",
            title="⏰ ESTIMACIÓN",
            border_style="yellow"
        ))

    def _display_plain_dashboard(self):
        """Display plain text dashboard"""
        os.system('clear' if os.name == 'posix' else 'cls')

        print("=" * 70)
        print(" PLAN MAESTRO - MONITOR DE EJECUCIÓN ".center(70))
        print("=" * 70)
        print(f"Started: {self.metrics['start_time'].strftime('%Y-%m-%d %H:%M')}")
        print()

        # Progress
        overall_progress = self.calculate_overall_progress()
        print(f"PROGRESO GENERAL: {overall_progress:.1f}%")
        print(f"[{'#' * int(overall_progress/5)}{'-' * (20 - int(overall_progress/5))}]")
        print()

        # Gaps by priority
        print("ESTADO DE BRECHAS:")
        print("-" * 70)

        for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            gaps_in_priority = [g for g, d in self.gaps.items() if d['priority'] == priority]
            print(f"\n{priority}:")
            for gap_id in gaps_in_priority:
                gap = self.gaps[gap_id]
                status_symbol = self.get_status_symbol(gap['status'])
                print(f"  {status_symbol} {gap_id}: {gap['progress']}/{gap['target']}% - {gap['status']}")

        print("\n" + "-" * 70)

        # Phases
        print("\nFASES DE EJECUCIÓN:")
        for phase_id, phase_data in self.phases.items():
            self.check_phase_status(phase_id)
            print(f"  {phase_id.upper()}: {phase_data['name']} - {phase_data['status']} ({phase_data['progress']}%)")

        # Estimated completion
        estimated = self.estimate_completion_time()
        print(f"\nFINALIZACIÓN ESTIMADA: {estimated.strftime('%Y-%m-%d %H:%M')}")
        print(f"TIEMPO RESTANTE: {estimated - datetime.now()}")
        print("=" * 70)

    def count_by_priority_and_status(self, priority: str, status: str) -> int:
        """Count gaps by priority and status"""
        return sum(1 for gap in self.gaps.values()
                  if gap['priority'] == priority and gap['status'] == status)

    def execute_phase(self, phase_id: str):
        """Execute a specific phase script"""
        phase_script = self.scripts_path / f"{phase_id}_*.py"
        phase_scripts = list(self.scripts_path.glob(f"{phase_id}_*.py"))

        if phase_scripts:
            script = phase_scripts[0]
            print(f"\n🚀 Ejecutando {phase_id}: {script.name}")

            result = subprocess.run(
                ['python3', str(script)],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print(f"✅ {phase_id} completada exitosamente")
            else:
                print(f"❌ Error en {phase_id}: {result.stderr}")

            return result.returncode == 0
        else:
            print(f"⚠️ Script para {phase_id} no encontrado")
            return False

    def validate_gate(self, gate_number: int) -> bool:
        """Validate quality gate"""
        gates = {
            1: {  # Security Checkpoint (24h)
                'name': 'Security Checkpoint',
                'criteria': [
                    ('security_sql', 'resolved'),
                    ('wizard_dashboard', 'resolved'),
                    ('sii_compliance', 'resolved')
                ]
            },
            2: {  # Performance Checkpoint (72h)
                'name': 'Performance Checkpoint',
                'criteria': [
                    ('f29_performance', 'resolved'),
                    ('dashboard_performance', 'resolved'),
                    ('cache_optimization', 'resolved')
                ]
            },
            3: {  # Functionality Checkpoint (7 days)
                'name': 'Functionality Checkpoint',
                'criteria': [
                    ('config_access', 'resolved'),
                    ('states_warnings', 'resolved'),
                    ('mobile_ux', 'resolved')
                ]
            },
            4: {  # Production Ready (14 days)
                'name': 'Production Ready',
                'criteria': [
                    ('localization', 'resolved'),
                    ('documentation', 'resolved'),
                    ('test_coverage', 'resolved')
                ]
            }
        }

        if gate_number not in gates:
            print(f"❌ Gate {gate_number} no válido")
            return False

        gate = gates[gate_number]
        print(f"\n🚪 Validando Gate {gate_number}: {gate['name']}")
        print("-" * 50)

        all_passed = True
        for gap_id, required_status in gate['criteria']:
            actual_status = self.gaps[gap_id]['status']
            passed = actual_status == required_status

            symbol = '✅' if passed else '❌'
            print(f"  {symbol} {gap_id}: {actual_status} (required: {required_status})")

            if not passed:
                all_passed = False

        print("-" * 50)
        if all_passed:
            print(f"✅ Gate {gate_number} APROBADO")
        else:
            print(f"❌ Gate {gate_number} NO APROBADO - Correcciones pendientes")

        return all_passed

    def generate_status_report(self):
        """Generate current status report"""
        report_time = datetime.now()
        report_file = self.reports_path / f"master_plan_status_{report_time.strftime('%Y%m%d_%H%M%S')}.json"

        status = {
            'timestamp': report_time.isoformat(),
            'overall_progress': self.calculate_overall_progress(),
            'gaps': self.gaps,
            'phases': self.phases,
            'metrics': {
                **self.metrics,
                'start_time': self.metrics['start_time'].isoformat(),
                'elapsed_time': str(datetime.now() - self.metrics['start_time'])
            },
            'estimated_completion': self.estimate_completion_time().isoformat()
        }

        with open(report_file, 'w') as f:
            json.dump(status, f, indent=2)

        print(f"\n📄 Reporte guardado: {report_file}")
        return report_file

    def run_interactive(self):
        """Run interactive monitoring session"""
        while True:
            self.display_dashboard()

            print("\n" + "=" * 70)
            print("COMANDOS DISPONIBLES:")
            print("  1. Ejecutar Fase 1 (Críticas)")
            print("  2. Ejecutar Fase 2 (Performance)")
            print("  3. Ejecutar Fase 3 (Funcionales)")
            print("  4. Ejecutar Fase 4 (Mejoras)")
            print("  v1-v4. Validar Gate 1-4")
            print("  r. Generar reporte de estado")
            print("  q. Salir")
            print("=" * 70)

            command = input("\nComando: ").strip().lower()

            if command == 'q':
                break
            elif command in ['1', '2', '3', '4']:
                phase_id = f"phase{command}"
                self.execute_phase(phase_id)
                input("\nPresione Enter para continuar...")
            elif command.startswith('v') and len(command) == 2:
                try:
                    gate_num = int(command[1])
                    self.validate_gate(gate_num)
                    input("\nPresione Enter para continuar...")
                except ValueError:
                    print("❌ Comando no válido")
            elif command == 'r':
                self.generate_status_report()
                input("\nPresione Enter para continuar...")
            else:
                print("❌ Comando no reconocido")
                time.sleep(2)

    def run_continuous(self, refresh_interval: int = 5):
        """Run continuous monitoring with auto-refresh"""
        print("🔄 Modo de monitoreo continuo activado (Ctrl+C para salir)")

        try:
            while True:
                self.display_dashboard()
                time.sleep(refresh_interval)

                # Auto-check phase statuses
                for phase_id in self.phases:
                    self.check_phase_status(phase_id)

                # Update metrics
                self.metrics['elapsed_time'] = datetime.now() - self.metrics['start_time']
                self.metrics['overall_progress'] = self.calculate_overall_progress()

        except KeyboardInterrupt:
            print("\n\n⏹️ Monitoreo detenido")
            self.generate_status_report()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Monitor del Plan Maestro de Cierre de Brechas')
    parser.add_argument('--mode', choices=['interactive', 'continuous', 'once'],
                       default='interactive',
                       help='Modo de ejecución')
    parser.add_argument('--refresh', type=int, default=5,
                       help='Intervalo de actualización en segundos (modo continuo)')
    parser.add_argument('--execute-phase', type=int, choices=[1, 2, 3, 4],
                       help='Ejecutar fase específica')
    parser.add_argument('--validate-gate', type=int, choices=[1, 2, 3, 4],
                       help='Validar gate específico')
    parser.add_argument('--report', action='store_true',
                       help='Generar reporte de estado')

    args = parser.parse_args()

    monitor = MasterPlanMonitor()

    if args.execute_phase:
        phase_id = f"phase{args.execute_phase}"
        success = monitor.execute_phase(phase_id)
        sys.exit(0 if success else 1)

    if args.validate_gate:
        passed = monitor.validate_gate(args.validate_gate)
        sys.exit(0 if passed else 1)

    if args.report:
        monitor.generate_status_report()
        sys.exit(0)

    if args.mode == 'once':
        monitor.display_dashboard()
    elif args.mode == 'continuous':
        monitor.run_continuous(args.refresh)
    else:  # interactive
        monitor.run_interactive()


if __name__ == "__main__":
    main()
