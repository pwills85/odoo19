#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test Execution Runner - FASE 0-1 (Payroll P0-P1 + DTE 52)
==========================================================

Ejecuta suite completa de tests para:
- FASE 0: Payroll P0-P1 (AFP, Reforma, Retenciones, Cálculos)
- FASE 1: DTE 52 (Guía de Despacho + Validaciones)

Genera reportes consolidados con cobertura, performance y failures.

Uso:
    python scripts/test_runner_fase_0_1.py [--fase 0|1|all] [--verbose] [--no-cov]
"""

import os
import sys
import subprocess
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
import argparse


class TestRunner:
    """Ejecutor de tests con reportes consolidados"""

    # Configuración FASE 0 - Payroll
    FASE_0_TESTS = {
        'name': 'FASE 0: Payroll P0-P1',
        'modules': ['l10n_cl_hr_payroll'],
        'test_files': [
            'tests/test_p0_afp_cap_2025.py',
            'tests/test_p0_reforma_2025.py',
            'tests/test_p0_multi_company.py',
            'tests/test_previred_integration.py',
            'tests/test_payslip_validations.py',
            'tests/test_payroll_calculation_p1.py',
            'tests/test_indicator_automation.py',
        ],
        'markers': 'p0_critical or p1_critical',
        'min_coverage': 90,
    }

    # Configuración FASE 1 - DTE 52
    FASE_1_TESTS = {
        'name': 'FASE 1: DTE 52 Guía Despacho',
        'modules': ['l10n_cl_dte', 'l10n_cl_financial_reports'],
        'test_files': [
            'tests/test_dte_52_validations.py',
            'tests/test_dte_workflow.py',
            'tests/test_dte_submission.py',
            'tests/test_sii_soap_client_unit.py',
            'tests/test_performance_metrics_unit.py',
        ],
        'markers': 'dte_52 or dte_integration',
        'min_coverage': 90,
    }

    def __init__(self, project_root: str = None):
        """Inicializa runner"""
        self.project_root = Path(project_root or os.getcwd())
        self.addons_root = self.project_root / 'addons' / 'localization'
        self.results = {}
        self.start_time = None
        self.end_time = None

    def run_fase_0(self, verbose: bool = False, with_coverage: bool = True) -> Dict:
        """Ejecuta FASE 0 tests"""
        print("\n" + "=" * 80)
        print("🧪 EJECUTANDO FASE 0: Payroll P0-P1")
        print("=" * 80)

        return self._run_tests(
            self.FASE_0_TESTS,
            verbose=verbose,
            with_coverage=with_coverage
        )

    def run_fase_1(self, verbose: bool = False, with_coverage: bool = True) -> Dict:
        """Ejecuta FASE 1 tests"""
        print("\n" + "=" * 80)
        print("🧪 EJECUTANDO FASE 1: DTE 52 Guía de Despacho")
        print("=" * 80)

        return self._run_tests(
            self.FASE_1_TESTS,
            verbose=verbose,
            with_coverage=with_coverage
        )

    def _run_tests(self, config: Dict, verbose: bool = False, with_coverage: bool = True) -> Dict:
        """Ejecuta tests con config específica"""
        start_time = time.time()
        results = {
            'config_name': config['name'],
            'modules': config['modules'],
            'start_time': datetime.now().isoformat(),
            'tests': {},
            'total_passed': 0,
            'total_failed': 0,
            'total_skipped': 0,
            'total_errors': 0,
            'coverage': {},
            'performance': {},
        }

        # Ejecutar cada test file
        for module in config['modules']:
            module_path = self.addons_root / module
            if not module_path.exists():
                print(f"⚠️  Módulo no encontrado: {module}")
                continue

            # Ejecutar tests del módulo
            cmd = self._build_pytest_command(
                module_path,
                verbose=verbose,
                with_coverage=with_coverage,
                markers=config.get('markers')
            )

            print(f"\n📦 Ejecutando: {module}")
            print(f"   Comando: {' '.join(cmd)}")
            print("-" * 70)

            try:
                result = subprocess.run(
                    cmd,
                    cwd=str(self.project_root),
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutos timeout
                )

                module_results = self._parse_pytest_output(result, module)
                results['tests'][module] = module_results

                # Acumular resultados
                results['total_passed'] += module_results.get('passed', 0)
                results['total_failed'] += module_results.get('failed', 0)
                results['total_skipped'] += module_results.get('skipped', 0)
                results['total_errors'] += module_results.get('errors', 0)

                # Mostrar resumen módulo
                self._print_module_summary(module_results)

            except subprocess.TimeoutExpired:
                print(f"❌ TIMEOUT: {module} excedió 5 minutos")
                results['tests'][module] = {'timeout': True}
            except Exception as e:
                print(f"❌ ERROR ejecutando {module}: {e}")
                results['tests'][module] = {'error': str(e)}

        duration = time.time() - start_time
        results['duration_seconds'] = duration
        results['end_time'] = datetime.now().isoformat()

        return results

    def _build_pytest_command(
        self,
        test_path: Path,
        verbose: bool = False,
        with_coverage: bool = True,
        markers: str = None
    ) -> List[str]:
        """Construye comando pytest"""
        cmd = ['pytest', str(test_path)]

        if verbose:
            cmd.append('-vv')
        else:
            cmd.append('-v')

        if with_coverage:
            cmd.extend([
                f'--cov={test_path.parent.parent}',
                '--cov-report=term-missing',
                '--cov-report=html:htmlcov',
                '--cov-report=json:coverage.json',
            ])

        if markers:
            cmd.extend(['-m', markers])

        cmd.extend([
            '--tb=short',
            '--strict-markers',
            '-p', 'no:warnings',
            '--color=yes',
        ])

        return cmd

    def _parse_pytest_output(self, result: subprocess.CompletedProcess, module: str) -> Dict:
        """Parsea output de pytest"""
        output = result.stdout + result.stderr
        parsed = {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
        }

        # Parsear línea de resumen (ej: "5 passed, 2 failed in 1.23s")
        for line in output.split('\n'):
            if 'passed' in line or 'failed' in line:
                # Extractar números
                parts = line.split()
                for i, part in enumerate(parts):
                    if 'passed' in part and i > 0:
                        try:
                            parsed['passed'] = int(parts[i-1])
                        except ValueError:
                            pass
                    elif 'failed' in part and i > 0:
                        try:
                            parsed['failed'] = int(parts[i-1])
                        except ValueError:
                            pass
                    elif 'skipped' in part and i > 0:
                        try:
                            parsed['skipped'] = int(parts[i-1])
                        except ValueError:
                            pass
                    elif 'error' in part and i > 0:
                        try:
                            parsed['errors'] = int(parts[i-1])
                        except ValueError:
                            pass

        return parsed

    def _print_module_summary(self, results: Dict):
        """Imprime resumen módulo"""
        passed = results.get('passed', 0)
        failed = results.get('failed', 0)
        skipped = results.get('skipped', 0)
        errors = results.get('errors', 0)
        rc = results.get('returncode', 1)

        if rc == 0:
            status = "✅ PASSED"
        else:
            status = "❌ FAILED"

        print(f"\n{status}")
        print(f"  Tests: {passed} passed, {failed} failed, {skipped} skipped, {errors} errors")

        if failed > 0 or errors > 0:
            print(f"\n  STDERR:")
            for line in results.get('stderr', '').split('\n')[-20:]:
                if line.strip():
                    print(f"    {line}")

    def generate_consolidated_report(self, all_results: Dict) -> str:
        """Genera reporte consolidado"""
        report = []
        report.append("# TEST EXECUTION REPORT - FASE 0-1")
        report.append(f"\n**Generado:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S CLT')}")
        report.append(f"\n**Rama:** feat/f1_pr3_reportes_f29_f22")
        report.append(f"\n**Commit:** {self._get_git_commit()}")

        # Resumen ejecutivo
        report.append("\n## Resumen Ejecutivo")
        report.append("\n| Métrica | FASE 0 | FASE 1 | Total |")
        report.append("|---------|--------|--------|-------|")

        total_passed = 0
        total_failed = 0

        for fase_key, fase_result in all_results.items():
            passed = fase_result.get('total_passed', 0)
            failed = fase_result.get('total_failed', 0)
            total_passed += passed
            total_failed += failed

        report.append(f"| Tests Passed | {all_results.get('FASE_0', {}).get('total_passed', 0)} | {all_results.get('FASE_1', {}).get('total_passed', 0)} | {total_passed} |")
        report.append(f"| Tests Failed | {all_results.get('FASE_0', {}).get('total_failed', 0)} | {all_results.get('FASE_1', {}).get('total_failed', 0)} | {total_failed} |")

        success_rate = (total_passed / (total_passed + total_failed) * 100) if (total_passed + total_failed) > 0 else 0
        report.append(f"| Success Rate | - | - | **{success_rate:.1f}%** |")

        # Detalles por FASE
        for fase_key, fase_result in all_results.items():
            report.append(f"\n## {fase_result.get('config_name')}")
            report.append(f"\n**Duración:** {fase_result.get('duration_seconds', 0):.2f}s")
            report.append(f"**Inicio:** {fase_result.get('start_time')}")
            report.append(f"**Fin:** {fase_result.get('end_time')}")

            report.append("\n### Resultados por Módulo")
            report.append("\n| Módulo | Passed | Failed | Skipped | Errors |")
            report.append("|--------|--------|--------|---------|--------|")

            for module, results in fase_result.get('tests', {}).items():
                p = results.get('passed', 0)
                f = results.get('failed', 0)
                s = results.get('skipped', 0)
                e = results.get('errors', 0)
                status = "✅" if f == 0 and e == 0 else "❌"
                report.append(f"| {status} {module} | {p} | {f} | {s} | {e} |")

        # Criterios de éxito
        report.append("\n## Criterios de Éxito")
        report.append("\n- [ ] Tests ejecutados: 100%")
        report.append("- [ ] Pass rate: >95%")
        report.append("- [ ] Coverage: >95% para lógica crítica")
        report.append("- [ ] Performance DTE: <2s")
        report.append("- [ ] 0 failures críticos")

        return "\n".join(report)

    def _get_git_commit(self) -> str:
        """Obtiene commit hash actual"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=str(self.project_root),
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def run_all(self, verbose: bool = False, with_coverage: bool = True) -> Dict:
        """Ejecuta FASE 0 + FASE 1"""
        self.start_time = time.time()

        results = {
            'FASE_0': self.run_fase_0(verbose=verbose, with_coverage=with_coverage),
            'FASE_1': self.run_fase_1(verbose=verbose, with_coverage=with_coverage),
        }

        self.end_time = time.time()

        # Generar reporte
        report = self.generate_consolidated_report(results)

        # Guardar reporte
        report_path = self.project_root / 'evidencias' / 'TEST_EXECUTION_REPORT_2025-11-08.md'
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, 'w') as f:
            f.write(report)

        print(f"\n✅ Reporte guardado: {report_path}")

        # Guardar JSON
        json_path = self.project_root / 'evidencias' / 'test_results_2025-11-08.json'
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"✅ Resultados JSON: {json_path}")

        return results


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description='Ejecuta test suite FASE 0-1'
    )
    parser.add_argument(
        '--fase',
        choices=['0', '1', 'all'],
        default='all',
        help='Qué FASE ejecutar (default: all)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--no-cov',
        action='store_true',
        help='Saltar coverage reports'
    )
    parser.add_argument(
        '--project-root',
        default=os.getcwd(),
        help='Ruta del proyecto Odoo'
    )

    args = parser.parse_args()

    runner = TestRunner(project_root=args.project_root)

    try:
        if args.fase == '0':
            results = {'FASE_0': runner.run_fase_0(verbose=args.verbose, with_coverage=not args.no_cov)}
        elif args.fase == '1':
            results = {'FASE_1': runner.run_fase_1(verbose=args.verbose, with_coverage=not args.no_cov)}
        else:
            results = runner.run_all(verbose=args.verbose, with_coverage=not args.no_cov)

        # Resumen final
        print("\n" + "=" * 80)
        print("📊 RESUMEN FINAL")
        print("=" * 80)

        total_passed = sum(r.get('total_passed', 0) for r in results.values())
        total_failed = sum(r.get('total_failed', 0) for r in results.values())

        print(f"✅ Tests Passed: {total_passed}")
        print(f"❌ Tests Failed: {total_failed}")

        if total_failed == 0:
            print("\n🎉 TODOS LOS TESTS PASARON")
            sys.exit(0)
        else:
            print(f"\n⚠️  {total_failed} tests fallaron")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n⚠️  Ejecución interrumpida por usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
