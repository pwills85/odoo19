#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Performance Benchmark: XML Generation with @lru_cache
======================================================

Benchmarks XML generation performance for 5 DTE types to validate H3 optimization.

**Created**: 2025-11-11 - H3 Gap Closure
**Target**: P95 380ms → <200ms (-47% improvement)

Methodology:
1. Generate 100 XML documents per DTE type (5 types × 100 = 500 total)
2. Measure time with time.perf_counter() (nanosecond precision)
3. Calculate P50, P95, P99 percentiles
4. Compare PRE-cache (baseline) vs POST-cache (optimized)

Usage:
    # Run with cache enabled (POST optimization)
    python3 scripts/benchmark_xml_generation.py

    # Run without cache (PRE optimization - requires code modification)
    # Comment out @lru_cache decorators in xml_generator.py
    python3 scripts/benchmark_xml_generation.py --baseline

Author: EERGYGROUP
"""

import sys
import os
import time
import statistics
from datetime import date, timedelta
from typing import Dict, List, Tuple
import argparse

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from addons.localization.l10n_cl_dte.libs.xml_generator import DTEXMLGenerator


class XMLBenchmark:
    """
    Performance benchmark for XML generation.

    Measures latency across 5 DTE types with realistic data.
    """

    def __init__(self, iterations: int = 100):
        """
        Initialize benchmark.

        Args:
            iterations (int): Number of iterations per DTE type (default: 100)
        """
        self.iterations = iterations
        self.generator = DTEXMLGenerator()
        self.results = {}

    def _get_sample_data_dte_33(self) -> Dict:
        """Generate realistic sample data for DTE 33 (Factura Electrónica)."""
        return {
            'folio': 12345,
            'fecha_emision': date.today().strftime('%Y-%m-%d'),
            'forma_pago': '1',  # Contado
            'emisor': {
                'rut': '760000000',
                'razon_social': 'EMPRESA DEMO SPA',
                'giro': 'Servicios de Consultoría Tecnológica',
                'acteco': [620200, 620100],
                'direccion': 'Av. Providencia 1234, Oficina 501',
                'comuna': 'Providencia',
                'ciudad': 'Santiago',
            },
            'receptor': {
                'rut': '761234560',
                'razon_social': 'CLIENTE EMPRESA LTDA',
                'giro': 'Comercio al por Mayor',
                'direccion': 'Calle Falsa 123',
                'comuna': 'Santiago',
                'ciudad': 'Santiago',
            },
            'totales': {
                'neto': 840336,
                'iva': 159664,
                'total': 1000000,
            },
            'lineas': [
                {
                    'numero': 1,
                    'nombre': 'Consultoría Desarrollo Software',
                    'descripcion': 'Desarrollo de módulo customizado Odoo 19',
                    'cantidad': 120,
                    'unidad': 'HRS',
                    'precio': 7003,
                    'descuento_porcentaje': 0,
                    'monto': 840360,
                },
            ],
        }

    def _get_sample_data_dte_34(self) -> Dict:
        """Generate realistic sample data for DTE 34 (Factura Exenta)."""
        return {
            'folio': 23456,
            'fecha_emision': date.today().strftime('%Y-%m-%d'),
            'emisor': {
                'rut': '760000000',
                'razon_social': 'EMPRESA DEMO SPA',
                'giro': 'Servicios de Educación',
                'acteco': [854900],
                'direccion': 'Av. Providencia 1234',
                'comuna': 'Providencia',
                'ciudad': 'Santiago',
            },
            'receptor': {
                'rut': '761234560',
                'razon_social': 'CLIENTE EMPRESA LTDA',
                'direccion': 'Calle Falsa 123',
                'comuna': 'Santiago',
                'ciudad': 'Santiago',
            },
            'totales': {
                'exento': 500000,
                'total': 500000,
            },
            'lineas': [
                {
                    'numero': 1,
                    'nombre': 'Curso de Capacitación',
                    'cantidad': 1,
                    'precio': 500000,
                    'monto': 500000,
                },
            ],
        }

    def _get_sample_data_dte_52(self) -> Dict:
        """Generate realistic sample data for DTE 52 (Guía de Despacho)."""
        return {
            'folio': 34567,
            'fecha_emision': date.today().strftime('%Y-%m-%d'),
            'tipo_traslado': '1',  # Operación constituye venta
            'emisor': {
                'rut': '760000000',
                'razon_social': 'EMPRESA DEMO SPA',
                'giro': 'Distribución de Productos',
                'acteco': [469000],
                'direccion': 'Av. Providencia 1234',
                'comuna': 'Providencia',
                'ciudad': 'Santiago',
            },
            'receptor': {
                'rut': '761234560',
                'razon_social': 'CLIENTE EMPRESA LTDA',
                'direccion': 'Calle Falsa 123',
                'comuna': 'Santiago',
                'ciudad': 'Santiago',
            },
            'transporte': {
                'patente': 'ABCD12',
                'rut_chofer': '12345678-9',
                'nombre_chofer': 'Juan Perez',
                'direccion_destino': 'Calle Falsa 123, Santiago',
            },
            'totales': {
                'neto': 840336,
                'iva': 159664,
                'total': 1000000,
            },
            'lineas': [
                {
                    'numero': 1,
                    'nombre': 'Producto A',
                    'cantidad': 10,
                    'precio': 84034,
                    'monto': 840340,
                },
            ],
        }

    def _get_sample_data_dte_56(self) -> Dict:
        """Generate realistic sample data for DTE 56 (Nota de Débito)."""
        return {
            'folio': 45678,
            'fecha_emision': date.today().strftime('%Y-%m-%d'),
            'emisor': {
                'rut': '760000000',
                'razon_social': 'EMPRESA DEMO SPA',
                'giro': 'Servicios',
                'acteco': [620200],
                'direccion': 'Av. Providencia 1234',
                'comuna': 'Providencia',
                'ciudad': 'Santiago',
            },
            'receptor': {
                'rut': '761234560',
                'razon_social': 'CLIENTE EMPRESA LTDA',
                'direccion': 'Calle Falsa 123',
                'comuna': 'Santiago',
                'ciudad': 'Santiago',
            },
            'documento_referencia': {
                'tipo_doc': '33',
                'folio': '12345',
                'fecha': (date.today() - timedelta(days=10)).strftime('%Y-%m-%d'),
                'razon': 'Intereses por mora',
            },
            'totales': {
                'neto': 42017,
                'iva': 7983,
                'total': 50000,
            },
            'lineas': [
                {
                    'numero': 1,
                    'nombre': 'Intereses Mora',
                    'cantidad': 1,
                    'precio': 42017,
                    'monto': 42017,
                },
            ],
        }

    def _get_sample_data_dte_61(self) -> Dict:
        """Generate realistic sample data for DTE 61 (Nota de Crédito)."""
        return {
            'folio': 56789,
            'fecha_emision': date.today().strftime('%Y-%m-%d'),
            'emisor': {
                'rut': '760000000',
                'razon_social': 'EMPRESA DEMO SPA',
                'giro': 'Servicios',
                'acteco': [620200],
                'direccion': 'Av. Providencia 1234',
                'comuna': 'Providencia',
                'ciudad': 'Santiago',
            },
            'receptor': {
                'rut': '761234560',
                'razon_social': 'CLIENTE EMPRESA LTDA',
                'direccion': 'Calle Falsa 123',
                'comuna': 'Santiago',
                'ciudad': 'Santiago',
            },
            'documento_referencia': {
                'tipo_doc': '33',
                'folio': '12345',
                'fecha': (date.today() - timedelta(days=5)).strftime('%Y-%m-%d'),
                'razon': 'Descuento por volumen',
            },
            'totales': {
                'neto': 84034,
                'iva': 15966,
                'total': 100000,
            },
            'lineas': [
                {
                    'numero': 1,
                    'nombre': 'Descuento Volumen',
                    'cantidad': 1,
                    'precio': 84034,
                    'monto': 84034,
                },
            ],
        }

    def benchmark_dte_type(self, dte_type: str, data: Dict) -> List[float]:
        """
        Benchmark single DTE type with N iterations.

        Args:
            dte_type (str): DTE type code ('33', '34', '52', '56', '61')
            data (dict): Sample data for generation

        Returns:
            List[float]: Latency measurements in milliseconds
        """
        times = []

        print(f"  Benchmarking DTE {dte_type}... ", end='', flush=True)

        for i in range(self.iterations):
            start = time.perf_counter()
            try:
                xml = self.generator.generate_dte_xml(dte_type, data)
            except Exception as e:
                print(f"\n  ❌ Error in iteration {i+1}: {e}")
                continue
            end = time.perf_counter()

            latency_ms = (end - start) * 1000  # Convert to milliseconds
            times.append(latency_ms)

        print(f"✅ {len(times)} iterations completed")

        return times

    def run_benchmark(self) -> Dict[str, List[float]]:
        """
        Run complete benchmark for all 5 DTE types.

        Returns:
            dict: {dte_type: [latencies_ms]}
        """
        print(f"\n{'='*70}")
        print(f"🚀 XML GENERATION PERFORMANCE BENCHMARK")
        print(f"{'='*70}")
        print(f"Iterations per DTE type: {self.iterations}")
        print(f"Total iterations: {self.iterations * 5}")
        print(f"{'='*70}\n")

        benchmarks = {
            '33': ('Factura Electrónica', self._get_sample_data_dte_33()),
            '34': ('Factura Exenta', self._get_sample_data_dte_34()),
            '52': ('Guía de Despacho', self._get_sample_data_dte_52()),
            '56': ('Nota de Débito', self._get_sample_data_dte_56()),
            '61': ('Nota de Crédito', self._get_sample_data_dte_61()),
        }

        results = {}

        for dte_type, (name, data) in benchmarks.items():
            print(f"📄 DTE {dte_type} - {name}")
            times = self.benchmark_dte_type(dte_type, data)
            results[dte_type] = times

        self.results = results
        return results

    def calculate_statistics(self, times: List[float]) -> Dict[str, float]:
        """
        Calculate percentile statistics.

        Args:
            times (list): List of latency measurements in milliseconds

        Returns:
            dict: {'p50', 'p95', 'p99', 'mean', 'min', 'max'}
        """
        if not times:
            return {}

        sorted_times = sorted(times)
        n = len(sorted_times)

        return {
            'p50': sorted_times[int(n * 0.50)],
            'p95': sorted_times[int(n * 0.95)],
            'p99': sorted_times[int(n * 0.99)],
            'mean': statistics.mean(sorted_times),
            'min': min(sorted_times),
            'max': max(sorted_times),
        }

    def print_results(self):
        """Print formatted benchmark results."""
        print(f"\n{'='*70}")
        print(f"📊 BENCHMARK RESULTS")
        print(f"{'='*70}\n")

        # Per-DTE-type results
        for dte_type, times in self.results.items():
            stats = self.calculate_statistics(times)

            print(f"DTE {dte_type}:")
            print(f"  Iterations:  {len(times)}")
            print(f"  P50 (median): {stats['p50']:7.2f} ms")
            print(f"  P95:          {stats['p95']:7.2f} ms")
            print(f"  P99:          {stats['p99']:7.2f} ms")
            print(f"  Mean:         {stats['mean']:7.2f} ms")
            print(f"  Min:          {stats['min']:7.2f} ms")
            print(f"  Max:          {stats['max']:7.2f} ms")
            print()

        # Aggregated results (all DTEs)
        all_times = []
        for times in self.results.values():
            all_times.extend(times)

        agg_stats = self.calculate_statistics(all_times)

        print(f"{'─'*70}")
        print(f"AGGREGATED (All 5 DTE types):")
        print(f"  Total iterations: {len(all_times)}")
        print(f"  P50 (median):     {agg_stats['p50']:7.2f} ms")
        print(f"  P95:              {agg_stats['p95']:7.2f} ms  ← TARGET: <200ms")
        print(f"  P99:              {agg_stats['p99']:7.2f} ms")
        print(f"  Mean:             {agg_stats['mean']:7.2f} ms")
        print(f"  Min:              {agg_stats['min']:7.2f} ms")
        print(f"  Max:              {agg_stats['max']:7.2f} ms")
        print(f"{'='*70}\n")

        # Check if target met
        if agg_stats['p95'] < 200:
            print(f"✅ TARGET MET: P95 {agg_stats['p95']:.2f}ms < 200ms")
            improvement_pct = ((380 - agg_stats['p95']) / 380) * 100
            print(f"✅ IMPROVEMENT: {improvement_pct:.1f}% vs baseline (380ms)")
        else:
            print(f"⚠️  TARGET NOT MET: P95 {agg_stats['p95']:.2f}ms ≥ 200ms")
            print(f"   (Target: <200ms, -47% vs 380ms baseline)")

        print()

    def save_results(self, filename: str = 'benchmark_results.txt'):
        """
        Save results to file.

        Args:
            filename (str): Output filename
        """
        with open(filename, 'w') as f:
            f.write(f"XML Generation Benchmark Results\n")
            f.write(f"================================\n\n")
            f.write(f"Date: {date.today()}\n")
            f.write(f"Iterations per DTE: {self.iterations}\n\n")

            for dte_type, times in self.results.items():
                stats = self.calculate_statistics(times)
                f.write(f"DTE {dte_type}:\n")
                f.write(f"  P50: {stats['p50']:.2f} ms\n")
                f.write(f"  P95: {stats['p95']:.2f} ms\n")
                f.write(f"  P99: {stats['p99']:.2f} ms\n\n")

            all_times = []
            for times in self.results.values():
                all_times.extend(times)
            agg_stats = self.calculate_statistics(all_times)

            f.write(f"AGGREGATED:\n")
            f.write(f"  P50: {agg_stats['p50']:.2f} ms\n")
            f.write(f"  P95: {agg_stats['p95']:.2f} ms\n")
            f.write(f"  P99: {agg_stats['p99']:.2f} ms\n")

        print(f"📁 Results saved to: {filename}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Benchmark XML generation performance (H3 optimization)'
    )
    parser.add_argument(
        '-i', '--iterations',
        type=int,
        default=100,
        help='Number of iterations per DTE type (default: 100)'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='benchmark_results.txt',
        help='Output file for results (default: benchmark_results.txt)'
    )
    parser.add_argument(
        '--baseline',
        action='store_true',
        help='Running baseline (PRE-cache) benchmark'
    )

    args = parser.parse_args()

    if args.baseline:
        print("\n⚠️  WARNING: Running BASELINE benchmark (PRE-cache)")
        print("   Make sure @lru_cache decorators are commented out!")
        print("   Press ENTER to continue or Ctrl+C to cancel...")
        input()

    # Run benchmark
    benchmark = XMLBenchmark(iterations=args.iterations)
    benchmark.run_benchmark()
    benchmark.print_results()
    benchmark.save_results(args.output)

    print(f"\n✅ Benchmark completed successfully!")


if __name__ == '__main__':
    main()
