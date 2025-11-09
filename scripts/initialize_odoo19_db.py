#!/usr/bin/env python3
"""
Script para inicializar base de datos odoo19 con módulos base
Ejecutar dentro del contenedor Odoo
"""

import subprocess
import sys
import time

def run_command(cmd, description):
    """Execute command and return exit code"""
    print(f"\n{'='*80}")
    print(f"{description}")
    print(f"{'='*80}")
    print(f"Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd, capture_output=True, text=True)

    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    print(f"\nExit Code: {result.returncode}")
    return result.returncode

def main():
    print(f"\n{'='*80}")
    print("INICIANDO PROCESO DE INSTALACIÓN DE ODOO19 DATABASE")
    print(f"{'='*80}\n")

    # Step 1: Initialize database with base modules
    install_cmd = [
        'odoo',
        '-c', '/etc/odoo/odoo.conf',
        '-d', 'odoo19',
        '-i', 'base,web,l10n_cl',
        '--stop-after-init',
        '--log-level=info',
        '--without-demo=all'
    ]

    exit_code = run_command(install_cmd, "INSTALANDO MÓDULOS BASE: base, web, l10n_cl")

    if exit_code != 0:
        print(f"\n❌ ERROR: Instalación falló con código {exit_code}")
        sys.exit(exit_code)

    # Step 2: Verify installation
    print(f"\n{'='*80}")
    print("VERIFICANDO INSTALACIÓN")
    print(f"{'='*80}\n")

    verify_cmd = [
        'psql',
        '-U', 'odoo',
        '-d', 'odoo19',
        '-h', 'db',
        '-c', "SELECT name, state FROM ir_module_module WHERE name IN ('base', 'web', 'l10n_cl');"
    ]

    run_command(verify_cmd, "CONSULTANDO ESTADO DE MÓDULOS")

    print(f"\n{'='*80}")
    print("✅ PROCESO COMPLETADO")
    print(f"{'='*80}\n")

    sys.exit(0)

if __name__ == '__main__':
    main()
