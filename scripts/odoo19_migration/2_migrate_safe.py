#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
ODOO 19 CE - SCRIPT DE MIGRACIÓN SEGURA
═══════════════════════════════════════════════════════════════════
Fecha: 2025-11-11
Autor: Sistema de Migración Odoo 19

OBJETIVO:
Aplicar correcciones SIN ERRORES basándose en los hallazgos de auditoría,
con confirmación en un trabajo retroalimentado hasta dejar al 100% los módulos.

CARACTERÍSTICAS:
- Lee hallazgos desde audit_findings.json
- Modo dry-run por defecto (preview sin aplicar cambios)
- Backup automático de archivos antes de modificar
- Aplicación inteligente según estrategia de reemplazo
- Validación después de cada cambio
- Rollback automático si falla validación

SEGURIDAD:
- NUNCA modifica archivos sin backup
- NUNCA aplica cambios en masa sin validación
- SIEMPRE verifica sintaxis después de cambios

SALIDA:
- migration_log.txt: Log detallado de cambios aplicados
- migration_results.json: Resultados estructurados
- Backups en: {file_path}.backup_{timestamp}
═══════════════════════════════════════════════════════════════════
"""

import os
import re
import json
import yaml
import shutil
import logging
import ast
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple

# ═══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# FUNCIONES DE BACKUP
# ═══════════════════════════════════════════════════════════════════

def create_backup(file_path: str) -> str:
    """Crea un backup timestamped del archivo."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.backup_{timestamp}"
    
    try:
        shutil.copy2(file_path, backup_path)
        logger.info(f"  ✓ Backup creado: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"  ✗ Error creando backup de {file_path}: {e}")
        raise


def restore_backup(backup_path: str, original_path: str):
    """Restaura un archivo desde su backup."""
    try:
        shutil.copy2(backup_path, original_path)
        logger.info(f"  ✓ Restaurado desde backup: {backup_path}")
    except Exception as e:
        logger.error(f"  ✗ Error restaurando backup {backup_path}: {e}")
        raise


# ═══════════════════════════════════════════════════════════════════
# FUNCIONES DE VALIDACIÓN
# ═══════════════════════════════════════════════════════════════════

def validate_python_syntax(file_path: str) -> Tuple[bool, str]:
    """Valida sintaxis Python usando AST."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        ast.parse(code, filename=file_path)
        return True, "Sintaxis OK"
    except SyntaxError as e:
        return False, f"Error de sintaxis en línea {e.lineno}: {e.msg}"
    except Exception as e:
        return False, f"Error validando sintaxis: {e}"


def validate_xml_syntax(file_path: str) -> Tuple[bool, str]:
    """Valida sintaxis XML."""
    try:
        ET.parse(file_path)
        return True, "XML OK"
    except ET.ParseError as e:
        return False, f"Error XML: {e}"
    except Exception as e:
        return False, f"Error validando XML: {e}"


def validate_file(file_path: str) -> Tuple[bool, str]:
    """Valida un archivo según su tipo."""
    if file_path.endswith('.py'):
        return validate_python_syntax(file_path)
    elif file_path.endswith('.xml'):
        return validate_xml_syntax(file_path)
    else:
        return True, "Tipo de archivo no requiere validación"


# ═══════════════════════════════════════════════════════════════════
# FUNCIONES DE MIGRACIÓN
# ═══════════════════════════════════════════════════════════════════

def apply_regex_replacement(file_path: str, pattern: Dict, dry_run: bool = True) -> Tuple[bool, str, Dict]:
    """Aplica un reemplazo regex en un archivo."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        regex = re.compile(pattern['regex_search'], re.MULTILINE | re.DOTALL)
        new_content = regex.sub(pattern['regex_replace'], original_content)
        
        if new_content == original_content:
            return False, "Sin cambios necesarios", {}
        
        changes_count = len(regex.findall(original_content))
        
        if not dry_run:
            # Crear backup antes de modificar
            backup_path = create_backup(file_path)
            
            # Escribir cambios
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            # Validar sintaxis
            valid, message = validate_file(file_path)
            if not valid:
                # Rollback si falla validación
                logger.error(f"  ✗ Validación falló: {message}")
                restore_backup(backup_path, file_path)
                return False, f"Rollback aplicado - {message}", {}
            
            return True, f"Aplicado: {changes_count} cambios", {'backup': backup_path, 'changes': changes_count}
        else:
            return True, f"DRY RUN: {changes_count} cambios serían aplicados", {'changes': changes_count}
    
    except Exception as e:
        logger.error(f"  ✗ Error aplicando migración: {e}")
        return False, str(e), {}


def migrate_sql_constraints(file_path: str, finding: Dict, dry_run: bool = True) -> Tuple[bool, str, Dict]:
    """Migra _sql_constraints a models.Constraint (requiere análisis AST)."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content, filename=file_path)
        
        # Buscar _sql_constraints
        modifications = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == '_sql_constraints':
                        # Parsear el valor (lista de tuplas)
                        if isinstance(node.value, ast.List):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Tuple) and len(elt.elts) == 3:
                                    constraint_name = ast.literal_eval(elt.elts[0])
                                    constraint_sql = ast.literal_eval(elt.elts[1])
                                    constraint_message = ast.literal_eval(elt.elts[2])
                                    
                                    # Generar nuevo código
                                    new_constraint = f"    {constraint_name} = models.Constraint('{constraint_sql}', '{constraint_message}')\n"
                                    modifications.append({
                                        'line': node.lineno,
                                        'old_code': ast.get_source_segment(content, node),
                                        'new_code': new_constraint
                                    })
        
        if not modifications:
            return False, "No se encontraron _sql_constraints activos", {}
        
        if not dry_run:
            # Aplicar modificaciones (por ahora, requiere revisión manual)
            logger.warning("  ⚠ Migración de _sql_constraints requiere revisión manual")
            logger.info("  💡 Sugerencia de migración:")
            for mod in modifications:
                logger.info(f"     Línea {mod['line']}: {mod['new_code']}")
            return False, "Requiere intervención manual", {'modifications': modifications}
        else:
            return True, f"DRY RUN: {len(modifications)} constraints serían migrados (requiere revisión manual)", {'modifications': modifications}
    
    except Exception as e:
        logger.error(f"  ✗ Error migrando _sql_constraints: {e}")
        return False, str(e), {}


def migrate_attrs_xml(file_path: str, finding: Dict, dry_run: bool = True) -> Tuple[bool, str, Dict]:
    """Migra attrs= en XML a expresiones Python directas (complejo)."""
    # Esta es una migración compleja que requiere parsing XML y transformación de lógica
    # Por ahora, se marca como manual
    logger.warning("  ⚠ Migración de attrs= requiere revisión manual (transformación compleja)")
    return False, "Requiere intervención manual - transformación attrs= a expresión Python", {}


def apply_migration(file_path: str, finding: Dict, pattern: Dict, dry_run: bool = True) -> Tuple[bool, str, Dict]:
    """Aplica migración según la estrategia definida."""
    strategy = pattern.get('replacement_strategy', 'regex')
    
    if strategy == 'ast_analysis':
        if pattern['id'] == 'sql_constraints':
            return migrate_sql_constraints(file_path, finding, dry_run)
        else:
            # Otros análisis AST
            return apply_regex_replacement(file_path, pattern, dry_run)
    elif strategy == 'ast_xml_analysis':
        if pattern['id'] == 'attrs_xml':
            return migrate_attrs_xml(file_path, finding, dry_run)
        else:
            return apply_regex_replacement(file_path, pattern, dry_run)
    elif strategy == 'manual':
        return False, "Requiere intervención manual", {}
    elif strategy == 'audit_only':
        return False, "Solo auditoría, no se aplica migración automática", {}
    else:
        # Estrategia regex estándar
        return apply_regex_replacement(file_path, pattern, dry_run)


# ═══════════════════════════════════════════════════════════════════
# FUNCIÓN PRINCIPAL DE MIGRACIÓN
# ═══════════════════════════════════════════════════════════════════

def run_migration(findings: List[Dict], config: Dict, dry_run: bool = True) -> Dict:
    """Ejecuta la migración basada en hallazgos de auditoría."""
    logger.info("═══════════════════════════════════════════════════════")
    logger.info(f"  INICIANDO MIGRACIÓN {'(DRY RUN)' if dry_run else '(REAL)'}")
    logger.info("═══════════════════════════════════════════════════════")
    
    # Crear mapa de patrones por ID
    patterns_map = {p['id']: p for p in config['deprecations']}
    
    # Agrupar hallazgos por archivo y patrón
    by_file = {}
    for finding in findings:
        file_path = finding['file']
        pattern_id = finding['id']
        
        if file_path not in by_file:
            by_file[file_path] = {}
        if pattern_id not in by_file[file_path]:
            by_file[file_path][pattern_id] = []
        by_file[file_path][pattern_id].append(finding)
    
    # Resultados
    results = {
        'timestamp': datetime.now().isoformat(),
        'dry_run': dry_run,
        'total_files': len(by_file),
        'successful': 0,
        'failed': 0,
        'manual_required': 0,
        'skipped': 0,
        'details': []
    }
    
    # Procesar cada archivo
    for file_path, patterns in by_file.items():
        logger.info(f"\nProcesando: {file_path}")
        
        for pattern_id, file_findings in patterns.items():
            pattern = patterns_map[pattern_id]
            logger.info(f"  Patrón: {pattern['name']} ({len(file_findings)} ocurrencias)")
            
            # Aplicar migración solo a la primera ocurrencia (para evitar conflictos)
            # Las demás se procesarán en la siguiente iteración
            finding = file_findings[0]
            
            success, message, details = apply_migration(file_path, finding, pattern, dry_run)
            
            result = {
                'file': file_path,
                'pattern_id': pattern_id,
                'pattern_name': pattern['name'],
                'success': success,
                'message': message,
                'details': details,
                'priority': pattern['priority']
            }
            results['details'].append(result)
            
            if success:
                results['successful'] += 1
                logger.info(f"  ✓ {message}")
            elif 'manual' in message.lower():
                results['manual_required'] += 1
                logger.warning(f"  ⚠ {message}")
            else:
                results['failed'] += 1
                logger.error(f"  ✗ {message}")
    
    return results


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Script de Migración Segura Odoo 19 CE')
    parser.add_argument('--dry-run', action='store_true', default=True,
                        help='Modo dry-run (preview sin aplicar cambios)')
    parser.add_argument('--apply', action='store_true',
                        help='Aplicar cambios reales (desactiva dry-run)')
    parser.add_argument('--priority', choices=['P0', 'P1', 'P2'], default=None,
                        help='Aplicar solo migraciones de una prioridad específica')
    args = parser.parse_args()
    
    dry_run = not args.apply  # Si --apply está presente, dry_run=False
    
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    CONFIG_PATH = PROJECT_ROOT / 'scripts' / 'odoo19_migration' / 'config' / 'deprecations.yaml'
    FINDINGS_PATH = PROJECT_ROOT / 'audit_findings.json'
    RESULTS_PATH = PROJECT_ROOT / ('migration_results_dryrun.json' if dry_run else 'migration_results.json')
    LOG_PATH = PROJECT_ROOT / ('migration_log_dryrun.txt' if dry_run else 'migration_log.txt')
    
    logger.info("═══════════════════════════════════════════════════════")
    logger.info("  SISTEMA DE MIGRACIÓN SEGURA ODOO 19 CE")
    logger.info("═══════════════════════════════════════════════════════")
    
    if not dry_run:
        logger.warning("⚠️  MODO REAL ACTIVADO - Se aplicarán cambios")
        logger.warning("⚠️  Se crearán backups automáticos de cada archivo")
    else:
        logger.info("ℹ️  MODO DRY RUN - Solo preview, sin aplicar cambios")
    
    # Validar paths
    if not FINDINGS_PATH.exists():
        logger.error(f"✗ Archivo de hallazgos no encontrado: {FINDINGS_PATH}")
        logger.error("  Ejecuta primero: python 1_audit_deprecations.py")
        return 1
    
    if not CONFIG_PATH.exists():
        logger.error(f"✗ Archivo de configuración no encontrado: {CONFIG_PATH}")
        return 1
    
    # Cargar datos
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    with open(FINDINGS_PATH, 'r', encoding='utf-8') as f:
        findings_data = json.load(f)
        findings = findings_data['findings']
    
    # Filtrar por prioridad si se especificó
    if args.priority:
        findings = [f for f in findings if f['priority'] == args.priority]
        logger.info(f"Filtrando solo prioridad: {args.priority} ({len(findings)} hallazgos)")
    
    # Ejecutar migración
    results = run_migration(findings, config, dry_run)
    
    # Guardar resultados
    with open(RESULTS_PATH, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Resumen
    logger.info("")
    logger.info("═══════════════════════════════════════════════════════")
    logger.info("  MIGRACIÓN COMPLETADA")
    logger.info("═══════════════════════════════════════════════════════")
    logger.info(f"  Total archivos: {results['total_files']}")
    logger.info(f"  Exitosos: {results['successful']}")
    logger.info(f"  Fallidos: {results['failed']}")
    logger.info(f"  Requieren manual: {results['manual_required']}")
    logger.info("")
    logger.info(f"  Resultados: {RESULTS_PATH}")
    logger.info("═══════════════════════════════════════════════════════")
    
    if not dry_run and results['successful'] > 0:
        logger.info("")
        logger.info("📋 SIGUIENTE PASO:")
        logger.info("  Ejecutar: python 3_validate_changes.py")
    
    return 0


if __name__ == "__main__":
    exit(main())
