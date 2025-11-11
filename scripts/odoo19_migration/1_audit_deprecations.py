#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
ODOO 19 CE - SCRIPT DE AUDITORÍA DE DEPRECACIONES
═══════════════════════════════════════════════════════════════════
Fecha: 2025-11-11
Autor: Sistema de Migración Odoo 19

OBJETIVO:
Auditar TODO el código del módulo en busca de técnicas, APIs, y patrones
obsoletos según Odoo 19 CE, basándose en el archivo de configuración YAML.

CARACTERÍSTICAS:
- Carga patrones desde deprecations.yaml
- Búsqueda inteligente con regex por tipo de archivo
- Generación de reporte Markdown con prioridades
- Soporte para AST analysis (Python) y XML parsing
- Estadísticas detalladas por módulo y categoría

SALIDA:
- audit_report.md: Reporte completo en Markdown
- audit_findings.json: Datos estructurados para el script de migración
═══════════════════════════════════════════════════════════════════
"""

import os
import re
import yaml
import json
import logging
import ast
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# FUNCIONES AUXILIARES
# ═══════════════════════════════════════════════════════════════════

def load_deprecation_patterns(config_path: str) -> Dict[str, Any]:
    """Carga patrones de deprecación desde archivo YAML."""
    logger.info(f"Cargando patrones de deprecación desde: {config_path}")
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            logger.info(f"✓ Cargados {len(config['deprecations'])} patrones de deprecación")
            return config
    except Exception as e:
        logger.error(f"✗ Error cargando configuración: {e}")
        raise


def should_process_file(file_path: str, pattern_def: Dict) -> bool:
    """Determina si un archivo debe ser procesado según el patrón."""
    file_path_obj = Path(file_path)
    
    # Verificar extensión de archivo
    files_include = pattern_def.get('files_include', '*.py')
    if files_include == '*.py' and file_path_obj.suffix != '.py':
        return False
    if files_include == '*.xml' and file_path_obj.suffix != '.xml':
        return False
    
    # Verificar path_include (puede ser lista o string)
    paths_include = pattern_def.get('paths_include')
    if paths_include:
        if isinstance(paths_include, list):
            # Debe coincidir con al menos uno de los paths
            return any(path_pattern in file_path for path_pattern in paths_include)
        elif isinstance(paths_include, str):
            return paths_include in file_path
    
    return True


def audit_file_regex(file_path: str, pattern_def: Dict) -> List[Dict]:
    """Audita un archivo usando búsqueda regex."""
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        regex = re.compile(pattern_def['regex_search'], re.MULTILINE | re.DOTALL)
        
        for match in regex.finditer(content):
            line_number = content.count('\n', 0, match.start()) + 1
            
            # Extraer contexto (3 líneas antes y después)
            lines = content[:match.end()].split('\n')
            start_line = max(0, line_number - 4)
            end_line = min(len(lines), line_number + 3)
            context_lines = lines[start_line:end_line]
            
            findings.append({
                'file': file_path,
                'id': pattern_def['id'],
                'name': pattern_def['name'],
                'category': pattern_def['category'],
                'priority': pattern_def['priority'],
                'severity': pattern_def.get('severity', 'unknown'),
                'line_number': line_number,
                'matched_text': match.group(0),
                'context': '\n'.join(context_lines),
                'description': pattern_def['description'],
                'deadline': pattern_def.get('deadline', 'N/A')
            })
    
    except Exception as e:
        logger.warning(f"⚠ Error auditando {file_path}: {e}")
    
    return findings


def audit_file_ast(file_path: str, pattern_def: Dict) -> List[Dict]:
    """Audita un archivo Python usando análisis AST."""
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content, filename=file_path)
        
        # Buscar _sql_constraints como ejemplo de análisis AST
        if pattern_def['id'] == 'sql_constraints':
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == '_sql_constraints':
                            line_number = node.lineno
                            
                            # Extraer el valor de la asignación
                            matched_text = ast.get_source_segment(content, node)
                            
                            findings.append({
                                'file': file_path,
                                'id': pattern_def['id'],
                                'name': pattern_def['name'],
                                'category': pattern_def['category'],
                                'priority': pattern_def['priority'],
                                'severity': pattern_def.get('severity', 'unknown'),
                                'line_number': line_number,
                                'matched_text': matched_text,
                                'context': matched_text,
                                'description': pattern_def['description'],
                                'deadline': pattern_def.get('deadline', 'N/A'),
                                'ast_analysis': True
                            })
    
    except SyntaxError as e:
        logger.warning(f"⚠ Error de sintaxis en {file_path}: {e}")
    except Exception as e:
        logger.warning(f"⚠ Error en análisis AST de {file_path}: {e}")
    
    return findings


def audit_file(file_path: str, pattern_def: Dict) -> List[Dict]:
    """Audita un archivo según el tipo de estrategia definida."""
    replacement_strategy = pattern_def.get('replacement_strategy', 'regex')
    
    if replacement_strategy in ['ast_analysis', 'ast_xml_analysis']:
        # Para Python, usar AST
        if file_path.endswith('.py') and replacement_strategy == 'ast_analysis':
            return audit_file_ast(file_path, pattern_def)
        # Para XML, por ahora usar regex (TODO: implementar XML parsing)
        return audit_file_regex(file_path, pattern_def)
    elif replacement_strategy == 'audit_only':
        # Solo reporte, sin sugerir cambios automáticos
        return audit_file_regex(file_path, pattern_def)
    else:
        # Estrategia regex estándar
        return audit_file_regex(file_path, pattern_def)


def run_audit(root_dir: str, config: Dict) -> List[Dict]:
    """Ejecuta la auditoría completa en el directorio raíz."""
    logger.info(f"═══════════════════════════════════════════════════════")
    logger.info(f"INICIANDO AUDITORÍA EN: {root_dir}")
    logger.info(f"═══════════════════════════════════════════════════════")
    
    patterns = config['deprecations']
    all_findings = []
    files_scanned = 0
    
    # Recorrer todos los archivos
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            
            # Verificar si algún patrón aplica a este archivo
            for pattern_def in patterns:
                if should_process_file(file_path, pattern_def):
                    findings = audit_file(file_path, pattern_def)
                    if findings:
                        all_findings.extend(findings)
            
            files_scanned += 1
            if files_scanned % 100 == 0:
                logger.info(f"  Escaneados {files_scanned} archivos...")
    
    logger.info(f"✓ Auditoría completada. Escaneados {files_scanned} archivos")
    logger.info(f"✓ Encontrados {len(all_findings)} hallazgos potenciales")
    
    return all_findings


def generate_statistics(findings: List[Dict]) -> Dict:
    """Genera estadísticas detalladas de los hallazgos."""
    stats = {
        'total': len(findings),
        'by_priority': defaultdict(int),
        'by_category': defaultdict(int),
        'by_severity': defaultdict(int),
        'by_module': defaultdict(int),
        'by_pattern': defaultdict(int)
    }
    
    for f in findings:
        stats['by_priority'][f['priority']] += 1
        stats['by_category'][f['category']] += 1
        stats['by_severity'][f['severity']] += 1
        stats['by_pattern'][f['id']] += 1
        
        # Extraer módulo del path
        if 'addons/localization/' in f['file']:
            module_path = f['file'].split('addons/localization/')[1]
            module_name = module_path.split('/')[0]
            stats['by_module'][module_name] += 1
    
    # Convertir defaultdict a dict normal
    stats['by_priority'] = dict(stats['by_priority'])
    stats['by_category'] = dict(stats['by_category'])
    stats['by_severity'] = dict(stats['by_severity'])
    stats['by_module'] = dict(stats['by_module'])
    stats['by_pattern'] = dict(stats['by_pattern'])
    
    return stats


def generate_markdown_report(findings: List[Dict], stats: Dict, output_path: str, config: Dict):
    """Genera un reporte completo en formato Markdown."""
    logger.info(f"Generando reporte Markdown en: {output_path}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        # Encabezado
        f.write("# 🔍 REPORTE DE AUDITORÍA DE DEPRECACIONES ODOO 19 CE\n\n")
        f.write(f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Sistema:** Script Automático de Auditoría v1.0\n")
        f.write(f"**Configuración:** deprecations.yaml v{config['metadata']['version']}\n\n")
        
        f.write("---\n\n")
        
        # Resumen Ejecutivo
        f.write("## 📊 RESUMEN EJECUTIVO\n\n")
        f.write(f"- **Total de hallazgos:** {stats['total']}\n")
        f.write(f"- **Críticos (P0):** {stats['by_priority'].get('P0', 0)} ⚠️\n")
        f.write(f"- **Altos (P1):** {stats['by_priority'].get('P1', 0)}\n")
        f.write(f"- **Medios (P2):** {stats['by_priority'].get('P2', 0)}\n")
        f.write(f"- **Deadline crítico:** {config['metadata']['critical_deadline']}\n\n")
        
        # Estadísticas por Prioridad
        f.write("### Por Prioridad\n\n")
        f.write("| Prioridad | Cantidad | Porcentaje |\n")
        f.write("|-----------|----------|------------|\n")
        for priority in ['P0', 'P1', 'P2']:
            count = stats['by_priority'].get(priority, 0)
            percentage = (count / stats['total'] * 100) if stats['total'] > 0 else 0
            f.write(f"| {priority} | {count} | {percentage:.1f}% |\n")
        f.write("\n")
        
        # Estadísticas por Módulo
        f.write("### Por Módulo\n\n")
        f.write("| Módulo | Cantidad |\n")
        f.write("|--------|----------|\n")
        for module, count in sorted(stats['by_module'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"| `{module}` | {count} |\n")
        f.write("\n")
        
        # Estadísticas por Categoría
        f.write("### Por Categoría\n\n")
        f.write("| Categoría | Cantidad |\n")
        f.write("|-----------|----------|\n")
        for category, count in sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"| {category} | {count} |\n")
        f.write("\n")
        
        f.write("---\n\n")
        
        # Hallazgos Detallados por Prioridad
        f.write("## 📋 HALLAZGOS DETALLADOS\n\n")
        
        for priority in ['P0', 'P1', 'P2']:
            priority_findings = [f for f in findings if f['priority'] == priority]
            if not priority_findings:
                continue
            
            icon = "🔴" if priority == "P0" else "🟡" if priority == "P1" else "🟢"
            f.write(f"### {icon} PRIORIDAD {priority}\n\n")
            
            # Agrupar por patrón
            by_pattern = defaultdict(list)
            for finding in priority_findings:
                by_pattern[finding['id']].append(finding)
            
            for pattern_id, pattern_findings in by_pattern.items():
                f.write(f"#### {pattern_findings[0]['name']}\n\n")
                f.write(f"**Categoría:** {pattern_findings[0]['category']}  \n")
                f.write(f"**Severidad:** {pattern_findings[0]['severity']}  \n")
                f.write(f"**Deadline:** {pattern_findings[0]['deadline']}  \n")
                f.write(f"**Ocurrencias:** {len(pattern_findings)}  \n\n")
                
                f.write(f"**Descripción:**\n{pattern_findings[0]['description']}\n\n")
                
                f.write("**Archivos afectados:**\n\n")
                for pf in pattern_findings[:10]:  # Limitar a 10 para legibilidad
                    f.write(f"- `{pf['file']}:{pf['line_number']}`\n")
                
                if len(pattern_findings) > 10:
                    f.write(f"\n... y {len(pattern_findings) - 10} más\n")
                
                f.write("\n")
        
        f.write("---\n\n")
        
        # Plan de Acción Sugerido
        f.write("## ✅ PLAN DE ACCIÓN SUGERIDO\n\n")
        f.write("### Fase 1: Críticos (P0) - Ejecutar INMEDIATAMENTE\n\n")
        p0_findings = [f for f in findings if f['priority'] == 'P0']
        by_pattern_p0 = defaultdict(int)
        for f in p0_findings:
            by_pattern_p0[f['name']] += 1
        
        for pattern_name, count in by_pattern_p0.items():
            f.write(f"- [ ] **{pattern_name}**: {count} ocurrencias\n")
        
        f.write("\n### Fase 2: Altos (P1) - Ejecutar en las próximas 2 semanas\n\n")
        p1_findings = [f for f in findings if f['priority'] == 'P1']
        by_pattern_p1 = defaultdict(int)
        for f in p1_findings:
            by_pattern_p1[f['name']] += 1
        
        for pattern_name, count in by_pattern_p1.items():
            f.write(f"- [ ] **{pattern_name}**: {count} ocurrencias\n")
        
        f.write("\n### Fase 3: Medios (P2) - Planificar para el próximo mes\n\n")
        p2_findings = [f for f in findings if f['priority'] == 'P2']
        by_pattern_p2 = defaultdict(int)
        for f in p2_findings:
            by_pattern_p2[f['name']] += 1
        
        for pattern_name, count in by_pattern_p2.items():
            f.write(f"- [ ] **{pattern_name}**: {count} ocurrencias\n")
        
        f.write("\n---\n\n")
        f.write(f"**Generado automáticamente por:** Sistema de Migración Odoo 19 CE\n")
        f.write(f"**Próximo paso:** Ejecutar `2_migrate_safe.py` en modo dry-run\n")
    
    logger.info("✓ Reporte Markdown generado exitosamente")


def save_findings_json(findings: List[Dict], output_path: str):
    """Guarda hallazgos en formato JSON para procesamiento posterior."""
    logger.info(f"Guardando hallazgos en JSON: {output_path}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': findings
        }, f, indent=2, ensure_ascii=False)
    
    logger.info("✓ Hallazgos guardados en JSON")


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    ADDONS_PATH = PROJECT_ROOT / 'addons' / 'localization'
    CONFIG_PATH = PROJECT_ROOT / 'scripts' / 'odoo19_migration' / 'config' / 'deprecations.yaml'
    REPORT_PATH = PROJECT_ROOT / 'audit_report.md'
    FINDINGS_JSON_PATH = PROJECT_ROOT / 'audit_findings.json'
    
    logger.info("═══════════════════════════════════════════════════════")
    logger.info("  SISTEMA DE AUDITORÍA ODOO 19 CE - DEPRECACIONES")
    logger.info("═══════════════════════════════════════════════════════")
    
    # Validar paths
    if not ADDONS_PATH.exists():
        logger.error(f"✗ Path de addons no encontrado: {ADDONS_PATH}")
        return 1
    
    if not CONFIG_PATH.exists():
        logger.error(f"✗ Archivo de configuración no encontrado: {CONFIG_PATH}")
        return 1
    
    # Cargar configuración
    config = load_deprecation_patterns(str(CONFIG_PATH))
    
    # Ejecutar auditoría
    findings = run_audit(str(ADDONS_PATH), config)
    
    # Generar estadísticas
    stats = generate_statistics(findings)
    
    # Generar reportes
    generate_markdown_report(findings, stats, str(REPORT_PATH), config)
    save_findings_json(findings, str(FINDINGS_JSON_PATH))
    
    logger.info("")
    logger.info("═══════════════════════════════════════════════════════")
    logger.info("  AUDITORÍA COMPLETADA")
    logger.info("═══════════════════════════════════════════════════════")
    logger.info(f"  Total hallazgos: {stats['total']}")
    logger.info(f"  Críticos (P0): {stats['by_priority'].get('P0', 0)}")
    logger.info(f"  Altos (P1): {stats['by_priority'].get('P1', 0)}")
    logger.info(f"  Medios (P2): {stats['by_priority'].get('P2', 0)}")
    logger.info("")
    logger.info(f"  Reporte: {REPORT_PATH}")
    logger.info(f"  Datos JSON: {FINDINGS_JSON_PATH}")
    logger.info("═══════════════════════════════════════════════════════")
    
    return 0


if __name__ == "__main__":
    exit(main())
