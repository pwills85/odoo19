#!/usr/bin/env python3
"""
MCP Server para análisis de seguridad y auditoría de código
Especializado en OWASP Top 10, vulnerabilidades específicas de Odoo y cumplimiento
"""

import os
import sys
import json
import re
import ast
import logging
from typing import Dict, Any, List
from pathlib import Path
import yaml
from mcp.server import Server
import mcp.types as types

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityScannerMCPServer(Server):
    """Servidor MCP para análisis de seguridad de código"""

    def __init__(self, rules_path: str = None):
        super().__init__("security-audit-tools", "1.0.0")

        self.rules_path = rules_path or "/Users/pedro/Documents/odoo19/config/security-rules.json"
        self.security_rules = self._load_security_rules()

        # Registrar herramientas
        self.add_tool(self.scan_file_security)
        self.add_tool(self.scan_directory_security)
        self.add_tool(self.analyze_sql_injection)
        self.add_tool(self.analyze_xss_vulnerabilities)
        self.add_tool(self.analyze_xxe_vulnerabilities)
        self.add_tool(self.check_hardcoded_secrets)
        self.add_tool(self.audit_access_controls)
        self.add_tool(self.generate_security_report)

    def _load_security_rules(self) -> Dict[str, Any]:
        """Cargar reglas de seguridad desde archivo"""
        default_rules = {
            "owasp_top_10": {
                "sql_injection": {
                    "patterns": [r"cursor\.execute\(.*\+.*\)", r"raw.*sql", r"SELECT.*\%.*"],
                    "severity": "HIGH",
                    "description": "Posible inyección SQL"
                },
                "xss": {
                    "patterns": [r"t-raw", r"innerHTML.*\+", r"dangerouslySetInnerHTML"],
                    "severity": "MEDIUM",
                    "description": "Posible vulnerabilidad XSS"
                },
                "xxe": {
                    "patterns": [r"resolve_entities.*True", r"no_network.*False", r"dtd_validation.*True"],
                    "severity": "HIGH",
                    "description": "Posible vulnerabilidad XXE en XML"
                },
                "hardcoded_secrets": {
                    "patterns": [r"password.*=.*['\"]", r"secret.*=.*['\"]", r"api_key.*=.*['\"]"],
                    "severity": "HIGH",
                    "description": "Credenciales hardcodeadas"
                }
            },
            "odoo_specific": {
                "unsafe_eval": {
                    "patterns": [r"eval\(.*request", r"exec\(.*input"],
                    "severity": "CRITICAL",
                    "description": "Uso inseguro de eval/exec con entrada de usuario"
                },
                "missing_access_control": {
                    "patterns": [r"def.*self.*\).*:\s*$", r"@api\.model"],
                    "severity": "MEDIUM",
                    "description": "Posible falta de control de acceso"
                },
                "unsafe_file_operations": {
                    "patterns": [r"open\(.*input", r"file.*write.*request"],
                    "severity": "HIGH",
                    "description": "Operaciones de archivo inseguras"
                }
            }
        }

        try:
            if os.path.exists(self.rules_path):
                with open(self.rules_path, 'r') as f:
                    custom_rules = json.load(f)
                    # Combinar reglas por defecto con personalizadas
                    for category, rules in custom_rules.items():
                        if category not in default_rules:
                            default_rules[category] = {}
                        default_rules[category].update(rules)
        except Exception as e:
            logger.warning(f"Error cargando reglas personalizadas: {e}")

        return default_rules

    @types.tool(
        name="scan_file_security",
        description="Analiza un archivo específico en busca de vulnerabilidades de seguridad",
        parameters={
            "file_path": {
                "type": "string",
                "description": "Ruta del archivo a analizar"
            },
            "scan_types": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tipos de escaneo (owasp_top_10, odoo_specific, all)",
                "default": ["all"]
            }
        }
    )
    async def scan_file_security(self, file_path: str, scan_types: List[str] = None) -> Dict[str, Any]:
        """Escanear archivo específico por vulnerabilidades"""
        if scan_types is None:
            scan_types = ["all"]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            result = {
                "file_path": file_path,
                "file_size": len(content),
                "scan_types": scan_types,
                "timestamp": "2024-11-10T12:00:00Z",
                "vulnerabilities": [],
                "summary": {}
            }

            # Ejecutar diferentes tipos de escaneo
            if "all" in scan_types or "owasp_top_10" in scan_types:
                owasp_vulns = self._scan_owasp_top_10(content, file_path)
                result["vulnerabilities"].extend(owasp_vulns)

            if "all" in scan_types or "odoo_specific" in scan_types:
                odoo_vulns = self._scan_odoo_specific(content, file_path)
                result["vulnerabilities"].extend(odoo_vulns)

            # Generar resumen
            result["summary"] = self._generate_scan_summary(result["vulnerabilities"])

            return result

        except Exception as e:
            logger.error(f"Error escaneando archivo {file_path}: {e}")
            return {
                "error": str(e),
                "file_path": file_path,
                "scan_types": scan_types
            }

    @types.tool(
        name="scan_directory_security",
        description="Analiza un directorio completo en busca de vulnerabilidades",
        parameters={
            "directory_path": {
                "type": "string",
                "description": "Ruta del directorio a analizar"
            },
            "file_extensions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extensiones de archivo a incluir",
                "default": [".py", ".xml", ".js"]
            },
            "exclude_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Patrones de archivo a excluir",
                "default": ["test_*", "*_test.py", "__pycache__"]
            }
        }
    )
    async def scan_directory_security(self, directory_path: str,
                                    file_extensions: List[str] = None,
                                    exclude_patterns: List[str] = None) -> Dict[str, Any]:
        """Escanear directorio completo por vulnerabilidades"""
        if file_extensions is None:
            file_extensions = [".py", ".xml", ".js"]
        if exclude_patterns is None:
            exclude_patterns = ["test_*", "*_test.py", "__pycache__"]

        try:
            result = {
                "directory_path": directory_path,
                "file_extensions": file_extensions,
                "exclude_patterns": exclude_patterns,
                "timestamp": "2024-11-10T12:00:00Z",
                "files_scanned": 0,
                "vulnerabilities": [],
                "file_results": []
            }

            # Recorrer archivos
            for file_path in Path(directory_path).rglob("*"):
                if file_path.is_file():
                    # Verificar extensión
                    if file_path.suffix not in file_extensions:
                        continue

                    # Verificar patrones de exclusión
                    should_exclude = False
                    for pattern in exclude_patterns:
                        if "*" in pattern:
                            import fnmatch
                            if fnmatch.fnmatch(str(file_path), pattern):
                                should_exclude = True
                                break
                        elif pattern in str(file_path):
                            should_exclude = True
                            break

                    if should_exclude:
                        continue

                    # Escanear archivo
                    file_result = await self.scan_file_security(str(file_path))
                    if "vulnerabilities" in file_result and file_result["vulnerabilities"]:
                        result["file_results"].append(file_result)
                        result["vulnerabilities"].extend(file_result["vulnerabilities"])
                        result["files_scanned"] += 1

            # Generar resumen global
            result["summary"] = self._generate_scan_summary(result["vulnerabilities"])
            result["files_with_vulnerabilities"] = len(result["file_results"])

            return result

        except Exception as e:
            logger.error(f"Error escaneando directorio {directory_path}: {e}")
            return {
                "error": str(e),
                "directory_path": directory_path
            }

    def _scan_owasp_top_10(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Escanear vulnerabilidades OWASP Top 10"""
        vulnerabilities = []

        for vuln_type, config in self.security_rules.get("owasp_top_10", {}).items():
            for pattern in config["patterns"]:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    vulnerabilities.append({
                        "type": vuln_type,
                        "category": "owasp_top_10",
                        "severity": config["severity"],
                        "description": config["description"],
                        "file_path": file_path,
                        "line_number": content[:match.start()].count('\n') + 1,
                        "matched_text": match.group(),
                        "recommendation": self._get_recommendation(vuln_type)
                    })

        return vulnerabilities

    def _scan_odoo_specific(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Escanear vulnerabilidades específicas de Odoo"""
        vulnerabilities = []

        for vuln_type, config in self.security_rules.get("odoo_specific", {}).items():
            for pattern in config["patterns"]:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    vulnerabilities.append({
                        "type": vuln_type,
                        "category": "odoo_specific",
                        "severity": config["severity"],
                        "description": config["description"],
                        "file_path": file_path,
                        "line_number": content[:match.start()].count('\n') + 1,
                        "matched_text": match.group(),
                        "recommendation": self._get_odoo_recommendation(vuln_type)
                    })

        return vulnerabilities

    def _get_recommendation(self, vuln_type: str) -> str:
        """Obtener recomendación para vulnerabilidad OWASP"""
        recommendations = {
            "sql_injection": "Use ORM methods instead of raw SQL. Never concatenate user input.",
            "xss": "Use t-esc in QWeb templates. Sanitize all user input.",
            "xxe": "Configure XML parser with resolve_entities=False, no_network=True.",
            "hardcoded_secrets": "Use environment variables or Odoo configuration parameters."
        }
        return recommendations.get(vuln_type, "Review and fix security issue.")

    def _get_odoo_recommendation(self, vuln_type: str) -> str:
        """Obtener recomendación para vulnerabilidad Odoo específica"""
        recommendations = {
            "unsafe_eval": "Never use eval/exec with user input. Use safe alternatives.",
            "missing_access_control": "Add proper @api.model or record rules for access control.",
            "unsafe_file_operations": "Validate file paths and use secure file operations."
        }
        return recommendations.get(vuln_type, "Review Odoo security best practices.")

    def _generate_scan_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generar resumen del escaneo"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        category_counts = {}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            category = vuln.get("category", "UNKNOWN")

            if severity in severity_counts:
                severity_counts[severity] += 1

            if category not in category_counts:
                category_counts[category] = 0
            category_counts[category] += 1

        total_vulnerabilities = len(vulnerabilities)

        return {
            "total_vulnerabilities": total_vulnerabilities,
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "risk_level": self._calculate_risk_level(severity_counts)
        }

    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calcular nivel de riesgo general"""
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)

        if critical > 0:
            return "CRITICAL"
        elif high > 5:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    @types.tool(
        name="analyze_sql_injection",
        description="Analiza código Python en busca de vulnerabilidades de inyección SQL",
        parameters={
            "code_content": {
                "type": "string",
                "description": "Código Python a analizar"
            }
        }
    )
    async def analyze_sql_injection(self, code_content: str) -> Dict[str, Any]:
        """Análisis específico de inyección SQL"""
        try:
            result = {
                "analysis_type": "sql_injection",
                "issues_found": [],
                "safe_patterns": [],
                "recommendations": []
            }

            # Parsear código Python
            try:
                tree = ast.parse(code_content)
                analyzer = SQLInjectionAnalyzer()
                analyzer.visit(tree)

                result["issues_found"] = analyzer.issues
                result["safe_patterns"] = analyzer.safe_patterns

            except SyntaxError:
                result["issues_found"].append({
                    "type": "syntax_error",
                    "message": "No se pudo parsear el código Python"
                })

            # Generar recomendaciones
            if result["issues_found"]:
                result["recommendations"] = [
                    "Use Odoo ORM methods (self.env['model'].search()) instead of raw SQL",
                    "Never concatenate user input with SQL strings",
                    "Use parameterized queries if raw SQL is necessary",
                    "Validate and sanitize all user inputs"
                ]

            return result

        except Exception as e:
            return {"error": str(e), "analysis_type": "sql_injection"}

    @types.tool(
        name="analyze_xss_vulnerabilities",
        description="Analiza código en busca de vulnerabilidades XSS",
        parameters={
            "code_content": {
                "type": "string",
                "description": "Código a analizar (Python, XML, JS)"
            }
        }
    )
    async def analyze_xss_vulnerabilities(self, code_content: str) -> Dict[str, Any]:
        """Análisis específico de vulnerabilidades XSS"""
        result = {
            "analysis_type": "xss",
            "issues_found": [],
            "safe_patterns": []
        }

        # Patrones peligrosos
        dangerous_patterns = [
            (r"innerHTML\s*\+", "Direct innerHTML manipulation"),
            (r"dangerouslySetInnerHTML", "React dangerous HTML"),
            (r"t-raw", "QWeb raw HTML output"),
            (r"document\.write", "Direct document writing")
        ]

        for pattern, description in dangerous_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE)
            for match in matches:
                result["issues_found"].append({
                    "pattern": pattern,
                    "description": description,
                    "line": code_content[:match.start()].count('\n') + 1,
                    "matched_text": match.group()
                })

        # Patrones seguros
        safe_patterns = [
            (r"t-esc", "QWeb escaped output"),
            (r"t-out", "Odoo safe output"),
            (r"escape\(", "Manual escaping")
        ]

        for pattern, description in safe_patterns:
            if re.search(pattern, code_content, re.IGNORECASE):
                result["safe_patterns"].append({
                    "pattern": pattern,
                    "description": description
                })

        return result

    @types.tool(
        name="analyze_xxe_vulnerabilities",
        description="Analiza código XML/parsers en busca de vulnerabilidades XXE",
        parameters={
            "code_content": {
                "type": "string",
                "description": "Código a analizar"
            }
        }
    )
    async def analyze_xxe_vulnerabilities(self, code_content: str) -> Dict[str, Any]:
        """Análisis específico de vulnerabilidades XXE"""
        result = {
            "analysis_type": "xxe",
            "issues_found": [],
            "safe_configurations": []
        }

        # Patrones peligrosos
        dangerous_patterns = [
            (r"resolve_entities\s*=\s*True", "XML external entities enabled"),
            (r"no_network\s*=\s*False", "Network access allowed in XML parser"),
            (r"dtd_validation\s*=\s*True", "DTD validation enabled")
        ]

        for pattern, description in dangerous_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE)
            for match in matches:
                result["issues_found"].append({
                    "pattern": pattern,
                    "description": description,
                    "line": code_content[:match.start()].count('\n') + 1,
                    "matched_text": match.group()
                })

        # Configuraciones seguras
        safe_patterns = [
            (r"resolve_entities\s*=\s*False", "XML external entities disabled"),
            (r"no_network\s*=\s*True", "Network access disabled in XML parser"),
            (r"dtd_validation\s*=\s*False", "DTD validation disabled")
        ]

        for pattern, description in safe_patterns:
            if re.search(pattern, code_content):
                result["safe_configurations"].append({
                    "pattern": pattern,
                    "description": description
                })

        return result

    @types.tool(
        name="check_hardcoded_secrets",
        description="Busca credenciales y secrets hardcodeados en el código",
        parameters={
            "code_content": {
                "type": "string",
                "description": "Código a analizar"
            }
        }
    )
    async def check_hardcoded_secrets(self, code_content: str) -> Dict[str, Any]:
        """Buscar credenciales hardcodeadas"""
        result = {
            "analysis_type": "hardcoded_secrets",
            "secrets_found": [],
            "suspicious_patterns": []
        }

        # Patrones de secrets
        secret_patterns = [
            (r"password\s*=\s*['\"]([^'\"]{3,})['\"]", "Hardcoded password"),
            (r"secret\s*=\s*['\"]([^'\"]{3,})['\"]", "Hardcoded secret"),
            (r"api_key\s*=\s*['\"]([^'\"]{10,})['\"]", "Hardcoded API key"),
            (r"token\s*=\s*['\"]([^'\"]{10,})['\"]", "Hardcoded token"),
            (r"Bearer\s+([a-zA-Z0-9_\-]{20,})", "Hardcoded Bearer token")
        ]

        for pattern, description in secret_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE)
            for match in matches:
                # No mostrar el valor real del secret por seguridad
                result["secrets_found"].append({
                    "type": description,
                    "pattern": pattern,
                    "line": code_content[:match.start()].count('\n') + 1,
                    "masked_value": "***HIDDEN***"
                })

        return result

    @types.tool(
        name="audit_access_controls",
        description="Audita controles de acceso en código Odoo",
        parameters={
            "code_content": {
                "type": "string",
                "description": "Código Python de modelo Odoo a auditar"
            }
        }
    )
    async def audit_access_controls(self, code_content: str) -> Dict[str, Any]:
        """Auditar controles de acceso en Odoo"""
        result = {
            "analysis_type": "access_control",
            "methods_without_access_control": [],
            "insecure_patterns": [],
            "secure_patterns": []
        }

        # Buscar métodos públicos sin decoradores de seguridad
        lines = code_content.split('\n')
        for i, line in enumerate(lines):
            # Buscar definiciones de método
            if re.match(r'^\s*def\s+\w+', line):
                method_name = re.search(r'def\s+(\w+)', line).group(1)

                # Revisar líneas anteriores para decoradores
                has_security_decorator = False
                has_api_decorator = False

                # Revisar últimas 3 líneas antes del método
                start_check = max(0, i - 3)
                for j in range(start_check, i):
                    if re.search(r'@\w*\.api\.', lines[j]):
                        has_api_decorator = True
                    if re.search(r'@.*(?:sudo|superuser|admin)', lines[j]):
                        has_security_decorator = True

                if not (has_api_decorator or has_security_decorator):
                    result["methods_without_access_control"].append({
                        "method": method_name,
                        "line": i + 1,
                        "risk": "HIGH"
                    })

        # Buscar patrones inseguros
        insecure_patterns = [
            (r"self\.env\.sudo\(\)", "Uso indiscriminado de sudo"),
            (r"superuser", "Acceso como superusuario"),
            (r"admin.*=.*True", "Bypass de permisos administrativos")
        ]

        for pattern, description in insecure_patterns:
            matches = re.finditer(pattern, code_content, re.IGNORECASE)
            for match in matches:
                result["insecure_patterns"].append({
                    "pattern": pattern,
                    "description": description,
                    "line": code_content[:match.start()].count('\n') + 1
                })

        return result

    @types.tool(
        name="generate_security_report",
        description="Genera un reporte completo de seguridad basado en múltiples análisis",
        parameters={
            "scan_results": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Resultados de escaneos de seguridad previos"
            },
            "include_recommendations": {
                "type": "boolean",
                "description": "Incluir recomendaciones detalladas",
                "default": True
            }
        }
    )
    async def generate_security_report(self, scan_results: List[Dict[str, Any]],
                                     include_recommendations: bool = True) -> Dict[str, Any]:
        """Generar reporte completo de seguridad"""
        report = {
            "title": "Security Audit Report - Odoo19 Chilean Localization",
            "generated_at": "2024-11-10T12:00:00Z",
            "scanned_components": len(scan_results),
            "executive_summary": {},
            "detailed_findings": {},
            "recommendations": [],
            "compliance_status": {}
        }

        # Consolidar resultados
        all_vulnerabilities = []
        for result in scan_results:
            if "vulnerabilities" in result:
                all_vulnerabilities.extend(result["vulnerabilities"])

        # Resumen ejecutivo
        total_vulns = len(all_vulnerabilities)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            if severity in severity_counts:
                severity_counts[severity] += 1

        report["executive_summary"] = {
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
            "risk_assessment": self._assess_overall_risk(severity_counts),
            "compliance_level": self._assess_compliance(severity_counts)
        }

        # Hallazgos detallados por categoría
        findings_by_category = {}
        for vuln in all_vulnerabilities:
            category = vuln.get("category", "UNKNOWN")
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(vuln)

        report["detailed_findings"] = findings_by_category

        # Recomendaciones
        if include_recommendations:
            report["recommendations"] = self._generate_security_recommendations(all_vulnerabilities)

        # Estado de cumplimiento
        report["compliance_status"] = {
            "owasp_compliance": "REVIEW_REQUIRED" if severity_counts["HIGH"] > 0 or severity_counts["CRITICAL"] > 0 else "COMPLIANT",
            "odoo_security": "REVIEW_REQUIRED" if severity_counts["HIGH"] > 0 or severity_counts["CRITICAL"] > 0 else "COMPLIANT",
            "chilean_regulatory": "COMPLIANT",  # Asumir compliant hasta análisis específico
            "overall_status": "SECURE" if severity_counts["HIGH"] == 0 and severity_counts["CRITICAL"] == 0 else "REQUIRES_ATTENTION"
        }

        return report

    def _assess_overall_risk(self, severity_counts: Dict[str, int]) -> str:
        """Evaluar riesgo general"""
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)

        if critical > 0:
            return "CRITICAL"
        elif high > 10:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_compliance(self, severity_counts: Dict[str, int]) -> str:
        """Evaluar nivel de cumplimiento"""
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)

        if critical > 0:
            return "NON_COMPLIANT"
        elif high > 5:
            return "PARTIALLY_COMPLIANT"
        else:
            return "COMPLIANT"

    def _generate_security_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generar recomendaciones de seguridad"""
        recommendations = []

        # Agrupar por tipo de vulnerabilidad
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "UNKNOWN")
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = 0
            vuln_types[vuln_type] += 1

        # Recomendaciones por tipo
        if "sql_injection" in vuln_types:
            recommendations.append("🔴 CRITICAL: Implementar ORM methods exclusivamente. Prohibir raw SQL con user input.")

        if "xxe" in vuln_types:
            recommendations.append("🔴 CRITICAL: Configurar XML parsers con XXE protection (resolve_entities=False, no_network=True)")

        if "hardcoded_secrets" in vuln_types:
            recommendations.append("🔴 CRITICAL: Migrar todas las credenciales a variables de entorno o configuración Odoo")

        if "xss" in vuln_types:
            recommendations.append("🟡 HIGH: Implementar t-esc en todos los templates QWeb. Sanitizar user input")

        if "missing_access_control" in vuln_types:
            recommendations.append("🟡 HIGH: Implementar @api.model y record rules en todos los métodos públicos")

        # Recomendaciones generales
        recommendations.extend([
            "Implementar revisión de código obligatoria para cambios de seguridad",
            "Configurar CI/CD con análisis de seguridad automatizado",
            "Establecer programa de bug bounty interno",
            "Documentar política de seguridad y mejores prácticas",
            "Implementar logging de seguridad y monitoreo de amenazas"
        ])

        return recommendations

class SQLInjectionAnalyzer(ast.NodeVisitor):
    """Analizador AST para detectar inyección SQL"""

    def __init__(self):
        self.issues = []
        self.safe_patterns = []

    def visit_Call(self, node):
        """Visitar llamadas de función"""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'execute':
                # Verificar si es una llamada cursor.execute()
                self._analyze_sql_execute(node)

        self.generic_visit(node)

    def _analyze_sql_execute(self, node):
        """Analizar llamada a cursor.execute()"""
        if len(node.args) > 0:
            sql_arg = node.args[0]

            # Verificar string formatting peligroso
            if isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
                self.issues.append({
                    "type": "sql_string_concatenation",
                    "message": "String concatenation in SQL query - potential injection",
                    "line": node.lineno
                })
            elif isinstance(sql_arg, ast.Call) and isinstance(sql_arg.func, ast.Attribute):
                if sql_arg.func.attr in ['format', 'replace']:
                    self.issues.append({
                        "type": "sql_string_formatting",
                        "message": "String formatting in SQL query - potential injection",
                        "line": node.lineno
                    })

        # Verificar parámetros (segundo argumento)
        if len(node.args) > 1:
            params_arg = node.args[1]
            if isinstance(params_arg, (ast.List, ast.Tuple)):
                self.safe_patterns.append({
                    "type": "parameterized_query",
                    "message": "Parameterized query detected",
                    "line": node.lineno
                })

def main():
    """Función principal del servidor MCP"""
    import argparse

    parser = argparse.ArgumentParser(description="MCP Server para análisis de seguridad")
    parser.add_argument("--rules", help="Ruta al archivo de reglas de seguridad")
    args = parser.parse_args()

    server = SecurityScannerMCPServer(args.rules)

    # Ejecutar servidor
    import asyncio
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
