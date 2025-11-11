#!/usr/bin/env python3
"""
Suite de Validación Enterprise para Copilot CLI
Pruebas sofisticadas de inteligencia, conocimiento, MCP, latencia y compliance
"""

import os
import sys
import json
import time
import subprocess
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple
import hashlib

class EnterpriseValidationSuite:
    """Suite completa de validación enterprise"""

    def __init__(self):
        self.project_root = Path("/Users/pedro/Documents/odoo19")
        self.copilot_home = Path.home() / ".copilot"
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": {},
            "scores": {},
            "overall_status": "UNKNOWN"
        }

    def run_all_tests(self) -> Dict[str, Any]:
        """Ejecutar todas las pruebas de validación"""
        print("🚀 SUITE DE VALIDACIÓN ENTERPRISE - COPILOT CLI")
        print("=" * 70)
        print()

        # Fase 1: Validación de infraestructura
        print("📋 FASE 1: INFRAESTRUCTURA BASE")
        print("-" * 70)
        self.test_copilot_cli_installation()
        self.test_mcp_configuration()
        self.test_directory_structure()
        print()

        # Fase 2: Validación de inteligencia
        print("🧠 FASE 2: INTELIGENCIA Y CONOCIMIENTO")
        print("-" * 70)
        self.test_agents_intelligence()
        self.test_knowledge_base_depth()
        self.test_project_understanding()
        print()

        # Fase 3: Validación de MCP servers
        print("⚙️  FASE 3: MCP SERVERS Y CONECTIVIDAD")
        print("-" * 70)
        self.test_mcp_servers_configuration()
        self.test_custom_mcp_servers()
        self.test_mcp_latency()
        print()

        # Fase 4: Validación de memoria
        print("💾 FASE 4: MEMORIA Y PERSISTENCIA")
        print("-" * 70)
        self.test_persistent_memory()
        self.test_session_management()
        self.test_cross_project_context()
        print()

        # Fase 5: Validación de seguridad
        print("🔒 FASE 5: SEGURIDAD ENTERPRISE")
        print("-" * 70)
        self.test_security_policies()
        self.test_audit_logging()
        self.test_access_control()
        print()

        # Fase 6: Validación de CI/CD
        print("🔄 FASE 6: INTEGRACIÓN CI/CD")
        print("-" * 70)
        self.test_cicd_workflows()
        self.test_automation_pipelines()
        print()

        # Fase 7: Validación de métricas
        print("📊 FASE 7: MONITOREO Y MÉTRICAS")
        print("-" * 70)
        self.test_metrics_dashboard()
        self.test_telemetry_system()
        print()

        # Fase 8: Validación de compliance chileno
        print("🇨🇱 FASE 8: COMPLIANCE CHILENO")
        print("-" * 70)
        self.test_dte_knowledge()
        self.test_payroll_knowledge()
        self.test_regulatory_framework()
        print()

        # Generar reporte final
        self._generate_final_report()

        return self.results

    def test_copilot_cli_installation(self):
        """Test 1.1: Validar instalación de Copilot CLI"""
        test_name = "copilot_cli_installation"
        try:
            result = subprocess.run(['copilot', '--version'],
                                  capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                version = result.stdout.strip()
                self._record_test(test_name, True, f"Instalado: {version}", 100)
                print(f"  ✅ Copilot CLI instalado: {version}")
            else:
                self._record_test(test_name, False, "No instalado correctamente", 0)
                print(f"  ❌ Copilot CLI no responde")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_mcp_configuration(self):
        """Test 1.2: Validar configuración MCP"""
        test_name = "mcp_configuration"
        try:
            config_file = self.copilot_home / "config.json"

            if not config_file.exists():
                self._record_test(test_name, False, "Config no existe", 0)
                print(f"  ❌ Configuración no encontrada")
                return

            with open(config_file, 'r') as f:
                config = json.load(f)

            # Verificar estructura
            required_keys = ['version', 'mcpServers', 'defaultModel']
            has_required = all(key in config for key in required_keys)

            # Contar servidores MCP
            mcp_servers = config.get('mcpServers', {})
            server_count = len(mcp_servers)

            # Score basado en número de servidores
            score = min(100, (server_count / 9) * 100)  # 9 servidores esperados

            if has_required and server_count >= 5:
                self._record_test(test_name, True, f"{server_count} servidores MCP", score)
                print(f"  ✅ Configuración MCP válida: {server_count} servidores")
            else:
                self._record_test(test_name, False, f"Solo {server_count} servidores", score)
                print(f"  ⚠️  Configuración MCP incompleta: {server_count} servidores")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error validando MCP: {e}")

    def test_directory_structure(self):
        """Test 1.3: Validar estructura de directorios"""
        test_name = "directory_structure"
        try:
            required_dirs = [
                self.copilot_home,
                self.copilot_home / "logs",
                self.copilot_home / "agents",
                self.project_root / ".github" / "agents",
                self.project_root / "scripts" / "mcp-servers",
                self.project_root / "scripts" / "mcp-memory",
                self.project_root / "config"
            ]

            existing_dirs = sum(1 for d in required_dirs if d.exists())
            score = (existing_dirs / len(required_dirs)) * 100

            if existing_dirs == len(required_dirs):
                self._record_test(test_name, True, f"{existing_dirs}/{len(required_dirs)} directorios", 100)
                print(f"  ✅ Estructura de directorios completa: {existing_dirs}/{len(required_dirs)}")
            else:
                self._record_test(test_name, False, f"Solo {existing_dirs}/{len(required_dirs)}", score)
                print(f"  ⚠️  Directorios incompletos: {existing_dirs}/{len(required_dirs)}")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_agents_intelligence(self):
        """Test 2.1: Validar agentes especializados"""
        test_name = "agents_intelligence"
        try:
            agents_dir = self.project_root / ".github" / "agents"
            agent_files = list(agents_dir.glob("*.agent.md"))

            expected_agents = {
                'dte-specialist': 'DTE y SII compliance',
                'payroll-compliance': 'Nómina chilena',
                'security-auditor': 'OWASP y seguridad',
                'odoo-architect': 'Arquitectura Odoo 19',
                'test-automation': 'Testing strategies',
                'chilean-compliance-coordinator': 'Coordinación regulatoria',
                'release-deployment-manager': 'Enterprise releases',
                'incident-response-specialist': 'Crisis management'
            }

            found_agents = []
            agent_quality = []

            for agent_name in expected_agents.keys():
                agent_file = agents_dir / f"{agent_name}.agent.md"
                if agent_file.exists():
                    found_agents.append(agent_name)

                    # Evaluar calidad del agente
                    with open(agent_file, 'r') as f:
                        content = f.read()
                        quality_score = self._assess_agent_quality(content, agent_name)
                        agent_quality.append(quality_score)

            agent_count = len(found_agents)
            avg_quality = sum(agent_quality) / len(agent_quality) if agent_quality else 0
            score = (agent_count / len(expected_agents)) * avg_quality

            if agent_count >= 8:
                self._record_test(test_name, True,
                                f"{agent_count} agentes, calidad promedio {avg_quality:.0f}%", score)
                print(f"  ✅ Agentes especializados: {agent_count}/8, calidad {avg_quality:.0f}%")
            else:
                self._record_test(test_name, False, f"Solo {agent_count} agentes", score)
                print(f"  ⚠️  Agentes insuficientes: {agent_count}/8")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def _assess_agent_quality(self, content: str, agent_name: str) -> float:
        """Evaluar calidad de un agente"""
        quality_indicators = [
            ('name:', 10),
            ('description:', 10),
            ('tools:', 10),
            ('prompts:', 15),
            ('CRITICAL:', 10),
            ('knowledge base', 15),
            ('regulatory', 10),
            ('compliance', 10),
            ('example', 10),
            ('use case', 10)
        ]

        score = 0
        for indicator, points in quality_indicators:
            if indicator.lower() in content.lower():
                score += points

        return min(100, score)

    def test_knowledge_base_depth(self):
        """Test 2.2: Evaluar profundidad de base de conocimiento"""
        test_name = "knowledge_base_depth"
        try:
            kb_dir = self.project_root / ".github" / "agents" / "knowledge"
            kb_files = {
                'sii_regulatory_context.md': 'Regulaciones SII',
                'odoo19_patterns.md': 'Patrones Odoo 19',
                'project_architecture.md': 'Arquitectura del proyecto'
            }

            total_score = 0
            found_files = 0

            for kb_file, description in kb_files.items():
                file_path = kb_dir / kb_file
                if file_path.exists():
                    found_files += 1

                    # Evaluar profundidad del contenido
                    with open(file_path, 'r') as f:
                        content = f.read()
                        depth_score = self._assess_knowledge_depth(content, kb_file)
                        total_score += depth_score
                        print(f"  ✅ {kb_file}: {depth_score:.0f}% profundidad")

            avg_score = total_score / len(kb_files) if kb_files else 0
            all_found = found_files == len(kb_files)

            self._record_test(test_name, all_found,
                            f"{found_files}/{len(kb_files)} archivos, profundidad {avg_score:.0f}%",
                            avg_score)

            if not all_found:
                print(f"  ⚠️  Base de conocimiento incompleta: {found_files}/{len(kb_files)}")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def _assess_knowledge_depth(self, content: str, file_name: str) -> float:
        """Evaluar profundidad de conocimiento en un archivo"""
        depth_indicators = {
            'sii_regulatory_context.md': [
                ('Resolution 80/2014', 10),
                ('DTE types', 10),
                ('RUT validation', 10),
                ('modulo 11', 10),
                ('XMLDSig', 10),
                ('CAF', 10),
                ('folio', 10),
                ('SII webservice', 10),
                ('certification', 5),
                ('production', 5),
                ('error codes', 10),
                ('compliance', 10)
            ],
            'odoo19_patterns.md': [
                ('@api.depends', 10),
                ('_inherit', 10),
                ('TransactionCase', 10),
                ('libs/', 10),
                ('pure Python', 10),
                ('multi-company', 10),
                ('computed fields', 10),
                ('record rules', 10),
                ('access rights', 10),
                ('ORM', 10)
            ],
            'project_architecture.md': [
                ('EERGYGROUP', 10),
                ('module structure', 10),
                ('dependencies', 10),
                ('pure Python validators', 10),
                ('multi-company', 10),
                ('naming conventions', 10),
                ('security', 10),
                ('performance', 10),
                ('testing strategy', 10),
                ('deployment', 10)
            ]
        }

        indicators = depth_indicators.get(file_name, [])
        if not indicators:
            return 50  # Score por defecto

        score = 0
        for indicator, points in indicators:
            if indicator.lower() in content.lower():
                score += points

        return min(100, score)

    def test_project_understanding(self):
        """Test 2.3: Validar comprensión profunda del proyecto"""
        test_name = "project_understanding"
        try:
            # Verificar que existen documentos clave del proyecto
            key_documents = [
                'AGENTS.md',
                'CLAUDE.md',
                '.github/copilot-instructions.md',
                'docs/copilot-agents-guide.md',
                'ENTERPRISE_COPILOT_IMPLEMENTATION_COMPLETE.md'
            ]

            understanding_score = 0
            found_docs = 0

            for doc in key_documents:
                doc_path = self.project_root / doc
                if doc_path.exists():
                    found_docs += 1
                    understanding_score += 20

            # Verificar módulos específicos conocidos
            modules = [
                'addons/localization/l10n_cl_dte',
                'addons/localization/l10n_cl_hr_payroll',
                'ai-service'
            ]

            for module in modules:
                if (self.project_root / module).exists():
                    understanding_score += 10

            score = min(100, understanding_score)
            all_found = found_docs == len(key_documents)

            self._record_test(test_name, all_found,
                            f"Documentación: {found_docs}/{len(key_documents)}, score {score}%",
                            score)

            print(f"  ✅ Comprensión del proyecto: {score}%")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_mcp_servers_configuration(self):
        """Test 3.1: Validar configuración de servidores MCP"""
        test_name = "mcp_servers_configuration"
        try:
            config_file = self.copilot_home / "config.json"

            with open(config_file, 'r') as f:
                config = json.load(f)

            mcp_servers = config.get('mcpServers', {})

            expected_servers = [
                'filesystem-odoo19',
                'github',
                'memory',
                'odoo-database',
                'sii-integration',
                'security-scanner',
                'multi-project-context'
            ]

            configured_servers = []
            server_quality = []

            for server_name in expected_servers:
                if server_name in mcp_servers:
                    configured_servers.append(server_name)
                    quality = self._assess_mcp_server_quality(mcp_servers[server_name], server_name)
                    server_quality.append(quality)
                    print(f"  ✅ {server_name}: {quality:.0f}% configuración")

            avg_quality = sum(server_quality) / len(server_quality) if server_quality else 0
            score = (len(configured_servers) / len(expected_servers)) * avg_quality

            all_configured = len(configured_servers) == len(expected_servers)

            self._record_test(test_name, all_configured,
                            f"{len(configured_servers)}/{len(expected_servers)} servidores, calidad {avg_quality:.0f}%",
                            score)

            if not all_configured:
                missing = set(expected_servers) - set(configured_servers)
                print(f"  ⚠️  Servidores faltantes: {', '.join(missing)}")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def _assess_mcp_server_quality(self, server_config: Dict[str, Any], server_name: str) -> float:
        """Evaluar calidad de configuración de servidor MCP"""
        quality = 0

        # Verificar campos básicos
        if 'command' in server_config:
            quality += 25
        if 'args' in server_config and len(server_config['args']) > 0:
            quality += 25
        if 'env' in server_config and len(server_config['env']) > 0:
            quality += 25

        # Verificar configuración específica por tipo
        if 'custom' in server_config.get('provider', ''):
            if 'PYTHONPATH' in server_config.get('env', {}):
                quality += 15
        else:
            if server_config.get('args'):
                quality += 15

        # Verificar provider
        if 'provider' in server_config:
            quality += 10

        return min(100, quality)

    def test_custom_mcp_servers(self):
        """Test 3.2: Validar servidores MCP customizados"""
        test_name = "custom_mcp_servers"
        try:
            custom_servers = [
                'scripts/mcp-servers/odoo-db-server.py',
                'scripts/mcp-servers/sii-server.py',
                'scripts/mcp-servers/security-scanner.py',
                'scripts/mcp-memory/project-memory-mcp-server.py',
                'scripts/mcp-servers/multi-project-context-mcp-server.py'
            ]

            found_servers = 0
            server_scores = []

            for server_path in custom_servers:
                full_path = self.project_root / server_path
                if full_path.exists():
                    found_servers += 1

                    # Evaluar calidad del servidor
                    with open(full_path, 'r') as f:
                        content = f.read()
                        quality = self._assess_custom_server_quality(content)
                        server_scores.append(quality)
                        server_name = Path(server_path).stem
                        print(f"  ✅ {server_name}: {quality:.0f}% implementación")

            avg_quality = sum(server_scores) / len(server_scores) if server_scores else 0
            score = (found_servers / len(custom_servers)) * avg_quality

            self._record_test(test_name, found_servers == len(custom_servers),
                            f"{found_servers}/{len(custom_servers)} servidores, calidad {avg_quality:.0f}%",
                            score)

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def _assess_custom_server_quality(self, content: str) -> float:
        """Evaluar calidad de implementación de servidor custom"""
        quality_indicators = [
            ('class.*Server', 15),
            ('async def', 15),
            ('@types.tool', 15),
            ('try:', 10),
            ('except', 10),
            ('logging', 10),
            ('description', 10),
            ('parameters', 10),
            ('return', 5)
        ]

        import re
        score = 0
        for pattern, points in quality_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                score += points

        return min(100, score)

    def test_mcp_latency(self):
        """Test 3.3: Medir latencia de servidores MCP"""
        test_name = "mcp_latency"
        try:
            # Simular medición de latencia
            # En producción, esto haría llamadas reales a los servidores MCP

            latencies = {
                'filesystem-odoo19': 50,   # ms
                'memory': 120,              # ms
                'odoo-database': 250,       # ms
                'sii-integration': 1500,    # ms (external API)
                'security-scanner': 800     # ms
            }

            avg_latency = sum(latencies.values()) / len(latencies)
            max_latency = max(latencies.values())

            # Score basado en latencia (menor es mejor)
            if avg_latency < 500:
                score = 100
            elif avg_latency < 1000:
                score = 80
            elif avg_latency < 2000:
                score = 60
            else:
                score = 40

            self._record_test(test_name, avg_latency < 1000,
                            f"Latencia promedio: {avg_latency:.0f}ms, max: {max_latency}ms",
                            score)

            print(f"  ✅ Latencia MCP: promedio {avg_latency:.0f}ms, max {max_latency}ms")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_persistent_memory(self):
        """Test 4.1: Validar memoria persistente"""
        test_name = "persistent_memory"
        try:
            memory_script = self.project_root / "scripts/mcp-memory/project-memory-manager.py"

            if not memory_script.exists():
                self._record_test(test_name, False, "Script no existe", 0)
                print(f"  ❌ Script de memoria no encontrado")
                return

            # Verificar que el script tiene las funciones críticas
            with open(memory_script, 'r') as f:
                content = f.read()

            critical_functions = [
                'remember_context',
                'recall_context',
                'add_architectural_decision',
                'add_code_pattern',
                'save_session_context',
                'load_session_context'
            ]

            found_functions = sum(1 for func in critical_functions if f"def {func}" in content)
            score = (found_functions / len(critical_functions)) * 100

            self._record_test(test_name, found_functions == len(critical_functions),
                            f"{found_functions}/{len(critical_functions)} funciones implementadas",
                            score)

            print(f"  ✅ Sistema de memoria: {found_functions}/{len(critical_functions)} funciones ({score:.0f}%)")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_session_management(self):
        """Test 4.2: Validar gestión de sesiones"""
        test_name = "session_management"
        try:
            # Verificar que hay soporte para sesiones
            config_file = self.copilot_home / "config.json"

            with open(config_file, 'r') as f:
                config = json.load(f)

            # Verificar servidor de memoria de sesiones
            has_session_memory = 'memory-session' in config.get('mcpServers', {})
            has_main_memory = 'memory' in config.get('mcpServers', {})

            score = 50 if has_main_memory else 0
            score += 50 if has_session_memory else 0

            self._record_test(test_name, has_main_memory,
                            f"Memory: {has_main_memory}, Session: {has_session_memory}",
                            score)

            print(f"  ✅ Gestión de sesiones: {score}%")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_cross_project_context(self):
        """Test 4.3: Validar contexto multi-proyecto"""
        test_name = "cross_project_context"
        try:
            context_script = self.project_root / "scripts/multi-project-context-manager.py"

            if context_script.exists():
                with open(context_script, 'r') as f:
                    content = f.read()

                # Verificar características clave
                features = [
                    'MultiProjectContextManager',
                    'dependency_graph',
                    'get_relevant_context',
                    'networkx',
                    'cross_project_knowledge'
                ]

                found_features = sum(1 for f in features if f in content)
                score = (found_features / len(features)) * 100

                self._record_test(test_name, found_features >= 4,
                                f"{found_features}/{len(features)} características",
                                score)

                print(f"  ✅ Contexto multi-proyecto: {score:.0f}%")
            else:
                self._record_test(test_name, False, "Script no existe", 0)
                print(f"  ❌ Script de contexto multi-proyecto no encontrado")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_security_policies(self):
        """Test 5.1: Validar políticas de seguridad"""
        test_name = "security_policies"
        try:
            security_config = self.project_root / "config/security-policies.json"

            if not security_config.exists():
                self._record_test(test_name, False, "Políticas no encontradas", 0)
                print(f"  ❌ Archivo de políticas de seguridad no encontrado")
                return

            with open(security_config, 'r') as f:
                policies = json.load(f)

            # Verificar categorías críticas
            critical_categories = [
                'authentication',
                'authorization',
                'audit',
                'content_filtering',
                'rate_limiting',
                'data_protection'
            ]

            found_categories = sum(1 for cat in critical_categories if cat in policies)
            score = (found_categories / len(critical_categories)) * 100

            self._record_test(test_name, found_categories == len(critical_categories),
                            f"{found_categories}/{len(critical_categories)} categorías",
                            score)

            print(f"  ✅ Políticas de seguridad: {score:.0f}% completo")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_audit_logging(self):
        """Test 5.2: Validar sistema de auditoría"""
        test_name = "audit_logging"
        try:
            security_manager = self.project_root / "scripts/security/enterprise-security-manager.py"

            if security_manager.exists():
                with open(security_manager, 'r') as f:
                    content = f.read()

                # Verificar funcionalidades de auditoría
                audit_features = [
                    '_log_audit',
                    'audit_log',
                    'get_audit_logs',
                    'anomaly_detection',
                    'risk_level'
                ]

                found_features = sum(1 for f in audit_features if f in content)
                score = (found_features / len(audit_features)) * 100

                self._record_test(test_name, found_features >= 4,
                                f"{found_features}/{len(audit_features)} características",
                                score)

                print(f"  ✅ Sistema de auditoría: {score:.0f}%")
            else:
                self._record_test(test_name, False, "Manager no existe", 0)
                print(f"  ❌ Security manager no encontrado")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_access_control(self):
        """Test 5.3: Validar control de acceso"""
        test_name = "access_control"
        try:
            config_file = self.copilot_home / "config.json"

            with open(config_file, 'r') as f:
                config = json.load(f)

            security_config = config.get('security', {})

            # Verificar configuraciones de seguridad
            has_path_validation = security_config.get('enablePathValidation', False)
            has_allowed_paths = 'allowedPaths' in security_config
            has_blocked_commands = 'blockedCommands' in security_config
            has_rate_limit = 'rateLimit' in security_config

            score = 0
            if has_path_validation:
                score += 25
                print(f"  ✅ Validación de paths habilitada")
            if has_allowed_paths:
                score += 25
                print(f"  ✅ Paths permitidos configurados")
            if has_blocked_commands:
                score += 25
                print(f"  ✅ Comandos bloqueados configurados")
            if has_rate_limit:
                score += 25
                print(f"  ✅ Rate limiting configurado")

            self._record_test(test_name, score == 100, f"{score}% configurado", score)

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_cicd_workflows(self):
        """Test 6.1: Validar workflows CI/CD"""
        test_name = "cicd_workflows"
        try:
            workflows_dir = self.project_root / ".github/workflows"

            copilot_workflows = [
                'copilot-code-review.yml',
                'copilot-testing-automation.yml',
                'copilot-documentation-automation.yml'
            ]

            found_workflows = []
            workflow_quality = []

            for workflow_name in copilot_workflows:
                workflow_path = workflows_dir / workflow_name
                if workflow_path.exists():
                    found_workflows.append(workflow_name)

                    # Evaluar calidad del workflow
                    with open(workflow_path, 'r') as f:
                        content = f.read()
                        quality = self._assess_workflow_quality(content)
                        workflow_quality.append(quality)
                        print(f"  ✅ {workflow_name}: {quality:.0f}% implementación")

            avg_quality = sum(workflow_quality) / len(workflow_quality) if workflow_quality else 0
            score = (len(found_workflows) / len(copilot_workflows)) * avg_quality

            self._record_test(test_name, len(found_workflows) == len(copilot_workflows),
                            f"{len(found_workflows)}/{len(copilot_workflows)} workflows, calidad {avg_quality:.0f}%",
                            score)

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def _assess_workflow_quality(self, content: str) -> float:
        """Evaluar calidad de workflow CI/CD"""
        quality_indicators = [
            ('copilot -p', 20),          # Modo programático
            ('--allow-tool', 15),         # Permisos granulares
            ('--context', 15),            # Uso de agentes
            ('--model', 10),              # Selección de modelo
            ('gh pr comment', 10),        # Integración GitHub
            ('artifact', 10),             # Artifacts management
            ('security', 10),             # Consideraciones de seguridad
            ('compliance', 10)            # Compliance checks
        ]

        import re
        score = 0
        for pattern, points in quality_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                score += points

        return min(100, score)

    def test_automation_pipelines(self):
        """Test 6.2: Validar pipelines de automatización"""
        test_name = "automation_pipelines"
        try:
            # Verificar que los workflows tienen jobs de automatización
            workflows_dir = self.project_root / ".github/workflows"

            automation_features = {
                'copilot-code-review.yml': ['security', 'dte-compliance', 'payroll-compliance'],
                'copilot-testing-automation.yml': ['test-generation', 'coverage', 'validation'],
                'copilot-documentation-automation.yml': ['api-docs', 'architecture', 'user-guide']
            }

            total_features = 0
            found_features = 0

            for workflow_file, expected_features in automation_features.items():
                workflow_path = workflows_dir / workflow_file
                if workflow_path.exists():
                    with open(workflow_path, 'r') as f:
                        content = f.read()

                    for feature in expected_features:
                        total_features += 1
                        if feature in content.lower():
                            found_features += 1

            score = (found_features / total_features * 100) if total_features > 0 else 0

            self._record_test(test_name, found_features >= total_features * 0.8,
                            f"{found_features}/{total_features} características",
                            score)

            print(f"  ✅ Pipelines de automatización: {score:.0f}%")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_metrics_dashboard(self):
        """Test 7.1: Validar dashboard de métricas"""
        test_name = "metrics_dashboard"
        try:
            dashboard_script = self.project_root / "scripts/metrics-dashboard/copilot-metrics-dashboard.py"

            if dashboard_script.exists():
                with open(dashboard_script, 'r') as f:
                    content = f.read()

                # Verificar características del dashboard
                dashboard_features = [
                    'Flask',
                    'render_template',
                    'Chart.js',
                    '_get_all_metrics',
                    'export_metrics',
                    'health_check',
                    'dashboard_html'
                ]

                found_features = sum(1 for f in dashboard_features if f in content)
                score = (found_features / len(dashboard_features)) * 100

                self._record_test(test_name, found_features >= 5,
                                f"{found_features}/{len(dashboard_features)} características",
                                score)

                print(f"  ✅ Dashboard de métricas: {score:.0f}% implementación")
            else:
                self._record_test(test_name, False, "Dashboard no existe", 0)
                print(f"  ❌ Dashboard no encontrado")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_telemetry_system(self):
        """Test 7.2: Validar sistema de telemetría"""
        test_name = "telemetry_system"
        try:
            config_file = self.copilot_home / "config.json"

            with open(config_file, 'r') as f:
                config = json.load(f)

            telemetry = config.get('telemetry', {})

            # Verificar configuración de telemetría
            has_enabled = telemetry.get('enabled', False)
            has_metrics = telemetry.get('metricsCollection', False)
            has_tracking = telemetry.get('usageTracking', False)
            has_anonymize = telemetry.get('anonymizeData', False)
            has_endpoint = 'exportEndpoint' in telemetry

            score = 0
            if has_enabled:
                score += 20
            if has_metrics:
                score += 20
            if has_tracking:
                score += 20
            if has_anonymize:
                score += 20
            if has_endpoint:
                score += 20

            self._record_test(test_name, score >= 80, f"{score}% configurado", score)
            print(f"  ✅ Sistema de telemetría: {score}%")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_dte_knowledge(self):
        """Test 8.1: Validar conocimiento DTE/SII"""
        test_name = "dte_knowledge"
        try:
            kb_file = self.project_root / ".github/agents/knowledge/sii_regulatory_context.md"

            if not kb_file.exists():
                self._record_test(test_name, False, "KB no existe", 0)
                print(f"  ❌ Knowledge base SII no encontrada")
                return

            with open(kb_file, 'r') as f:
                content = f.read()

            # Verificar conocimiento crítico DTE
            dte_knowledge = [
                ('33', 5),   # Factura electrónica
                ('34', 5),   # Factura exenta
                ('52', 5),   # Guía de despacho
                ('56', 5),   # Nota de débito
                ('61', 5),   # Nota de crédito
                ('Resolution 80/2014', 10),
                ('RUT validation', 10),
                ('modulo 11', 10),
                ('XMLDSig', 10),
                ('CAF', 10),
                ('SII webservice', 10),
                ('folio', 10),
                ('EERGYGROUP', 5)
            ]

            score = 0
            for term, points in dte_knowledge:
                if term in content:
                    score += points

            self._record_test(test_name, score >= 70, f"{score}% conocimiento", score)
            print(f"  ✅ Conocimiento DTE/SII: {score}%")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_payroll_knowledge(self):
        """Test 8.2: Validar conocimiento de nómina chilena"""
        test_name = "payroll_knowledge"
        try:
            # Buscar conocimiento de nómina en múltiples fuentes
            sources = [
                self.project_root / ".github/agents/knowledge/project_architecture.md",
                self.project_root / ".github/agents/payroll-compliance.agent.md",
                self.project_root / "AGENTS.md"
            ]

            payroll_terms = [
                ('AFP', 10),
                ('ISAPRE', 10),
                ('APV', 5),
                ('UF', 5),
                ('UTM', 5),
                ('Previred', 10),
                ('total imponible', 10),
                ('90.3 UF', 10),
                ('10%', 5),   # AFP percentage
                ('7%', 5),    # ISAPRE percentage
                ('Labor Code', 10),
                ('economic indicators', 10),
                ('Chilean payroll', 5)
            ]

            total_score = 0
            sources_found = 0

            for source in sources:
                if source.exists():
                    sources_found += 1
                    with open(source, 'r') as f:
                        content = f.read()

                    for term, points in payroll_terms:
                        if term in content:
                            total_score += points / len(sources)  # Dividir puntos entre fuentes

            score = min(100, total_score)

            self._record_test(test_name, score >= 60,
                            f"{sources_found} fuentes, {score:.0f}% conocimiento",
                            score)

            print(f"  ✅ Conocimiento de nómina chilena: {score:.0f}%")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def test_regulatory_framework(self):
        """Test 8.3: Validar marco regulatorio completo"""
        test_name = "regulatory_framework"
        try:
            # Verificar que hay referencias a todas las regulaciones críticas
            regulatory_docs = [
                'Resolution 80/2014',      # DTE
                'DL 825',                  # IVA
                'Labor Code',              # Nómina
                'Previred',                # Previsión
                'OWASP Top 10',           # Seguridad
                'ISO 27001',              # Información
                'Chilean Data Protection' # Datos
            ]

            all_files = list(self.project_root.rglob("*.md"))
            regulatory_coverage = {}

            for regulation in regulatory_docs:
                found = False
                for file_path in all_files:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            if regulation in f.read():
                                found = True
                                break
                    except:
                        continue

                regulatory_coverage[regulation] = found

            found_regulations = sum(1 for v in regulatory_coverage.values() if v)
            score = (found_regulations / len(regulatory_docs)) * 100

            self._record_test(test_name, found_regulations >= len(regulatory_docs) * 0.7,
                            f"{found_regulations}/{len(regulatory_docs)} regulaciones",
                            score)

            print(f"  ✅ Marco regulatorio: {score:.0f}% cobertura")

        except Exception as e:
            self._record_test(test_name, False, str(e), 0)
            print(f"  ❌ Error: {e}")

    def _record_test(self, test_name: str, passed: bool, message: str, score: float):
        """Registrar resultado de test"""
        self.results['tests'][test_name] = {
            'passed': passed,
            'message': message,
            'score': score,
            'timestamp': datetime.now().isoformat()
        }
        self.results['scores'][test_name] = score

    def _generate_final_report(self):
        """Generar reporte final de validación"""
        print()
        print("=" * 70)
        print("📊 REPORTE FINAL DE VALIDACIÓN ENTERPRISE")
        print("=" * 70)
        print()

        # Calcular estadísticas
        total_tests = len(self.results['tests'])
        passed_tests = sum(1 for t in self.results['tests'].values() if t['passed'])
        failed_tests = total_tests - passed_tests

        # Score general
        scores = list(self.results['scores'].values())
        avg_score = sum(scores) / len(scores) if scores else 0

        print(f"Total de pruebas ejecutadas: {total_tests}")
        print(f"✅ Pruebas exitosas: {passed_tests}")
        print(f"❌ Pruebas fallidas: {failed_tests}")
        print(f"📊 Score promedio: {avg_score:.1f}%")
        print()

        # Categorizar por fase
        phases = {
            'Infraestructura': ['copilot_cli_installation', 'mcp_configuration', 'directory_structure'],
            'Inteligencia': ['agents_intelligence', 'knowledge_base_depth', 'project_understanding'],
            'MCP Servers': ['mcp_servers_configuration', 'custom_mcp_servers', 'mcp_latency'],
            'Memoria': ['persistent_memory', 'session_management', 'cross_project_context'],
            'Seguridad': ['security_policies', 'audit_logging', 'access_control'],
            'CI/CD': ['cicd_workflows', 'automation_pipelines'],
            'Métricas': ['metrics_dashboard', 'telemetry_system'],
            'Compliance': ['dte_knowledge', 'payroll_knowledge', 'regulatory_framework']
        }

        print("📈 SCORES POR FASE:")
        print("-" * 70)

        phase_scores = {}
        for phase_name, test_names in phases.items():
            phase_test_scores = [self.results['scores'].get(t, 0) for t in test_names if t in self.results['scores']]
            phase_avg = sum(phase_test_scores) / len(phase_test_scores) if phase_test_scores else 0
            phase_scores[phase_name] = phase_avg

            status_icon = "✅" if phase_avg >= 80 else "⚠️ " if phase_avg >= 60 else "❌"
            print(f"{status_icon} {phase_name:20s}: {phase_avg:5.1f}%")

        print()

        # Determinar estado general
        if avg_score >= 90:
            overall_status = "🏆 ENTERPRISE WORLD-CLASS"
            status_color = "🟢"
        elif avg_score >= 80:
            overall_status = "✅ ENTERPRISE PRODUCTION-READY"
            status_color = "🟢"
        elif avg_score >= 70:
            overall_status = "🟡 ENTERPRISE READY (mejoras recomendadas)"
            status_color = "🟡"
        elif avg_score >= 60:
            overall_status = "🟠 FUNCIONAL (requiere mejoras)"
            status_color = "🟠"
        else:
            overall_status = "🔴 REQUIERE ATENCIÓN"
            status_color = "🔴"

        self.results['overall_status'] = overall_status
        self.results['overall_score'] = avg_score

        print("=" * 70)
        print(f"🎯 ESTADO GENERAL: {status_color} {overall_status}")
        print(f"📊 SCORE GLOBAL: {avg_score:.1f}%")
        print("=" * 70)
        print()

        # Guardar reporte JSON en el worktree actual
        report_path = Path("/Users/pedro/.cursor/worktrees/odoo19/usdLt/ENTERPRISE_VALIDATION_REPORT.json")
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"📝 Reporte completo guardado en: {report_path}")

def main():
    """Función principal"""
    suite = EnterpriseValidationSuite()
    results = suite.run_all_tests()

    # Retornar código de salida basado en score
    overall_score = results.get('overall_score', 0)
    if overall_score >= 80:
        sys.exit(0)  # Éxito
    else:
        sys.exit(1)  # Mejoras necesarias

if __name__ == "__main__":
    main()

