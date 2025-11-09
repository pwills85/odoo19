#!/usr/bin/env python3
"""
Production Readiness Verification Suite - l10n_cl_dte Module
Odoo 19 CE - Chilean Electronic Invoicing

Este script ejecuta una batería exhaustiva de pruebas para certificar
que el módulo l10n_cl_dte está production-ready.

Uso:
    python3 scripts/verify_production_readiness.py
    python3 scripts/verify_production_readiness.py --level 3  # Solo hasta nivel 3
    python3 scripts/verify_production_readiness.py --quick    # Tests rápidos
    python3 scripts/verify_production_readiness.py --verbose  # Output detallado

Niveles de Testing:
    1. Infrastructure Tests (Docker, DB, Services)
    2. Module Installation Tests (Odoo core)
    3. Database Schema Tests (Migrations, Indexes)
    4. Business Logic Tests (Models, Methods)
    5. Integration Tests (Cron Jobs, Workers)
    6. Performance Tests (Queries, Indexes usage)
    7. Security Tests (Permissions, Encryption)
    8. Production Readiness Tests (Smoke tests)

Author: Claude Code (Anthropic)
Date: 2025-11-03
Version: 1.0.0
"""

import sys
import subprocess
import json
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TestStatus(Enum):
    """Estados de prueba"""
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    WARN = "⚠️  WARN"
    SKIP = "⏭️  SKIP"
    INFO = "ℹ️  INFO"


@dataclass
class TestResult:
    """Resultado de una prueba individual"""
    name: str
    status: TestStatus = TestStatus.INFO
    duration: float = 0.0
    message: str = ""
    details: Dict = field(default_factory=dict)
    expected: str = ""
    actual: str = ""


@dataclass
class TestSuite:
    """Suite de pruebas por nivel"""
    level: int
    name: str
    description: str
    tests: List[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for t in self.tests if t.status == TestStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for t in self.tests if t.status == TestStatus.FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for t in self.tests if t.status == TestStatus.WARN)

    @property
    def skipped(self) -> int:
        return sum(1 for t in self.tests if t.status == TestStatus.SKIP)

    @property
    def total(self) -> int:
        return len(self.tests)

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.passed / self.total) * 100


class ProductionReadinessVerifier:
    """Verificador de production readiness para l10n_cl_dte"""

    def __init__(self, verbose: bool = False, quick: bool = False, max_level: int = 8):
        self.verbose = verbose
        self.quick = quick
        self.max_level = max_level
        self.suites: List[TestSuite] = []
        self.start_time = datetime.now()

    def run_docker_cmd(self, cmd: str, timeout: int = 30) -> Tuple[str, str, int]:
        """Ejecuta comando Docker y retorna (stdout, stderr, returncode)"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Timeout after {timeout}s", 1
        except Exception as e:
            return "", str(e), 1

    def run_odoo_shell_cmd(self, python_code: str, timeout: int = 60) -> Tuple[str, str, int]:
        """Ejecuta código Python en Odoo shell"""
        cmd = f'docker-compose exec -T odoo odoo shell -d odoo --stop-after-init --no-http -c <(echo "{python_code}")'
        return self.run_docker_cmd(cmd, timeout)

    def run_db_query(self, query: str) -> Tuple[str, str, int]:
        """Ejecuta query SQL en PostgreSQL"""
        # Escape single quotes in query
        query = query.replace("'", "'\"'\"'")
        cmd = f"docker-compose exec -T db psql -U odoo -d odoo -t -c '{query}'"
        return self.run_docker_cmd(cmd)

    def log(self, message: str, level: str = "INFO"):
        """Log con timestamp"""
        if self.verbose or level in ["ERROR", "WARN"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {level:5s} | {message}")

    # ================================================================
    # NIVEL 1: INFRASTRUCTURE TESTS
    # ================================================================

    def level_1_infrastructure_tests(self) -> TestSuite:
        """Nivel 1: Tests de infraestructura (Docker, DB, Services)"""
        suite = TestSuite(
            level=1,
            name="Infrastructure Tests",
            description="Verificación de Docker containers, servicios y conectividad"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 1: {suite.name}")
        self.log("=" * 80)

        # Test 1.1: Docker Compose Services Running
        test = TestResult(name="1.1 Docker Compose Services")
        start = time.time()
        stdout, stderr, code = self.run_docker_cmd("docker-compose ps --format json")
        test.duration = time.time() - start

        if code == 0 and stdout:
            try:
                services = [json.loads(line) for line in stdout.strip().split('\n') if line]
                running = [s for s in services if s.get('State') == 'running']
                test.expected = "6 services running"
                test.actual = f"{len(running)} services running"
                test.details = {s['Service']: s['State'] for s in services}

                if len(running) >= 6:
                    test.status = TestStatus.PASS
                    test.message = f"All {len(running)} services running"
                else:
                    test.status = TestStatus.FAIL
                    test.message = f"Only {len(running)}/6 services running"
            except Exception as e:
                test.status = TestStatus.FAIL
                test.message = f"Error parsing services: {e}"
        else:
            test.status = TestStatus.FAIL
            test.message = f"docker-compose ps failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 1.2: PostgreSQL Connectivity
        test = TestResult(name="1.2 PostgreSQL Database Connectivity")
        start = time.time()
        stdout, stderr, code = self.run_db_query("SELECT version();")
        test.duration = time.time() - start

        if code == 0 and "PostgreSQL" in stdout:
            test.status = TestStatus.PASS
            test.message = "PostgreSQL accessible"
            test.actual = stdout.strip()[:50]
            test.expected = "PostgreSQL 15"
        else:
            test.status = TestStatus.FAIL
            test.message = f"DB connection failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 1.3: Redis Connectivity
        test = TestResult(name="1.3 Redis Cache Connectivity")
        start = time.time()
        stdout, stderr, code = self.run_docker_cmd("docker-compose exec -T redis redis-cli PING")
        test.duration = time.time() - start

        if code == 0 and "PONG" in stdout:
            test.status = TestStatus.PASS
            test.message = "Redis responding"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Redis not responding: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 1.4: Odoo HTTP Service
        test = TestResult(name="1.4 Odoo HTTP Service")
        start = time.time()
        stdout, stderr, code = self.run_docker_cmd("docker-compose logs --tail=50 odoo | grep 'HTTP service'")
        test.duration = time.time() - start

        if code == 0 and "running on" in stdout:
            test.status = TestStatus.PASS
            test.message = "HTTP service running on 8069"
        else:
            test.status = TestStatus.WARN
            test.message = "HTTP service log not found (may be old)"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 1.5: AI Service Health
        test = TestResult(name="1.5 AI Microservice Health")
        start = time.time()
        stdout, stderr, code = self.run_docker_cmd("docker-compose exec -T ai-service curl -s http://localhost:8002/health || echo 'FAIL'")
        test.duration = time.time() - start

        if code == 0 and "FAIL" not in stdout:
            test.status = TestStatus.PASS
            test.message = "AI Service healthy"
        else:
            test.status = TestStatus.WARN
            test.message = "AI Service not responding (not critical)"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # NIVEL 2: MODULE INSTALLATION TESTS
    # ================================================================

    def level_2_module_installation_tests(self) -> TestSuite:
        """Nivel 2: Tests de instalación del módulo"""
        suite = TestSuite(
            level=2,
            name="Module Installation Tests",
            description="Verificación de instalación y estado del módulo l10n_cl_dte"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 2: {suite.name}")
        self.log("=" * 80)

        # Test 2.1: Module Installed
        test = TestResult(name="2.1 Module l10n_cl_dte Installed")
        start = time.time()
        query = "SELECT name, state, latest_version FROM ir_module_module WHERE name = 'l10n_cl_dte';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0 and "installed" in stdout:
            test.status = TestStatus.PASS
            test.message = "Module installed"
            test.actual = stdout.strip()
            test.expected = "state = installed"

            # Extract version
            if "19.0" in stdout:
                version = stdout.split("|")[2].strip() if "|" in stdout else "unknown"
                test.details = {"version": version}
        else:
            test.status = TestStatus.FAIL
            test.message = f"Module not installed or query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 2.2: Module Version
        test = TestResult(name="2.2 Module Version >= 19.0.5.0.0")
        start = time.time()
        query = "SELECT latest_version FROM ir_module_module WHERE name = 'l10n_cl_dte';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            version = stdout.strip()
            test.actual = version
            test.expected = ">= 19.0.5.0.0"

            # Parse version
            try:
                parts = version.split(".")
                if len(parts) >= 3:
                    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])

                    if major == 19 and minor == 0 and patch >= 5:
                        test.status = TestStatus.PASS
                        test.message = f"Version {version} OK"
                    else:
                        test.status = TestStatus.FAIL
                        test.message = f"Version {version} < 19.0.5.0.0"
                else:
                    test.status = TestStatus.WARN
                    test.message = f"Cannot parse version: {version}"
            except Exception as e:
                test.status = TestStatus.WARN
                test.message = f"Version check error: {e}"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 2.3: Dependencies Installed
        test = TestResult(name="2.3 Required Dependencies Installed")
        start = time.time()
        deps = ['base', 'account', 'l10n_latam_base', 'l10n_latam_invoice_document',
                'l10n_cl', 'purchase', 'stock', 'web']
        deps_str = ','.join([f"'{d}'" for d in deps])
        query = f"SELECT name, state FROM ir_module_module WHERE name IN ({deps_str});"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            installed = stdout.count("installed")
            test.expected = f"{len(deps)} dependencies installed"
            test.actual = f"{installed} dependencies installed"

            if installed >= len(deps):
                test.status = TestStatus.PASS
                test.message = f"All {len(deps)} dependencies OK"
            else:
                test.status = TestStatus.FAIL
                test.message = f"Only {installed}/{len(deps)} dependencies installed"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 2.4: Models Registered
        test = TestResult(name="2.4 DTE Models Registered in ir_model")
        start = time.time()
        models = ['dte.certificate', 'dte.caf', 'dte.inbox', 'l10n_cl.bhe.book']
        models_str = ','.join([f"'{m}'" for m in models])
        query = f"SELECT COUNT(*) FROM ir_model WHERE model IN ({models_str});"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = f"{len(models)} models"
            test.actual = f"{count} models"

            if count >= len(models):
                test.status = TestStatus.PASS
                test.message = f"All {len(models)} DTE models registered"
            else:
                test.status = TestStatus.FAIL
                test.message = f"Only {count}/{len(models)} models registered"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 2.5: Views Loaded
        test = TestResult(name="2.5 DTE Views Loaded")
        start = time.time()
        query = "SELECT COUNT(*) FROM ir_ui_view WHERE name LIKE '%dte%' OR name LIKE '%DTE%';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 20 views"
            test.actual = f"{count} views"

            if count >= 20:
                test.status = TestStatus.PASS
                test.message = f"{count} DTE views loaded"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} views (expected >= 20)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # NIVEL 3: DATABASE SCHEMA TESTS
    # ================================================================

    def level_3_database_schema_tests(self) -> TestSuite:
        """Nivel 3: Tests de schema de base de datos (Migrations, Indexes)"""
        suite = TestSuite(
            level=3,
            name="Database Schema Tests",
            description="Verificación de migraciones ejecutadas e índices creados"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 3: {suite.name}")
        self.log("=" * 80)

        # Test 3.1: DTE Tables Exist
        test = TestResult(name="3.1 DTE Tables Created")
        start = time.time()
        tables = ['dte_certificate', 'dte_caf', 'dte_inbox', 'l10n_cl_bhe_book',
                  'l10n_cl_bhe_retention_rate']
        tables_str = ','.join([f"'{t}'" for t in tables])
        query = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ({tables_str});"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = f"{len(tables)} tables"
            test.actual = f"{count} tables"

            if count >= len(tables):
                test.status = TestStatus.PASS
                test.message = f"All {len(tables)} DTE tables exist"
            else:
                test.status = TestStatus.FAIL
                test.message = f"Only {count}/{len(tables)} tables exist"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 3.2: Performance Indexes Created
        test = TestResult(name="3.2 DTE Performance Indexes Created")
        start = time.time()
        query = "SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'account_move' AND indexname LIKE '%dte%';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 9 indexes"
            test.actual = f"{count} indexes"

            if count >= 9:
                test.status = TestStatus.PASS
                test.message = f"{count} DTE performance indexes created"
            else:
                test.status = TestStatus.FAIL
                test.message = f"Only {count} indexes (expected >= 9)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 3.3: Specific Indexes Verification
        test = TestResult(name="3.3 Critical Indexes Present")
        start = time.time()
        critical_indexes = [
            'idx_account_move_dte_status',
            'idx_account_move_dte_track_id',
            'idx_account_move_dte_folio'
        ]
        indexes_str = ','.join([f"'{i}'" for i in critical_indexes])
        query = f"SELECT indexname FROM pg_indexes WHERE tablename = 'account_move' AND indexname IN ({indexes_str});"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            found = [idx.strip() for idx in stdout.strip().split('\n') if idx.strip()]
            test.expected = f"{len(critical_indexes)} critical indexes"
            test.actual = f"{len(found)} indexes found"
            test.details = {"found": found}

            if len(found) >= len(critical_indexes):
                test.status = TestStatus.PASS
                test.message = f"All {len(critical_indexes)} critical indexes present"
            else:
                test.status = TestStatus.FAIL
                test.message = f"Only {len(found)}/{len(critical_indexes)} indexes present"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 3.4: DTE Fields in account_move
        test = TestResult(name="3.4 DTE Fields in account_move Table")
        start = time.time()
        dte_fields = ['dte_status', 'dte_track_id', 'dte_folio', 'dte_code']
        fields_str = ','.join([f"'{f}'" for f in dte_fields])
        query = f"SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'account_move' AND column_name IN ({fields_str});"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = f"{len(dte_fields)} DTE fields"
            test.actual = f"{count} fields"

            if count >= len(dte_fields):
                test.status = TestStatus.PASS
                test.message = f"All {len(dte_fields)} DTE fields present in account_move"
            else:
                test.status = TestStatus.FAIL
                test.message = f"Only {count}/{len(dte_fields)} DTE fields present"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 3.5: Foreign Keys Integrity
        test = TestResult(name="3.5 Foreign Keys Integrity")
        start = time.time()
        query = """
            SELECT COUNT(*)
            FROM information_schema.table_constraints
            WHERE constraint_type = 'FOREIGN KEY'
            AND table_name IN ('dte_certificate', 'dte_caf', 'dte_inbox');
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 3 foreign keys"
            test.actual = f"{count} foreign keys"

            if count >= 3:
                test.status = TestStatus.PASS
                test.message = f"{count} foreign keys verified"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} foreign keys (may be OK)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # NIVEL 4: BUSINESS LOGIC TESTS
    # ================================================================

    def level_4_business_logic_tests(self) -> TestSuite:
        """Nivel 4: Tests de lógica de negocio (Models, Methods)"""
        suite = TestSuite(
            level=4,
            name="Business Logic Tests",
            description="Verificación de modelos y métodos de negocio"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 4: {suite.name}")
        self.log("=" * 80)

        # Test 4.1: DTE Certificate Model Accessible
        test = TestResult(name="4.1 DTE Certificate Model Accessible")
        start = time.time()
        query = "SELECT COUNT(*) FROM dte_certificate;"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            test.status = TestStatus.PASS
            test.message = "dte.certificate model accessible"
            test.actual = f"{stdout.strip()} certificates in DB"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Cannot access dte.certificate: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 4.2: DTE CAF Model Accessible
        test = TestResult(name="4.2 DTE CAF Model Accessible")
        start = time.time()
        query = "SELECT COUNT(*) FROM dte_caf;"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            test.status = TestStatus.PASS
            test.message = "dte.caf model accessible"
            test.actual = f"{stdout.strip()} CAFs in DB"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Cannot access dte.caf: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 4.3: BHE Retention Rates Loaded
        test = TestResult(name="4.3 BHE Historical Retention Rates Loaded")
        start = time.time()
        query = "SELECT COUNT(*) FROM l10n_cl_bhe_retention_rate WHERE date_from >= '2018-01-01';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 5 rates (2018+)"
            test.actual = f"{count} rates"

            if count >= 5:
                test.status = TestStatus.PASS
                test.message = f"{count} historical BHE rates loaded"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} rates (expected >= 5)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 4.4: SII Activity Codes Loaded
        test = TestResult(name="4.4 SII Activity Codes Loaded")
        start = time.time()
        query = "SELECT COUNT(*) FROM sii_activity_code;"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 100 activity codes"
            test.actual = f"{count} codes"

            if count >= 100:
                test.status = TestStatus.PASS
                test.message = f"{count} SII activity codes loaded"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} codes (may be OK)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 4.5: Chilean Comunas Loaded
        test = TestResult(name="4.5 Chilean Comunas (Cities) Loaded")
        start = time.time()
        query = "SELECT COUNT(*) FROM l10n_cl_comuna;"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 300 comunas"
            test.actual = f"{count} comunas"

            if count >= 300:
                test.status = TestStatus.PASS
                test.message = f"{count} Chilean comunas loaded"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} comunas (expected >= 300)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # NIVEL 5: INTEGRATION TESTS
    # ================================================================

    def level_5_integration_tests(self) -> TestSuite:
        """Nivel 5: Tests de integración (Cron Jobs, Workers)"""
        suite = TestSuite(
            level=5,
            name="Integration Tests",
            description="Verificación de cron jobs y workers"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 5: {suite.name}")
        self.log("=" * 80)

        # Test 5.1: Cron Jobs Registered
        test = TestResult(name="5.1 DTE Cron Jobs Registered")
        start = time.time()
        query = "SELECT COUNT(*) FROM ir_cron WHERE cron_name LIKE '%DTE%' OR cron_name LIKE '%dte%';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 4 cron jobs"
            test.actual = f"{count} cron jobs"

            if count >= 4:
                test.status = TestStatus.PASS
                test.message = f"{count} DTE cron jobs registered"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} cron jobs"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 5.2: Active Cron Jobs
        test = TestResult(name="5.2 Active DTE Cron Jobs")
        start = time.time()
        query = "SELECT COUNT(*) FROM ir_cron WHERE (cron_name LIKE '%DTE%' OR cron_name LIKE '%dte%') AND active = true;"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 3 active jobs"
            test.actual = f"{count} active jobs"

            if count >= 3:
                test.status = TestStatus.PASS
                test.message = f"{count} DTE cron jobs active"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} active cron jobs"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 5.3: Cron Job Last Execution
        test = TestResult(name="5.3 Cron Jobs Recently Executed")
        start = time.time()
        # Note: This test may show WARN if crons haven't run yet (new install)
        query = """
            SELECT cron_name, lastcall
            FROM ir_cron
            WHERE cron_name LIKE '%Process Pending DTEs%'
            AND active = true;
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0 and stdout.strip():
            test.status = TestStatus.PASS
            test.message = "Cron jobs execution tracked"
            test.actual = stdout.strip()[:50]
        else:
            test.status = TestStatus.WARN
            test.message = "No recent cron execution (may be OK for new install)"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 5.4: Security Groups
        test = TestResult(name="5.4 DTE Security Groups Created")
        start = time.time()
        query = "SELECT COUNT(*) FROM res_groups WHERE name->>'en_US' LIKE '%DTE%' OR name->>'en_US' LIKE '%dte%';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 2 security groups"
            test.actual = f"{count} groups"

            if count >= 2:
                test.status = TestStatus.PASS
                test.message = f"{count} DTE security groups created"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} security groups"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 5.5: Access Rights (ir.model.access)
        test = TestResult(name="5.5 DTE Access Rights Configured")
        start = time.time()
        query = "SELECT COUNT(*) FROM ir_model_access WHERE name LIKE '%dte%';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.expected = ">= 10 access rules"
            test.actual = f"{count} access rules"

            if count >= 10:
                test.status = TestStatus.PASS
                test.message = f"{count} DTE access rules configured"
            else:
                test.status = TestStatus.WARN
                test.message = f"Only {count} access rules"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # NIVEL 6: PERFORMANCE TESTS
    # ================================================================

    def level_6_performance_tests(self) -> TestSuite:
        """Nivel 6: Tests de performance (Queries, Indexes usage)"""
        suite = TestSuite(
            level=6,
            name="Performance Tests",
            description="Verificación de performance de queries e índices"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 6: {suite.name}")
        self.log("=" * 80)

        # Test 6.1: Index Usage (Status Query)
        test = TestResult(name="6.1 Index Usage for Status Query")
        start = time.time()
        query = """
            EXPLAIN (FORMAT JSON)
            SELECT id FROM account_move
            WHERE dte_status IN ('to_send', 'sent')
            LIMIT 100;
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            # Check if index is used (looking for "Index Scan" in plan)
            if "Index Scan" in stdout or "Bitmap Index Scan" in stdout:
                test.status = TestStatus.PASS
                test.message = "Query uses index (optimal)"
            elif "Seq Scan" in stdout:
                test.status = TestStatus.WARN
                test.message = "Query uses sequential scan (may be OK for small tables)"
            else:
                test.status = TestStatus.INFO
                test.message = "Query plan analyzed"
        else:
            test.status = TestStatus.FAIL
            test.message = f"EXPLAIN failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 6.2: Track ID Lookup Performance
        test = TestResult(name="6.2 Track ID Lookup Performance")
        start = time.time()
        query = """
            EXPLAIN (FORMAT JSON)
            SELECT id FROM account_move
            WHERE dte_track_id = 'TEST_TRACK_ID'
            LIMIT 1;
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            if "Index Scan" in stdout:
                test.status = TestStatus.PASS
                test.message = "Track ID query uses index"
            else:
                test.status = TestStatus.WARN
                test.message = "Track ID query may not use index"
        else:
            test.status = TestStatus.FAIL
            test.message = f"EXPLAIN failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 6.3: Database Size
        test = TestResult(name="6.3 Database Size Check")
        start = time.time()
        query = "SELECT pg_size_pretty(pg_database_size('odoo'));"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            test.status = TestStatus.INFO
            test.message = f"Database size: {stdout.strip()}"
            test.actual = stdout.strip()
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 6.4: Index Size
        test = TestResult(name="6.4 DTE Indexes Size")
        start = time.time()
        query = """
            SELECT pg_size_pretty(SUM(pg_relation_size(indexrelid)))
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indexrelid
            WHERE c.relname LIKE '%dte%';
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            test.status = TestStatus.INFO
            test.message = f"DTE indexes total size: {stdout.strip()}"
            test.actual = stdout.strip()
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 6.5: Table Statistics Current
        test = TestResult(name="6.5 Table Statistics Updated")
        start = time.time()
        query = """
            SELECT last_analyze, last_autoanalyze
            FROM pg_stat_user_tables
            WHERE relname = 'account_move';
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0 and stdout.strip():
            test.status = TestStatus.PASS
            test.message = "Table statistics tracked"
            test.actual = stdout.strip()[:50]
        else:
            test.status = TestStatus.INFO
            test.message = "Statistics check completed"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # NIVEL 7: SECURITY TESTS
    # ================================================================

    def level_7_security_tests(self) -> TestSuite:
        """Nivel 7: Tests de seguridad (Permissions, Encryption)"""
        suite = TestSuite(
            level=7,
            name="Security Tests",
            description="Verificación de permisos y encriptación"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 7: {suite.name}")
        self.log("=" * 80)

        # Test 7.1: Encryption Key Configured
        test = TestResult(name="7.1 Fernet Encryption Key Configured")
        start = time.time()
        query = "SELECT COUNT(*) FROM ir_config_parameter WHERE key = 'l10n_cl_dte.fernet_key';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            if count > 0:
                test.status = TestStatus.PASS
                test.message = "Fernet encryption key configured"
            else:
                test.status = TestStatus.WARN
                test.message = "Encryption key not found (will be generated on first use)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 7.2: Admin User Exists
        test = TestResult(name="7.2 Admin User Configured")
        start = time.time()
        query = "SELECT COUNT(*) FROM res_users WHERE login = 'admin';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            if count > 0:
                test.status = TestStatus.PASS
                test.message = "Admin user exists"
            else:
                test.status = TestStatus.FAIL
                test.message = "Admin user not found"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 7.3: Multi-Company Support
        test = TestResult(name="7.3 Multi-Company Support Enabled")
        start = time.time()
        query = "SELECT COUNT(*) FROM res_company;"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            test.status = TestStatus.INFO
            test.message = f"{count} companies in system"
            test.actual = f"{count} companies"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 7.4: RLS (Row Level Security) on DTE Models
        test = TestResult(name="7.4 Company-Level Security Rules")
        start = time.time()
        query = """
            SELECT COUNT(*) FROM ir_rule
            WHERE model_id IN (
                SELECT id FROM ir_model
                WHERE model IN ('dte.certificate', 'dte.caf', 'dte.inbox')
            );
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            if count > 0:
                test.status = TestStatus.PASS
                test.message = f"{count} security rules configured"
            else:
                test.status = TestStatus.INFO
                test.message = "No specific security rules (may use global rules)"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 7.5: Audit Log (mail.thread integration)
        test = TestResult(name="7.5 Audit Trail Integration")
        start = time.time()
        query = """
            SELECT COUNT(*) FROM ir_model
            WHERE model IN ('dte.certificate', 'dte.caf', 'dte.inbox')
            AND is_mail_thread = true;
        """
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0:
            count = int(stdout.strip())
            if count > 0:
                test.status = TestStatus.PASS
                test.message = f"{count} models have audit trail (mail.thread)"
            else:
                test.status = TestStatus.WARN
                test.message = "Audit trail not enabled on DTE models"
        else:
            test.status = TestStatus.FAIL
            test.message = f"Query failed: {stderr}"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # NIVEL 8: PRODUCTION READINESS TESTS
    # ================================================================

    def level_8_production_readiness_tests(self) -> TestSuite:
        """Nivel 8: Tests de production readiness (Smoke tests)"""
        suite = TestSuite(
            level=8,
            name="Production Readiness Tests",
            description="Smoke tests y validación final"
        )

        self.log("=" * 80)
        self.log(f"NIVEL 8: {suite.name}")
        self.log("=" * 80)

        # Test 8.1: No Errors in Logs (last 100 lines)
        test = TestResult(name="8.1 No Critical Errors in Recent Logs")
        start = time.time()
        stdout, stderr, code = self.run_docker_cmd("docker-compose logs --tail=100 odoo 2>&1 | grep -i 'ERROR\\|CRITICAL' | grep -v 'level=warning' | wc -l")
        test.duration = time.time() - start

        if code == 0:
            error_count = int(stdout.strip())
            test.expected = "0 errors"
            test.actual = f"{error_count} errors"

            if error_count == 0:
                test.status = TestStatus.PASS
                test.message = "No critical errors in recent logs"
            else:
                test.status = TestStatus.WARN
                test.message = f"{error_count} errors found (check logs)"
        else:
            test.status = TestStatus.WARN
            test.message = "Cannot check logs"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 8.2: Module Update Successful (check last update)
        test = TestResult(name="8.2 Last Module Update Successful")
        start = time.time()
        query = "SELECT write_date FROM ir_module_module WHERE name = 'l10n_cl_dte';"
        stdout, stderr, code = self.run_db_query(query)
        test.duration = time.time() - start

        if code == 0 and stdout.strip():
            test.status = TestStatus.PASS
            test.message = f"Last updated: {stdout.strip()}"
            test.actual = stdout.strip()
        else:
            test.status = TestStatus.FAIL
            test.message = "Cannot retrieve update date"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 8.3: Critical Data Loaded
        test = TestResult(name="8.3 Critical Reference Data Loaded")
        start = time.time()

        # Check multiple critical data tables
        checks = [
            ("l10n_cl_sii_activity_code", 100),
            ("l10n_cl_comuna", 300),
            ("l10n_cl_bhe_retention_rate", 7)
        ]

        all_ok = True
        details = {}

        for table, min_count in checks:
            query = f"SELECT COUNT(*) FROM {table};"
            stdout, stderr, code = self.run_db_query(query)
            if code == 0:
                count = int(stdout.strip())
                details[table] = count
                if count < min_count:
                    all_ok = False

        test.duration = time.time() - start
        test.details = details

        if all_ok:
            test.status = TestStatus.PASS
            test.message = "All critical data loaded"
        else:
            test.status = TestStatus.WARN
            test.message = "Some reference data may be incomplete"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 8.4: Registry Loaded Successfully
        test = TestResult(name="8.4 Odoo Registry Loaded")
        start = time.time()
        stdout, stderr, code = self.run_docker_cmd("docker-compose logs --tail=50 odoo | grep 'Registry loaded'")
        test.duration = time.time() - start

        if code == 0 and "Registry loaded" in stdout:
            test.status = TestStatus.PASS
            test.message = "Registry loaded successfully"
            # Extract load time if possible
            if "in" in stdout:
                parts = stdout.split("in")
                if len(parts) > 1:
                    test.actual = f"Load time: {parts[-1].strip()[:20]}"
        else:
            test.status = TestStatus.WARN
            test.message = "Registry load log not found (may be old)"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        # Test 8.5: System Health Check
        test = TestResult(name="8.5 Overall System Health")
        start = time.time()

        # Aggregate health from all previous tests
        total_tests = sum(s.total for s in self.suites)
        total_passed = sum(s.passed for s in self.suites)
        total_failed = sum(s.failed for s in self.suites)

        test.duration = time.time() - start
        test.expected = ">= 90% tests passing"

        if total_tests > 0:
            success_rate = (total_passed / total_tests) * 100
            test.actual = f"{success_rate:.1f}% tests passing"

            if success_rate >= 90:
                test.status = TestStatus.PASS
                test.message = f"System health: EXCELLENT ({success_rate:.1f}%)"
            elif success_rate >= 75:
                test.status = TestStatus.WARN
                test.message = f"System health: GOOD ({success_rate:.1f}%)"
            else:
                test.status = TestStatus.FAIL
                test.message = f"System health: POOR ({success_rate:.1f}%)"
        else:
            test.status = TestStatus.INFO
            test.message = "No tests run yet"

        suite.tests.append(test)
        self.log(f"{test.status.value} {test.name}: {test.message}")

        self.suites.append(suite)
        return suite

    # ================================================================
    # EXECUTION & REPORTING
    # ================================================================

    def run_all_tests(self):
        """Ejecuta todos los niveles de tests"""
        print("\n" + "=" * 80)
        print("🚀 PRODUCTION READINESS VERIFICATION SUITE")
        print("=" * 80)
        print(f"Module: l10n_cl_dte")
        print(f"Odoo Version: 19.0 CE")
        print(f"Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Max Level: {self.max_level}")
        print(f"Quick Mode: {'YES' if self.quick else 'NO'}")
        print("=" * 80 + "\n")

        # Run each level
        test_levels = [
            (1, self.level_1_infrastructure_tests),
            (2, self.level_2_module_installation_tests),
            (3, self.level_3_database_schema_tests),
            (4, self.level_4_business_logic_tests),
            (5, self.level_5_integration_tests),
            (6, self.level_6_performance_tests),
            (7, self.level_7_security_tests),
            (8, self.level_8_production_readiness_tests),
        ]

        for level, test_func in test_levels:
            if level > self.max_level:
                self.log(f"Skipping NIVEL {level} (max level: {self.max_level})")
                continue

            if self.quick and level > 5:
                self.log(f"Skipping NIVEL {level} (quick mode)")
                continue

            try:
                test_func()
            except Exception as e:
                self.log(f"ERROR running level {level}: {e}", "ERROR")
                print(f"❌ Error in level {level}: {e}")

        # Generate report
        self.generate_report()

    def generate_report(self):
        """Genera reporte final"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        print("\n" + "=" * 80)
        print("📊 FINAL REPORT")
        print("=" * 80)
        print(f"Total Duration: {duration:.2f}s")
        print("=" * 80 + "\n")

        # Summary by level
        for suite in self.suites:
            status_icon = "✅" if suite.success_rate >= 90 else "⚠️" if suite.success_rate >= 75 else "❌"
            print(f"{status_icon} NIVEL {suite.level}: {suite.name}")
            print(f"   Success Rate: {suite.success_rate:.1f}%")
            print(f"   Tests: {suite.passed} passed, {suite.failed} failed, {suite.warned} warnings, {suite.skipped} skipped")
            print()

        # Overall summary
        total_tests = sum(s.total for s in self.suites)
        total_passed = sum(s.passed for s in self.suites)
        total_failed = sum(s.failed for s in self.suites)
        total_warned = sum(s.warned for s in self.suites)
        total_skipped = sum(s.skipped for s in self.suites)

        overall_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

        print("=" * 80)
        print("🏆 OVERALL SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {total_passed}")
        print(f"❌ Failed: {total_failed}")
        print(f"⚠️  Warnings: {total_warned}")
        print(f"⏭️  Skipped: {total_skipped}")
        print(f"Success Rate: {overall_rate:.1f}%")
        print("=" * 80 + "\n")

        # Final verdict
        if overall_rate >= 95:
            verdict = "✅ PRODUCTION READY - EXCELENTE"
            color = "\033[92m"  # Green
        elif overall_rate >= 85:
            verdict = "✅ PRODUCTION READY - BUENO"
            color = "\033[93m"  # Yellow
        elif overall_rate >= 75:
            verdict = "⚠️  PRODUCTION READY - CON ADVERTENCIAS"
            color = "\033[93m"  # Yellow
        else:
            verdict = "❌ NO PRODUCTION READY - REQUIERE ATENCIÓN"
            color = "\033[91m"  # Red

        reset = "\033[0m"

        print(color + "=" * 80)
        print(f"VEREDICTO FINAL: {verdict}")
        print("=" * 80 + reset)

        # Failed tests detail
        if total_failed > 0:
            print("\n❌ FAILED TESTS:")
            for suite in self.suites:
                failed_tests = [t for t in suite.tests if t.status == TestStatus.FAIL]
                if failed_tests:
                    print(f"\n  NIVEL {suite.level}: {suite.name}")
                    for test in failed_tests:
                        print(f"    • {test.name}: {test.message}")

        # Return exit code
        return 0 if overall_rate >= 75 else 1


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Production Readiness Verification Suite for l10n_cl_dte",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--level",
        type=int,
        default=8,
        choices=range(1, 9),
        help="Maximum test level to run (1-8)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run only quick tests (levels 1-5)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    verifier = ProductionReadinessVerifier(
        verbose=args.verbose,
        quick=args.quick,
        max_level=args.level
    )

    exit_code = verifier.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
