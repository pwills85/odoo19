#!/usr/bin/env python3
"""
Validation Suite for Claude Code Improvements
Tests Extended Thinking, MCP Servers, and Haiku Optimization
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# ANSI colors
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

class ValidationSuite:
    def __init__(self):
        self.base_path = Path("/Users/pedro/Documents/odoo19/.claude")
        self.results = {
            "extended_thinking": {},
            "mcp_servers": {},
            "haiku_agents": {},
            "summary": {}
        }
        self.passed = 0
        self.failed = 0
        self.warnings = 0

    def print_header(self, title: str):
        """Print section header"""
        print(f"\n{BOLD}{BLUE}{'='*80}{RESET}")
        print(f"{BOLD}{BLUE}{title.center(80)}{RESET}")
        print(f"{BOLD}{BLUE}{'='*80}{RESET}\n")

    def print_test(self, name: str, status: str, details: str = ""):
        """Print test result"""
        if status == "PASS":
            symbol = f"{GREEN}✅{RESET}"
            self.passed += 1
        elif status == "WARN":
            symbol = f"{YELLOW}⚠️{RESET}"
            self.warnings += 1
        else:
            symbol = f"{RED}❌{RESET}"
            self.failed += 1

        print(f"{symbol} {name:<60} [{status}]")
        if details:
            print(f"   {details}")

    def validate_extended_thinking(self) -> Dict:
        """Validate Extended Thinking configuration"""
        self.print_header("TEST 1: EXTENDED THINKING VALIDATION")

        agents_to_check = [
            "odoo-dev-precision.md",
            "test-automation.md",
            "docker-devops.md",
            "ai-fastapi-dev.md"
        ]

        results = {}

        for agent_file in agents_to_check:
            agent_path = self.base_path / "agents" / agent_file

            if not agent_path.exists():
                self.print_test(
                    f"Agent exists: {agent_file}",
                    "FAIL",
                    f"File not found: {agent_path}"
                )
                results[agent_file] = {"exists": False, "has_extended_thinking": False}
                continue

            content = agent_path.read_text()

            # Check if file has YAML frontmatter
            if not content.startswith("---"):
                self.print_test(
                    f"Valid YAML frontmatter: {agent_file}",
                    "FAIL",
                    "No YAML frontmatter found"
                )
                results[agent_file] = {"exists": True, "has_extended_thinking": False}
                continue

            # Check for extended_thinking
            has_extended = "extended_thinking: true" in content

            if has_extended:
                self.print_test(
                    f"Extended Thinking enabled: {agent_file}",
                    "PASS",
                    "✓ extended_thinking: true found"
                )
                results[agent_file] = {"exists": True, "has_extended_thinking": True}
            else:
                self.print_test(
                    f"Extended Thinking enabled: {agent_file}",
                    "FAIL",
                    "extended_thinking: true NOT found"
                )
                results[agent_file] = {"exists": True, "has_extended_thinking": False}

        self.results["extended_thinking"] = results
        return results

    def validate_mcp_servers(self) -> Dict:
        """Validate MCP Servers configuration"""
        self.print_header("TEST 2: MCP SERVERS VALIDATION")

        mcp_path = self.base_path / "mcp.json"
        results = {}

        # Check if mcp.json exists
        if not mcp_path.exists():
            self.print_test(
                "MCP configuration file exists",
                "FAIL",
                f"File not found: {mcp_path}"
            )
            results["file_exists"] = False
            self.results["mcp_servers"] = results
            return results

        self.print_test(
            "MCP configuration file exists",
            "PASS",
            f"Found: {mcp_path}"
        )
        results["file_exists"] = True

        # Validate JSON syntax
        try:
            with open(mcp_path) as f:
                mcp_config = json.load(f)

            self.print_test(
                "Valid JSON syntax",
                "PASS",
                "JSON parsed successfully"
            )
            results["valid_json"] = True
        except json.JSONDecodeError as e:
            self.print_test(
                "Valid JSON syntax",
                "FAIL",
                f"JSON parse error: {e}"
            )
            results["valid_json"] = False
            self.results["mcp_servers"] = results
            return results

        # Check required servers
        required_servers = ["postgres", "filesystem", "git"]
        results["servers"] = {}

        if "mcpServers" not in mcp_config:
            self.print_test(
                "mcpServers key exists",
                "FAIL",
                "mcpServers not found in configuration"
            )
            results["has_mcp_servers_key"] = False
            self.results["mcp_servers"] = results
            return results

        self.print_test(
            "mcpServers key exists",
            "PASS"
        )
        results["has_mcp_servers_key"] = True

        for server_name in required_servers:
            if server_name in mcp_config["mcpServers"]:
                server_config = mcp_config["mcpServers"][server_name]

                # Validate server structure
                has_command = "command" in server_config
                has_args = "args" in server_config

                if has_command and has_args:
                    self.print_test(
                        f"MCP Server configured: {server_name}",
                        "PASS",
                        f"Command: {server_config['command']}"
                    )
                    results["servers"][server_name] = {
                        "exists": True,
                        "valid": True,
                        "command": server_config["command"]
                    }
                else:
                    self.print_test(
                        f"MCP Server configured: {server_name}",
                        "WARN",
                        "Missing 'command' or 'args' field"
                    )
                    results["servers"][server_name] = {
                        "exists": True,
                        "valid": False
                    }
            else:
                self.print_test(
                    f"MCP Server configured: {server_name}",
                    "FAIL",
                    f"Server '{server_name}' not found in configuration"
                )
                results["servers"][server_name] = {
                    "exists": False,
                    "valid": False
                }

        # Test npx availability
        try:
            subprocess.run(
                ["npx", "--version"],
                capture_output=True,
                check=True,
                timeout=5
            )
            self.print_test(
                "npx command available",
                "PASS",
                "npx is installed and accessible"
            )
            results["npx_available"] = True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            self.print_test(
                "npx command available",
                "WARN",
                "npx not found - MCP servers will not work"
            )
            results["npx_available"] = False

        self.results["mcp_servers"] = results
        return results

    def validate_haiku_agents(self) -> Dict:
        """Validate Haiku-optimized agents"""
        self.print_header("TEST 3: HAIKU AGENTS VALIDATION")

        haiku_agents = [
            "quick-status-checker.md",
            "quick-file-finder.md",
            "quick-code-validator.md"
        ]

        results = {}

        for agent_file in haiku_agents:
            agent_path = self.base_path / "agents" / agent_file

            if not agent_path.exists():
                self.print_test(
                    f"Haiku agent exists: {agent_file}",
                    "FAIL",
                    f"File not found: {agent_path}"
                )
                results[agent_file] = {"exists": False}
                continue

            content = agent_path.read_text()

            # Check for model: haiku
            has_haiku = "model: haiku" in content

            # Check for cost_category
            has_cost_category = "cost_category: low" in content

            # Check for appropriate tools
            has_tools = "tools:" in content

            # Check for max_tokens (should be lower for haiku)
            has_max_tokens = "max_tokens:" in content

            agent_valid = all([has_haiku, has_tools])

            if agent_valid:
                self.print_test(
                    f"Haiku agent configured: {agent_file}",
                    "PASS",
                    "✓ model: haiku, tools configured"
                )
                results[agent_file] = {
                    "exists": True,
                    "has_haiku": True,
                    "has_cost_category": has_cost_category,
                    "has_tools": has_tools,
                    "has_max_tokens": has_max_tokens
                }
            else:
                status = "WARN" if has_tools else "FAIL"
                self.print_test(
                    f"Haiku agent configured: {agent_file}",
                    status,
                    f"Haiku: {has_haiku}, Tools: {has_tools}"
                )
                results[agent_file] = {
                    "exists": True,
                    "has_haiku": has_haiku,
                    "has_cost_category": has_cost_category,
                    "has_tools": has_tools,
                    "has_max_tokens": has_max_tokens
                }

        self.results["haiku_agents"] = results
        return results

    def validate_documentation(self) -> Dict:
        """Validate documentation updates"""
        self.print_header("TEST 4: DOCUMENTATION VALIDATION")

        results = {}

        # Check for README or documentation about improvements
        docs_to_check = [
            "README.md",
            "AGENTS_README.md"
        ]

        for doc_file in docs_to_check:
            doc_path = self.base_path / doc_file

            if doc_path.exists():
                self.print_test(
                    f"Documentation exists: {doc_file}",
                    "PASS"
                )
                results[doc_file] = {"exists": True}
            else:
                self.print_test(
                    f"Documentation exists: {doc_file}",
                    "WARN",
                    "Consider documenting the improvements"
                )
                results[doc_file] = {"exists": False}

        return results

    def generate_summary(self):
        """Generate test summary"""
        self.print_header("VALIDATION SUMMARY")

        total_tests = self.passed + self.failed + self.warnings
        success_rate = (self.passed / total_tests * 100) if total_tests > 0 else 0

        print(f"{GREEN}✅ Passed:{RESET}   {self.passed}")
        print(f"{YELLOW}⚠️  Warnings:{RESET} {self.warnings}")
        print(f"{RED}❌ Failed:{RESET}   {self.failed}")
        print(f"\n{BOLD}Success Rate: {success_rate:.1f}%{RESET}")

        self.results["summary"] = {
            "total_tests": total_tests,
            "passed": self.passed,
            "warnings": self.warnings,
            "failed": self.failed,
            "success_rate": success_rate
        }

        # Save results to JSON
        results_path = self.base_path / "tests" / "validation_results.json"
        results_path.parent.mkdir(exist_ok=True)

        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\n{BLUE}📊 Results saved to:{RESET} {results_path}")

        # Determine exit code
        if self.failed > 0:
            print(f"\n{RED}{BOLD}❌ VALIDATION FAILED{RESET}")
            return 1
        elif self.warnings > 0:
            print(f"\n{YELLOW}{BOLD}⚠️  VALIDATION PASSED WITH WARNINGS{RESET}")
            return 0
        else:
            print(f"\n{GREEN}{BOLD}✅ ALL VALIDATIONS PASSED{RESET}")
            return 0

    def run_all_tests(self):
        """Run all validation tests"""
        print(f"{BOLD}{BLUE}")
        print("╔" + "═"*78 + "╗")
        print("║" + "CLAUDE CODE IMPROVEMENTS VALIDATION SUITE".center(78) + "║")
        print("╚" + "═"*78 + "╝")
        print(RESET)

        self.validate_extended_thinking()
        self.validate_mcp_servers()
        self.validate_haiku_agents()
        self.validate_documentation()

        return self.generate_summary()


def main():
    suite = ValidationSuite()
    exit_code = suite.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
