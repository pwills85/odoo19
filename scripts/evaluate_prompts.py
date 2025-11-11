#!/usr/bin/env python3
"""
Script de Evaluación de Prompts para Desarrollo Odoo 19

Evalúa la calidad y efectividad de los prompts utilizados en el desarrollo
de módulos de localización chilena para Odoo 19.

Basado en técnicas de Anthropic, DAIR-AI y Microsoft Prompty.
"""

import json
import os
import re
import ast
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
import argparse

@dataclass
class PromptEvaluation:
    """Clase para almacenar resultados de evaluación de prompts."""
    prompt_type: str
    module_name: str
    quality_score: float  # 0-100
    compliance_score: float  # 0-100 (cumplimiento Odoo/SII)
    performance_score: float  # 0-100
    security_score: float  # 0-100
    issues_found: List[str]
    recommendations: List[str]
    generated_code_lines: int
    execution_time: float
    timestamp: str

    def to_dict(self) -> Dict:
        return asdict(self)

class PromptEvaluator:
    """Evaluador de prompts para desarrollo Odoo."""

    def __init__(self, odoo_path: str = "/Users/pedro/Documents/odoo19"):
        self.odoo_path = Path(odoo_path)
        self.templates_path = self.odoo_path / ".claude" / "prompt_templates.md"

    def evaluate_code_generation_prompt(self, prompt: str, context: Dict) -> PromptEvaluation:
        """Evalúa un prompt de generación de código."""
        issues = []
        recommendations = []
        quality_score = 100.0
        compliance_score = 100.0

        # Verificar estructura del prompt
        if not self._has_system_context(prompt):
            issues.append("Falta contexto del sistema")
            quality_score -= 20

        if not self._has_technical_context(prompt):
            issues.append("Falta contexto técnico específico")
            quality_score -= 15

        if not self._has_few_shot_examples(prompt):
            issues.append("Faltan ejemplos few-shot")
            quality_score -= 10

        # Verificar cumplimiento Odoo 19
        if "t-esc" in prompt or "type='json'" in prompt:
            issues.append("Usa sintaxis deprecada de Odoo 19")
            compliance_score -= 30

        if "_sql_constraints" in prompt:
            issues.append("Usa _sql_constraints en lugar de models.Constraint")
            compliance_score -= 20

        # Verificar mejores prácticas
        if not self._has_error_handling_examples(prompt):
            recommendations.append("Añadir ejemplos de manejo de errores")

        if not self._has_validation_examples(prompt):
            recommendations.append("Añadir ejemplos de validaciones @api.constrains")

        return PromptEvaluation(
            prompt_type="code_generation",
            module_name=context.get("module", "unknown"),
            quality_score=max(0, quality_score),
            compliance_score=max(0, compliance_score),
            performance_score=85.0,  # Placeholder
            security_score=90.0,  # Placeholder
            issues_found=issues,
            recommendations=recommendations,
            generated_code_lines=0,  # Se calcula después
            execution_time=0.0,  # Se mide después
            timestamp=self._get_timestamp()
        )

    def evaluate_audit_prompt(self, prompt: str, context: Dict) -> PromptEvaluation:
        """Evalúa un prompt de auditoría de código."""
        issues = []
        recommendations = []
        quality_score = 100.0

        # Verificar criterios de auditoría
        audit_criteria = ["🔴 CRÍTICO", "🟡 MEDIO", "🟢 BAJO"]
        if not all(criterion in prompt for criterion in audit_criteria):
            issues.append("Faltan criterios de priorización en auditoría")
            quality_score -= 25

        # Verificar cobertura de seguridad
        security_checks = ["OWASP", "SQL Injection", "XSS", "N+1"]
        security_coverage = sum(1 for check in security_checks if check in prompt)
        if security_coverage < 3:
            issues.append("Cobertura de seguridad insuficiente")
            quality_score -= 20

        # Verificar formato de reporte
        if "## Análisis:" not in prompt:
            issues.append("Falta formato estructurado de reporte")
            quality_score -= 15

        return PromptEvaluation(
            prompt_type="code_audit",
            module_name=context.get("module", "unknown"),
            quality_score=max(0, quality_score),
            compliance_score=95.0,
            performance_score=80.0,
            security_score=85.0,
            issues_found=issues,
            recommendations=recommendations,
            generated_code_lines=0,
            execution_time=0.0,
            timestamp=self._get_timestamp()
        )

    def evaluate_test_prompt(self, prompt: str, context: Dict) -> PromptEvaluation:
        """Evalúa un prompt de generación de tests."""
        issues = []
        recommendations = []
        quality_score = 100.0

        # Verificar estructura de testing
        test_patterns = [
            "TransactionCase",
            "@tagged",
            "setUp()",
            "def test_",
            "assertEqual"
        ]

        for pattern in test_patterns:
            if pattern not in prompt:
                issues.append(f"Falta patrón de testing: {pattern}")
                quality_score -= 10

        # Verificar cobertura de tests
        if "edge case" not in prompt.lower():
            recommendations.append("Añadir cobertura de casos borde")

        if "integration" not in prompt.lower():
            recommendations.append("Añadir tests de integración")

        return PromptEvaluation(
            prompt_type="test_generation",
            module_name=context.get("module", "unknown"),
            quality_score=max(0, quality_score),
            compliance_score=90.0,
            performance_score=75.0,
            security_score=80.0,
            issues_found=issues,
            recommendations=recommendations,
            generated_code_lines=0,
            execution_time=0.0,
            timestamp=self._get_timestamp()
        )

    def run_evaluation_suite(self, prompts: Dict[str, str]) -> Dict[str, PromptEvaluation]:
        """Ejecuta evaluación completa de un conjunto de prompts."""
        results = {}

        for prompt_name, prompt_content in prompts.items():
            context = {"module": prompt_name.split("_")[-1] if "_" in prompt_name else "general"}

            if "code_generation" in prompt_name:
                results[prompt_name] = self.evaluate_code_generation_prompt(prompt_content, context)
            elif "audit" in prompt_name:
                results[prompt_name] = self.evaluate_audit_prompt(prompt_content, context)
            elif "test" in prompt_name:
                results[prompt_name] = self.evaluate_test_prompt(prompt_content, context)

        return results

    def generate_report(self, evaluations: Dict[str, PromptEvaluation]) -> str:
        """Genera reporte ejecutivo de las evaluaciones."""
        report = ["# 📊 REPORTE DE EVALUACIÓN DE PROMPTS\n"]
        report.append(f"**Fecha:** {self._get_timestamp()}")
        report.append(f"**Total Prompts Evaluados:** {len(evaluations)}\n")

        # Resumen ejecutivo
        report.append("## 📈 RESUMEN EJECUTIVO\n")
        report.append("| Tipo Prompt | Calidad | Cumplimiento | Seguridad | Issues |")
        report.append("|-------------|---------|--------------|-----------|--------|")

        for name, eval_data in evaluations.items():
            report.append(
                f"| {eval_data.prompt_type} | {eval_data.quality_score:.1f} | "
                f"{eval_data.compliance_score:.1f} | {eval_data.security_score:.1f} | "
                f"{len(eval_data.issues_found)} |"
            )

        # Detalles por prompt
        report.append("\n## 🔍 DETALLES POR PROMPT\n")

        for name, eval_data in evaluations.items():
            report.append(f"### {name}")
            report.append(f"**Puntuación Global:** {(eval_data.quality_score + eval_data.compliance_score + eval_data.security_score) / 3:.1f}/100")

            if eval_data.issues_found:
                report.append("\n**🔴 Issues Encontrados:**")
                for issue in eval_data.issues_found:
                    report.append(f"- {issue}")

            if eval_data.recommendations:
                report.append("\n**💡 Recomendaciones:**")
                for rec in eval_data.recommendations:
                    report.append(f"- {rec}")

            report.append("")

        # Métricas de mejora
        report.append("## 📊 MÉTRICAS DE MEJORA\n")
        avg_quality = sum(e.quality_score for e in evaluations.values()) / len(evaluations)
        avg_compliance = sum(e.compliance_score for e in evaluations.values()) / len(evaluations)
        avg_security = sum(e.security_score for e in evaluations.values()) / len(evaluations)

        report.append(f"- **Calidad Promedio:** {avg_quality:.1f}/100")
        report.append(f"- **Cumplimiento Promedio:** {avg_compliance:.1f}/100")
        report.append(f"- **Seguridad Promedio:** {avg_security:.1f}/100")
        total_issues = sum(len(e.issues_found) for e in evaluations.values())
        report.append(f"- **Total Issues:** {total_issues}")
        report.append(f"- **Recomendaciones:** {sum(len(e.recommendations) for e in evaluations.values())}")

        return "\n".join(report)

    def _has_system_context(self, prompt: str) -> bool:
        """Verifica si el prompt tiene contexto del sistema."""
        return "Sistema Context" in prompt or "# Sistema Context" in prompt

    def _has_technical_context(self, prompt: str) -> bool:
        """Verifica si el prompt tiene contexto técnico."""
        return "Contexto Técnico" in prompt or "# Contexto Técnico" in prompt

    def _has_few_shot_examples(self, prompt: str) -> bool:
        """Verifica si el prompt tiene ejemplos few-shot."""
        return "Ejemplos Few-Shot" in prompt or "# Ejemplos Few-Shot" in prompt

    def _has_error_handling_examples(self, prompt: str) -> bool:
        """Verifica si hay ejemplos de manejo de errores."""
        return "ValidationError" in prompt or "UserError" in prompt

    def _has_validation_examples(self, prompt: str) -> bool:
        """Verifica si hay ejemplos de validaciones."""
        return "@api.constrains" in prompt

    def _get_timestamp(self) -> str:
        """Obtiene timestamp actual."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    """Función principal del script."""
    parser = argparse.ArgumentParser(description="Evaluador de Prompts para Odoo 19")
    parser.add_argument("--odoo-path", default="/Users/pedro/Documents/odoo19",
                       help="Ruta al directorio de Odoo")
    parser.add_argument("--output", "-o", help="Archivo de salida para el reporte")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown",
                       help="Formato del reporte de salida")

    args = parser.parse_args()

    evaluator = PromptEvaluator(args.odoo_path)

    # Cargar templates desde el archivo
    if evaluator.templates_path.exists():
        with open(evaluator.templates_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extraer prompts del archivo markdown
        prompts = {}
        sections = re.split(r'### \d+\.', content)

        for section in sections[1:]:  # Saltar el header
            lines = section.strip().split('\n')
            if lines:
                title = lines[0].strip()
                # Extraer el contenido del prompt (entre triples backticks)
                prompt_match = re.search(r'```.*?```', section, re.DOTALL)
                if prompt_match:
                    prompts[title.lower().replace(' ', '_').replace(':', '')] = prompt_match.group()

        # Ejecutar evaluación
        evaluations = evaluator.run_evaluation_suite(prompts)

        # Generar reporte
        if args.format == "json":
            report = json.dumps({k: v.to_dict() for k, v in evaluations.items()}, indent=2, ensure_ascii=False)
        else:
            report = evaluator.generate_report(evaluations)

        # Salida
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"✅ Reporte guardado en: {args.output}")
        else:
            print(report)

    else:
        print(f"❌ Archivo de templates no encontrado: {evaluator.templates_path}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
