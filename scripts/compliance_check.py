#!/usr/bin/env python3
"""
Compliance Check Script

Captura métricas de calidad y genera una baseline JSON o un reporte comparativo.
- Lint: ruff o flake8 (si están instalados)
- Tests + cobertura: pytest + coverage (si están instalados)
- i18n: cobertura aproximada de es_CL y en_US leyendo archivos .po
- Seguridad básica: patrones de riesgo en .py (eval/exec/os.system/subprocess shell=True)

Uso:
  # Generar baseline
  python3 scripts/compliance_check.py --baseline -o .compliance/baseline_YYYYMMDD.json

  # Reporte comparando contra baseline y fallando si hay regresión
  python3 scripts/compliance_check.py --report --compare .compliance/baseline_YYYYMMDD.json --fail-on-regression
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

ROOT = Path(__file__).resolve().parents[1]


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run_cmd(cmd: List[str], timeout: int = 600) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
        return 127, "", str(e)


def collect_lint() -> Dict[str, Any]:
    # Prefer ruff, fallback to flake8
    if which("ruff"):
        rc, out, err = run_cmd(["ruff", "check", "."])
        # Count lines that look like diagnostics: path:line:col
        pattern = re.compile(r":\d+:\d+\s")
        issues = sum(1 for line in out.splitlines() if pattern.search(line))
        if rc == 0:
            issues = 0  # ruff exits 0 when clean
        return {"tool": "ruff", "ran": True, "issues": int(issues), "rc": rc}
    if which("flake8"):
        rc, out, err = run_cmd(["flake8", "."])
        issues = len([ln for ln in out.splitlines() if ln.strip()])
        if rc == 0:
            issues = 0
        return {"tool": "flake8", "ran": True, "issues": int(issues), "rc": rc}
    return {"tool": None, "ran": False, "issues": None, "rc": None}


def collect_pytest_coverage(timeout: int = 1800) -> Dict[str, Any]:
    if not which("pytest"):
        return {"ran": False, "coverage_percent": None, "rc": None}
    # Run with coverage over whole repo; adapt if slow.
    rc, out, err = run_cmd(["pytest", "--maxfail=1", "--disable-warnings", "--cov=.", "--cov-report=term"], timeout=timeout)
    coverage = None
    # Try to parse a TOTAL line like: TOTAL    123     4    96%
    m = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", out)
    if m:
        coverage = float(m.group(1))
    else:
        # Fallback: search for any XX% at line containing 'TOTAL'
        for line in out.splitlines():
            if "TOTAL" in line and "%" in line:
                pct = re.search(r"(\d+)%", line)
                if pct:
                    coverage = float(pct.group(1))
                    break
    return {"ran": True, "coverage_percent": coverage, "rc": rc}


def _parse_po_naive(po_text: str) -> Tuple[int, int]:
    """Very naive PO parser: count entries with non-empty msgstr.
    Returns (total_entries, translated_entries).
    """
    total = 0
    translated = 0
    lines = po_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("msgid "):
            # Skip header entry msgid ""
            header = line.strip() == 'msgid ""'
            # advance to msgstr
            j = i + 1
            while j < len(lines) and not lines[j].startswith("msgstr "):
                j += 1
            if j < len(lines):
                msgstr_line = lines[j].strip()
                if not header:
                    total += 1
                    # consider translated if msgstr is not empty
                    if msgstr_line != 'msgstr ""':
                        translated += 1
                i = j
        i += 1
    return total, translated


def collect_i18n_coverage(langs: List[str] = ["es_CL", "en_US"]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for lang in langs:
        total_entries = 0
        translated_entries = 0
        files = list(ROOT.glob(f"**/i18n/{lang}.po"))
        # Also support scattered po files named lang.po not under i18n
        files += [p for p in ROOT.glob(f"**/{lang}.po") if "/i18n/" not in str(p)]
        for po_path in files:
            try:
                text = po_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            t, tr = _parse_po_naive(text)
            total_entries += t
            translated_entries += tr
        coverage = None
        if total_entries > 0:
            coverage = round(100.0 * translated_entries / max(total_entries, 1), 2)
        result[lang] = {
            "files": len(files),
            "total_entries": total_entries,
            "translated_entries": translated_entries,
            "coverage_percent": coverage,
        }
    return result


SECURITY_PATTERNS = {
    "eval": re.compile(r"\beval\("),
    "exec": re.compile(r"\bexec\("),
    "os_system": re.compile(r"\bos\.system\("),
    "subprocess_shell_true": re.compile(r"subprocess\.(run|Popen)\(.*shell=True")
}


def collect_security_scan() -> Dict[str, Any]:
    counts = {k: 0 for k in SECURITY_PATTERNS}
    py_files = [p for p in ROOT.glob("**/*.py") if ".venv/" not in str(p) and "env/" not in str(p) and "node_modules/" not in str(p)]
    for path in py_files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for key, pat in SECURITY_PATTERNS.items():
            counts[key] += len(pat.findall(text))
    return counts


DEFAULT_TARGETS = {
    "lint_max": 0,
    "coverage_min": 45.0,
    "i18n_min": {"es_CL": 90.0, "en_US": 80.0},
}


def load_targets(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return DEFAULT_TARGETS
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_TARGETS


def make_baseline() -> Dict[str, Any]:
    data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "root": str(ROOT),
        "lint": collect_lint(),
        "tests": collect_pytest_coverage(),
        "i18n": collect_i18n_coverage(),
        "security": collect_security_scan(),
        "notes": [],
        "version": 1,
    }
    if not data["lint"]["ran"]:
        data["notes"].append("Lint no disponible (ruff/flake8 no instalados)")
    if not data["tests"]["ran"]:
        data["notes"].append("pytest/coverage no disponibles")
    return data


def report(current: Dict[str, Any], prev: Optional[Dict[str, Any]], targets: Dict[str, Any], fail_on_regression: bool) -> int:
    failures: List[str] = []
    # Threshold checks
    lint_issues = current.get("lint", {}).get("issues")
    if lint_issues is not None and lint_issues > targets.get("lint_max", 0):
        failures.append(f"Lint issues {lint_issues} > {targets.get('lint_max', 0)}")

    coverage = current.get("tests", {}).get("coverage_percent")
    if coverage is not None and coverage < targets.get("coverage_min", 0):
        failures.append(f"Coverage {coverage}% < {targets.get('coverage_min', 0)}%")

    for lang, min_pct in targets.get("i18n_min", {}).items():
        cov = current.get("i18n", {}).get(lang, {}).get("coverage_percent")
        if cov is not None and cov < min_pct:
            failures.append(f"i18n {lang} {cov}% < {min_pct}%")

    # Regression checks against previous baseline
    if prev and fail_on_regression:
        prev_cov = prev.get("tests", {}).get("coverage_percent")
        if coverage is not None and prev_cov is not None and coverage + 0.1 < prev_cov:
            failures.append(f"Coverage decreased: {coverage}% < {prev_cov}%")
        if lint_issues is not None:
            prev_lint = prev.get("lint", {}).get("issues")
            if isinstance(prev_lint, (int, float)) and lint_issues > prev_lint:
                failures.append(f"Lint issues increased: {lint_issues} > {prev_lint}")
        for lang in ("es_CL", "en_US"):
            cov = current.get("i18n", {}).get(lang, {}).get("coverage_percent")
            prev_l = prev.get("i18n", {}).get(lang, {}).get("coverage_percent")
            if cov is not None and prev_l is not None and cov + 0.1 < prev_l:
                failures.append(f"i18n {lang} decreased: {cov}% < {prev_l}%")

    # Print concise human-readable summary
    print("\nCompliance Report")
    print("=================")
    print(f"Lint: tool={current['lint'].get('tool')} issues={current['lint'].get('issues')}")
    print(f"Coverage: {coverage}% (ran={current['tests'].get('ran')})")
    for lang in ("es_CL", "en_US"):
        cov = current.get("i18n", {}).get(lang, {}).get("coverage_percent")
        print(f"i18n {lang}: {cov}%")
    print("Security (counts):", json.dumps(current.get("security", {}), ensure_ascii=False))

    if failures:
        print("\nFailures:")
        for f in failures:
            print(f"- {f}")
        return 2 if fail_on_regression else 0

    print("\nStatus: OK (no umbrales incumplidos ni regresiones detectadas)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Compliance check: baseline y reporte")
    parser.add_argument("--baseline", action="store_true", help="Genera baseline JSON (stdout o archivo con -o)")
    parser.add_argument("--report", action="store_true", help="Ejecuta chequeos y compara contra targets y/o baseline previa")
    parser.add_argument("-o", "--output", help="Ruta de salida JSON para baseline")
    parser.add_argument("--compare", help="Ruta a baseline JSON previa para comparar")
    parser.add_argument("--targets", help="Archivo JSON con umbrales a usar")
    parser.add_argument("--fail-on-regression", action="store_true", help="Devuelve exit code != 0 si hay regresiones vs --compare")

    args = parser.parse_args()

    if not args.baseline and not args.report:
        parser.print_help()
        return 0

    if args.baseline:
        data = make_baseline()
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Baseline escrita en {out_path}")
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        # If only baseline requested, don't proceed to report
        if not args.report:
            return 0

    targets = load_targets(args.targets)
    prev = None
    if args.compare and Path(args.compare).exists():
        try:
            prev = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"Advertencia: no se pudo leer baseline previa: {e}")

    current = make_baseline()
    return report(current, prev, targets, args.fail_on_regression)


if __name__ == "__main__":
    sys.exit(main())
