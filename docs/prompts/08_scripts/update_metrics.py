#!/usr/bin/env python3
"""
update_metrics.py - Actualiza metrics_history.json con nuevos reportes auditoría

Versión: 2.0
Uso: python3 update_metrics.py <audit_report_path> <sprint_id> [audit_type]

Ejemplos:
  # Auditoría inicial
  python3 update_metrics.py docs/prompts/06_outputs/2025-11/consolidados/CONSOLIDATED_REPORT_360_2025-11-12.md 1 initial

  # Re-auditoría post-Sprint
  python3 update_metrics.py docs/prompts/06_outputs/2025-11/re_auditorias/RE_AUDIT_SPRINT_1_2025-11-19.md 2 re_audit
"""

import json
import sys
import re
from datetime import datetime
from pathlib import Path

METRICS_FILE = Path("docs/prompts/06_outputs/metrics_history.json")
DASHBOARD_FILE = Path("docs/prompts/06_outputs/METRICS_DASHBOARD.md")

def parse_consolidated_report(report_path: str) -> dict:
    """Extrae métricas de reporte consolidado markdown"""

    with open(report_path, 'r', encoding='utf-8') as f:
        content = f.read()

    metrics = {
        'scores': {},
        'findings': {},
        'effort_hours': 0,
        'compliance_p0_rate': 0,
    }

    # Extraer scores (regex patterns)
    # Score Global: **77/100**
    score_match = re.search(r'Score Global:\s*\*?\*?(\d+)/100', content)
    if score_match:
        metrics['scores']['global'] = int(score_match.group(1))

    # Compliance: 80/100
    compliance_match = re.search(r'Compliance.*?(\d+)/100', content)
    if compliance_match:
        metrics['scores']['compliance'] = int(compliance_match.group(1))

    # Backend: 78/100
    backend_match = re.search(r'Backend.*?(\d+)/100', content)
    if backend_match:
        metrics['scores']['backend'] = int(backend_match.group(1))

    # Frontend: 73/100
    frontend_match = re.search(r'Frontend.*?(\d+)/100', content)
    if frontend_match:
        metrics['scores']['frontend'] = int(frontend_match.group(1))

    # Hallazgos: P0: 25, P1: 28, P2: 20
    p0_match = re.search(r'P0:\s*(\d+)', content)
    p1_match = re.search(r'P1:\s*(\d+)', content)
    p2_match = re.search(r'P2:\s*(\d+)', content)

    if p0_match:
        metrics['findings']['p0'] = int(p0_match.group(1))
    if p1_match:
        metrics['findings']['p1'] = int(p1_match.group(1))
    if p2_match:
        metrics['findings']['p2'] = int(p2_match.group(1))

    metrics['findings']['total'] = sum(metrics['findings'].values())

    # Esfuerzo Total: 53h
    effort_match = re.search(r'Esfuerzo Total:\s*(\d+)h', content)
    if effort_match:
        metrics['effort_hours'] = int(effort_match.group(1))

    # Compliance Rate: 80.4%
    rate_match = re.search(r'Compliance.*?Rate:\s*([\d.]+)%', content)
    if rate_match:
        metrics['compliance_p0_rate'] = float(rate_match.group(1))

    return metrics

def update_metrics(audit_report_path: str, sprint_id: int, audit_type: str = 'initial'):
    """Actualiza metrics_history.json con nuevo sprint"""

    # Leer métricas actuales
    with open(METRICS_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Parsear reporte
    metrics = parse_consolidated_report(audit_report_path)

    # Crear entry nuevo sprint
    new_sprint = {
        "sprint_id": sprint_id,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "audit_type": audit_type,
        "description": f"{'Re-auditoría' if audit_type == 're_audit' else 'Auditoría'} Sprint {sprint_id}",
        "scores": metrics['scores'],
        "findings": metrics['findings'],
        "effort_hours": metrics['effort_hours'],
        "compliance_p0_rate": metrics['compliance_p0_rate'],
        "compliance_p0_deadline": "2025-03-01",
        "deadline_days_remaining": (datetime(2025, 3, 1) - datetime.now()).days,
        "risk_level": "LOW" if metrics['compliance_p0_rate'] == 100 else ("MEDIUM" if metrics['compliance_p0_rate'] > 90 else "HIGH"),
        "reports": {
            "consolidated": audit_report_path
        }
    }

    # Si es re_audit, calcular mejoras
    if audit_type == 're_audit' and len(data['sprints']) > 0:
        prev_sprint = data['sprints'][-1]

        score_delta = metrics['scores']['global'] - prev_sprint['scores']['global']
        score_percent = (score_delta / prev_sprint['scores']['global']) * 100
        findings_closed = prev_sprint['findings']['total'] - metrics['findings']['total']

        new_sprint['improvement'] = {
            "score_delta": score_delta,
            "score_percent": round(score_percent, 1),
            "findings_closed": findings_closed,
            "roi_1_month": None,  # Calcular manualmente
            "roi_1_year": None
        }

    # Agregar sprint
    data['sprints'].append(new_sprint)

    # Actualizar trends
    data['trends']['score_evolution'].append(metrics['scores']['global'])
    data['trends']['findings_evolution'].append(metrics['findings']['total'])
    data['trends']['compliance_evolution'].append(metrics['compliance_p0_rate'])

    # Actualizar summary
    data['summary']['total_sprints'] = len(data['sprints'])
    data['summary']['current_score'] = metrics['scores']['global']
    data['summary']['current_compliance'] = metrics['compliance_p0_rate']
    data['summary']['current_risk'] = new_sprint['risk_level']

    if len(data['sprints']) > 1:
        first_score = data['sprints'][0]['scores']['global']
        data['summary']['score_improvement_total'] = metrics['scores']['global'] - first_score
        data['summary']['score_improvement_percent'] = round(((metrics['scores']['global'] - first_score) / first_score) * 100, 1)

    data['last_updated'] = datetime.now().isoformat()

    # Guardar
    with open(METRICS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"✅ Métricas actualizadas: Sprint {sprint_id} ({audit_type})")
    print(f"   Score: {metrics['scores']['global']}/100")
    print(f"   Hallazgos: {metrics['findings']['total']} (P0: {metrics['findings']['p0']}, P1: {metrics['findings']['p1']}, P2: {metrics['findings']['p2']})")

    # Regenerar dashboard
    generate_dashboard_markdown(data)

def generate_dashboard_markdown(data: dict):
    """Genera METRICS_DASHBOARD.md con gráficos ASCII"""

    sprints = data['sprints']
    trends = data['trends']
    summary = data['summary']

    # Calcular gráfico ASCII scores
    scores = trends['score_evolution']
    max_score = max(scores)
    min_score = min(scores)
    scale = 10  # Altura gráfico

    lines = []
    for i in range(100, 50, -10):
        line = f"{i:3d} ┤"
        for s in scores:
            if abs(s - i) < 5:
                line += "●─────"
            else:
                line += "      "
        lines.append(line)

    chart = "\n".join(lines)
    chart += f"\n    └{'──────' * len(scores)}\n"
    chart += f"     {'   '.join([f'S{i}' for i in range(len(scores))])}"

    # Generar markdown
    md = f"""# 📊 DASHBOARD MÉTRICAS - Odoo 19 Localización Chile

**Última actualización:** {data['last_updated']}
**Sprints completados:** {summary['total_sprints']}
**Sistema versión:** {data['metrics_version']}

---

## 📈 Evolución Scores

```
{chart}
```

**Score Global:** {trends['score_evolution'][0]} → {summary['current_score']} (+{summary['score_improvement_total']} puntos, +{summary['score_improvement_percent']}%)

---

## 🎯 Compliance P0

| Sprint | Fecha | Rate | Status | Deadline |
|--------|-------|------|--------|----------|
"""

    for sprint in sprints:
        status_icon = "✅" if sprint['compliance_p0_rate'] == 100 else ("🟡" if sprint['compliance_p0_rate'] > 90 else "🔴")
        md += f"| S{sprint['sprint_id']} | {sprint['date']} | {sprint['compliance_p0_rate']}% | {status_icon} {sprint['risk_level']} | {sprint['deadline_days_remaining']} días |\n"

    md += f"""
**Status actual:** {summary['current_compliance']}% (objetivo: 100%)
**Deadline P0:** 2025-03-01

---

## 🔢 Hallazgos por Severidad

| Sprint | Fecha | P0 | P1 | P2 | Total | Δ Total |
|--------|-------|----|----|----|----|---------|
"""

    for i, sprint in enumerate(sprints):
        delta = ""
        if i > 0:
            prev_total = sprints[i-1]['findings']['total']
            delta = f"↓{prev_total - sprint['findings']['total']}" if sprint['findings']['total'] < prev_total else f"↑{sprint['findings']['total'] - prev_total}"

        md += f"| S{sprint['sprint_id']} | {sprint['date']} | {sprint['findings']['p0']} | {sprint['findings']['p1']} | {sprint['findings']['p2']} | {sprint['findings']['total']} | {delta} |\n"

    md += f"""
**Mejora total:** {sprints[0]['findings']['total']} → {sprints[-1]['findings']['total']} hallazgos ({round((1 - sprints[-1]['findings']['total']/sprints[0]['findings']['total'])*100, 1)}% reducción)

---

## 💰 ROI Validado

| Sprint | Tipo | Inversión (h) | ROI 1 mes | ROI 1 año | Status |
|--------|------|--------------|-----------|-----------|--------|
"""

    for sprint in sprints:
        if 'improvement' in sprint and sprint['improvement'].get('roi_1_month'):
            md += f"| S{sprint['sprint_id']} | {sprint['audit_type']} | {sprint['effort_hours']}h | {sprint['improvement']['roi_1_month']}% | {sprint['improvement']['roi_1_year']}% | ✅ |\n"
        else:
            md += f"| S{sprint['sprint_id']} | {sprint['audit_type']} | {sprint['effort_hours']}h | - | - | ⏳ Pendiente |\n"

    md += f"""
---

## 🏆 Top Mejoras por Sprint

"""

    for sprint in sprints:
        md += f"### Sprint {sprint['sprint_id']} ({sprint['date']})\n"
        md += f"- **Score:** {sprint['scores']['global']}/100\n"
        md += f"- **Hallazgos:** {sprint['findings']['total']} (P0: {sprint['findings']['p0']}, P1: {sprint['findings']['p1']}, P2: {sprint['findings']['p2']})\n"
        if 'improvement' in sprint:
            md += f"- **Mejora:** +{sprint['improvement']['score_delta']} puntos (+{sprint['improvement']['score_percent']}%), {sprint['improvement']['findings_closed']} hallazgos cerrados\n"
        md += "\n"

    md += f"""---

## 📂 Reportes Disponibles

"""

    for sprint in sprints:
        md += f"### Sprint {sprint['sprint_id']}\n"
        for report_type, path in sprint['reports'].items():
            md += f"- [{report_type.title()}]({path})\n"
        md += "\n"

    md += f"""---

**Generado automáticamente por:** update_metrics.py
**Versión sistema:** {data['metadata']['schema_version']}
**Template:** MEJORA_6_metrics v2.2
"""

    # Guardar dashboard
    with open(DASHBOARD_FILE, 'w', encoding='utf-8') as f:
        f.write(md)

    print(f"✅ Dashboard actualizado: {DASHBOARD_FILE}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: python3 update_metrics.py <audit_report_path> <sprint_id> [audit_type]")
        print("\nEjemplos:")
        print("  python3 update_metrics.py docs/prompts/06_outputs/2025-11/consolidados/CONSOLIDATED_REPORT_360_2025-11-12.md 1 initial")
        print("  python3 update_metrics.py docs/prompts/06_outputs/2025-11/re_auditorias/RE_AUDIT_SPRINT_1_2025-11-19.md 2 re_audit")
        sys.exit(1)

    report_path = sys.argv[1]
    sprint_id = int(sys.argv[2])
    audit_type = sys.argv[3] if len(sys.argv) > 3 else 'initial'

    update_metrics(report_path, sprint_id, audit_type)
