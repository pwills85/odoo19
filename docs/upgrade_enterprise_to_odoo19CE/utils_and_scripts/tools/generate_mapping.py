#!/usr/bin/env python3
"""
Genera un mapeo inicial de módulos Enterprise -> (Política CE/OCA/CE-Pro) con prioridad y alternativas sugeridas.

Entradas:
- reports/enterprise_catalog.json: catálogo generado por tools/scan_enterprise.py
- reports/summary_by_domain.json: dominios y conteos (tools/summarize_by_domain.py)

Salidas:
- reports/enterprise_to_ce_mapping.csv
- reports/priority_backlog.md

Notas:
- Heurísticas conservadoras, centradas en:
  * Replicar en CE-Pro: UI/Framework clave (web_enterprise, web_grid/gantt/dashboard) y reporting contable (account_reports)
  * Reemplazar con CE/OCA: funcionalidades con sustitutos maduros en OCA (assets, budget, intrastat, SEPA, barcode, quality, subscription/contract)
  * No replicar: integraciones SaaS/cloud propietarias o verticales complejas (online_sync, plaid, yodlee, taxcloud, invoice_extract, IoT/PoS específicos, carriers)
- Este archivo es un punto de partida para revisión; ajústese a la realidad del proyecto y país.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS_DIR = os.path.join(WORKSPACE_ROOT, "reports")
CATALOG_JSON = os.path.join(REPORTS_DIR, "enterprise_catalog.json")
SUMMARY_JSON = os.path.join(REPORTS_DIR, "summary_by_domain.json")
OUTPUT_CSV = os.path.join(REPORTS_DIR, "enterprise_to_ce_mapping.csv")
OUTPUT_BACKLOG = os.path.join(REPORTS_DIR, "priority_backlog.md")


@dataclass
class Mapping:
    module: str
    domain: str
    depends: str
    policy: str  # REPLICATE_CE_PRO | REPLACE_CE_OCA | NO_REPLICATE
    priority: str  # P1 | P2 | P3
    alternative: str
    rationale: str


def load_inputs() -> Tuple[List[dict], Dict[str, str]]:
    with open(CATALOG_JSON, "r", encoding="utf-8") as f:
        catalog = json.load(f)
    with open(SUMMARY_JSON, "r", encoding="utf-8") as f:
        summary = json.load(f)
    # Construye mapa módulo -> dominio
    module_to_domain: Dict[str, str] = {}
    for domain, modules in summary.get("domains", {}).items():
        for m in modules:
            module_to_domain[m] = domain
    return catalog, module_to_domain


def in_any(name: str, needles: List[str]) -> bool:
    return any(n in name for n in needles)


def map_module(mod: dict, module_to_domain: Dict[str, str]) -> Mapping:
    mname = mod.get("module") or ""
    depends = (mod.get("depends") or "").strip()
    domain = module_to_domain.get(mname, "other")

    policy = "NO_REPLICATE"
    priority = "P3"
    alt = ""
    why = "Heurística por dominio/funcionalidad."

    # Atajos por nombre
    if mname in {"web_enterprise"}:
        return Mapping(mname, domain, depends, "REPLICATE_CE_PRO", "P1", "Phoenix: web_enterprise_theme_ce", "UI backend moderno en CE 19 (OWL/SCSS). Alto impacto.")
    if mname in {"account_reports"}:
        return Mapping(mname, domain, depends, "REPLICATE_CE_PRO", "P1", "Quantum: financial_reports_dynamic", "Motor de reportes contables dinámicos con drilldown.")

    # UI/Framework
    if domain == "ui_framework":
        if mname in {"web_grid", "web_gantt", "web_dashboard", "web_cohort"}:
            policy, priority, alt, why = (
                "REPLICATE_CE_PRO",
                "P2",
                "Phoenix: vistas grid/gantt/dashboard CE",
                "Vistas avanzadas reutilizables en CE 19 (OWL).",
            )
        elif mname in {"web_studio", "website_studio", "web_mobile"}:
            policy, priority, alt, why = (
                "NO_REPLICATE",
                "P3",
                "",
                "Builders/Studio propietarios o móviles con bajo ROI.",
            )
        elif mname.startswith("website_"):
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Funcionalidad website enterprise; deferir.")
        else:
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", why)

    # Accounting
    elif domain == "accounting":
        if mname in {"account_asset", "account_budget", "account_intrastat", "account_batch_payment", "account_sepa", "account_sepa_direct_debit"}:
            alt_map = {
                "account_asset": "OCA/account-financial-tools: account_asset*",
                "account_budget": "OCA/account-budgeting",
                "account_intrastat": "OCA/intrastat",
                "account_batch_payment": "OCA/account-payment",
                "account_sepa": "OCA/account-payment: SEPA",
                "account_sepa_direct_debit": "OCA/account-payment: SEPA DD",
            }
            policy, priority, alt, why = (
                "REPLACE_CE_OCA",
                "P2",
                alt_map[mname],
                "Sustitutos maduros en OCA.",
            )
        elif mname in {"account_online_sync", "account_plaid", "account_yodlee", "account_taxcloud", "account_invoice_extract", "account_predictive_bills"}:
            policy, priority, alt, why = (
                "NO_REPLICATE",
                "P3",
                "",
                "Dependencias SaaS/IA propietarias o servicios cerrados.",
            )
        elif mname == "currency_rate_live":
            policy, priority, alt, why = (
                "REPLACE_CE_OCA",
                "P2",
                "OCA/currency: currency_rate_update",
                "Actualización de tasas con fuentes libres.",
            )
        elif mname == "account_reports_followup":
            policy, priority, alt, why = (
                "REPLACE_CE_OCA",
                "P2",
                "OCA/credit-control",
                "Seguimiento de cobros con OCA.",
            )
        elif mname.startswith("l10n_"):
            policy, priority, alt, why = (
                "NO_REPLICATE",
                "P3",
                "Usar localizaciones OCA/país en CE",
                "Reportes y EDI locales enterprise; fuera de alcance.",
            )
        elif mname == "account_accountant":
            policy, priority, alt, why = (
                "REPLACE_CE_OCA",
                "P2",
                "OCA/account-financial-tools",
                "Metapaquete de utilidades contables.",
            )
        elif mname == "account_3way_match":
            policy, priority, alt, why = (
                "REPLACE_CE_OCA",
                "P3",
                "OCA/purchase-workflow (triple validación/controls)",
                "Controles de compras equivalentes en OCA.",
            )
        else:
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/account-*", "Sustituible en OCA/CE.")

    # Inventario/MRP
    elif domain == "inventory_mrp":
        if mname in {"stock_barcode", "stock_barcode_mobile", "delivery_barcode"}:
            policy, priority, alt, why = (
                "REPLACE_CE_OCA",
                "P2",
                "OCA/stock-logistics-barcode",
                "Lectura de códigos de barras comunitaria.",
            )
        elif mname.startswith("delivery_"):
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Carriers específicos de pago; deferir.")
        elif mname in {"quality", "quality_control", "quality_mrp", "quality_mrp_workorder", "quality_iot", "quality_mrp_iot"}:
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/quality", "Calidad en OCA.")
        elif mname in {"mrp_plm", "mrp_workorder", "mrp_mps"}:
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Vertical MRP avanzada enterprise; deferir.")
        else:
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/stock-*", "Equivalentes OCA/CE.")

    # Documentos/Colaboración
    elif domain == "documents_collab":
        if mname == "documents":
            policy, priority, alt, why = (
                "REPLACE_CE_OCA",
                "P3",
                "OCA/dms; document_attachment_manage (este repo)",
                "DMS comunitario básico en lugar de Enterprise Documents.",
            )
        elif in_any(mname, ["documents_", "sign"]):
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Firma y automatismos enterprise; deferir.")
        else:
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", why)

    # Proyectos/Helpdesk
    elif domain == "projects_helpdesk":
        if mname.startswith("helpdesk"):
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/helpdesk", "Helpdesk comunitario.")
        elif mname in {"timesheet_grid", "timesheet_grid_sale"}:
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/timesheet", "Grid/Reportes con OCA.")
        else:
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Extras enterprise; baja prioridad.")

    # Ventas/PoS
    elif domain == "sales_pos":
        if mname.startswith("pos_"):
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "PoS enterprise/IoT; deferir.")
        elif mname.startswith("sale_subscription"):
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P2", "OCA/contract", "Contratos y facturación recurrente en OCA.")
        elif mname in {"sale_coupon", "sale_coupon_delivery"}:
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/sale-workflow (coupons/discounts)", "Promos mediante OCA.")
        elif mname == "sale_ebay":
            policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Conector vertical/externo; deferir.")
        else:
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/sale-*", "Equivalentes OCA/CE.")

    # Marketing
    elif domain == "marketing":
        policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Automatización marketing enterprise; deferir.")

    # IoT / Localizaciones / Otros
    elif domain in {"iot", "localizations"}:
        policy, priority, alt, why = ("NO_REPLICATE", "P3", "", "Fuera de alcance CE-Pro núcleo.")
    else:
        # other: casos junto a OCA
        if mname == "analytic_enterprise":
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P2", "OCA/account-analytic", "Analítica en OCA.")
        elif mname == "inter_company_rules":
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/multi-company", "Reglas intercompañía en OCA.")
        else:
            policy, priority, alt, why = ("REPLACE_CE_OCA", "P3", "OCA/*", "Sustituible por familia OCA.")

    return Mapping(mname, domain, depends, policy, priority, alt, why)


def generate_mapping_rows(catalog: List[dict], module_to_domain: Dict[str, str]) -> List[Mapping]:
    rows: List[Mapping] = []
    for mod in catalog:
        rows.append(map_module(mod, module_to_domain))
    return rows


def write_csv(rows: List[Mapping]) -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    headers = [
        "module",
        "domain",
        "depends",
        "policy",
        "priority",
        "ce_oca_alternative",
        "rationale",
    ]
    with open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            w.writerow([r.module, r.domain, r.depends, r.policy, r.priority, r.alternative, r.rationale])


def write_backlog(rows: List[Mapping]) -> None:
    by_p: Dict[str, List[Mapping]] = {"P1": [], "P2": [], "P3": []}
    for r in rows:
        by_p.setdefault(r.priority, []).append(r)

    lines: List[str] = []
    lines.append("# Priority Backlog (heurístico)\n")
    lines.append("\n")
    for p in ["P1", "P2", "P3"]:
        items = sorted(by_p.get(p, []), key=lambda x: (x.policy, x.domain, x.module))
        lines.append(f"## {p}\n\n")
        for it in items:
            alt = f" — Alt: {it.alternative}" if it.alternative else ""
            lines.append(f"- [{it.policy}] `{it.module}` ({it.domain}){alt} — {it.rationale}\n")
        lines.append("\n")

    with open(OUTPUT_BACKLOG, "w", encoding="utf-8") as f:
        f.write("".join(lines))


def main() -> None:
    catalog, module_to_domain = load_inputs()
    rows = generate_mapping_rows(catalog, module_to_domain)
    write_csv(rows)
    write_backlog(rows)
    print(f"OK: mapping generado -> {os.path.relpath(OUTPUT_CSV, WORKSPACE_ROOT)}, {os.path.relpath(OUTPUT_BACKLOG, WORKSPACE_ROOT)}")


if __name__ == "__main__":
    main()
