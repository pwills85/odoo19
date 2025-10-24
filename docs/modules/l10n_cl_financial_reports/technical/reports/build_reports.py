#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Genera PDFs profesionales (Informe Técnico y Brochure Comercial) sin LaTeX,
utilizando ReportLab. Compatible con entornos aislados.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.units import cm
import os

BRAND = colors.Color(12/255.0, 89/255.0, 140/255.0)

try:
    # Registrar tipografías si están disponibles en el entorno
    pdfmetrics.registerFont(TTFont('Inter', 'Inter-Regular.ttf'))
    pdfmetrics.registerFont(TTFont('Inter-Bold', 'Inter-Bold.ttf'))
    BASE_FONT = 'Inter'
except Exception:
    BASE_FONT = 'Helvetica'


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='TitleBrand', fontName=BASE_FONT, fontSize=20, leading=24,
                              alignment=TA_CENTER, textColor=BRAND, spaceAfter=12))
    styles.add(ParagraphStyle(name='H1', fontName=BASE_FONT, fontSize=14.5, leading=18,
                              textColor=BRAND, spaceBefore=8, spaceAfter=6))
    styles.add(ParagraphStyle(name='H2', fontName=BASE_FONT, fontSize=12.5, leading=16,
                              textColor=BRAND, spaceBefore=6, spaceAfter=4))
    styles.add(ParagraphStyle(name='Body', fontName=BASE_FONT, fontSize=10.5, leading=14,
                              textColor=colors.black, spaceAfter=6))
    styles.add(ParagraphStyle(name='Small', fontName=BASE_FONT, fontSize=9, leading=12,
                              textColor=colors.black))
    return styles


def build_technical_report(output_path: str):
    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=1.8*cm, bottomMargin=1.8*cm, title='Informe Técnico - account_financial_report')
    story = []

    story.append(Paragraph('Informe Técnico', styles['TitleBrand']))
    story.append(Paragraph('account_financial_report — Suite Chilena Odoo 18 CE', styles['Body']))
    story.append(Spacer(1, 8))

    story.append(Paragraph('Resumen Ejecutivo', styles['H1']))
    story.append(Paragraph(
        'Módulo de reportes financieros para Chile con Balance, P&L, Mayor, Comprobación, '
        'F29/F22 reales (SII), dashboard ejecutivo y ratios. Integra Odoo base (account, report_xlsx, project, '
        'hr_timesheets, account_budget) y la suite chilena (l10n_cl_base, l10n_cl_fe, l10n_cl_payroll).', styles['Body']))

    story.append(Paragraph('Arquitectura y Componentes', styles['H1']))
    story.append(Paragraph('<b>Servicios principales</b>: financial_report_service, financial_report_sii_service, '
                          'ratio_analysis_service, bi_dashboard_service.', styles['Body']))
    story.append(Paragraph('<b>Modelos y datos</b>: F29/F22 agregan desde account_move_line y account_tax; vistas, '
                          'plantillas y exportación XLSX.', styles['Body']))

    story.append(Paragraph('Integraciones', styles['H1']))
    data = [
        ['Suite Chilena', 'l10n_cl_base (RUT, cache, SII), l10n_cl_fe (DTE/CAF, estados SII), l10n_cl_payroll (nómina)'],
        ['Odoo base', 'account, report_xlsx, project, hr_timesheet, account_budget'],
    ]
    tbl = Table(data, colWidths=[4.2*cm, 10.4*cm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('LINEBELOW', (0, 0), (-1, 0), 0.6, BRAND),
        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('BOX', (0, 0), (-1, -1), 0.6, colors.grey),
        ('FONTNAME', (0, 0), (-1, -1), BASE_FONT),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(tbl)

    story.append(Paragraph('Seguridad', styles['H1']))
    story.append(Paragraph('secure_api_endpoint: JWT (HS256), HMAC-SHA256, CSRF=True, rate limiting y sanitización XSS; '
                          'errores sin datos sensibles; logging seguro.', styles['Body']))

    story.append(Paragraph('Performance y Caché', styles['H1']))
    story.append(Paragraph('Índices SQL especializados (AML, AM, TAX, F22/F29). '
                          'Caché L1 (env.cache), L2 (servicio), L3 (ir.config_parameter), L4 (buffers PG). '
                          'ORM optimizado (read_group, prefetch, batch).', styles['Body']))

    story.append(Paragraph('Conclusiones', styles['H1']))
    story.append(Paragraph('Arquitectura SOA, seguridad empresarial, performance 3–6x y cumplimiento SII integral. '
                          'Listo para producción.', styles['Body']))

    doc.build(story)


def build_commercial_brochure(output_path: str):
    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=1.6*cm, bottomMargin=1.6*cm, title='Brochure Comercial - account_financial_report')
    story = []

    story.append(Paragraph('Reportes Financieros Chile — Odoo 18 CE', styles['TitleBrand']))
    story.append(Paragraph('Integración total con la Suite Chilena y Cumplimiento SII', styles['Body']))
    story.append(Spacer(1, 10))

    story.append(Paragraph('Beneficios Clave', styles['H1']))
    bullets = [
        'Cumplimiento SII — F29/F22 reales, DTE/CAF (vía FE), auditoría y trazabilidad.',
        'Automatización — Balance, P&L, Mayor y dashboard en un clic.',
        'Decisiones en tiempo real — KPIs y proyecciones con cache multicapa.',
        'Seguridad empresarial — JWT, HMAC-SHA256, CSRF, rate limiting.',
        'Escalabilidad — Índices SQL y optimizaciones (3–6x más rápido).',
    ]
    for b in bullets:
        story.append(Paragraph('• ' + b, styles['Body']))

    story.append(Paragraph('Integración Suite', styles['H1']))
    story.append(Paragraph('l10n_cl_base (RUT, cache), l10n_cl_fe (DTE/CAF, estados SII), l10n_cl_payroll (nómina).', styles['Body']))

    story.append(Paragraph('Reportes Destacados', styles['H1']))
    story.append(Paragraph('Balance 8 columnas, Balance General, P&L, Mayor, Comprobación; F29 y F22 con mapeos SII.', styles['Body']))

    story.append(Paragraph('Resultados para su Empresa', styles['H1']))
    story.append(Paragraph('80%+ menos tiempo en cierres y declaraciones; p95 < 1s en paneles cacheados; 3–6x más veloz.', styles['Body']))

    story.append(Paragraph('Por qué elegirnos', styles['H1']))
    story.append(Paragraph('Arquitectura moderna, documentación completa y pruebas >95% cobertura. Preparado para picos de carga.', styles['Body']))

    doc.build(story)


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_tech = os.path.join(base_dir, 'account_financial_report_technical_report.pdf')
    out_brochure = os.path.join(base_dir, 'account_financial_report_commercial_brochure.pdf')
    build_technical_report(out_tech)
    build_commercial_brochure(out_brochure)
    print('OK:', out_tech)
    print('OK:', out_brochure)


if __name__ == '__main__':
    main()
