# -*- coding: utf-8 -*-
{
    'name': 'Chilean Localization - Electronic Invoicing (DTE)',
    'version': '19.0.1.0.0',
    'category': 'Accounting/Localizations',
    'summary': 'Facturación Electrónica Chilena - DTE (SII)',
    'description': """
Chilean Electronic Invoicing - DTE
===================================

Módulo de facturación electrónica para Chile según normativa del SII 
(Servicio de Impuestos Internos).

Características principales:
-----------------------------
* Generación de DTEs (Documentos Tributarios Electrónicos)
  - DTE 33: Factura Electrónica
  - DTE 61: Nota de Crédito Electrónica
  - DTE 56: Nota de Débito Electrónica
  - DTE 52: Guía de Despacho Electrónica
  - DTE 34: Liquidación de Honorarios

* Firma digital PKCS#1 con certificados digitales
* Comunicación SOAP con servidores SII
* Recepción de compras electrónicas
* Validación de RUT chileno
* Gestión de folios y certificados
* Reportes SII (Consumo de folios, Libro compra/venta)
* Gestión de retenciones IUE (DTE 34)
* Integración con microservicios (DTE Service, AI Service)
* Auditoría completa de operaciones

Integración con Odoo Base:
--------------------------
* Extiende account.move (facturas)
* Extiende purchase.order (liquidación honorarios)
* Extiende stock.picking (guías de despacho)
* Extiende account.journal (control de folios)
* Extiende res.partner (validación RUT)
* Extiende res.company (datos tributarios Chile)

Requisitos:
-----------
* Certificado digital clase 2 o 3 del SII
* Acceso a servicios web del SII
* DTE Microservice (FastAPI) en ejecución
* AI Service (opcional, para funciones avanzadas)

Autor: Eergygroup
Licencia: LGPL-3
""",
    'author': 'Eergygroup',
    'website': 'https://www.eergygroup.com',
    'license': 'LGPL-3',
    'depends': [
        'base',
        'account',
        'l10n_latam_base',              # Base LATAM: tipos de identificación
        'l10n_latam_invoice_document',  # Documentos fiscales LATAM
        'l10n_cl',                       # Localización Chile: plan contable, impuestos, RUT
        'purchase',                      # Para DTE 34 (Liquidación Honorarios)
        'stock',                         # Para DTE 52 (Guías de Despacho)
        'web',
    ],
    'external_dependencies': {
        'python': [
            'lxml',
            'requests',
            'pyOpenSSL',
            'cryptography',
            'zeep',
            'pika',  # RabbitMQ client
        ],
    },
    'data': [
        # Seguridad
        'security/ir.model.access.csv',
        'security/security_groups.xml',
        
        # Datos base
        'data/dte_document_types.xml',
        'data/sii_activity_codes.xml',
        
        # Vistas principales
        'views/menus.xml',
        'views/dte_certificate_views.xml',
        'views/account_move_dte_views.xml',
        'views/account_journal_dte_views.xml',
        'views/purchase_order_dte_views.xml',
        'views/stock_picking_dte_views.xml',
        'views/dte_communication_views.xml',
        'views/retencion_iue_views.xml',
        
        # Wizards
        'wizard/upload_certificate_views.xml',
        'wizard/send_dte_batch_views.xml',
        'wizard/generate_consumo_folios_views.xml',
        'wizard/generate_libro_views.xml',
        
        # Reportes
        'reports/dte_invoice_report.xml',
        'reports/dte_receipt_report.xml',
        
        # Configuración
        'views/res_config_settings_views.xml',
    ],
    'demo': [
        'data/demo_dte_data.xml',
    ],
    'installable': True,
    'application': False,
    'auto_install': False,
    # 'post_init_hook': 'post_init_hook',  # Removido - función no implementada
}

