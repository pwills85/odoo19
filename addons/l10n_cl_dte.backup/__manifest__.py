# -*- coding: utf-8 -*-
{
    'name': 'Chilean Electronic Invoicing (DTE) - RabbitMQ Integration',
    'version': '19.0.1.0.0',
    'category': 'Accounting/Localizations',
    'summary': 'DTE con integración asíncrona RabbitMQ',
    'description': """
Chilean Electronic Invoicing with RabbitMQ
===========================================
* Integración asíncrona con DTE Service vía RabbitMQ
* Procesamiento en background de DTEs
* Retry automático y Dead Letter Queues
* Webhook para notificaciones
    """,
    'author': 'Eergygroup',
    'website': 'https://eergygroup.com',
    'depends': [
        'account',
        'l10n_cl',
        'l10n_latam_invoice_document',
    ],
    'external_dependencies': {
        'python': ['pika'],
    },
    'data': [
        # 'security/ir.model.access.csv',
        # 'views/account_move_dte_views.xml',
    ],
    'installable': True,
    'application': False,
    'auto_install': False,
    'license': 'LGPL-3',
}
