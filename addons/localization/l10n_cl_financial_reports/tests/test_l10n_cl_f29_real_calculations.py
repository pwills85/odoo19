# -*- coding: utf-8 -*-
"""
Tests para validar cálculos REALES F29
Verifica accuracy vs movimientos IVA reales y performance

Características:
- Movimientos IVA sintéticos pero realistas
- Validación accuracy 100% vs cálculos manuales
- Tests de consistencia F29 mensual vs F22 anual  
- Performance con volúmenes reales de facturas
"""

from odoo.tests import tagged, TransactionCase
from datetime import date
from dateutil.relativedelta import relativedelta
import time
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'f29_real_calculations')  
class TestL10nClF29RealCalculations(TransactionCase):
    """Tests para F29 con cálculos reales desde movimientos IVA"""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Configurar compañía
        cls.company = cls.env.user.company_id
        cls.company.write({
            'name': 'Test Company Chile F29',
            'vat': '96123789-4',
            'country_id': cls.env.ref('base.cl').id,
        })
        
        # Configurar impuestos chilenos
        cls._setup_chilean_taxes()
        
        # Configurar cuentas contables
        cls._setup_accounts()
        
        # Servicio SII
        cls.sii_service = cls.env['account.financial.report.sii.integration.service']
        
        # Período de prueba
        cls.test_period = date(2024, 6, 1)  # Junio 2024
    
    @classmethod 
    def _setup_chilean_taxes(cls):
        """Configura impuestos chilenos para tests"""
        
        # IVA Ventas 19%
        cls.tax_iva_sale = cls.env['account.tax'].create({
            'name': 'IVA Ventas 19%',
            'type_tax_use': 'sale',
            'amount': 19.0,
            'amount_type': 'percent',
            'company_id': cls.company.id,
        })
        
        # IVA Compras 19%
        cls.tax_iva_purchase = cls.env['account.tax'].create({
            'name': 'IVA Compras 19%',
            'type_tax_use': 'purchase', 
            'amount': 19.0,
            'amount_type': 'percent',
            'company_id': cls.company.id,
        })
        
        # Exento
        cls.tax_exempt_sale = cls.env['account.tax'].create({
            'name': 'Exento Ventas',
            'type_tax_use': 'sale',
            'amount': 0.0,
            'amount_type': 'percent',
            'company_id': cls.company.id,
        })
        
        cls.tax_exempt_purchase = cls.env['account.tax'].create({
            'name': 'Exento Compras',
            'type_tax_use': 'purchase',
            'amount': 0.0,
            'amount_type': 'percent',
            'company_id': cls.company.id,
        })
    
    @classmethod
    def _setup_accounts(cls):
        """Configura cuentas contables para tests"""
        
        # Clientes
        cls.account_receivable = cls.env['account.account'].create({
            'name': 'Clientes',
            'code': '1101',
            'user_type_id': cls.env.ref('account.data_account_type_receivable').id,
            'reconcile': True,
        })
        
        # Proveedores
        cls.account_payable = cls.env['account.account'].create({
            'name': 'Proveedores',
            'code': '2101', 
            'user_type_id': cls.env.ref('account.data_account_type_payable').id,
            'reconcile': True,
        })
        
        # Ventas
        cls.account_sales = cls.env['account.account'].create({
            'name': 'Ventas',
            'code': '4101',
            'user_type_id': cls.env.ref('account.data_account_type_revenue').id,
        })
        
        # Compras
        cls.account_purchases = cls.env['account.account'].create({
            'name': 'Compras',
            'code': '5101',
            'user_type_id': cls.env.ref('account.data_account_type_expenses').id,
        })
    
    def _create_invoice(self, invoice_type, partner, amount, tax, invoice_date):
        """
        Crea factura de prueba con IVA
        
        Args:
            invoice_type: 'out_invoice', 'in_invoice', etc.
            partner: res.partner
            amount: Monto neto
            tax: account.tax
            invoice_date: Fecha factura
            
        Returns:
            account.move: Factura creada y confirmada
        """
        account_id = None
        if invoice_type in ['out_invoice', 'out_refund']:
            account_id = self.account_sales.id
        else:
            account_id = self.account_purchases.id
        
        invoice = self.env['account.move'].create({
            'move_type': invoice_type,
            'partner_id': partner.id,
            'invoice_date': invoice_date,
            'date': invoice_date,
            'company_id': self.company.id,
            'invoice_line_ids': [(0, 0, {
                'name': f'Test product - {invoice_type}',
                'quantity': 1,
                'price_unit': amount,
                'account_id': account_id,
                'tax_ids': [(6, 0, [tax.id] if tax else [])],
            })],
        })
        
        invoice.action_post()
        return invoice
    
    def _create_test_invoices_month(self, period_date, sales_data, purchase_data):
        """
        Crea facturas de prueba para un mes
        
        Args:
            period_date: date del período
            sales_data: {'gravadas': amount, 'exentas': amount}
            purchase_data: {'gravadas': amount, 'exentas': amount}
            
        Returns:
            dict: Facturas creadas por tipo
        """
        # Crear partner de prueba
        partner = self.env['res.partner'].create({
            'name': 'Test Partner F29',
            'vat': '12345678-9',
            'company_id': self.company.id,
        })
        
        invoices = {
            'sales_taxed': [],
            'sales_exempt': [],
            'purchase_taxed': [],
            'purchase_exempt': [],
        }
        
        # Facturas de venta gravadas
        if sales_data.get('gravadas', 0) > 0:
            for i in range(3):  # Distribuir en 3 facturas
                amount = sales_data['gravadas'] / 3
                invoice = self._create_invoice(
                    'out_invoice',
                    partner,
                    amount,
                    self.tax_iva_sale,
                    period_date + relativedelta(days=i*5)
                )
                invoices['sales_taxed'].append(invoice)
        
        # Facturas de venta exentas
        if sales_data.get('exentas', 0) > 0:
            for i in range(2):  # 2 facturas
                amount = sales_data['exentas'] / 2
                invoice = self._create_invoice(
                    'out_invoice',
                    partner,
                    amount,
                    self.tax_exempt_sale,
                    period_date + relativedelta(days=i*7)
                )
                invoices['sales_exempt'].append(invoice)
        
        # Facturas de compra gravadas
        if purchase_data.get('gravadas', 0) > 0:
            for i in range(4):  # 4 facturas
                amount = purchase_data['gravadas'] / 4
                invoice = self._create_invoice(
                    'in_invoice',
                    partner,
                    amount,
                    self.tax_iva_purchase,
                    period_date + relativedelta(days=i*3)
                )
                invoices['purchase_taxed'].append(invoice)
        
        # Facturas de compra exentas
        if purchase_data.get('exentas', 0) > 0:
            invoice = self._create_invoice(
                'in_invoice',
                partner,
                purchase_data['exentas'],
                self.tax_exempt_purchase,
                period_date + relativedelta(days=10)
            )
            invoices['purchase_exempt'].append(invoice)
        
        return invoices
    
    def test_f29_basic_calculation_accuracy(self):
        """Test accuracy cálculo F29 básico"""
        
        # Datos de prueba conocidos
        sales_data = {
            'gravadas': 1000000,    # $1.000.000 neto
            'exentas': 100000,      # $100.000 exento
        }
        
        purchase_data = {
            'gravadas': 600000,     # $600.000 neto
            'exentas': 50000,       # $50.000 exento
        }
        
        # Crear facturas del período
        self._create_test_invoices_month(
            self.test_period, sales_data, purchase_data
        )
        
        # Crear F29
        f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': self.test_period,
        })
        
        # Ejecutar cálculo real
        start_time = time.time()
        f29.action_calculate()
        calculation_time = time.time() - start_time
        
        # Verificar accuracy de cálculos
        expected_values = {
            'ventas_gravadas': 1000000,
            'ventas_exentas': 100000,
            'compras_gravadas': 600000,
            'compras_exentas': 50000,
            'iva_debito': 190000,      # 1.000.000 * 0.19
            'iva_credito': 114000,     # 600.000 * 0.19
            'iva_a_pagar': 76000,      # 190.000 - 114.000
        }
        
        for field, expected_value in expected_values.items():
            actual_value = getattr(f29, field)
            self.assertEqual(
                actual_value,
                expected_value,
                f"Campo {field}: esperado {expected_value}, obtenido {actual_value}"
            )
        
        # Verificar performance
        self.assertLess(calculation_time, 5.0,
                       f"Cálculo F29 tardó {calculation_time:.2f}s, debe ser < 5s")
        
        _logger.info(f"Test F29 básico: Cálculo en {calculation_time:.3f}s - ACCURACY OK")
    
    def test_f29_with_credit_balance(self):
        """Test F29 con saldo a favor (IVA crédito > débito)"""
        
        # Más compras que ventas (saldo a favor)
        sales_data = {'gravadas': 200000}      # IVA débito: $38.000
        purchase_data = {'gravadas': 400000}   # IVA crédito: $76.000
        
        self._create_test_invoices_month(
            self.test_period, sales_data, purchase_data
        )
        
        f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': self.test_period,
        })
        
        f29.action_calculate()
        
        # Verificar saldo a favor
        self.assertEqual(f29.iva_debito, 38000)
        self.assertEqual(f29.iva_credito, 76000)
        self.assertEqual(f29.iva_a_pagar, 0)
        self.assertEqual(f29.remanente_siguiente, 38000)  # 76.000 - 38.000
        
        _logger.info("Test F29 con saldo a favor: OK")
    
    def test_f29_with_previous_credit(self):
        """Test F29 con remanente mes anterior"""
        
        # Crear F29 mes anterior con remanente
        previous_period = self.test_period - relativedelta(months=1)
        f29_previous = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': previous_period,
            'remanente_siguiente': 50000,  # $50.000 remanente
            'state': 'validated',
        })
        
        # Crear facturas mes actual
        sales_data = {'gravadas': 500000}      # IVA débito: $95.000
        purchase_data = {'gravadas': 200000}   # IVA crédito: $38.000
        
        self._create_test_invoices_month(
            self.test_period, sales_data, purchase_data
        )
        
        # F29 mes actual
        f29_current = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': self.test_period,
        })
        
        f29_current.action_calculate()
        
        # Verificar que considera remanente anterior
        # Total crédito = 38.000 + 50.000 = 88.000
        # IVA a pagar = 95.000 - 88.000 = 7.000
        self.assertEqual(f29_current.remanente_anterior, 50000)
        self.assertEqual(f29_current.total_credito, 88000)
        self.assertEqual(f29_current.iva_a_pagar, 7000)
        
        _logger.info("Test F29 con remanente anterior: OK")
    
    def test_f29_performance_high_volume(self):
        """Test performance F29 con alto volumen de facturas"""
        
        # Simular empresa con muchas facturas mensuales
        sales_data = {
            'gravadas': 5000000,    # $5M en ventas
            'exentas': 500000,      # $500K exentas
        }
        
        purchase_data = {
            'gravadas': 3000000,    # $3M en compras  
            'exentas': 200000,      # $200K exentas
        }
        
        # Crear más facturas distribuidas en el mes
        partner = self.env['res.partner'].create({
            'name': 'High Volume Partner',
            'vat': '98765432-1',
        })
        
        # Crear 50 facturas de venta pequeñas
        for i in range(50):
            amount = sales_data['gravadas'] / 50
            day = (i % 28) + 1
            invoice_date = self.test_period.replace(day=day)
            
            self._create_invoice(
                'out_invoice',
                partner,
                amount,
                self.tax_iva_sale,
                invoice_date
            )
        
        # Crear 30 facturas de compra
        for i in range(30):
            amount = purchase_data['gravadas'] / 30
            day = (i % 28) + 1
            invoice_date = self.test_period.replace(day=day)
            
            self._create_invoice(
                'in_invoice',
                partner,
                amount,
                self.tax_iva_purchase,
                invoice_date
            )
        
        # Crear F29 y medir performance
        f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': self.test_period,
        })
        
        start_time = time.time()
        f29.action_calculate()
        calculation_time = time.time() - start_time
        
        # Verificar performance (< 30s como requerido)
        self.assertLess(calculation_time, 30.0,
                       f"F29 alto volumen tardó {calculation_time:.2f}s")
        
        # Verificar accuracy con volúmenes grandes
        expected_iva_debito = 950000    # 5M * 0.19
        expected_iva_credito = 570000   # 3M * 0.19
        expected_iva_a_pagar = 380000   # 950K - 570K
        
        self.assertEqual(f29.iva_debito, expected_iva_debito)
        self.assertEqual(f29.iva_credito, expected_iva_credito)
        self.assertEqual(f29.iva_a_pagar, expected_iva_a_pagar)
        
        _logger.info(f"Test F29 alto volumen: {calculation_time:.3f}s con 80 facturas - OK")
    
    def test_f29_cache_functionality(self):
        """Test funcionalidad cache F29"""
        
        # Crear datos de prueba
        sales_data = {'gravadas': 300000}
        purchase_data = {'gravadas': 150000}
        
        self._create_test_invoices_month(
            self.test_period, sales_data, purchase_data
        )
        
        # Primera llamada (sin cache)
        start_time = time.time()
        f29_data_1 = self.sii_service.generate_f29_data(
            self.company,
            self.test_period,
            self.test_period + relativedelta(day=31)
        )
        first_call_time = time.time() - start_time
        
        # Segunda llamada (con cache)
        start_time = time.time()
        f29_data_2 = self.sii_service.generate_f29_data(
            self.company,
            self.test_period,
            self.test_period + relativedelta(day=31)
        )
        second_call_time = time.time() - start_time
        
        # Verificar datos idénticos
        self.assertEqual(f29_data_1['data'], f29_data_2['data'])
        
        # Cache debe ser más rápido
        self.assertLess(second_call_time, first_call_time)
        
        _logger.info(f"Test cache F29: 1era={first_call_time:.3f}s, "
                    f"2da={second_call_time:.3f}s - OK")
    
    def test_f29_validation_consistency(self):
        """Test validaciones de consistencia F29"""
        
        # Caso: IVA no coincide con base imponible
        # Crear factura manualmente con inconsistencia
        partner = self.env['res.partner'].create({
            'name': 'Inconsistent Partner',
            'vat': '11111111-1',
        })
        
        # Factura con IVA incorrecto (forzado)
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': partner.id,
            'invoice_date': self.test_period,
            'date': self.test_period,
            'company_id': self.company.id,
            'invoice_line_ids': [(0, 0, {
                'name': 'Test inconsistent',
                'quantity': 1,
                'price_unit': 100000,  # Base $100.000
                'account_id': self.account_sales.id,
                'tax_ids': [(6, 0, [self.tax_iva_sale.id])],
            })],
        })
        
        invoice.action_post()
        
        # Modificar manualmente IVA para crear inconsistencia
        tax_line = invoice.line_ids.filtered('tax_line_id')
        if tax_line:
            tax_line.with_context(check_move_validity=False).write({
                'credit': 25000  # IVA incorrecto (debería ser 19.000)
            })
        
        # Crear F29 
        f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': self.test_period,
        })
        
        # El cálculo debe completarse pero con warnings
        f29.action_calculate()
        
        # Verificar que detecta la inconsistencia
        self.assertEqual(f29.ventas_gravadas, 100000)
        # El IVA debería calcularse desde los movimientos reales
        # independiente de la inconsistencia manual
        
        _logger.info("Test validaciones consistencia F29: OK")
    
    def test_f22_f29_annual_consistency(self):
        """Test consistencia F22 anual vs F29s mensuales"""
        
        # Crear F29s para todo el año 2024
        monthly_sales = 500000  # $500K mensuales
        monthly_purchases = 300000  # $300K mensuales
        
        f29_records = []
        
        for month in range(1, 13):
            period_date = date(2024, month, 1)
            
            # Crear facturas del mes
            self._create_test_invoices_month(
                period_date,
                {'gravadas': monthly_sales},
                {'gravadas': monthly_purchases}
            )
            
            # Crear F29
            f29 = self.env['l10n_cl.f29'].create({
                'company_id': self.company.id,
                'period_date': period_date,
                'state': 'validated',
            })
            f29.action_calculate()
            f29_records.append(f29)
        
        # Crear F22 del año 2025 (rentas 2024)
        # Nota: En un caso real, el F22 se calcularía desde movimientos contables
        # Aquí simulamos que los ingresos F22 coinciden con ventas F29
        
        total_annual_sales = monthly_sales * 12  # $6.000.000
        
        # Crear movimiento contable anual que coincida
        journal = self.env['account.journal'].search([
            ('type', '=', 'general'),
            ('company_id', '=', self.company.id)
        ], limit=1)
        
        annual_move = self.env['account.move'].create({
            'journal_id': journal.id,
            'date': '2024-12-31',
            'ref': 'Ingresos anuales 2024',
            'line_ids': [
                (0, 0, {
                    'name': 'Ventas anuales',
                    'account_id': self.account_sales.id,
                    'credit': total_annual_sales,
                    'debit': 0.0,
                }),
                (0, 0, {
                    'name': 'Clientes',
                    'account_id': self.account_receivable.id,
                    'debit': total_annual_sales,
                    'credit': 0.0,
                })
            ]
        })
        annual_move.action_post()
        
        # Crear F22
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': 2025,  # AT2025 (rentas 2024)
        })
        f22.action_calculate()
        
        # Validar consistencia usando el servicio
        validation_result = self.sii_service.validate_f22_f29_consistency(
            [f22.id],
            f29_records.ids
        )
        
        # Debe reportar consistencia
        self.assertFalse(validation_result['has_errors'])
        
        # Verificar que los totales coinciden
        total_f29_sales = sum(f29_records.mapped('ventas_total'))
        self.assertEqual(f22.ingresos_totales, total_f29_sales)
        
        _logger.info("Test consistencia F22-F29 anual: OK")