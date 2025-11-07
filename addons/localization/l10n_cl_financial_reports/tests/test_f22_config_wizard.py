# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestF22ConfigWizard(TransactionCase):
    """
    Tests para wizard de configuración F22
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Crear compañía de prueba
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company CL',
            'currency_id': cls.env.ref('base.CLP').id,
        })

        # Crear cuentas contables de prueba
        cls.account_type_expense = cls.env['account.account.type'].search([
            ('internal_group', '=', 'expense')
        ], limit=1)

        cls.account_type_liability = cls.env['account.account.type'].search([
            ('internal_group', '=', 'liability')
        ], limit=1)

        cls.cuenta_gasto = cls.env['account.account'].create({
            'name': 'Gasto Impuesto Primera Categoría',
            'code': '5105',
            'account_type': 'expense',
            'company_id': cls.company.id,
        })

        cls.cuenta_impuesto_pagar = cls.env['account.account'].create({
            'name': 'Impuesto Renta por Pagar',
            'code': '2103',
            'account_type': 'liability_current',
            'company_id': cls.company.id,
        })

        cls.cuenta_gasto_otra_compania = cls.env['account.account'].create({
            'name': 'Gasto Impuesto Otra Compañía',
            'code': '5106',
            'account_type': 'expense',
            'company_id': cls.env.company.id,  # Otra compañía
        })

    def test_01_wizard_creation(self):
        """Test que el wizard se crea correctamente con valores por defecto"""
        wizard = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })

        self.assertEqual(wizard.company_id, self.company)
        self.assertEqual(wizard.cuenta_gasto_impuesto, self.cuenta_gasto)
        self.assertEqual(wizard.cuenta_impuesto_por_pagar, self.cuenta_impuesto_pagar)

    def test_02_wizard_default_company(self):
        """Test que el wizard usa la compañía actual por defecto"""
        wizard = self.env['l10n_cl_f22.config.wizard'].with_company(self.company).create({
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })

        # Debe usar la compañía del contexto
        self.assertTrue(wizard.company_id)

    def test_03_constraint_cuentas_diferentes(self):
        """Test que el constraint valida que las cuentas sean diferentes"""
        with self.assertRaises(ValidationError) as context:
            self.env['l10n_cl_f22.config.wizard'].create({
                'company_id': self.company.id,
                'cuenta_gasto_impuesto': self.cuenta_gasto.id,
                'cuenta_impuesto_por_pagar': self.cuenta_gasto.id,  # Misma cuenta!
            })

        self.assertIn('diferentes', str(context.exception).lower())

    def test_04_constraint_cuentas_misma_compania(self):
        """Test que el constraint valida que las cuentas pertenezcan a la compañía"""
        with self.assertRaises(ValidationError) as context:
            self.env['l10n_cl_f22.config.wizard'].create({
                'company_id': self.company.id,
                'cuenta_gasto_impuesto': self.cuenta_gasto_otra_compania.id,  # Otra compañía!
                'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
            })

        self.assertIn('no pertenece', str(context.exception).lower())

    def test_05_action_apply_configuration_saves_to_ir_config_parameter(self):
        """Test que action_apply_configuration guarda en ir.config_parameter"""
        wizard = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })

        # Aplicar configuración
        result = wizard.action_apply_configuration()

        # Verificar que retorna acción de notificación
        self.assertEqual(result['type'], 'ir.actions.client')
        self.assertEqual(result['tag'], 'display_notification')
        self.assertEqual(result['params']['type'], 'success')

        # Verificar que se guardó en ir.config_parameter
        IrConfigParameter = self.env['ir.config_parameter'].sudo()
        company_id = self.company.id

        key_gasto = f'l10n_cl_f22.cuenta_gasto_impuesto.{company_id}'
        key_impuesto = f'l10n_cl_f22.cuenta_impuesto_por_pagar.{company_id}'

        saved_gasto_id = IrConfigParameter.get_param(key_gasto)
        saved_impuesto_id = IrConfigParameter.get_param(key_impuesto)

        self.assertEqual(int(saved_gasto_id), self.cuenta_gasto.id)
        self.assertEqual(int(saved_impuesto_id), self.cuenta_impuesto_pagar.id)

    def test_06_get_f22_config_retrieves_saved_configuration(self):
        """Test que get_f22_config obtiene la configuración guardada"""
        # Guardar configuración primero
        wizard = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })
        wizard.action_apply_configuration()

        # Obtener configuración
        config = self.env['l10n_cl_f22.config.wizard'].get_f22_config(self.company.id)

        self.assertIsNotNone(config)
        self.assertEqual(config['cuenta_gasto_impuesto'], self.cuenta_gasto)
        self.assertEqual(config['cuenta_impuesto_por_pagar'], self.cuenta_impuesto_pagar)

    def test_07_get_f22_config_returns_none_when_no_config(self):
        """Test que get_f22_config retorna None cuando no hay configuración"""
        # Crear una nueva compañía sin configuración
        new_company = self.env['res.company'].create({
            'name': 'New Company Without Config',
            'currency_id': self.env.ref('base.CLP').id,
        })

        config = self.env['l10n_cl_f22.config.wizard'].get_f22_config(new_company.id)

        self.assertIsNone(config)

    def test_08_compute_config_existente(self):
        """Test que _compute_config_existente detecta configuración previa"""
        wizard = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })

        # Antes de guardar, no debe haber configuración
        self.assertFalse(wizard.config_existente)

        # Guardar configuración
        wizard.action_apply_configuration()

        # Crear nuevo wizard para la misma compañía
        wizard2 = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })

        # Ahora debe detectar configuración existente
        self.assertTrue(wizard2.config_existente)
        self.assertIn(self.cuenta_gasto.code, wizard2.cuenta_gasto_actual)
        self.assertIn(self.cuenta_impuesto_pagar.code, wizard2.cuenta_impuesto_actual)

    def test_09_action_cancel_closes_wizard(self):
        """Test que action_cancel cierra el wizard sin guardar"""
        wizard = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })

        result = wizard.action_cancel()

        self.assertEqual(result['type'], 'ir.actions.act_window_close')

        # Verificar que NO se guardó en ir.config_parameter
        IrConfigParameter = self.env['ir.config_parameter'].sudo()
        company_id = self.company.id

        key_gasto = f'l10n_cl_f22.cuenta_gasto_impuesto.{company_id}'
        saved_gasto_id = IrConfigParameter.get_param(key_gasto)

        # No debe existir (o debe ser None)
        self.assertFalse(saved_gasto_id)

    def test_10_wizard_update_configuration_overwrites(self):
        """Test que una segunda configuración sobrescribe la primera"""
        # Primera configuración
        wizard1 = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })
        wizard1.action_apply_configuration()

        # Crear una nueva cuenta de gasto
        nueva_cuenta_gasto = self.env['account.account'].create({
            'name': 'Nueva Cuenta Gasto Impuesto',
            'code': '5107',
            'account_type': 'expense',
            'company_id': self.company.id,
        })

        # Segunda configuración (actualización)
        wizard2 = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': nueva_cuenta_gasto.id,  # Nueva cuenta
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })
        wizard2.action_apply_configuration()

        # Obtener configuración
        config = self.env['l10n_cl_f22.config.wizard'].get_f22_config(self.company.id)

        # Debe tener la nueva cuenta
        self.assertEqual(config['cuenta_gasto_impuesto'], nueva_cuenta_gasto)
        self.assertEqual(config['cuenta_impuesto_por_pagar'], self.cuenta_impuesto_pagar)

    def test_11_wizard_multicompany_isolation(self):
        """Test que las configuraciones están aisladas por compañía"""
        # Crear segunda compañía con sus propias cuentas
        company2 = self.env['res.company'].create({
            'name': 'Test Company 2',
            'currency_id': self.env.ref('base.CLP').id,
        })

        cuenta_gasto2 = self.env['account.account'].create({
            'name': 'Gasto Impuesto Compañía 2',
            'code': '5108',
            'account_type': 'expense',
            'company_id': company2.id,
        })

        cuenta_impuesto_pagar2 = self.env['account.account'].create({
            'name': 'Impuesto Renta Compañía 2',
            'code': '2104',
            'account_type': 'liability_current',
            'company_id': company2.id,
        })

        # Configurar compañía 1
        wizard1 = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': self.company.id,
            'cuenta_gasto_impuesto': self.cuenta_gasto.id,
            'cuenta_impuesto_por_pagar': self.cuenta_impuesto_pagar.id,
        })
        wizard1.action_apply_configuration()

        # Configurar compañía 2
        wizard2 = self.env['l10n_cl_f22.config.wizard'].create({
            'company_id': company2.id,
            'cuenta_gasto_impuesto': cuenta_gasto2.id,
            'cuenta_impuesto_por_pagar': cuenta_impuesto_pagar2.id,
        })
        wizard2.action_apply_configuration()

        # Verificar que cada compañía tiene su propia configuración
        config1 = self.env['l10n_cl_f22.config.wizard'].get_f22_config(self.company.id)
        config2 = self.env['l10n_cl_f22.config.wizard'].get_f22_config(company2.id)

        self.assertEqual(config1['cuenta_gasto_impuesto'], self.cuenta_gasto)
        self.assertEqual(config2['cuenta_gasto_impuesto'], cuenta_gasto2)

        # Las configuraciones no deben mezclarse
        self.assertNotEqual(config1['cuenta_gasto_impuesto'], config2['cuenta_gasto_impuesto'])
