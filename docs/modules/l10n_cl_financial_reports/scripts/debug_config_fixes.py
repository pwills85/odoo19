#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
"""
Script de debugging para verificar las correcciones de configuración
del módulo account_financial_report

Este script verifica:
1. Referencias correctas a modelos F29 y F22 en cron jobs
2. XPath correctos en vistas de configuración
3. Campos de configuración disponibles en res.config.settings
4. Sintaxis XML válida en todos los archivos corregidos

🔗 REFERENCIAS:
- GUIA_TECNICA_DESARROLLO_MODULOS_ODOO18_CE.md: Debugging - Sección 6.0
- account_financial_report_improvement_plan_20250107.md
"""

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigFixesDebugger:
    """Debugger para verificar correcciones de configuración"""

    def __init__(self, module_path):
        self.module_path = Path(module_path)
        self.errors = []
        self.warnings = []
        self.success_count = 0

    def debug_all(self):
        """Ejecutar todas las verificaciones de debugging"""
        logger.info("🔍 Iniciando debugging de correcciones de configuración...")

        # Verificar archivos XML
        self.debug_cron_xml()
        self.debug_config_settings_xml()
        self.debug_performance_settings_xml()

        # Verificar manifest
        self.debug_manifest_references()

        # Verificar modelos Python
        self.debug_python_models()

        # Generar reporte
        self.generate_debug_report()

    def debug_cron_xml(self):
        """Debuggear archivo de cron jobs"""
        logger.info("🕒 Debugging cron jobs XML...")

        cron_file = self.module_path / "data/l10n_cl_tax_forms_cron.xml"

        try:
            tree = ET.parse(cron_file)
            root = tree.getroot()

            # Verificar external IDs de modelos
            models_found = []
            for record in root.findall(".//record[@model='ir.model']"):
                model_name = record.find("field[@name='model']").text
                models_found.append(model_name)
                logger.info(f"✓ External ID encontrado para modelo: {model_name}")

            if 'l10n_cl.f29' not in models_found:
                self.errors.append("External ID para modelo l10n_cl.f29 no encontrado")
            else:
                self.success_count += 1

            if 'l10n_cl.f22' not in models_found:
                self.errors.append("External ID para modelo l10n_cl.f22 no encontrado")
            else:
                self.success_count += 1

            # Verificar cron jobs
            cron_jobs = []
            for record in root.findall(".//record[@model='ir.cron']"):
                name = record.find("field[@name='name']").text
                model_ref = record.find("field[@name='model_id']").get('ref')
                cron_jobs.append({'name': name, 'model_ref': model_ref})
                logger.info(f"✓ Cron job encontrado: {name} -> {model_ref}")

            if len(cron_jobs) >= 3:  # F29, F22, y check status
                self.success_count += 1
            else:
                self.warnings.append(f"Solo {len(cron_jobs)} cron jobs encontrados, esperados: 3")

        except Exception as e:
            self.errors.append(f"Error parsing cron XML: {str(e)}")

    def debug_config_settings_xml(self):
        """Debuggear archivo de configuración de settings"""
        logger.info("⚙️ Debugging config settings XML...")

        settings_file = self.module_path / "views/res_config_settings_views.xml"

        try:
            tree = ET.parse(settings_file)
            root = tree.getroot()

            # Verificar herencia correcta
            for record in root.findall(".//record[@model='ir.ui.view']"):
                inherit_id = record.find("field[@name='inherit_id']").get('ref')
                if inherit_id == 'base.view_res_config_settings':
                    logger.info("✓ Herencia correcta: base.view_res_config_settings")
                    self.success_count += 1
                else:
                    self.errors.append(f"Herencia incorrecta: {inherit_id}")

            # Verificar XPath correcto
            xpath_elements = root.findall(".//xpath")
            for xpath in xpath_elements:
                expr = xpath.get('expr')
                if expr == "//div[@id='settings']":
                    logger.info("✓ XPath correcto encontrado: //div[@id='settings']")
                    self.success_count += 1
                else:
                    self.warnings.append(f"XPath encontrado: {expr}")

            # Verificar campos de configuración
            fields_found = []
            for field in root.findall(".//field"):
                field_name = field.get('name')
                if field_name and field_name.startswith('financial_report_'):
                    fields_found.append(field_name)
                    logger.info(f"✓ Campo de configuración encontrado: {field_name}")

            expected_fields = [
                'financial_report_auto_refresh',
                'financial_report_cache_timeout',
                'enable_query_optimization',
                'enable_prefetch_optimization',
                'financial_report_batch_size'
            ]

            missing_fields = set(expected_fields) - set(fields_found)
            if missing_fields:
                self.warnings.append(f"Campos faltantes: {missing_fields}")
            else:
                self.success_count += 1

        except Exception as e:
            self.errors.append(f"Error parsing config settings XML: {str(e)}")

    def debug_performance_settings_xml(self):
        """Debuggear archivo de configuración de rendimiento"""
        logger.info("🚀 Debugging performance settings XML...")

        perf_file = self.module_path / "views/res_config_settings_performance_views.xml"

        try:
            tree = ET.parse(perf_file)
            root = tree.getroot()

            # Verificar que no esté vacío
            records = root.findall(".//record")
            if len(records) >= 2:  # Performance + monitoring views
                logger.info(f"✓ Archivo implementado con {len(records)} vistas")
                self.success_count += 1
            else:
                self.warnings.append(f"Solo {len(records)} vistas encontradas en performance settings")

            # Verificar elementos de UI específicos
            ui_elements = [
                './/div[@class="alert alert-info"]',
                './/h3',
                './/div[@class="badge badge-success"]'
            ]

            for element_path in ui_elements:
                elements = root.findall(element_path)
                if elements:
                    logger.info(f"✓ Elementos UI encontrados: {element_path} ({len(elements)})")
                    self.success_count += 1
                else:
                    self.warnings.append(f"Elementos UI faltantes: {element_path}")

        except Exception as e:
            self.errors.append(f"Error parsing performance settings XML: {str(e)}")

    def debug_manifest_references(self):
        """Debuggear referencias en el manifest"""
        logger.info("📋 Debugging manifest references...")

        manifest_file = self.module_path / "__manifest__.py"

        try:
            with open(manifest_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Verificar archivos habilitados
            enabled_files = [
                'data/l10n_cl_tax_forms_cron.xml',
                'views/res_config_settings_views.xml',
                'views/res_config_settings_performance_views.xml'
            ]

            for file_ref in enabled_files:
                if f'"{file_ref}"' in content and '# Fixed:' in content:
                    logger.info(f"✓ Archivo habilitado en manifest: {file_ref}")
                    self.success_count += 1
                elif f'# "{file_ref}"' in content:
                    self.errors.append(f"Archivo aún comentado en manifest: {file_ref}")
                else:
                    self.warnings.append(f"Referencia no encontrada en manifest: {file_ref}")

        except Exception as e:
            self.errors.append(f"Error leyendo manifest: {str(e)}")

    def debug_python_models(self):
        """Debuggear modelos Python relacionados"""
        logger.info("🐍 Debugging Python models...")

        # Verificar modelo de configuración
        config_model = self.module_path / "models/res_config_settings.py"

        if config_model.exists():
            try:
                with open(config_model, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Verificar campos de configuración
                config_fields = [
                    'financial_report_auto_refresh',
                    'financial_report_cache_timeout',
                    'enable_query_optimization',
                    'enable_prefetch_optimization',
                    'financial_report_batch_size'
                ]

                for field in config_fields:
                    if field in content:
                        logger.info(f"✓ Campo Python encontrado: {field}")
                        self.success_count += 1
                    else:
                        self.warnings.append(f"Campo Python faltante: {field}")

            except Exception as e:
                self.errors.append(f"Error leyendo config model: {str(e)}")
        else:
            self.warnings.append("Archivo res_config_settings.py no encontrado")

        # Verificar modelos F29 y F22
        for model_name in ['l10n_cl_f29.py', 'l10n_cl_f22.py']:
            model_file = self.module_path / f"models/{model_name}"
            if model_file.exists():
                logger.info(f"✓ Modelo encontrado: {model_name}")
                self.success_count += 1
            else:
                self.errors.append(f"Modelo faltante: {model_name}")

    def generate_debug_report(self):
        """Generar reporte de debugging"""
        logger.info("\n" + "="*60)
        logger.info("📊 REPORTE DE DEBUGGING - CORRECCIONES CONFIG")
        logger.info("="*60)

        logger.info(f"✅ Verificaciones exitosas: {self.success_count}")
        logger.info(f"⚠️  Advertencias: {len(self.warnings)}")
        logger.info(f"❌ Errores: {len(self.errors)}")

        if self.warnings:
            logger.warning("\n⚠️ ADVERTENCIAS:")
            for warning in self.warnings:
                logger.warning(f"  - {warning}")

        if self.errors:
            logger.error("\n❌ ERRORES:")
            for error in self.errors:
                logger.error(f"  - {error}")
        else:
            logger.info("\n🎉 ¡Todas las correcciones implementadas correctamente!")

        # Status final
        total_checks = self.success_count + len(self.warnings) + len(self.errors)
        success_rate = (self.success_count / total_checks * 100) if total_checks > 0 else 0

        logger.info(f"\n📈 Tasa de éxito: {success_rate:.1f}%")

        if success_rate >= 90:
            logger.info("🏆 EXCELENTE: Correcciones implementadas exitosamente")
            return True
        elif success_rate >= 75:
            logger.warning("⚠️  BUENO: Correcciones mayormente implementadas")
            return True
        else:
            logger.error("❌ CRÍTICO: Correcciones requieren revisión")
            return False

def main():
    """Función principal"""
    if len(sys.argv) > 1:
        module_path = sys.argv[1]
    else:
        module_path = "/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/dev_odoo_18/addons/account_financial_report"

    if not os.path.exists(module_path):
        logger.error(f"❌ Ruta del módulo no encontrada: {module_path}")
        sys.exit(1)

    debugger = ConfigFixesDebugger(module_path)
    success = debugger.debug_all()

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
