# Auditoría Fase 10 - Reporte Ejecutivo

## Executive Summary (Estado: ⚠️)
- 2025-11-09 · Auditoría funcional profunda módulos DTE y Nómina Chile (Odoo 11 vs roadmap Odoo 19). Alcance: DTE, factoring, indicadores, nómina, reportes y comparativo.
- 📌 Know-how crítico identificado en producción: boletas, factoring, consumo de folios, catálogos SBIF, indicadores previsionales, Previred y workflows completos de usuario. `l10n_cl_fe/README.md:11`, `l10n_cl_hr/README.md:18`
- ⚠️ Gaps regulatorios 2025 (Ley 21.735) y carencias en stack Odoo 19 (sin boletas/factoring, sin indicadores financieros) requieren plan específico para no degradar operación. `l10n_cl_hr/model/hr_indicadores_previsionales.py:56`, `addons/localization/l10n_cl_dte/__manifest__.py:16`

## Technical Analysis
### DTE / Facturación
- Models clave: `sii.document_class` + `account.journal.sii_document_class` definen códigos y secuencias; las facturas añaden campos `document_class_id`, `sii_result` y colas automáticas. `l10n_cl_fe/models/sii_document_class.py:7`, `l10n_cl_fe/models/account_invoice.py:143`
- Infraestructura DTE completa: firma (`sii.firma`), CAF (`dte.caf`), colas (`sii.cola_envio`) y sobres (`sii.xml.envio`) orquestan envío/consulta SII. `l10n_cl_fe/models/sii_firma.py:21`, `l10n_cl_fe/models/caf.py:18`, `l10n_cl_fe/models/sii_cola_envio.py:18`
- Factoring integrado mediante `l10n_cl_dte_factoring` (campos `cesionario_id`, `sii_cesion_result` y nuevos tipos en la cola). `l10n_cl_dte_factoring/models/invoice.py:24`, `l10n_cl_dte_factoring/models/sii_cola_envio.py:9`

### Nómina
- Contratos almacenan parámetros previsionales (AFP/ISAPRE/APV, cargas, asignaciones) usados por reglas. `l10n_cl_hr/model/hr_contract.py:45`
- Indicadores (`hr.indicadores`) concentran tasas y topes; payslip vincula `indicadores_id` y movimientos Previred. `l10n_cl_hr/model/hr_indicadores_previsionales.py:56`, `l10n_cl_hr/model/hr_payslip.py:47`
- Exportes críticos: wizard Previred (CSV) y Libro de Remuneraciones (PDF) mantienen relaciones regulatorias vigentes. `l10n_cl_hr/views/wizard_export_csv_previred_view.xml:4`, `l10n_cl_hr/views/hr_salary_books.xml:4`

### Datos Maestros / Menús / Reportes
- Catálogos SII (documentos, responsabilidades, actividades, oficinas) y SBIF (bancos) precargados garantizan consistencia. `l10n_cl_fe/data/sii.document_class.csv:1`, `l10n_cl_banks_sbif/__manifest__.py:31`
- Menús SII centralizan configuración y operaciones (recepción XML, cola, libros, CAF). `l10n_cl_fe/views/sii_menuitem.xml:4`, `l10n_cl_fe/views/consumo_folios.xml:147`
- Reportes DTE (libros, consumo, honorarios) ofrecen botones “Validate / Download XML / Send XML / Ask for DTE” en cada formulario. `l10n_cl_fe/views/libro_compra_venta.xml:30`

### Regulación 2025
- Modelos actuales carecen de campos/reglas para el aporte patronal 6 % y seguro social, y las pruebas dedicadas fallan. `l10n_cl_hr/model/hr_indicadores_previsionales.py:56`, `evidencias/sprint1_tests_analysis.log:73`
- El módulo de indicadores financieros sigue apuntando a SBIF, no a CMF. `l10n_cl_financial_indicators/README.md:17`

### Comparación Odoo 11 vs Odoo 19
- Odoo 19 DTE se limita a alcance B2B sin boletas ni factura compra. `addons/localization/l10n_cl_dte/__manifest__.py:16`
- Stack Odoo 19 no incluye factoring ni indicadores financieros; README solo menciona `l10n_cl`, `l10n_cl_edi`, `l10n_cl_reports`, `l10n_cl_hr_payroll`. `addons/localization/README.md:7`
- Odoo 19 Nómina depende de microservicios para Reforma 2025, mientras producción es on-prem. `addons/localization/l10n_cl_hr_payroll/__manifest__.py:51`

## Findings
- 🔴 (P1) **Boletas y factoring fuera del roadmap Odoo 19:** El manifiesto nuevo excluye documentos 39/41/46, arriesgando pérdida de flujos B2C y cesiones. `addons/localization/l10n_cl_dte/__manifest__.py:16`
- 🔴 (P1) **Reforma 2025 sin soporte real:** Modelos actuales no contienen campos ni reglas para el 6 % patronal; pruebas Ley 21.735 fallan. `l10n_cl_hr/model/hr_indicadores_previsionales.py:56`, `evidencias/sprint1_tests_analysis.log:73`
- 🟡 (P2) **Indicadores financieros dependen de SBIF:** README aún referencia `api.sbif.cl`, API discontinuada desde integración CMF; se requiere nuevo proveedor antes de 2025. `l10n_cl_financial_indicators/README.md:17`
- 🟡 (P2) **Exportes Previred y libros acoplados a layouts 2024:** Wizards actuales no generan columnas nuevas ni validaciones de Reforma 2025. `l10n_cl_hr/wizard/wizard_export_csv_previred.py:130`
- 🟢 (Info) **Infraestructura DTE y nómina se encuentra bien modularizada**, facilitando portabilidad si se planifica adecuadamente.

## Recommendations
1. **Boletas & Factoring:** Portar `l10n_cl_fe`/`l10n_cl_dte_factoring` a Odoo 19 o extender `l10n_cl_dte` para incluir doc types 39/41/46 y cesiones antes de congelar roadmap. `l10n_cl_dte_factoring/__manifest__.py:3`
2. **Reforma Ley 21.735:** Diseñar plan de datos (nuevos campos en `hr.indicadores`, estructuras de reglas), actualizar wizards Previred y añadir pruebas verdes antes de agosto 2025. `l10n_cl_hr/model/hr_indicadores_previsionales.py:56`
3. **Indicadores Financieros:** Migrar integraciones a API CMF/Banco Central y desacoplar dependencias SBIF. `l10n_cl_financial_indicators/README.md:17`
4. **Estrategia Nómina Odoo 19:** Definir si se adopta microservicio; de lo contrario, portar lógica on-prem y solo usar AI Service para validaciones auxiliares.
5. **Documentar y migrar data masters** (bancos SBIF, AFP/ISAPRE, oficinas SII) asegurando scripts reproducibles.

## Code Examples
```python
# account.move total builder used by DTE XML – preserves logic for migration
# l10n_cl_fe/models/account_invoice.py:1327-1378
    def _totales_normal(self, currency_id, MntExe, MntNeto, IVA, TasaIVA,
                        MntTotal=0, MntBase=0):
        Totales = {}
        if currency_id != self.currency_base():
            Totales['TpoMoneda'] = self._acortar_str(currency_id.abreviatura, 15)
        if MntNeto > 0:
            if currency_id != self.currency_id:
                MntNeto = currency_id.compute(MntNeto, self.currency_id)
            Totales['MntNeto'] = currency_id.round(MntNeto)
        # ... (mantener lógica para IVA / MntTotal al portar a Odoo 19)
```
```xml
<!-- Wizard Previred actual: referencias para extender layout 2025 -->
<!-- l10n_cl_hr/views/wizard_export_csv_previred_view.xml:4-24 -->
<form string="Previred">
  <group colspan="2">
    <field name="date_from"/>
    <field name="date_to"/>
    <field name="file_data" filename="file_name" readonly="1"/>
  </group>
  <footer>
    <button string="Generar reporte" name="action_generate_csv" type="object" class="oe_highlight"/>
    <button string="Cerrar" special="cancel" type="object" class="oe_link"/>
  </footer>
</form>
```
