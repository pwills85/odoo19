/** @odoo-module **/

import { registry } from "@web/core/registry";
import { Component, onWillStart, useState } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { session } from "@web/session";

class FinancialReportViewer extends Component {
    static template = "financialreportviewer_template";

    setup() {
        this.orm = useService("orm");
        this.rpc = useService("rpc");
        this.action = useService("action");
        
        this.state = useState({
            report_name: this.props.action.name,
            company_name: session.company_name,
            lines: [],
            totals: {},
        });

        onWillStart(async () => {
            await this.loadReportData();
        });
    }

    async loadReportData() {
        const reportModel = this.props.action.context.active_model;
        const reportId = this.props.action.context.active_id;
        const reportCode = this.props.action.context.report_code;

        const data = await this.rpc('/financial_reports/get_report_data', {
            report_options: {
                report_model: reportModel,
                report_id: reportId,
                report_code: reportCode,
            }
        });

        if (data.error) {
            console.error(data.error);
        } else {
            this.state.lines = data.lines;
            this.state.totals = data.totals;
            this.state.report_name = data.report_name;
            this.state.company_name = data.company_name;
            this.state.report_code = reportCode; // Store report code to select template
        }
    }

    onLineClick(line) {
        // Drill-down functionality
        if (!line.id) return; // Not a detail line
        
        this.action.doAction({
            type: 'ir.actions.act_window',
            name: `Movimientos de ${line.name}`,
            res_model: 'account.move.line',
            views: [[false, 'list'], [false, 'form']],
            domain: [['account_id', '=', line.id]],
            target: 'current',
        });
    }
    
    exportReport(format) {
        // Placeholder for export functionality
        // console.log(`Exporting to ${format}...`);
    }

    formatCurrency(amount) {
        return new Intl.NumberFormat('es-CL', { style: 'currency', currency: 'CLP' }).format(amount);
    }
}

FinancialReportViewer.template = "account_financial_report.FinancialReportViewer";

registry.category("actions").add("financial_report_viewer", FinancialReportViewer);
