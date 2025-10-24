/** @odoo-module **/

import { registry } from "@web/core/registry";
import { Component, onWillStart, useState } from "@odoo/owl";
import { useService } from "@odoo/owl";

class RatioDashboard extends Component {
    static template = "ratiodashboard_template";

    setup() {
        this.orm = useService("orm");
        this.rpc = useService("rpc");
        this.state = useState({ ratios: [] });

        onWillStart(async () => {
            await this.loadRatioData();
        });
    }

    async loadRatioData() {
        const reportModel = this.props.action.context.active_model;
        const reportId = this.props.action.context.active_id;

        // We need to call a method on the model to get the ratios
        const ratioData = await this.orm.call(
            reportModel,
            "get_ratios_for_dashboard",
            [reportId]
        );
        
        this.state.ratios = this.processRatioData(ratioData);
    }
    
    processRatioData(data) {
        return Object.entries(data).map(([key, value]) => {
            let interpretation = '';
            let cssClass = '';
            // Simple interpretation logic
            if (key.includes('ratio')) {
                if (value > 2) { interpretation = 'Strong'; cssClass = 'text-success'; }
                else if (value > 1) { interpretation = 'Good'; cssClass = 'text-info'; }
                else { interpretation = 'Weak'; cssClass = 'text-danger'; }
            }
            return { name: key.replace(/_/g, ' ').toUpperCase(), value: value, interpretation: interpretation, class: cssClass };
        });
    }
}

RatioDashboard.template = "account_financial_report.RatioDashboard";
registry.category("actions").add("ratio_dashboard", RatioDashboard);
