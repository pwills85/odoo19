
/** @odoo-module **/

import { patch } from "@web/core/utils/patch";
import { AccountReportLineName } from "@account/components/account_report_line/line_name/line_name";
import { useService } from "@odoo/owl";

patch(AccountReportLineName.prototype, {
    setup() {
        super.setup();
        this.orm = useService("orm");
    },

    async onToggleKpi(line) {
        const line_id = line.res_id;
        if (!line_id) {
            console.error("Cannot toggle KPI for a line without a database ID.");
            return;
        }

        try {
            await this.orm.write("account.report.line", [line_id], { is_kpi: !line.is_kpi });
            // We need to trigger a reload of the report to reflect the change.
            // The controller is responsible for this. We can emit an event upwards.
            this.env.bus.trigger("reload_report");

        } catch (error) {
            console.error("Failed to toggle KPI status:", error);
            // Optionally, display a notification to the user
            this.env.services.notification.add("Failed to update KPI status.", {
                type: "danger",
            });
        }
    }
});
