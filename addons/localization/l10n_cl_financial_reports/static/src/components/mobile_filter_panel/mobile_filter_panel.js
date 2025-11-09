/** @odoo-module **/

import { Component, useState, onMounted } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@odoo/owl";

export class MobileFilterPanel extends Component {
    static template = "account_financial_report.MobileFilterPanel";
    static props = {
        filters: { type: Object, optional: true },
        presets: { type: Array, optional: true },
        onApplyFilters: Function,
        onClose: { type: Function, optional: true },
    };

    setup() {
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        
        // Initialize state with current filters
        this.state = useState({
            activeTab: 'period', // 'period' | 'company' | 'advanced'
            tempFilters: { ...(this.props.filters || {}) },
            showDatePicker: false,
            customStartDate: null,
            customEndDate: null,
            expandedSections: {
                period: true,
                company: false,
                account: false,
                analytics: false,
            },
        });
        
        // Predefined mobile-friendly periods
        this.mobilePeriods = [
            { id: 'today', label: 'Hoy', icon: 'fa-calendar-check-o' },
            { id: 'yesterday', label: 'Ayer', icon: 'fa-calendar-minus-o' },
            { id: 'this_week', label: 'Esta Semana', icon: 'fa-calendar-week' },
            { id: 'last_week', label: 'Semana Pasada', icon: 'fa-calendar' },
            { id: 'this_month', label: 'Este Mes', icon: 'fa-calendar-o' },
            { id: 'last_month', label: 'Mes Pasado', icon: 'fa-calendar' },
            { id: 'this_quarter', label: 'Este Trimestre', icon: 'fa-chart-line' },
            { id: 'last_quarter', label: 'Trimestre Pasado', icon: 'fa-chart-area' },
            { id: 'this_year', label: 'Este Año', icon: 'fa-calendar-alt' },
            { id: 'last_year', label: 'Año Pasado', icon: 'fa-history' },
            { id: 'custom', label: 'Personalizado', icon: 'fa-cog' },
        ];
        
        onMounted(() => {
            this._initializeFromCurrentFilters();
        });
    }
    
    _initializeFromCurrentFilters() {
        if (this.props.filters) {
            this.state.tempFilters = { ...this.props.filters };
            
            // Set active period if exists
            if (this.props.filters.period_id) {
                const period = this.mobilePeriods.find(p => p.id === this.props.filters.period_id);
                if (period) {
                    this.state.selectedPeriod = period.id;
                }
            }
        }
    }
    
    switchTab(tab) {
        this.state.activeTab = tab;
    }
    
    toggleSection(section) {
        this.state.expandedSections[section] = !this.state.expandedSections[section];
    }
    
    selectPeriod(periodId) {
        this.state.tempFilters.period_id = periodId;
        
        if (periodId === 'custom') {
            this.state.showDatePicker = true;
        } else {
            this.state.showDatePicker = false;
            // Calculate dates based on period
            const dates = this._calculatePeriodDates(periodId);
            this.state.tempFilters.date_from = dates.start;
            this.state.tempFilters.date_to = dates.end;
        }
    }
    
    _calculatePeriodDates(periodId) {
        const today = new Date();
        let start, end;
        
        switch (periodId) {
            case 'today':
                start = end = today;
                break;
            case 'yesterday':
                start = end = new Date(today.getTime() - 24 * 60 * 60 * 1000);
                break;
            case 'this_week':
                start = this._getWeekStart(today);
                end = today;
                break;
            case 'last_week':
                const lastWeek = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
                start = this._getWeekStart(lastWeek);
                end = new Date(start.getTime() + 6 * 24 * 60 * 60 * 1000);
                break;
            case 'this_month':
                start = new Date(today.getFullYear(), today.getMonth(), 1);
                end = today;
                break;
            case 'last_month':
                start = new Date(today.getFullYear(), today.getMonth() - 1, 1);
                end = new Date(today.getFullYear(), today.getMonth(), 0);
                break;
            case 'this_quarter':
                const quarter = Math.floor(today.getMonth() / 3);
                start = new Date(today.getFullYear(), quarter * 3, 1);
                end = today;
                break;
            case 'last_quarter':
                const lastQuarter = Math.floor(today.getMonth() / 3) - 1;
                start = new Date(today.getFullYear(), lastQuarter * 3, 1);
                end = new Date(today.getFullYear(), (lastQuarter + 1) * 3, 0);
                break;
            case 'this_year':
                start = new Date(today.getFullYear(), 0, 1);
                end = today;
                break;
            case 'last_year':
                start = new Date(today.getFullYear() - 1, 0, 1);
                end = new Date(today.getFullYear() - 1, 11, 31);
                break;
            default:
                start = end = today;
        }
        
        return {
            start: this._formatDate(start),
            end: this._formatDate(end)
        };
    }
    
    _getWeekStart(date) {
        const d = new Date(date);
        const day = d.getDay();
        const diff = d.getDate() - day + (day === 0 ? -6 : 1);
        return new Date(d.setDate(diff));
    }
    
    _formatDate(date) {
        return date.toISOString().split('T')[0];
    }
    
    handleCustomDateChange(field, value) {
        this.state.tempFilters[field] = value;
    }
    
    toggleCompany(companyId) {
        if (!this.state.tempFilters.company_ids) {
            this.state.tempFilters.company_ids = [];
        }
        
        const index = this.state.tempFilters.company_ids.indexOf(companyId);
        if (index > -1) {
            this.state.tempFilters.company_ids.splice(index, 1);
        } else {
            this.state.tempFilters.company_ids.push(companyId);
        }
    }
    
    clearAllFilters() {
        this.state.tempFilters = {};
        this.state.showDatePicker = false;
        this.notification.add('Filtros eliminados', { type: 'info' });
    }
    
    applyFilters() {
        // Validate filters before applying
        if (this.state.tempFilters.period_id === 'custom') {
            if (!this.state.tempFilters.date_from || !this.state.tempFilters.date_to) {
                this.notification.add('Por favor selecciona las fechas', { type: 'warning' });
                return;
            }
        }
        
        // Apply filters
        this.props.onApplyFilters(this.state.tempFilters);
        
        // Close panel if callback provided
        if (this.props.onClose) {
            this.props.onClose();
        }
        
        this.notification.add('Filtros aplicados', { type: 'success' });
    }
    
    loadPreset(preset) {
        this.state.tempFilters = { ...preset.filters };
        this.notification.add(`Preset "${preset.name}" cargado`, { type: 'info' });
    }
    
    get activeFiltersCount() {
        return Object.keys(this.state.tempFilters).filter(key => {
            const value = this.state.tempFilters[key];
            return value && (Array.isArray(value) ? value.length > 0 : true);
        }).length;
    }
    
    get selectedPeriodLabel() {
        const period = this.mobilePeriods.find(p => p.id === this.state.tempFilters.period_id);
        return period ? period.label : 'Seleccionar período';
    }
}

registry.category("components").add(
    "account_financial_report.MobileFilterPanel",
    MobileFilterPanel
);