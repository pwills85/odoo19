/** @odoo-module **/
/**
 * Filter Panel Component
 * Panel de filtros avanzados siguiendo documentación técnica
 */

import { Component, useState, onWillStart, useRef } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { _t } from "@web/core/l10n/translation";
import { Dropdown } from "@web/core/dropdown/dropdown";
import { DateTimeInput } from "@web/core/datetime/datetime_input";
import { Many2OneField } from "@web/views/fields/many2one/many2one_field";

export class FilterPanel extends Component {
    static template = "account_financial_report.FilterPanel";
    static components = { 
        Dropdown,
        DateTimeInput,
        Many2OneField
    };
    static props = {
        filters: Object,
        onFiltersChanged: Function,
        expanded: { type: Boolean, optional: true }
    };
    
    setup() {
        // Servicios
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.dialog = useService("dialog");
        
        // Estado
        this.state = useState({
            isExpanded: this.props.expanded !== false,
            isLoading: false,
            filterOptions: null,
            activePreset: null,
            // Filtros locales
            localFilters: { ...this.props.filters },
            // Estado de validación
            errors: []
        });
        
        // Referencias
        this.panelRef = useRef("filterPanel");
        
        // Hooks
        onWillStart(async () => {
            await this.loadFilterOptions();
            await this.loadFilterPresets();
        });
    }
    
    /**
     * Carga las opciones disponibles para los filtros
     */
    async loadFilterOptions() {
        try {
            const options = await this.rpc("/web/dataset/call_kw", {
                model: "financial.filter.service",
                method: "get_filter_options",
                args: [],
                kwargs: {}
            });
            
            this.state.filterOptions = options;
            
        } catch (error) {
            console.error("Error loading filter options:", error);
            this.notification.add(
                _t("Error loading filter options"),
                { type: "danger" }
            );
        }
    }
    
    /**
     * Carga los presets de filtros disponibles
     */
    async loadFilterPresets() {
        try {
            const presets = await this.rpc("/web/dataset/call_kw", {
                model: "financial.filter.service",
                method: "get_filter_presets",
                args: [],
                kwargs: { include_shared: true }
            });
            
            this.filterPresets = presets;
            
        } catch (error) {
            console.error("Error loading filter presets:", error);
        }
    }
    
    /**
     * Aplica un período predefinido
     */
    async onPeriodSelect(periodKey) {
        const result = await this.rpc("/web/dataset/call_kw", {
            model: "financial.filter.service",
            method: "apply_period_filter",
            args: [periodKey],
            kwargs: {}
        });
        
        if (result) {
            this.state.localFilters = {
                ...this.state.localFilters,
                date_from: result.date_from,
                date_to: result.date_to,
                period: periodKey
            };
            
            this.applyFilters();
        }
    }
    
    /**
     * Maneja cambios en los filtros
     */
    onFilterChange(filterName, value) {
        this.state.localFilters[filterName] = value;
        
        // Si cambió manualmente las fechas, quitar el período predefinido
        if (filterName === 'date_from' || filterName === 'date_to') {
            delete this.state.localFilters.period;
        }
        
        // Aplicar con debounce para evitar múltiples llamadas
        this.debouncedApplyFilters();
    }
    
    /**
     * Aplica los filtros con debounce
     */
    debouncedApplyFilters = this._debounce(() => {
        this.applyFilters();
    }, 500);
    
    /**
     * Aplica los filtros activos
     */
    async applyFilters() {
        // Validar filtros
        const errors = await this.validateFilters();
        if (errors.length > 0) {
            this.state.errors = errors;
            return;
        }
        
        this.state.errors = [];
        
        // Limpiar filtros vacíos
        const cleanFilters = {};
        for (const [key, value] of Object.entries(this.state.localFilters)) {
            if (value !== null && value !== undefined && value !== '') {
                cleanFilters[key] = value;
            }
        }
        
        // Notificar al componente padre
        this.props.onFiltersChanged(cleanFilters);
    }
    
    /**
     * Valida los filtros
     */
    async validateFilters() {
        const errors = await this.rpc("/web/dataset/call_kw", {
            model: "financial.filter.service",
            method: "validate_filters",
            args: [this.state.localFilters],
            kwargs: {}
        });
        
        return errors;
    }
    
    /**
     * Limpia todos los filtros
     */
    onClearFilters() {
        this.state.localFilters = {
            date_from: null,
            date_to: null
        };
        this.state.activePreset = null;
        this.applyFilters();
    }
    
    /**
     * Guarda el preset actual
     */
    async onSavePreset() {
        const dialog = await this.dialog.add(SavePresetDialog, {
            filters: this.state.localFilters,
            onSave: async (name, shared) => {
                try {
                    await this.rpc("/web/dataset/call_kw", {
                        model: "financial.filter.service",
                        method: "save_filter_preset",
                        args: [name, this.state.localFilters, shared],
                        kwargs: {}
                    });
                    
                    this.notification.add(
                        _t("Filter preset saved successfully"),
                        { type: "success" }
                    );
                    
                    // Recargar presets
                    await this.loadFilterPresets();
                    
                } catch (error) {
                    this.notification.add(
                        _t("Error saving filter preset"),
                        { type: "danger" }
                    );
                }
            }
        });
    }
    
    /**
     * Carga un preset guardado
     */
    async onLoadPreset(presetId) {
        try {
            const filters = await this.rpc("/web/dataset/call_kw", {
                model: "financial.filter.service",
                method: "apply_filter_preset",
                args: [presetId],
                kwargs: {}
            });
            
            if (filters) {
                this.state.localFilters = filters;
                this.state.activePreset = presetId;
                this.applyFilters();
            }
            
        } catch (error) {
            this.notification.add(
                _t("Error loading filter preset"),
                { type: "danger" }
            );
        }
    }
    
    /**
     * Toggle panel expandido/colapsado
     */
    onToggleExpanded() {
        this.state.isExpanded = !this.state.isExpanded;
    }
    
    /**
     * Utilidad de debounce
     */
    _debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    // ========================================
    // Getters para la plantilla
    // ========================================
    
    get periodOptions() {
        if (!this.state.filterOptions) return [];
        
        return Object.entries(this.state.filterOptions.periods).map(([key, period]) => ({
            id: key,
            text: period.name,
            icon: period.icon
        }));
    }
    
    get hasActiveFilters() {
        const filters = this.state.localFilters;
        return Object.keys(filters).some(key => 
            filters[key] !== null && 
            filters[key] !== undefined && 
            filters[key] !== ''
        );
    }
    
    get activeFilterCount() {
        const filters = this.state.localFilters;
        return Object.keys(filters).filter(key => 
            filters[key] !== null && 
            filters[key] !== undefined && 
            filters[key] !== '' &&
            key !== 'period' // No contar el período como filtro separado
        ).length;
    }
    
    get filterSummary() {
        const summary = [];
        const filters = this.state.localFilters;
        
        // Período o rango de fechas
        if (filters.period && this.state.filterOptions) {
            const period = this.state.filterOptions.periods[filters.period];
            if (period) {
                summary.push(period.name);
            }
        } else if (filters.date_from || filters.date_to) {
            const from = filters.date_from || '...';
            const to = filters.date_to || '...';
            summary.push(`${from} - ${to}`);
        }
        
        // Compañía
        if (filters.company_id && this.state.filterOptions) {
            const company = this.state.filterOptions.companies.find(
                c => c.id === filters.company_id
            );
            if (company) {
                summary.push(company.name);
            }
        }
        
        // Departamento
        if (filters.department_id && this.state.filterOptions) {
            const dept = this.state.filterOptions.departments.find(
                d => d.id === filters.department_id
            );
            if (dept) {
                summary.push(dept.name);
            }
        }
        
        return summary.join(' • ');
    }
}

/**
 * Dialog para guardar preset de filtros
 */
class SavePresetDialog extends Component {
    static template = "account_financial_report.SavePresetDialog";
    static props = {
        close: Function,
        filters: Object,
        onSave: Function
    };
    
    setup() {
        this.state = useState({
            name: '',
            shared: false,
            description: ''
        });
    }
    
    onConfirm() {
        if (!this.state.name.trim()) {
            return;
        }
        
        this.props.onSave(this.state.name, this.state.shared);
        this.props.close();
    }
}