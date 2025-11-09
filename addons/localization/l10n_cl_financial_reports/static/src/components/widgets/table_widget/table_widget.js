/** @odoo-module **/
/**
 * Table Widget Component con Virtual Scrolling
 * Optimizado para grandes datasets según documentación de rendimiento
 */

import { Component, useState, onWillStart, useRef, onMounted, onWillUnmount } from "@odoo/owl";
import { useService } from "@odoo/owl";
import { _t } from "@web/core/l10n/translation";
import { useVirtualList } from "@web/core/virtual_list_hook";
import { memoize } from "@web/core/utils/functions";

export class TableWidget extends Component {
    static template = "account_financial_report.TableWidget";
    static props = {
        widgetData: Object,
        config: Object,
        filters: { type: Object, optional: true },
        size: { type: Object, optional: true },
        websocketService: { type: Object, optional: true }
    };
    
    setup() {
        // Servicios
        this.rpc = useService("rpc");
        this.notification = useService("notification");
        this.websocketService = this.props.websocketService || useService("dashboard.websocket", { optional: true });
        
        // Referencias
        this.tableRef = useRef("tableContainer");
        this.searchInputRef = useRef("searchInput");
        this.websocketSubscription = null;
        
        // Estado reactivo
        this.state = useState({
            isLoading: true,
            hasError: false,
            errorMessage: "",
            data: { columns: [], rows: [], total_count: 0 },
            // Paginación
            currentPage: 1,
            pageSize: this.props.widgetData.table_config?.pageSize || 10,
            // Ordenamiento
            sortColumn: null,
            sortDirection: 'asc',
            // Búsqueda
            searchTerm: "",
            // Selección
            selectedRows: new Set()
        });
        
        // Virtual scrolling para performance
        if (this.props.widgetData.table_config?.virtualScroll) {
            this.virtualList = useVirtualList({
                items: () => this.filteredAndSortedRows,
                itemHeight: 40,
                windowHeight: 400
            });
        }
        
        // Memoización para cálculos pesados
        this.getFilteredRows = memoize(() => {
            if (!this.state.searchTerm) {
                return this.state.data.rows;
            }
            
            const searchLower = this.state.searchTerm.toLowerCase();
            return this.state.data.rows.filter(row => {
                return Object.values(row).some(value => 
                    String(value).toLowerCase().includes(searchLower)
                );
            });
        });
        
        // Hooks
        onWillStart(async () => {
            await this.loadData();
        });
        
        onMounted(() => {
            this.setupKeyboardShortcuts();
            this.subscribeToRealTimeUpdates();
        });
        
        onWillUnmount(() => {
            this.unsubscribeFromRealTimeUpdates();
        });
    }
    
    /**
     * Suscribe a actualizaciones en tiempo real
     */
    subscribeToRealTimeUpdates() {
        if (!this.websocketService || !this.props.widgetData.id) {
            return;
        }
        
        // Suscribir al widget
        this.websocketService.subscribeToWidget(
            this.props.widgetData.id,
            this.props.widgetData.widget_type,
            this.props.filters
        );
        
        // Escuchar actualizaciones usando el event bus
        const eventBus = this.websocketService.getEventBus();
        if (eventBus) {
            this.websocketSubscription = eventBus.addEventListener(
                `widget-update-${this.props.widgetData.id}`,
                this.handleRealTimeUpdate.bind(this)
            );
        }
    }
    
    /**
     * Desuscribe de actualizaciones en tiempo real
     */
    unsubscribeFromRealTimeUpdates() {
        if (!this.websocketService || !this.props.widgetData.id) {
            return;
        }
        
        // Desuscribir del widget
        this.websocketService.unsubscribeFromWidget(this.props.widgetData.id);
        
        // Remover listener del event bus
        if (this.websocketSubscription) {
            const eventBus = this.websocketService.getEventBus();
            if (eventBus) {
                eventBus.removeEventListener(
                    `widget-update-${this.props.widgetData.id}`,
                    this.websocketSubscription
                );
            }
        }
    }
    
    /**
     * Maneja actualizaciones en tiempo real
     */
    handleRealTimeUpdate(event) {
        const { data, timestamp } = event.detail || event;
        
        // Actualizar datos del estado
        this.state.data = data;
        
        // Resetear página si los datos cambiaron mucho
        if (data.total_count !== this.state.data.total_count) {
            this.state.currentPage = 1;
        }
        
        // Limpiar selección ya que los IDs pueden haber cambiado
        this.state.selectedRows.clear();
        
        // Mostrar indicador de actualización
        this.showUpdateIndicator(timestamp);
    }
    
    /**
     * Muestra indicador visual de actualización
     */
    showUpdateIndicator(timestamp) {
        // Agregar clase de animación temporal
        const container = this.tableRef.el;
        if (container) {
            container.classList.add('o_table_updating');
            setTimeout(() => {
                container.classList.remove('o_table_updating');
            }, 1000);
        }
        
        // Mostrar notificación sutil
        this.notification.add(
            _t("Table data updated"),
            { type: "info", sticky: false }
        );
    }
    
    /**
     * Carga datos desde el servicio
     */
    async loadData() {
        this.state.isLoading = true;
        this.state.hasError = false;
        
        try {
            const params = {
                model: this.props.widgetData.data_service_model,
                method: this.props.widgetData.data_service_method,
                args: [],
                kwargs: {
                    ...this.props.filters,
                    limit: this.state.pageSize,
                    offset: (this.state.currentPage - 1) * this.state.pageSize
                }
            };
            
            const data = await this.rpc("/web/dataset/call_kw", params);
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            this.state.data = data;
            
        } catch (error) {
            console.error("Error loading table data:", error);
            this.state.hasError = true;
            this.state.errorMessage = error.message || _t("Failed to load table data");
            this.notification.add(
                _t("Error loading table data"),
                { type: "danger" }
            );
        } finally {
            this.state.isLoading = false;
        }
    }
    
    /**
     * Configura atajos de teclado
     */
    setupKeyboardShortcuts() {
        const container = this.tableRef.el;
        if (!container) return;
        
        container.addEventListener('keydown', (e) => {
            // Ctrl+F para buscar
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                this.searchInputRef.el?.focus();
            }
            // Escape para limpiar búsqueda
            else if (e.key === 'Escape' && this.state.searchTerm) {
                this.state.searchTerm = "";
            }
        });
    }
    
    /**
     * Obtiene las filas filtradas y ordenadas
     */
    get filteredAndSortedRows() {
        let rows = this.getFilteredRows();
        
        // Aplicar ordenamiento si existe
        if (this.state.sortColumn) {
            const column = this.state.sortColumn;
            const direction = this.state.sortDirection === 'asc' ? 1 : -1;
            
            rows = [...rows].sort((a, b) => {
                let aVal = a[column.field];
                let bVal = b[column.field];
                
                // Manejo especial por tipo
                if (column.type === 'date') {
                    aVal = new Date(aVal);
                    bVal = new Date(bVal);
                } else if (column.type === 'currency' || column.type === 'number') {
                    aVal = parseFloat(aVal) || 0;
                    bVal = parseFloat(bVal) || 0;
                }
                
                if (aVal < bVal) return -direction;
                if (aVal > bVal) return direction;
                return 0;
            });
        }
        
        return rows;
    }
    
    /**
     * Obtiene las filas para la página actual
     */
    get paginatedRows() {
        const start = (this.state.currentPage - 1) * this.state.pageSize;
        const end = start + this.state.pageSize;
        return this.filteredAndSortedRows.slice(start, end);
    }
    
    /**
     * Calcula el número total de páginas
     */
    get totalPages() {
        return Math.ceil(this.filteredAndSortedRows.length / this.state.pageSize);
    }
    
    /**
     * Maneja el cambio de página
     */
    onPageChange(page) {
        if (page >= 1 && page <= this.totalPages) {
            this.state.currentPage = page;
            
            // Si estamos usando paginación del servidor
            if (this.props.widgetData.table_config?.serverPagination) {
                this.loadData();
            }
        }
    }
    
    /**
     * Maneja el ordenamiento de columnas
     */
    onColumnSort(column) {
        if (!column.sortable) return;
        
        if (this.state.sortColumn?.field === column.field) {
            // Cambiar dirección
            this.state.sortDirection = this.state.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            // Nueva columna
            this.state.sortColumn = column;
            this.state.sortDirection = 'asc';
        }
        
        // Volver a la primera página al ordenar
        this.state.currentPage = 1;
    }
    
    /**
     * Maneja la búsqueda
     */
    onSearchInput(ev) {
        this.state.searchTerm = ev.target.value;
        this.state.currentPage = 1; // Volver a la primera página
    }
    
    /**
     * Maneja la selección de filas
     */
    onRowSelect(row, ev) {
        const rowId = row.id;
        
        if (ev.ctrlKey || ev.metaKey) {
            // Multi-selección
            if (this.state.selectedRows.has(rowId)) {
                this.state.selectedRows.delete(rowId);
            } else {
                this.state.selectedRows.add(rowId);
            }
        } else {
            // Selección simple
            this.state.selectedRows.clear();
            this.state.selectedRows.add(rowId);
        }
        
        // Forzar re-render
        this.state.selectedRows = new Set(this.state.selectedRows);
    }
    
    /**
     * Exporta los datos de la tabla
     */
    async onExportClick() {
        try {
            // Obtener todos los datos (sin paginación)
            const allData = await this._getAllData();
            
            // Convertir a CSV
            const csv = this._convertToCSV(allData);
            
            // Descargar
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement("a");
            const url = URL.createObjectURL(blob);
            
            link.setAttribute("href", url);
            link.setAttribute("download", `${this.props.widgetData.name}_${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
        } catch (error) {
            this.notification.add(
                _t("Error exporting data"),
                { type: "danger" }
            );
        }
    }
    
    /**
     * Obtiene todos los datos sin paginación
     */
    async _getAllData() {
        const params = {
            model: this.props.widgetData.data_service_model,
            method: this.props.widgetData.data_service_method,
            args: [],
            kwargs: {
                ...this.props.filters,
                limit: false
            }
        };
        
        const data = await this.rpc("/web/dataset/call_kw", params);
        return data;
    }
    
    /**
     * Convierte datos a CSV
     */
    _convertToCSV(data) {
        const columns = data.columns || this.state.data.columns;
        const rows = data.rows || [];
        
        // Headers
        const headers = columns.map(col => col.header).join(',');
        
        // Rows
        const csvRows = rows.map(row => {
            return columns.map(col => {
                let value = row[col.field] || '';
                // Escapar comillas y comas
                if (String(value).includes(',') || String(value).includes('"')) {
                    value = `"${String(value).replace(/"/g, '""')}"`;
                }
                return value;
            }).join(',');
        });
        
        return [headers, ...csvRows].join('\n');
    }
    
    /**
     * Formatea el valor según el tipo de columna
     */
    formatCellValue(value, column) {
        if (value === null || value === undefined) {
            return '-';
        }
        
        switch (column.type) {
            case 'currency':
                return new Intl.NumberFormat('es-CL', {
                    style: 'currency',
                    currency: 'CLP'
                }).format(value);
                
            case 'number':
                return new Intl.NumberFormat('es-CL').format(value);
                
            case 'date':
                return new Date(value).toLocaleDateString('es-CL');
                
            case 'datetime':
                return new Date(value).toLocaleString('es-CL');
                
            case 'percentage':
                return `${(value * 100).toFixed(2)}%`;
                
            case 'boolean':
                return value ? '✓' : '✗';
                
            default:
                return String(value);
        }
    }
    
    /**
     * Getters para la plantilla
     */
    get widgetTitle() {
        return this.props.widgetData.name || _t("Data Table");
    }
    
    get widgetIcon() {
        return this.props.widgetData.icon || 'fa-table';
    }
    
    get showExportButton() {
        return this.props.widgetData.exportable !== false;
    }
    
    get showSearch() {
        return this.props.widgetData.table_config?.searchable !== false;
    }
    
    get showPagination() {
        return this.props.widgetData.table_config?.pagination !== false && 
               this.totalPages > 1;
    }
    
    get visibleRows() {
        // Si usamos virtual scrolling
        if (this.virtualList) {
            return this.virtualList.visibleItems;
        }
        // Si no, usar paginación normal
        return this.paginatedRows;
    }
    
    get paginationInfo() {
        const start = (this.state.currentPage - 1) * this.state.pageSize + 1;
        const end = Math.min(start + this.state.pageSize - 1, this.filteredAndSortedRows.length);
        const total = this.filteredAndSortedRows.length;
        
        return _t("Showing %(start)s to %(end)s of %(total)s entries", {
            start,
            end,
            total
        });
    }
}