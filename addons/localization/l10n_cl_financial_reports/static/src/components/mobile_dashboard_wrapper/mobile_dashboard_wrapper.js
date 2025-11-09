
/** @odoo-module **/

import { Component, useState, onMounted, onWillUnmount } from '@odoo/owl';
import { useService } from '@web/core/utils/hooks';

export class MobileDashboardWrapper extends Component {
    setup() {
        this.orm = useService('orm');
        this.notification = useService('notification');

        this.state = useState({
            isMobile: window.innerWidth <= 768,
            orientation: window.innerWidth > window.innerHeight ? 'landscape' : 'portrait',
            isOnline: navigator.onLine,
            activeTab: 'overview',
            isRefreshing: false,
        });

        onMounted(() => {
            this.bindMobileEvents();
            this.detectDevice();
            this.setupOfflineSupport();
        });

        onWillUnmount(() => {
            this.unbindMobileEvents();
        });
    }

    bindMobileEvents() {
        // Orientation change
        window.addEventListener('orientationchange', this.handleOrientationChange.bind(this));
        window.addEventListener('resize', this.handleResize.bind(this));

        // Online/offline
        window.addEventListener('online', this.handleOnline.bind(this));
        window.addEventListener('offline', this.handleOffline.bind(this));

        // Custom gesture events
        document.addEventListener('gesture:swipe:down', this.handlePullRefresh.bind(this));
        document.addEventListener('dashboard:refresh', this.refreshData.bind(this));
    }

    unbindMobileEvents() {
        window.removeEventListener('orientationchange', this.handleOrientationChange);
        window.removeEventListener('resize', this.handleResize);
        window.removeEventListener('online', this.handleOnline);
        window.removeEventListener('offline', this.handleOffline);
        document.removeEventListener('gesture:swipe:down', this.handlePullRefresh);
        document.removeEventListener('dashboard:refresh', this.refreshData);
    }

    detectDevice() {
        const userAgent = navigator.userAgent;
        const isIOS = /iPad|iPhone|iPod/.test(userAgent);
        const isAndroid = /Android/.test(userAgent);

        document.body.classList.add(
            isIOS ? 'ios-device' :
            isAndroid ? 'android-device' :
            'desktop-device'
        );

        // Add touch capability class
        if ('ontouchstart' in window) {
            document.body.classList.add('touch-device');
        }
    }

    setupOfflineSupport() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/account_financial_report/static/sw.js')
                .then(registration => {
                    console.log('SW registered:', registration);
                })
                .catch(error => {
                    console.log('SW registration failed:', error);
                });
        }
    }

    handleOrientationChange() {
        setTimeout(() => {
            this.state.orientation = window.innerWidth > window.innerHeight ? 'landscape' : 'portrait';
            this.state.isMobile = window.innerWidth <= 768;

            // Trigger layout recalculation
            this.env.bus.trigger('orientation:changed', {
                orientation: this.state.orientation,
                isMobile: this.state.isMobile
            });
        }, 100);
    }

    handleResize() {
        this.state.isMobile = window.innerWidth <= 768;
    }

    handleOnline() {
        this.state.isOnline = true;
        this.notification.add('Back online', { type: 'success' });

        // Sync offline data if any
        this.syncOfflineData();
    }

    handleOffline() {
        this.state.isOnline = false;
        this.notification.add('Working offline', { type: 'warning' });
    }

    async handlePullRefresh(event) {
        if (this.state.isRefreshing) return;

        this.state.isRefreshing = true;

        try {
            await this.refreshData();
            this.notification.add('Data refreshed', { type: 'success' });
        } catch (error) {
            this.notification.add('Refresh failed', { type: 'danger' });
        } finally {
            this.state.isRefreshing = false;
        }
    }

    async refreshData() {
        // Refresh dashboard data
        this.env.bus.trigger('dashboard:refresh-requested');
    }

    async syncOfflineData() {
        // Sync any offline changes when back online
        try {
            const offlineData = localStorage.getItem('offline_changes');
            if (offlineData) {
                const changes = JSON.parse(offlineData);
                // Process offline changes
                for (const change of changes) {
                    await this.orm.write(change.model, change.ids, change.values);
                }
                localStorage.removeItem('offline_changes');
            }
        } catch (error) {
            console.error('Error syncing offline data:', error);
        }
    }

    switchTab(tabName) {
        this.state.activeTab = tabName;
        this.env.bus.trigger('mobile:tab-changed', { tab: tabName });
    }

    getTabClass(tabName) {
        return this.state.activeTab === tabName ? 'nav-tab active' : 'nav-tab';
    }

    get mobileClasses() {
        const classes = ['mobile-dashboard-wrapper'];

        if (this.state.isMobile) classes.push('mobile-mode');
        classes.push(this.state.orientation);
        if (!this.state.isOnline) classes.push('offline-mode');
        if (this.state.isRefreshing) classes.push('refreshing');

        return classes.join(' ');
    }
}

MobileDashboardWrapper.template = 'account_financial_report.MobileDashboardWrapper';
MobileDashboardWrapper.props = {
    dashboardData: Object,
    widgets: Array,
};
