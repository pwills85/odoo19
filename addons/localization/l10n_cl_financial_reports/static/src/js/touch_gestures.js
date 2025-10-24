
/** @odoo-module **/

/**
 * Touch Gestures Support for Financial Dashboard
 * Provides swipe, pinch, tap, and other mobile interactions
 */

class TouchGestureManager {
    constructor() {
        this.isTouch = 'ontouchstart' in window;
        this.gestureState = {
            startX: 0,
            startY: 0,
            currentX: 0,
            currentY: 0,
            isDragging: false,
            startTime: 0,
        };

        this.init();
    }

    init() {
        if (!this.isTouch) return;

        document.body.classList.add('touch-enabled');
        this.bindEvents();
        this.setupSwipeNavigation();
        this.setupPullToRefresh();
        this.setupDoubleTap();
    }

    bindEvents() {
        // Touch events
        document.addEventListener('touchstart', this.handleTouchStart.bind(this), {passive: false});
        document.addEventListener('touchmove', this.handleTouchMove.bind(this), {passive: false});
        document.addEventListener('touchend', this.handleTouchEnd.bind(this), {passive: false});

        // Prevent default behaviors on dashboard
        const dashboard = document.querySelector('.financial-dashboard');
        if (dashboard) {
            dashboard.addEventListener('touchstart', (e) => {
                if (e.touches.length > 1) {
                    e.preventDefault(); // Prevent zoom on multi-touch
                }
            });
        }
    }

    handleTouchStart(e) {
        const touch = e.touches[0];
        this.gestureState = {
            startX: touch.clientX,
            startY: touch.clientY,
            currentX: touch.clientX,
            currentY: touch.clientY,
            isDragging: false,
            startTime: Date.now(),
        };
    }

    handleTouchMove(e) {
        if (!e.touches[0]) return;

        const touch = e.touches[0];
        this.gestureState.currentX = touch.clientX;
        this.gestureState.currentY = touch.clientY;
        this.gestureState.isDragging = true;

        const deltaX = this.gestureState.currentX - this.gestureState.startX;
        const deltaY = this.gestureState.currentY - this.gestureState.startY;

        // Handle swipe navigation
        this.handleSwipeNavigation(deltaX, deltaY, e);

        // Handle pull to refresh
        this.handlePullToRefresh(deltaY, e);
    }

    handleTouchEnd(e) {
        if (!this.gestureState.isDragging) return;

        const deltaX = this.gestureState.currentX - this.gestureState.startX;
        const deltaY = this.gestureState.currentY - this.gestureState.startY;
        const deltaTime = Date.now() - this.gestureState.startTime;

        // Determine gesture type
        const isSwipe = Math.abs(deltaX) > 50 || Math.abs(deltaY) > 50;
        const isQuick = deltaTime < 300;

        if (isSwipe && isQuick) {
            this.processSwipeGesture(deltaX, deltaY);
        }

        // Reset state
        this.gestureState.isDragging = false;
        this.hidePullRefresh();
    }

    processSwipeGesture(deltaX, deltaY) {
        const absX = Math.abs(deltaX);
        const absY = Math.abs(deltaY);

        if (absX > absY) {
            // Horizontal swipe
            if (deltaX > 0) {
                this.onSwipeRight();
            } else {
                this.onSwipeLeft();
            }
        } else {
            // Vertical swipe
            if (deltaY > 0) {
                this.onSwipeDown();
            } else {
                this.onSwipeUp();
            }
        }
    }

    setupSwipeNavigation() {
        // Setup swipe indicators
        const dashboard = document.querySelector('.financial-dashboard');
        if (!dashboard) return;

        const leftIndicator = document.createElement('div');
        leftIndicator.className = 'swipe-indicator left';
        leftIndicator.innerHTML = '←';

        const rightIndicator = document.createElement('div');
        rightIndicator.className = 'swipe-indicator right';
        rightIndicator.innerHTML = '→';

        dashboard.style.position = 'relative';
        dashboard.appendChild(leftIndicator);
        dashboard.appendChild(rightIndicator);
    }

    handleSwipeNavigation(deltaX, deltaY, e) {
        const absX = Math.abs(deltaX);
        const absY = Math.abs(deltaY);

        if (absX > absY && absX > 20) {
            const indicators = document.querySelectorAll('.swipe-indicator');
            indicators.forEach(indicator => {
                if ((deltaX > 0 && indicator.classList.contains('left')) ||
                    (deltaX < 0 && indicator.classList.contains('right'))) {
                    indicator.classList.add('visible');
                } else {
                    indicator.classList.remove('visible');
                }
            });
        }
    }

    setupPullToRefresh() {
        const dashboard = document.querySelector('.financial-dashboard');
        if (!dashboard) return;

        const refreshElement = document.createElement('div');
        refreshElement.className = 'pull-refresh';
        refreshElement.innerHTML = `
            <div class="refresh-icon">⟲</div>
            <div>Pull to refresh</div>
        `;
        refreshElement.style.display = 'none';

        dashboard.insertBefore(refreshElement, dashboard.firstChild);
    }

    handlePullToRefresh(deltaY, e) {
        if (deltaY < 50 || window.scrollY > 0) return;

        const refreshElement = document.querySelector('.pull-refresh');
        if (!refreshElement) return;

        refreshElement.style.display = 'block';
        refreshElement.style.opacity = Math.min(deltaY / 100, 1);

        if (deltaY > 100) {
            refreshElement.querySelector('.refresh-icon').style.animation = 'spin 1s linear infinite';
            e.preventDefault();
        }
    }

    hidePullRefresh() {
        const refreshElement = document.querySelector('.pull-refresh');
        if (refreshElement) {
            setTimeout(() => {
                refreshElement.style.display = 'none';
                refreshElement.style.opacity = 0;
                refreshElement.querySelector('.refresh-icon').style.animation = '';
            }, 300);
        }
    }

    setupDoubleTap() {
        let tapTimeout;
        let tapCount = 0;

        document.addEventListener('touchend', (e) => {
            tapCount++;

            if (tapCount === 1) {
                tapTimeout = setTimeout(() => {
                    tapCount = 0;
                }, 300);
            } else if (tapCount === 2) {
                clearTimeout(tapTimeout);
                tapCount = 0;
                this.onDoubleTap(e);
            }
        });
    }

    // Gesture handlers
    onSwipeLeft() {
        // Navigate to next widget/page
        this.triggerEvent('swipe:left');
        this.navigateWidgets('next');
    }

    onSwipeRight() {
        // Navigate to previous widget/page
        this.triggerEvent('swipe:right');
        this.navigateWidgets('previous');
    }

    onSwipeUp() {
        // Show more details or collapse
        this.triggerEvent('swipe:up');
    }

    onSwipeDown() {
        // Refresh data
        this.triggerEvent('swipe:down');
        this.refreshDashboard();
    }

    onDoubleTap(e) {
        // Toggle widget fullscreen
        const widget = e.target.closest('.widget-card');
        if (widget) {
            widget.classList.toggle('fullscreen');
            this.triggerEvent('doubletap', {target: widget});
        }
    }

    navigateWidgets(direction) {
        const widgets = document.querySelectorAll('.widget-card');
        const activeWidget = document.querySelector('.widget-card.active');

        if (!activeWidget && widgets.length > 0) {
            widgets[0].classList.add('active');
            return;
        }

        const currentIndex = Array.from(widgets).indexOf(activeWidget);
        let nextIndex;

        if (direction === 'next') {
            nextIndex = (currentIndex + 1) % widgets.length;
        } else {
            nextIndex = currentIndex > 0 ? currentIndex - 1 : widgets.length - 1;
        }

        activeWidget.classList.remove('active');
        widgets[nextIndex].classList.add('active');
        widgets[nextIndex].scrollIntoView({behavior: 'smooth', block: 'center'});
    }

    refreshDashboard() {
        // Trigger dashboard refresh
        const refreshEvent = new CustomEvent('dashboard:refresh', {
            detail: { trigger: 'gesture' }
        });
        document.dispatchEvent(refreshEvent);
    }

    triggerEvent(eventName, data = {}) {
        const event = new CustomEvent(`gesture:${eventName}`, {
            detail: data,
            bubbles: true
        });
        document.dispatchEvent(event);
    }

    // Haptic feedback (if supported)
    vibrate(pattern = [50]) {
        if ('vibrate' in navigator) {
            navigator.vibrate(pattern);
        }
    }

    // Touch-friendly scrolling
    enableSmoothScrolling() {
        document.documentElement.style.scrollBehavior = 'smooth';

        // Add momentum scrolling for iOS
        const scrollableElements = document.querySelectorAll('.o_content, .table-responsive');
        scrollableElements.forEach(el => {
            el.style.webkitOverflowScrolling = 'touch';
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new TouchGestureManager();
    });
} else {
    new TouchGestureManager();
}

// Export for use in other modules
export { TouchGestureManager };
