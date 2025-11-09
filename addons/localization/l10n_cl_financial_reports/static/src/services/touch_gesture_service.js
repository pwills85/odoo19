/** @odoo-module **/

/**
 * Touch Gesture Service for Mobile Dashboard
 * Handles swipe, pinch, and other touch gestures
 */
export class TouchGestureService {
    constructor() {
        this.touchStartX = null;
        this.touchStartY = null;
        this.touchStartTime = null;
        this.touchDistance = null;
        this.listeners = new Map();
    }
    
    /**
     * Add swipe gesture listener to an element
     * @param {HTMLElement} element 
     * @param {Object} handlers - { onSwipeLeft, onSwipeRight, onSwipeUp, onSwipeDown }
     * @param {Object} options - { threshold: 50, restraint: 100, allowedTime: 500 }
     */
    addSwipeListener(element, handlers, options = {}) {
        const config = {
            threshold: options.threshold || 50, // Required min distance traveled
            restraint: options.restraint || 100, // Maximum distance allowed perpendicular
            allowedTime: options.allowedTime || 500, // Maximum time allowed to travel
            ...options
        };
        
        const handleTouchStart = (e) => {
            const touchObj = e.changedTouches[0];
            this.touchStartX = touchObj.pageX;
            this.touchStartY = touchObj.pageY;
            this.touchStartTime = new Date().getTime();
            e.preventDefault();
        };
        
        const handleTouchEnd = (e) => {
            const touchObj = e.changedTouches[0];
            const distX = touchObj.pageX - this.touchStartX;
            const distY = touchObj.pageY - this.touchStartY;
            const elapsedTime = new Date().getTime() - this.touchStartTime;
            
            if (elapsedTime <= config.allowedTime) {
                // Check horizontal swipe
                if (Math.abs(distX) >= config.threshold && Math.abs(distY) <= config.restraint) {
                    if (distX > 0 && handlers.onSwipeRight) {
                        handlers.onSwipeRight();
                    } else if (distX < 0 && handlers.onSwipeLeft) {
                        handlers.onSwipeLeft();
                    }
                }
                // Check vertical swipe
                else if (Math.abs(distY) >= config.threshold && Math.abs(distX) <= config.restraint) {
                    if (distY > 0 && handlers.onSwipeDown) {
                        handlers.onSwipeDown();
                    } else if (distY < 0 && handlers.onSwipeUp) {
                        handlers.onSwipeUp();
                    }
                }
            }
        };
        
        element.addEventListener('touchstart', handleTouchStart, { passive: false });
        element.addEventListener('touchend', handleTouchEnd, { passive: false });
        
        // Store listeners for cleanup
        this.listeners.set(element, {
            touchstart: handleTouchStart,
            touchend: handleTouchEnd
        });
    }
    
    /**
     * Add pinch gesture listener to an element
     * @param {HTMLElement} element 
     * @param {Object} handlers - { onPinchIn, onPinchOut }
     * @param {Object} options - { threshold: 0.1 }
     */
    addPinchListener(element, handlers, options = {}) {
        const config = {
            threshold: options.threshold || 0.1, // Minimum scale change
            ...options
        };
        
        let initialDistance = null;
        let currentDistance = null;
        
        const getDistance = (touches) => {
            const dx = touches[0].pageX - touches[1].pageX;
            const dy = touches[0].pageY - touches[1].pageY;
            return Math.sqrt(dx * dx + dy * dy);
        };
        
        const handleTouchStart = (e) => {
            if (e.touches.length === 2) {
                initialDistance = getDistance(e.touches);
                e.preventDefault();
            }
        };
        
        const handleTouchMove = (e) => {
            if (e.touches.length === 2 && initialDistance) {
                currentDistance = getDistance(e.touches);
                e.preventDefault();
            }
        };
        
        const handleTouchEnd = (e) => {
            if (initialDistance && currentDistance) {
                const scale = currentDistance / initialDistance;
                
                if (Math.abs(1 - scale) > config.threshold) {
                    if (scale > 1 && handlers.onPinchOut) {
                        handlers.onPinchOut(scale);
                    } else if (scale < 1 && handlers.onPinchIn) {
                        handlers.onPinchIn(scale);
                    }
                }
            }
            
            initialDistance = null;
            currentDistance = null;
        };
        
        element.addEventListener('touchstart', handleTouchStart, { passive: false });
        element.addEventListener('touchmove', handleTouchMove, { passive: false });
        element.addEventListener('touchend', handleTouchEnd, { passive: false });
        
        // Store listeners for cleanup
        const existing = this.listeners.get(element) || {};
        this.listeners.set(element, {
            ...existing,
            pinchStart: handleTouchStart,
            pinchMove: handleTouchMove,
            pinchEnd: handleTouchEnd
        });
    }
    
    /**
     * Add long press gesture listener
     * @param {HTMLElement} element 
     * @param {Function} handler 
     * @param {Number} duration - Duration in ms (default 500)
     */
    addLongPressListener(element, handler, duration = 500) {
        let pressTimer = null;
        let isLongPress = false;
        
        const handleTouchStart = (e) => {
            isLongPress = false;
            pressTimer = setTimeout(() => {
                isLongPress = true;
                handler(e);
            }, duration);
        };
        
        const handleTouchEnd = () => {
            clearTimeout(pressTimer);
        };
        
        const handleTouchMove = () => {
            clearTimeout(pressTimer);
        };
        
        element.addEventListener('touchstart', handleTouchStart);
        element.addEventListener('touchend', handleTouchEnd);
        element.addEventListener('touchmove', handleTouchMove);
        
        // Store listeners for cleanup
        const existing = this.listeners.get(element) || {};
        this.listeners.set(element, {
            ...existing,
            longPressStart: handleTouchStart,
            longPressEnd: handleTouchEnd,
            longPressMove: handleTouchMove
        });
    }
    
    /**
     * Add double tap gesture listener
     * @param {HTMLElement} element 
     * @param {Function} handler 
     * @param {Number} delay - Max delay between taps (default 300ms)
     */
    addDoubleTapListener(element, handler, delay = 300) {
        let lastTap = 0;
        
        const handleTouchEnd = (e) => {
            const currentTime = new Date().getTime();
            const tapLength = currentTime - lastTap;
            
            if (tapLength < delay && tapLength > 0) {
                handler(e);
                e.preventDefault();
            }
            
            lastTap = currentTime;
        };
        
        element.addEventListener('touchend', handleTouchEnd);
        
        // Store listeners for cleanup
        const existing = this.listeners.get(element) || {};
        this.listeners.set(element, {
            ...existing,
            doubleTap: handleTouchEnd
        });
    }
    
    /**
     * Add drag gesture listener
     * @param {HTMLElement} element 
     * @param {Object} handlers - { onDragStart, onDrag, onDragEnd }
     */
    addDragListener(element, handlers) {
        let isDragging = false;
        let startX = 0;
        let startY = 0;
        let currentX = 0;
        let currentY = 0;
        
        const handleTouchStart = (e) => {
            isDragging = true;
            const touch = e.touches[0];
            startX = touch.pageX;
            startY = touch.pageY;
            currentX = startX;
            currentY = startY;
            
            if (handlers.onDragStart) {
                handlers.onDragStart({ x: startX, y: startY });
            }
            
            e.preventDefault();
        };
        
        const handleTouchMove = (e) => {
            if (!isDragging) return;
            
            const touch = e.touches[0];
            currentX = touch.pageX;
            currentY = touch.pageY;
            
            if (handlers.onDrag) {
                handlers.onDrag({
                    x: currentX,
                    y: currentY,
                    deltaX: currentX - startX,
                    deltaY: currentY - startY
                });
            }
            
            e.preventDefault();
        };
        
        const handleTouchEnd = (e) => {
            if (!isDragging) return;
            
            isDragging = false;
            
            if (handlers.onDragEnd) {
                handlers.onDragEnd({
                    x: currentX,
                    y: currentY,
                    deltaX: currentX - startX,
                    deltaY: currentY - startY
                });
            }
        };
        
        element.addEventListener('touchstart', handleTouchStart, { passive: false });
        element.addEventListener('touchmove', handleTouchMove, { passive: false });
        element.addEventListener('touchend', handleTouchEnd, { passive: false });
        
        // Store listeners for cleanup
        const existing = this.listeners.get(element) || {};
        this.listeners.set(element, {
            ...existing,
            dragStart: handleTouchStart,
            dragMove: handleTouchMove,
            dragEnd: handleTouchEnd
        });
    }
    
    /**
     * Remove all gesture listeners from an element
     * @param {HTMLElement} element 
     */
    removeAllListeners(element) {
        const listeners = this.listeners.get(element);
        if (!listeners) return;
        
        // Remove swipe listeners
        if (listeners.touchstart) {
            element.removeEventListener('touchstart', listeners.touchstart);
        }
        if (listeners.touchend) {
            element.removeEventListener('touchend', listeners.touchend);
        }
        
        // Remove pinch listeners
        if (listeners.pinchStart) {
            element.removeEventListener('touchstart', listeners.pinchStart);
            element.removeEventListener('touchmove', listeners.pinchMove);
            element.removeEventListener('touchend', listeners.pinchEnd);
        }
        
        // Remove long press listeners
        if (listeners.longPressStart) {
            element.removeEventListener('touchstart', listeners.longPressStart);
            element.removeEventListener('touchend', listeners.longPressEnd);
            element.removeEventListener('touchmove', listeners.longPressMove);
        }
        
        // Remove double tap listener
        if (listeners.doubleTap) {
            element.removeEventListener('touchend', listeners.doubleTap);
        }
        
        // Remove drag listeners
        if (listeners.dragStart) {
            element.removeEventListener('touchstart', listeners.dragStart);
            element.removeEventListener('touchmove', listeners.dragMove);
            element.removeEventListener('touchend', listeners.dragEnd);
        }
        
        this.listeners.delete(element);
    }
    
    /**
     * Utility: Check if device supports touch
     */
    static isTouchDevice() {
        return 'ontouchstart' in window || 
               navigator.maxTouchPoints > 0 || 
               navigator.msMaxTouchPoints > 0;
    }
    
    /**
     * Utility: Get touch position
     */
    static getTouchPosition(e) {
        const touch = e.touches[0] || e.changedTouches[0];
        return {
            x: touch.pageX,
            y: touch.pageY,
            clientX: touch.clientX,
            clientY: touch.clientY
        };
    }
    
    /**
     * Utility: Prevent default touch behavior
     */
    static preventDefaultTouch(element) {
        element.addEventListener('touchstart', (e) => e.preventDefault(), { passive: false });
        element.addEventListener('touchmove', (e) => e.preventDefault(), { passive: false });
    }
}