(() => {
    if (window.__cpanelTurboInitLoaded) return;
    window.__cpanelTurboInitLoaded = true;

    let firstTurboLoadHandled = false;
    const trackedIntervals = new Set();
    const trackedSockets = new Set();

    const nativeSetInterval = window.setInterval.bind(window);
    const nativeClearInterval = window.clearInterval.bind(window);
    const NativeWebSocket = window.WebSocket;

    function patchRuntimeResources() {
        if (!window.__cpanelTurboRuntimePatched) {
            window.__cpanelTurboRuntimePatched = true;

            window.setInterval = function patchedSetInterval(callback, timeout, ...args) {
                const id = nativeSetInterval(callback, timeout, ...args);
                trackedIntervals.add(id);
                return id;
            };

            window.clearInterval = function patchedClearInterval(id) {
                trackedIntervals.delete(id);
                return nativeClearInterval(id);
            };

            if (typeof NativeWebSocket === 'function') {
                const PatchedWebSocket = function (...args) {
                    const socket = new NativeWebSocket(...args);
                    trackedSockets.add(socket);
                    socket.addEventListener('close', () => {
                        trackedSockets.delete(socket);
                    });
                    return socket;
                };

                PatchedWebSocket.prototype = NativeWebSocket.prototype;
                Object.setPrototypeOf(PatchedWebSocket, NativeWebSocket);
                PatchedWebSocket.CONNECTING = NativeWebSocket.CONNECTING;
                PatchedWebSocket.OPEN = NativeWebSocket.OPEN;
                PatchedWebSocket.CLOSING = NativeWebSocket.CLOSING;
                PatchedWebSocket.CLOSED = NativeWebSocket.CLOSED;
                window.WebSocket = PatchedWebSocket;
            }
        }
    }

    function cleanupTrackedResources() {
        trackedIntervals.forEach((id) => {
            try {
                nativeClearInterval(id);
            } catch {
                // ignore
            }
        });
        trackedIntervals.clear();

        trackedSockets.forEach((socket) => {
            try {
                if (socket && socket.readyState === 0) socket.close(1000, 'Turbo navigation');
                if (socket && socket.readyState === 1) socket.close(1000, 'Turbo navigation');
            } catch {
                // ignore
            }
        });
        trackedSockets.clear();
    }

    function dispatchCompatDOMContentLoaded() {
        if (!firstTurboLoadHandled) {
            firstTurboLoadHandled = true;
            return;
        }
        document.dispatchEvent(new Event('DOMContentLoaded'));
    }

    function dispatchPageLifecycleEvents() {
        document.dispatchEvent(new Event('cpanel:page-load'));
    }

    function dispatchBeforeCache() {
        document.dispatchEvent(new Event('cpanel:before-cache'));
    }

    document.addEventListener('turbo:load', () => {
        patchRuntimeResources();
        dispatchCompatDOMContentLoaded();
        dispatchPageLifecycleEvents();
    });

    document.addEventListener('turbo:before-cache', () => {
        cleanupTrackedResources();
        dispatchBeforeCache();
    });

    // Non-Turbo fallback for direct loads or pages with data-turbo disabled.
    document.addEventListener('DOMContentLoaded', () => {
        patchRuntimeResources();
        if (document.documentElement.hasAttribute('data-turbo-preview')) return;
        dispatchPageLifecycleEvents();
    });
})();
