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

    function shouldIsolateInlineScript(script) {
        if (!script || script.src) return false;
        if (script.dataset && script.dataset.turboEval === 'false') return false;
        if (script.dataset && script.dataset.cpanelIsolate === 'false') return false;

        const type = String(script.type || '').trim().toLowerCase();
        if (!type) return true;
        if (type === 'text/javascript' || type === 'application/javascript') return true;
        return false;
    }

    function isolateInlineScriptScopesInBody(bodyEl) {
        if (!bodyEl) return;
        const scripts = bodyEl.querySelectorAll('script');
        scripts.forEach((script) => {
            if (!shouldIsolateInlineScript(script)) return;
            if (script.dataset && script.dataset.cpanelIsolated === '1') return;

            const source = String(script.textContent || '');
            if (!source.trim()) return;

            // Prevent global const/let collisions across Turbo page visits.
            script.textContent = `(function(){\n${source}\n})();`;
            if (script.dataset) {
                script.dataset.cpanelIsolated = '1';
            }
        });
    }

    function applyFormTurboCompatibility() {
        // Turbo is great for page navigation, but legacy forms can violate Turbo redirect rules.
        // Keep forms native by default. Explicitly opt-in with data-turbo="true" where needed.
        const forms = document.querySelectorAll('form');
        forms.forEach((form) => {
            if (!(form instanceof HTMLFormElement)) return;
            if (form.getAttribute('data-turbo') === 'true') return;
            form.setAttribute('data-turbo', 'false');
        });
    }

    document.addEventListener('turbo:load', () => {
        patchRuntimeResources();
        applyFormTurboCompatibility();
        dispatchCompatDOMContentLoaded();
        dispatchPageLifecycleEvents();
    });

    document.addEventListener('turbo:before-cache', () => {
        cleanupTrackedResources();
        dispatchBeforeCache();
    });

    document.addEventListener('turbo:before-render', (event) => {
        const newBody = event && event.detail ? event.detail.newBody : null;
        isolateInlineScriptScopesInBody(newBody);
    });

    // Non-Turbo fallback for direct loads or pages with data-turbo disabled.
    document.addEventListener('DOMContentLoaded', () => {
        patchRuntimeResources();
        applyFormTurboCompatibility();
        if (document.documentElement.hasAttribute('data-turbo-preview')) return;
        dispatchPageLifecycleEvents();
    });
})();
