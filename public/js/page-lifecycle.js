(() => {
    if (window.__cpanelPageLifecycleLoaded) return;
    window.__cpanelPageLifecycleLoaded = true;

    function dispatchLoadEvents() {
        document.dispatchEvent(new Event('turbo:load'));
        document.dispatchEvent(new Event('cpanel:page-load'));
    }

    function dispatchBeforeCacheEvents() {
        document.dispatchEvent(new Event('turbo:before-cache'));
        document.dispatchEvent(new Event('cpanel:before-cache'));
    }

    document.addEventListener('DOMContentLoaded', dispatchLoadEvents, { once: true });
    window.addEventListener('beforeunload', dispatchBeforeCacheEvents);
})();
