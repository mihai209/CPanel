(function themeLoader() {
    let lifecycleBound = false;

    function moveThemeStylesheetLast() {
        const link = document.getElementById('cpanel-theme-css');
        if (!link || !document.head) return;
        document.head.appendChild(link);
    }

    function bindLifecycleEvents() {
        if (lifecycleBound) return;
        lifecycleBound = true;
        document.addEventListener('turbo:load', moveThemeStylesheetLast);
    }

    bindLifecycleEvents();
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', moveThemeStylesheetLast, { once: true });
    } else {
        moveThemeStylesheetLast();
    }
})();
