(() => {
    if (window.__cpanelNavbarDropdownLoaded) return;
    window.__cpanelNavbarDropdownLoaded = true;

    const initialized = new WeakSet();

    function getDropdownToggles() {
        return document.querySelectorAll('.navbar .dropdown-toggle[data-bs-toggle="dropdown"]');
    }

    function initNavbarDropdowns() {
        if (!window.bootstrap || !window.bootstrap.Dropdown) return;

        const toggles = getDropdownToggles();
        toggles.forEach((toggle) => {
            if (!(toggle instanceof HTMLElement)) return;
            if (!initialized.has(toggle)) {
                toggle.addEventListener('click', (event) => {
                    // Fallback safety for Turbo restoration edge-cases.
                    if (!window.bootstrap || !window.bootstrap.Dropdown) return;
                    event.preventDefault();
                    event.stopPropagation();
                    const instance = window.bootstrap.Dropdown.getOrCreateInstance(toggle, { autoClose: true });
                    instance.toggle();
                });
                initialized.add(toggle);
            }

            window.bootstrap.Dropdown.getOrCreateInstance(toggle, { autoClose: true });
        });
    }

    function cleanupNavbarDropdowns() {
        if (!window.bootstrap || !window.bootstrap.Dropdown) return;
        getDropdownToggles().forEach((toggle) => {
            const instance = window.bootstrap.Dropdown.getInstance(toggle);
            if (instance) instance.dispose();
        });
    }

    document.addEventListener('turbo:load', initNavbarDropdowns);
    document.addEventListener('turbo:before-cache', cleanupNavbarDropdowns);
    document.addEventListener('DOMContentLoaded', initNavbarDropdowns, { once: true });
})();
