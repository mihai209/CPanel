(() => {
    if (window.__cpanelMobileLayoutLoaded) return;
    window.__cpanelMobileLayoutLoaded = true;

    const MOBILE_QUERY = '(max-width: 991.98px)';

    function isMobileView() {
        return window.matchMedia(MOBILE_QUERY).matches;
    }

    function setupAdminSidebarMobile() {
        const sidebar = document.getElementById('adminSidebar');
        const toggle = document.getElementById('adminSidebarMobileToggle');
        const backdrop = document.getElementById('adminSidebarBackdrop');
        if (!sidebar || !toggle || !backdrop) return;
        if (toggle.dataset.mobileBound === '1') return;
        toggle.dataset.mobileBound = '1';

        const openSidebar = () => {
            if (!isMobileView()) return;
            sidebar.classList.add('show-mobile');
            backdrop.classList.add('show');
            document.body.classList.add('admin-sidebar-open');
        };

        const closeSidebar = () => {
            sidebar.classList.remove('show-mobile');
            backdrop.classList.remove('show');
            document.body.classList.remove('admin-sidebar-open');
        };

        toggle.addEventListener('click', (event) => {
            event.preventDefault();
            if (sidebar.classList.contains('show-mobile')) {
                closeSidebar();
            } else {
                openSidebar();
            }
        });

        backdrop.addEventListener('click', closeSidebar);

        sidebar.querySelectorAll('a.nav-link').forEach((link) => {
            if (link.dataset.mobileCloseBound === '1') return;
            link.dataset.mobileCloseBound = '1';
            link.addEventListener('click', () => {
                if (isMobileView()) closeSidebar();
            });
        });

        window.addEventListener('resize', () => {
            if (!isMobileView()) closeSidebar();
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') closeSidebar();
        });
    }

    function setupServerSidebarMobile() {
        const sidebar = document.getElementById('sidebar');
        const toggle = document.getElementById('sidebarToggle');
        if (!sidebar || !toggle) return;
        if (toggle.dataset.mobileSidebarBound === '1') return;
        toggle.dataset.mobileSidebarBound = '1';

        let backdrop = document.getElementById('serverSidebarBackdrop');
        if (!backdrop) {
            backdrop = document.createElement('div');
            backdrop.id = 'serverSidebarBackdrop';
            backdrop.className = 'server-sidebar-backdrop';
            document.body.appendChild(backdrop);
        }

        const openSidebar = () => {
            if (!isMobileView()) return;
            sidebar.classList.add('show');
            sidebar.classList.add('open');
            sidebar.classList.remove('collapsed');
            backdrop.classList.add('show');
            document.body.classList.add('server-sidebar-open');
        };

        const closeSidebar = () => {
            sidebar.classList.remove('show');
            sidebar.classList.remove('open');
            backdrop.classList.remove('show');
            document.body.classList.remove('server-sidebar-open');
        };

        // Capture phase: prevents page-level handlers from toggling collapsed in reverse on mobile.
        toggle.addEventListener('click', (event) => {
            if (!isMobileView()) return;
            event.preventDefault();
            event.stopImmediatePropagation();
            if (sidebar.classList.contains('show') || sidebar.classList.contains('open')) {
                closeSidebar();
            } else {
                openSidebar();
            }
        }, true);

        backdrop.addEventListener('click', closeSidebar);
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') closeSidebar();
        });

        window.addEventListener('resize', () => {
            if (!isMobileView()) closeSidebar();
        });
    }

    function enhanceTablesResponsive() {
        const tables = document.querySelectorAll('table.table, table.table-dark, table[data-responsive-table="true"]');
        tables.forEach((table) => {
            if (!(table instanceof HTMLElement)) return;
            if (table.dataset.responsiveWrapped === '1') return;
            if (table.closest('.table-responsive')) {
                table.dataset.responsiveWrapped = '1';
                return;
            }

            const wrapper = document.createElement('div');
            wrapper.className = 'table-responsive';
            table.parentNode.insertBefore(wrapper, table);
            wrapper.appendChild(table);
            table.dataset.responsiveWrapped = '1';
        });
    }

    function initMobileLayout() {
        setupAdminSidebarMobile();
        setupServerSidebarMobile();
        enhanceTablesResponsive();
    }

    document.addEventListener('DOMContentLoaded', initMobileLayout, { once: true });
    document.addEventListener('cpanel:page-load', initMobileLayout);
    document.addEventListener('cpanel:before-cache', () => {
        document.body.classList.remove('admin-sidebar-open', 'server-sidebar-open');
        const adminBackdrop = document.getElementById('adminSidebarBackdrop');
        if (adminBackdrop) adminBackdrop.classList.remove('show');
        const serverBackdrop = document.getElementById('serverSidebarBackdrop');
        if (serverBackdrop) serverBackdrop.classList.remove('show');
        const adminSidebar = document.getElementById('adminSidebar');
        if (adminSidebar) adminSidebar.classList.remove('show-mobile');
        const serverSidebar = document.getElementById('sidebar');
        if (serverSidebar) {
            serverSidebar.classList.remove('show');
            serverSidebar.classList.remove('open');
        }
    });
})();
