import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes, useLocation } from 'react-router-dom';
import { ReactRoutes, resolveServerReactPage } from './ReactRoutes.js';
import { DashboardPage } from './dashboard.jsx';
import { ServerConsolePage } from './server-console.jsx';
import { ServerFilesPage } from './server-files.jsx';
import { ServerBackupsPage } from './server-backups.jsx';
import { ServerNetworkPage } from './server-network.jsx';
import { ServerApiPage } from './server-api.jsx';
import { ServerDatabasesPage } from './server-databases.jsx';
import { ServerUsersPage } from './server-users.jsx';
import { ServerSchedulesPage } from './server-schedules.jsx';
import { ServerStartupPage } from './server-startup.jsx';
import { ServerFileEditorPage } from './server-file-editor.jsx';
import { ServerMinecraftCenterPage } from './server-minecraft-center.jsx';
import { ServerMinecraftWorldCenterPage } from './server-minecraft-world-center.jsx';
import { ServerMinecraftAddonsPage } from './server-minecraft-addons.jsx';
import { ServerMinecraftInstallerPage } from './server-minecraft-installer.jsx';
import { ServerMinecraftAdminPage } from './server-minecraft-admin.jsx';
import { ServerMinecraftConfigsPage } from './server-minecraft-configs.jsx';
import { ServerOverviewPage } from './server-overview.jsx';
import { ServerActivityPage } from './server-activity.jsx';
import { ServerTimelinePage } from './server-timeline.jsx';
import { ServerNotFoundPage } from './server-not-found.jsx';
import { ServerNoPermissionsPage } from './server-no-permissions.jsx';
import { ServerSuspendedPage } from './server-suspended.jsx';
import { AccountPage } from './account.jsx';
import { DeviceLoginPage } from './device-login.jsx';
import { ExperimentalFeaturesPage } from './experimental-features.jsx';
import { ChangeViewPage } from './change-view.jsx';
import ReactAppShell from './components/ReactAppShell.jsx';

const initialPageData = window.__CPANEL_REACT_PAGE_DATA__ || {};
const root = createRoot(document.getElementById('reactRoot'));
const HARD_FALLBACK_GUARD_KEY = 'cpanel.react.hard-fallback';

function normalizePathname(pathname) {
    const value = String(pathname || '/').trim();
    if (!value || value === '') return ReactRoutes.dashboard;
    return value.endsWith('/') && value !== '/' ? value.slice(0, -1) : value;
}

function resolveComponentForPath(pathname) {
    const current = normalizePathname(pathname);
    if (current === ReactRoutes.dashboard) return DashboardPage;
    const serverRoute = resolveServerReactPage(current);
    if (serverRoute) {
        if (serverRoute.page === 'console') return ServerConsolePage;
        if (serverRoute.page === 'files') return ServerFilesPage;
        if (serverRoute.page === 'backups') return ServerBackupsPage;
        if (serverRoute.page === 'network') return ServerNetworkPage;
        if (serverRoute.page === 'api') return ServerApiPage;
        if (serverRoute.page === 'databases') return ServerDatabasesPage;
        if (serverRoute.page === 'users') return ServerUsersPage;
        if (serverRoute.page === 'schedules') return ServerSchedulesPage;
        if (serverRoute.page === 'startup') return ServerStartupPage;
        if (serverRoute.page === 'files/edit') return ServerFileEditorPage;
        if (serverRoute.page === 'minecraft-center') return ServerMinecraftCenterPage;
        if (serverRoute.page === 'minecraft/world-center') return ServerMinecraftWorldCenterPage;
        if (serverRoute.page === 'minecraft/addons') return ServerMinecraftAddonsPage;
        if (serverRoute.page === 'minecraft/installer') return ServerMinecraftInstallerPage;
        if (serverRoute.page === 'minecraft/admin') return ServerMinecraftAdminPage;
        if (serverRoute.page === 'minecraft/configs') return ServerMinecraftConfigsPage;
        if (serverRoute.page === 'overview') return ServerOverviewPage;
        if (serverRoute.page === 'activity') return ServerActivityPage;
        if (serverRoute.page === 'timeline') return ServerTimelinePage;
        if (serverRoute.page === 'notfound') return ServerNotFoundPage;
        if (serverRoute.page === 'no-permissions') return ServerNoPermissionsPage;
        if (serverRoute.page === 'suspended') return ServerSuspendedPage;
    }
    if (current === ReactRoutes.account) return AccountPage;
    if (current === ReactRoutes.deviceLogin) return DeviceLoginPage;
    if (current === ReactRoutes.experimentalFeatures) return ExperimentalFeaturesPage;
    if (current === ReactRoutes.changeView) return ChangeViewPage;
    return null;
}

async function fetchReactPageData(pathname, search = '') {
    const target = new URL(`${pathname || '/'}${search || ''}`, window.location.origin);
    target.searchParams.set('__reactData', '1');
    const response = await fetch(target.toString(), {
        headers: {
            Accept: 'application/json',
            'X-React-Page-Data': '1'
        },
        credentials: 'same-origin'
    });
    if (!response.ok) {
        throw new Error(`Failed to load route data (${response.status})`);
    }
    const payload = await response.json();
    if (!payload || typeof payload !== 'object' || !payload.routePath) {
        throw new Error('Invalid route payload');
    }
    return payload;
}

function readHardFallbackGuard() {
    try {
        const raw = sessionStorage.getItem(HARD_FALLBACK_GUARD_KEY);
        return raw ? JSON.parse(raw) : null;
    } catch {
        return null;
    }
}

function clearHardFallbackGuard(pathname = '') {
    try {
        const current = readHardFallbackGuard();
        const normalized = `${pathname || ''}`;
        if (!current || !normalized || current.path === normalized) {
            sessionStorage.removeItem(HARD_FALLBACK_GUARD_KEY);
        }
    } catch {
        // Ignore session storage failures.
    }
}

function performSafeHardFallback(pathname, search = '') {
    const target = `${pathname || '/'}${search || ''}`;
    const now = Date.now();
    const current = readHardFallbackGuard();
    if (current && current.path === target && now - Number(current.at || 0) < 8000) {
        return false;
    }
    try {
        sessionStorage.setItem(HARD_FALLBACK_GUARD_KEY, JSON.stringify({
            path: target,
            at: now
        }));
    } catch {
        // Ignore session storage failures.
    }
    window.location.replace(target);
    return true;
}

function LoadingRoute({ pageData, pathname }) {
    return (
        <ReactAppShell pageData={pageData} subtitle="Loading React route">
            <main className="react-experimental-layout">
                <div className="react-experimental-scroll">
                    <div className="react-account-card">
                        <div className="react-account-section-title">Loading</div>
                        <div className="react-account-muted">{`Loading ${pathname}...`}</div>
                    </div>
                </div>
            </main>
        </ReactAppShell>
    );
}

function FullReloadFallback() {
    const location = useLocation();
    const [blocked, setBlocked] = React.useState(false);
    React.useEffect(() => {
        const didFallback = performSafeHardFallback(location.pathname, location.search || '');
        if (!didFallback) {
            setBlocked(true);
        }
    }, [location.pathname, location.search]);
    if (!blocked) return null;
    return (
        <ReactAppShell pageData={initialPageData} subtitle="React fallback blocked">
            <main className="react-experimental-layout">
                <div className="react-experimental-scroll">
                    <div className="react-account-card">
                        <div className="react-account-section-title">React route fallback was blocked</div>
                        <div className="react-account-muted">
                            The same route tried to hard-reload repeatedly. The auto-reload was stopped to avoid an infinite loop.
                        </div>
                        <div className="react-account-inline-actions" style={{ marginTop: '14px' }}>
                            <a href="/experimental/change-view" className="react-account-button is-primary">Open Change View</a>
                        </div>
                    </div>
                </div>
            </main>
        </ReactAppShell>
    );
}

function RoutedPage() {
    const location = useLocation();
    const pathname = normalizePathname(location.pathname);
    const [pageData, setPageData] = React.useState(initialPageData);
    const [loading, setLoading] = React.useState(false);
    const [fallbackBlocked, setFallbackBlocked] = React.useState(false);

    React.useEffect(() => {
        const targetPath = normalizePathname(location.pathname);
        const currentPath = normalizePathname(pageData.routePath || initialPageData.routePath || '/');
        const PageComponent = resolveComponentForPath(targetPath);
        if (!PageComponent) {
            const didFallback = performSafeHardFallback(location.pathname, location.search || '');
            if (!didFallback) {
                setFallbackBlocked(true);
            }
            return;
        }
        clearHardFallbackGuard(`${location.pathname}${location.search || ''}`);
        setFallbackBlocked(false);
        if (targetPath === currentPath) return;

        let cancelled = false;
        setLoading(true);
        fetchReactPageData(targetPath, location.search || '')
            .then((nextPageData) => {
                if (cancelled) return;
                setPageData(nextPageData);
                setLoading(false);
                clearHardFallbackGuard(`${location.pathname}${location.search || ''}`);
                setFallbackBlocked(false);
            })
            .catch(() => {
                if (cancelled) return;
                const didFallback = performSafeHardFallback(location.pathname, location.search || '');
                if (!didFallback) {
                    setLoading(false);
                    setFallbackBlocked(true);
                }
            });

        return () => {
            cancelled = true;
        };
    }, [location.pathname, location.search, pageData.routePath]);

    const CurrentComponent = resolveComponentForPath(pathname);
    if (!CurrentComponent) {
        return <FullReloadFallback />;
    }
    if (fallbackBlocked) {
        return (
            <ReactAppShell pageData={pageData} subtitle="React route fallback blocked">
                <main className="react-experimental-layout">
                    <div className="react-experimental-scroll">
                        <div className="react-account-card">
                            <div className="react-account-section-title">React route fallback was blocked</div>
                            <div className="react-account-muted">
                                This route kept trying to reload itself. Auto-reload was stopped so you can switch back to EJS or report the route.
                            </div>
                            <div className="react-account-inline-actions" style={{ marginTop: '14px' }}>
                                <a href="/experimental/change-view" className="react-account-button is-primary">Open Change View</a>
                            </div>
                        </div>
                    </div>
                </main>
            </ReactAppShell>
        );
    }
    if (loading && normalizePathname(pageData.routePath || '/') !== pathname) {
        return <LoadingRoute pageData={pageData} pathname={pathname} />;
    }
    return <CurrentComponent pageData={pageData} />;
}

function AppRouter() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path={ReactRoutes.dashboard} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverConsolePattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverFilesPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverBackupsPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverNetworkPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverApiPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverDatabasesPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverUsersPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverSchedulesPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverStartupPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverFilesEditPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverMinecraftCenterPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverMinecraftWorldCenterPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverMinecraftAddonsPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverMinecraftInstallerPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverMinecraftAdminPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverMinecraftConfigsPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverOverviewPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverActivityPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverTimelinePattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverNotFoundPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverNoPermissionsPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.serverSuspendedPattern} element={<RoutedPage />} />
                <Route path={ReactRoutes.account} element={<RoutedPage />} />
                <Route path={ReactRoutes.deviceLogin} element={<RoutedPage />} />
                <Route path={ReactRoutes.experimentalFeatures} element={<RoutedPage />} />
                <Route path={ReactRoutes.changeView} element={<RoutedPage />} />
                <Route path="*" element={<FullReloadFallback />} />
            </Routes>
        </BrowserRouter>
    );
}

root.render(<AppRouter />);
if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
    window.__CPANEL_REACT_BOOTED__();
}
