import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes, useLocation } from 'react-router-dom';
import { ReactRoutes, isServerConsolePath } from './ReactRoutes.js';
import { DashboardPage } from './dashboard.jsx';
import { ServerConsolePage } from './server-console.jsx';
import { AccountPage } from './account.jsx';
import { DeviceLoginPage } from './device-login.jsx';
import { ExperimentalFeaturesPage } from './experimental-features.jsx';
import { ChangeViewPage } from './change-view.jsx';
import ReactAppShell from './components/ReactAppShell.jsx';

const initialPageData = window.__CPANEL_REACT_PAGE_DATA__ || {};
const root = createRoot(document.getElementById('reactRoot'));

function normalizePathname(pathname) {
    const value = String(pathname || '/').trim();
    if (!value || value === '') return ReactRoutes.dashboard;
    return value.endsWith('/') && value !== '/' ? value.slice(0, -1) : value;
}

function resolveComponentForPath(pathname) {
    const current = normalizePathname(pathname);
    if (current === ReactRoutes.dashboard) return DashboardPage;
    if (isServerConsolePath(current)) return ServerConsolePage;
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
    React.useEffect(() => {
        window.location.assign(`${location.pathname}${location.search || ''}`);
    }, [location.pathname, location.search]);
    return null;
}

function RoutedPage() {
    const location = useLocation();
    const pathname = normalizePathname(location.pathname);
    const [pageData, setPageData] = React.useState(initialPageData);
    const [loading, setLoading] = React.useState(false);

    React.useEffect(() => {
        const targetPath = normalizePathname(location.pathname);
        const currentPath = normalizePathname(pageData.routePath || initialPageData.routePath || '/');
        const PageComponent = resolveComponentForPath(targetPath);
        if (!PageComponent) {
            window.location.assign(`${location.pathname}${location.search || ''}`);
            return;
        }
        if (targetPath === currentPath) return;

        let cancelled = false;
        setLoading(true);
        fetchReactPageData(targetPath, location.search || '')
            .then((nextPageData) => {
                if (cancelled) return;
                setPageData(nextPageData);
                setLoading(false);
            })
            .catch(() => {
                if (cancelled) return;
                window.location.assign(`${location.pathname}${location.search || ''}`);
            });

        return () => {
            cancelled = true;
        };
    }, [location.pathname, location.search, pageData.routePath]);

    const CurrentComponent = resolveComponentForPath(pathname);
    if (!CurrentComponent) {
        return <FullReloadFallback />;
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
