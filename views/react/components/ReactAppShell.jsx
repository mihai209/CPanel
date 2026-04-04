import React from 'react';
import { NavLink } from 'react-router-dom';
import { ReactRoutes, resolveBrandImage, resolveUserAvatar } from '../ReactRoutes.js';

function InternalTopAction({ to, icon, title }) {
    return (
        <NavLink
            to={to}
            title={title}
            className={({ isActive }) => `react-top-action${isActive ? ' is-active' : ''}`}
        >
            <i className={`bi ${icon}`}></i>
        </NavLink>
    );
}

export default function ReactAppShell({
    pageData = {},
    subtitle = 'React view beta',
    pageClassName = '',
    shellClassName = '',
    children
}) {
    const brandImage = resolveBrandImage(pageData);
    const userAvatar = resolveUserAvatar(pageData.user || {}, brandImage);

    return (
        <div className={`react-basic-page${pageClassName ? ` ${pageClassName}` : ''}`}>
            <div className={`react-basic-shell${shellClassName ? ` ${shellClassName}` : ''}`}>
                <header className="react-basic-topbar">
                    <div className="react-basic-brand">
                        <div className="react-basic-brand-mark">
                            <img src={brandImage} alt={pageData.brandName || 'CPanel'} className="react-brand-image" />
                        </div>
                        <div>
                            <div className="react-basic-brand-title">{pageData.brandName || 'CPanel'}</div>
                            <div className="react-basic-brand-subtitle">{subtitle}</div>
                        </div>
                    </div>

                    <div className="react-basic-actions">
                        <InternalTopAction to={ReactRoutes.dashboard} icon="bi-grid-1x2" title="Dashboard" />
                        <InternalTopAction to={ReactRoutes.experimentalFeatures} icon="bi-sliders" title="Experimental Features" />
                        <InternalTopAction to={ReactRoutes.account} icon="bi-person" title="Account" />
                        <a className="react-top-action" href={ReactRoutes.themes} title="Themes">
                            <i className="bi bi-palette2"></i>
                        </a>
                        <div className="react-basic-user">
                            <img
                                src={userAvatar}
                                alt={pageData.user && pageData.user.username ? pageData.user.username : 'User'}
                                className="react-basic-user-avatar"
                            />
                            <span>{pageData.user && pageData.user.username ? `@${pageData.user.username}` : 'Unknown'}</span>
                        </div>
                    </div>
                </header>
                {children}
            </div>
        </div>
    );
}
