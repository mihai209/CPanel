import React from 'react';
import { createRoot } from 'react-dom/client';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const root = createRoot(document.getElementById('reactRoot'));

function resolveBrandImage() {
    return data.faviconUrl || '/assets/rocky.png';
}

function resolveUserAvatar(user) {
    if (user && user.avatarProvider === 'url' && user.avatarUrl) {
        return user.avatarUrl;
    }
    if (user && user.gravatarHash) {
        return `https://www.gravatar.com/avatar/${user.gravatarHash}?d=retro&s=120`;
    }
    return resolveBrandImage();
}

function TopAction({ href, icon, title }) {
    return (
        <a className="react-top-action" href={href} title={title}>
            <i className={`bi ${icon}`}></i>
        </a>
    );
}

function LinkedProviderCard({ provider }) {
    return (
        <div className="react-account-provider">
            <div className="react-account-provider-main">
                <i className={`bi ${provider.icon}`} style={{ color: provider.color }}></i>
                <div>
                    <strong>{provider.name}</strong>
                    <span>{provider.isLinked ? 'Linked to this account' : 'Available to connect'}</span>
                </div>
            </div>
            {provider.isLinked ? (
                <form method="POST" action={provider.unlinkAction}>
                    <button type="submit" className="react-account-button is-danger">Unlink</button>
                </form>
            ) : (
                <a href={provider.linkAction} className="react-account-button is-ghost">Connect</a>
            )}
        </div>
    );
}

function AccountApp() {
    const user = data.user || {};
    const linkedProviders = Array.isArray(data.linkedProviders) ? data.linkedProviders : [];
    const avatar = resolveUserAvatar(user);
    const brandImage = resolveBrandImage();
    const [setupState, setSetupState] = React.useState({ loading: false, qrCodeUrl: '', secret: '', code: '', error: '' });
    const [disableState, setDisableState] = React.useState({ password: '', loading: false, error: '' });

    const start2FASetup = async () => {
        setSetupState((current) => ({ ...current, loading: true, error: '' }));
        try {
            const response = await fetch('/account/2fa/setup');
            const payload = await response.json();
            if (!response.ok || payload.error) {
                throw new Error(payload.error || 'Failed to initialize 2FA.');
            }
            setSetupState({
                loading: false,
                qrCodeUrl: payload.qrCodeUrl || '',
                secret: payload.secret || '',
                code: '',
                error: ''
            });
        } catch (error) {
            setSetupState((current) => ({
                ...current,
                loading: false,
                error: error && error.message ? error.message : 'Failed to initialize 2FA.'
            }));
        }
    };

    const enable2FA = async () => {
        if (!setupState.code || setupState.code.trim().length !== 6) {
            setSetupState((current) => ({ ...current, error: 'Enter the 6-digit code from your authenticator app.' }));
            return;
        }
        setSetupState((current) => ({ ...current, loading: true, error: '' }));
        try {
            const response = await fetch('/account/2fa/enable', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: setupState.code.trim() })
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) {
                throw new Error(payload.error || 'Failed to enable 2FA.');
            }
            window.location.replace('/account?success=' + encodeURIComponent('2FA enabled successfully.'));
        } catch (error) {
            setSetupState((current) => ({
                ...current,
                loading: false,
                error: error && error.message ? error.message : 'Failed to enable 2FA.'
            }));
        }
    };

    const disable2FA = async () => {
        if (!disableState.password) {
            setDisableState((current) => ({ ...current, error: 'Current password is required.' }));
            return;
        }
        setDisableState((current) => ({ ...current, loading: true, error: '' }));
        try {
            const response = await fetch('/account/2fa/disable', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: disableState.password })
            });
            const payload = await response.json();
            if (!response.ok || !payload.success) {
                throw new Error(payload.error || 'Failed to disable 2FA.');
            }
            window.location.replace('/account?success=' + encodeURIComponent('2FA disabled successfully.'));
        } catch (error) {
            setDisableState((current) => ({
                ...current,
                loading: false,
                error: error && error.message ? error.message : 'Failed to disable 2FA.'
            }));
        }
    };

    return (
        <div className="react-basic-page react-account-page">
            <div className="react-basic-shell react-account-shell">
                <header className="react-basic-topbar">
                    <div className="react-basic-brand">
                        <div className="react-basic-brand-mark">
                            <img src={brandImage} alt={data.brandName || 'CPanel'} className="react-brand-image" />
                        </div>
                        <div>
                            <div className="react-basic-brand-title">{data.brandName || 'CPanel'}</div>
                            <div className="react-basic-brand-subtitle">Account surface</div>
                        </div>
                    </div>

                    <div className="react-basic-actions">
                        <TopAction href="/" icon="bi-grid-1x2" title="Dashboard" />
                        <TopAction href="/experimental-features" icon="bi-sliders" title="Experimental Features" />
                        <TopAction href="/themes" icon="bi-palette2" title="Themes" />
                        <div className="react-basic-user">
                            <img src={avatar} alt={user.username || 'User'} className="react-basic-user-avatar" />
                            <span>{user.username ? `@${user.username}` : 'Unknown'}</span>
                        </div>
                    </div>
                </header>

                <main className="react-account-layout">
                    <section className="react-account-main">
                        <div className="react-account-scroll">
                            {data.success ? (
                                <div className="react-account-flash is-success">{data.success}</div>
                            ) : null}
                            {data.error ? (
                                <div className="react-account-flash is-danger">{data.error}</div>
                            ) : null}

                            <div className="react-account-grid">
                                <div className="react-account-card react-account-profile-card">
                                    <div className="react-account-profile">
                                        <img src={avatar} alt={user.username || 'User'} className="react-account-avatar" />
                                        <div>
                                            <h1>{[user.firstName, user.lastName].filter(Boolean).join(' ') || user.username || 'Account'}</h1>
                                            <div className="react-account-username">@{user.username || 'unknown'}</div>
                                            <div className="react-account-email">{user.email || 'No email set'}</div>
                                        </div>
                                    </div>
                                    <div className="react-account-badges">
                                        <span className={`react-account-badge ${user.twoFactorEnabled ? 'is-success' : 'is-muted'}`}>
                                            {user.twoFactorEnabled ? '2FA Active' : '2FA Inactive'}
                                        </span>
                                        <span className="react-account-badge is-info">Theme: {data.activeTheme || 'default'}</span>
                                    </div>
                                    <div className="react-account-inline-actions">
                                        <a href="/account/device-login" className="react-account-button is-ghost">Device History</a>
                                        <a href="/themes" className="react-account-button is-ghost">Themes</a>
                                        <a href="/experimental-features" className="react-account-button is-ghost">Experimental</a>
                                    </div>
                                </div>

                                <div className="react-account-card">
                                    <div className="react-account-section-title">Account Details</div>
                                    <form method="POST" action="/account/update" className="react-account-form">
                                        <div className="react-account-form-grid">
                                            <label>
                                                <span>First Name</span>
                                                <input type="text" name="firstName" defaultValue={user.firstName || ''} required />
                                            </label>
                                            <label>
                                                <span>Last Name</span>
                                                <input type="text" name="lastName" defaultValue={user.lastName || ''} required />
                                            </label>
                                        </div>
                                        <label>
                                            <span>Email</span>
                                            <input type="email" name="email" defaultValue={user.email || ''} required />
                                        </label>
                                        <div className="react-account-form-grid">
                                            <label>
                                                <span>Avatar Provider</span>
                                                <select name="avatarProvider" defaultValue={user.avatarProvider || 'gravatar'}>
                                                    <option value="gravatar">Gravatar</option>
                                                    <option value="url">Custom URL</option>
                                                </select>
                                            </label>
                                            <label>
                                                <span>Avatar URL</span>
                                                <input type="url" name="avatarUrl" defaultValue={user.avatarUrl || ''} placeholder="https://example.com/avatar.png" />
                                            </label>
                                        </div>
                                        <label>
                                            <span>Username</span>
                                            <input type="text" value={user.username || ''} readOnly />
                                        </label>
                                        <div className="react-account-form-actions">
                                            <button type="submit" className="react-account-button is-primary">Save Account</button>
                                        </div>
                                    </form>
                                </div>

                                <div className="react-account-card">
                                    <div className="react-account-section-title">Update Password</div>
                                    <form method="POST" action="/account/password" className="react-account-form">
                                        <label>
                                            <span>Current Password</span>
                                            <input type="password" name="currentPassword" required />
                                        </label>
                                        <label>
                                            <span>New Password</span>
                                            <input type="password" name="newPassword" required />
                                        </label>
                                        <label>
                                            <span>Confirm New Password</span>
                                            <input type="password" name="confirmPassword" required />
                                        </label>
                                        <div className="react-account-form-actions">
                                            <button type="submit" className="react-account-button is-primary">Update Password</button>
                                        </div>
                                    </form>
                                </div>

                                <div className="react-account-card">
                                    <div className="react-account-section-title">Linked Accounts</div>
                                    <div className="react-account-provider-list">
                                        {linkedProviders.length > 0 ? linkedProviders.map((provider) => (
                                            <LinkedProviderCard key={provider.id} provider={provider} />
                                        )) : (
                                            <div className="react-account-muted">No external providers are configured for this account yet.</div>
                                        )}
                                    </div>
                                </div>

                                <div className="react-account-card">
                                    <div className="react-account-section-title">Two-Factor Authentication</div>
                                    {user.twoFactorEnabled ? (
                                        <div className="react-account-twofa-block">
                                            <div className="react-account-muted">Two-factor authentication is enabled. Enter your current password to disable it.</div>
                                            <label>
                                                <span>Current Password</span>
                                                <input
                                                    type="password"
                                                    value={disableState.password}
                                                    onChange={(event) => setDisableState((current) => ({ ...current, password: event.target.value }))}
                                                />
                                            </label>
                                            {disableState.error ? <div className="react-account-inline-error">{disableState.error}</div> : null}
                                            <button type="button" className="react-account-button is-danger" onClick={disable2FA} disabled={disableState.loading}>
                                                {disableState.loading ? 'Disabling...' : 'Disable 2FA'}
                                            </button>
                                        </div>
                                    ) : (
                                        <div className="react-account-twofa-block">
                                            <div className="react-account-muted">Start setup to receive a QR code and manual secret for your authenticator app.</div>
                                            <button type="button" className="react-account-button is-primary" onClick={start2FASetup} disabled={setupState.loading}>
                                                {setupState.loading ? 'Loading...' : 'Start 2FA Setup'}
                                            </button>
                                            {setupState.qrCodeUrl ? (
                                                <div className="react-account-twofa-setup">
                                                    <div className="react-account-twofa-qr-wrap">
                                                        <img src={setupState.qrCodeUrl} alt="2FA QR code" className="react-account-twofa-qr" />
                                                    </div>
                                                    <label>
                                                        <span>Manual Secret</span>
                                                        <input type="text" value={setupState.secret} readOnly />
                                                    </label>
                                                    <label>
                                                        <span>Verification Code</span>
                                                        <input
                                                            type="text"
                                                            value={setupState.code}
                                                            maxLength={6}
                                                            onChange={(event) => setSetupState((current) => ({ ...current, code: event.target.value.replace(/[^0-9]/g, '') }))}
                                                            placeholder="000000"
                                                        />
                                                    </label>
                                                    {setupState.error ? <div className="react-account-inline-error">{setupState.error}</div> : null}
                                                    <button type="button" className="react-account-button is-primary" onClick={enable2FA} disabled={setupState.loading}>
                                                        {setupState.loading ? 'Verifying...' : 'Verify and Enable'}
                                                    </button>
                                                </div>
                                            ) : null}
                                            {!setupState.qrCodeUrl && setupState.error ? <div className="react-account-inline-error">{setupState.error}</div> : null}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </section>
                </main>
            </div>
        </div>
    );
}

root.render(<AccountApp />);
if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
    window.__CPANEL_REACT_BOOTED__();
}
