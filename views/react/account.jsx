import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes, resolveBrandImage, resolveUserAvatar } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'account';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function LinkedProviderCard({ provider }) {
    return (
        <div className="bg-neutral-900 border border-neutral-700/50 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between mb-2">
            <div className="flex items-center gap-3">
                <i className={`bi ${provider.icon} text-2xl`} style={{ color: provider.color }}></i>
                <div>
                    <strong className="block text-sm font-bold text-neutral-200">{provider.name}</strong>
                    <span className="text-xs text-neutral-400">{provider.isLinked ? 'Linked to this account' : 'Available to connect'}</span>
                </div>
            </div>
            <div className="mt-4 sm:mt-0 shrink-0">
                {provider.isLinked ? (
                    <form method="POST" action={provider.unlinkAction}>
                        <button type="submit" className="bg-red-600/20 hover:bg-red-600/30 text-red-400 hover:text-red-300 border border-red-600/30 text-xs font-semibold py-1.5 px-4 rounded transition-colors w-full sm:w-auto">
                            Unlink
                        </button>
                    </form>
                ) : (
                    <a href={provider.linkAction} className="inline-block bg-neutral-700 hover:bg-neutral-600 text-neutral-200 text-xs font-semibold py-1.5 px-4 rounded transition-colors text-center w-full sm:w-auto">
                        Connect
                    </a>
                )}
            </div>
        </div>
    );
}

export function AccountPage({ pageData = data }) {
    const user = pageData.user || {};
    const linkedProviders = Array.isArray(pageData.linkedProviders) ? pageData.linkedProviders : [];
    const avatar = resolveUserAvatar(user, resolveBrandImage(pageData));
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

    const inputClass = "w-full bg-neutral-900 border border-neutral-700/50 rounded p-2.5 text-sm text-neutral-200 focus:ring-2 focus:ring-primary-500 focus:border-transparent outline-none transition-shadow";
    const labelClass = "block text-xs font-bold text-neutral-400 uppercase tracking-wide mb-1.5";

    return (
        <ReactAppShell pageData={pageData} subtitle="Account surface">
            <PageContentBlock title="Your Account">
                {pageData.success && (
                    <div className="bg-green-600/20 border border-green-600/50 text-green-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3">
                        <i className="bi bi-check-circle-fill text-green-500"></i>
                        {pageData.success}
                    </div>
                )}
                {pageData.error && (
                    <div className="bg-red-600/20 border border-red-600/50 text-red-100 p-4 rounded-lg mb-6 shadow-sm flex items-center gap-3">
                        <i className="bi bi-exclamation-triangle-fill text-red-500"></i>
                        {pageData.error}
                    </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                    
                    {/* Left Column (Profile & Integrations) */}
                    <div className="lg:col-span-4 flex flex-col gap-6">
                        
                        {/* Profile Card */}
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                            <div className="flex flex-col items-center text-center">
                                <img src={avatar} alt={user.username || 'User'} className="w-24 h-24 rounded-full border-4 border-neutral-700 shadow-md mb-4" />
                                <h1 className="text-xl font-bold text-white leading-tight">
                                    {[user.firstName, user.lastName].filter(Boolean).join(' ') || user.username || 'Account'}
                                </h1>
                                <div className="text-sm text-neutral-400 mt-1 font-mono">@{user.username || 'unknown'}</div>
                                <div className="text-sm text-neutral-500 mt-0.5">{user.email || 'No email set'}</div>
                                
                                <div className="flex flex-wrap items-center justify-center gap-2 mt-4">
                                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide ${user.twoFactorEnabled ? 'bg-green-600/20 text-green-400 border border-green-600/30' : 'bg-neutral-700 text-neutral-400'}`}>
                                        {user.twoFactorEnabled ? '2FA Active' : '2FA Inactive'}
                                    </span>
                                    <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide bg-primary-600/20 text-primary-400 border border-primary-600/30">
                                        Theme: {pageData.activeTheme || 'default'}
                                    </span>
                                </div>
                            </div>
                            
                            <div className="mt-8 flex flex-col gap-2">
                                <Link to={ReactRoutes.deviceLogin} className="w-full bg-neutral-700/50 hover:bg-neutral-700 text-neutral-300 text-sm font-semibold py-2 px-4 rounded transition-colors text-center border border-transparent hover:border-neutral-600 flex justify-center items-center gap-2">
                                    <i className="bi bi-clock-history"></i> Device History
                                </Link>
                                <a href={ReactRoutes.themes} className="w-full bg-neutral-700/50 hover:bg-neutral-700 text-neutral-300 text-sm font-semibold py-2 px-4 rounded transition-colors text-center border border-transparent hover:border-neutral-600 flex justify-center items-center gap-2">
                                    <i className="bi bi-palette2"></i> Themes
                                </a>
                                <Link to={ReactRoutes.experimentalFeatures} className="w-full bg-neutral-700/50 hover:bg-neutral-700 text-neutral-300 text-sm font-semibold py-2 px-4 rounded transition-colors text-center border border-transparent hover:border-neutral-600 flex justify-center items-center gap-2">
                                    <i className="bi bi-stars"></i> Experimental
                                </Link>
                            </div>
                        </div>

                        {/* Linked Accounts */}
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                            <h2 className="text-lg font-bold text-neutral-100 mb-4">Linked Accounts</h2>
                            <div>
                                {linkedProviders.length > 0 ? linkedProviders.map((provider) => (
                                    <LinkedProviderCard key={provider.id} provider={provider} />
                                )) : (
                                    <div className="text-sm text-neutral-400 text-center py-4">No external providers are configured for this account yet.</div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Right Column (Forms) */}
                    <div className="lg:col-span-8 flex flex-col gap-6">
                        
                        {/* Account Details */}
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                            <h2 className="text-lg font-bold text-neutral-100 mb-6">Account Details</h2>
                            <form method="POST" action="/account/update" className="flex flex-col gap-5">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                                    <label>
                                        <span className={labelClass}>First Name</span>
                                        <input type="text" name="firstName" defaultValue={user.firstName || ''} required className={inputClass} />
                                    </label>
                                    <label>
                                        <span className={labelClass}>Last Name</span>
                                        <input type="text" name="lastName" defaultValue={user.lastName || ''} required className={inputClass} />
                                    </label>
                                </div>
                                
                                <label>
                                    <span className={labelClass}>Email</span>
                                    <input type="email" name="email" defaultValue={user.email || ''} required className={inputClass} />
                                </label>
                                
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                                    <label>
                                        <span className={labelClass}>Avatar Provider</span>
                                        <select name="avatarProvider" defaultValue={user.avatarProvider || 'gravatar'} className={`${inputClass} pr-8 appearance-none`}>
                                            <option value="gravatar">Gravatar</option>
                                            <option value="url">Custom URL</option>
                                        </select>
                                    </label>
                                    <label>
                                        <span className={labelClass}>Avatar URL</span>
                                        <input type="url" name="avatarUrl" defaultValue={user.avatarUrl || ''} placeholder="https://example.com/avatar.png" className={inputClass} />
                                    </label>
                                </div>
                                
                                <label>
                                    <span className={labelClass}>Username</span>
                                    <input type="text" value={user.username || ''} readOnly className={`${inputClass} bg-neutral-800/50 cursor-not-allowed text-neutral-500 ring-0 focus:ring-0`} />
                                    <span className="block text-xs text-neutral-500 mt-1">Usernames cannot be changed.</span>
                                </label>
                                
                                <div className="mt-2 flex justify-end">
                                    <button type="submit" className="bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm">Save Account</button>
                                </div>
                            </form>
                        </div>

                        {/* Password */}
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                            <h2 className="text-lg font-bold text-neutral-100 mb-6">Update Password</h2>
                            <form method="POST" action="/account/password" className="flex flex-col gap-5">
                                <label>
                                    <span className={labelClass}>Current Password</span>
                                    <input type="password" name="currentPassword" required className={inputClass} />
                                </label>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                                    <label>
                                        <span className={labelClass}>New Password</span>
                                        <input type="password" name="newPassword" required className={inputClass} />
                                    </label>
                                    <label>
                                        <span className={labelClass}>Confirm New Password</span>
                                        <input type="password" name="confirmPassword" required className={inputClass} />
                                    </label>
                                </div>
                                <div className="mt-2 flex justify-end">
                                    <button type="submit" className="bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm">Update Password</button>
                                </div>
                            </form>
                        </div>

                        {/* Two-Factor Authentication */}
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                            <h2 className="text-lg font-bold text-neutral-100 mb-4">Two-Factor Authentication</h2>
                            {user.twoFactorEnabled ? (
                                <div>
                                    <p className="text-sm text-neutral-400 mb-5">Two-factor authentication is currently enabled on your account. If you would like to disable it, you must securely confirm your password below.</p>
                                    <div className="flex flex-col sm:flex-row gap-4 items-end">
                                        <label className="flex-1 w-full">
                                            <span className={labelClass}>Current Password</span>
                                            <input
                                                type="password"
                                                value={disableState.password}
                                                onChange={(e) => setDisableState({ ...disableState, password: e.target.value })}
                                                className={inputClass}
                                            />
                                        </label>
                                        <button 
                                            type="button" 
                                            className="w-full sm:w-auto bg-red-600 hover:bg-red-500 text-white font-semibold flex-shrink-0 h-10 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50" 
                                            onClick={disable2FA} 
                                            disabled={disableState.loading}
                                        >
                                            {disableState.loading ? 'Disabling...' : 'Disable 2FA'}
                                        </button>
                                    </div>
                                    {disableState.error && <p className="text-red-400 text-sm mt-2 font-bold">{disableState.error}</p>}
                                </div>
                            ) : (
                                <div>
                                    <p className="text-sm text-neutral-400 mb-5">Enable two-factor authentication to add an extra layer of security to your account. You will be required to input a code generated by your authenticator app each time you log in.</p>
                                    
                                    {!setupState.qrCodeUrl ? (
                                        <button 
                                            type="button" 
                                            className="bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50" 
                                            onClick={start2FASetup} 
                                            disabled={setupState.loading}
                                        >
                                            {setupState.loading ? 'Connecting...' : 'Begin Setup'}
                                        </button>
                                    ) : (
                                        <div className="bg-neutral-900 border border-neutral-700/50 rounded-lg p-6 flex flex-col md:flex-row items-center md:items-start gap-8">
                                            <div className="bg-white p-2 rounded shrink-0 shadow-lg">
                                                <img src={setupState.qrCodeUrl} alt="2FA QR code" className="w-32 h-32 md:w-40 md:h-40" style={{ imageRendering: 'pixelated' }} />
                                            </div>
                                            <div className="flex-1 w-full">
                                                <label className="block mb-4">
                                                    <span className={labelClass}>Manual Setup Key</span>
                                                    <input type="text" value={setupState.secret} readOnly className={`${inputClass} font-mono`} onClick={(e) => e.target.select()} />
                                                    <span className="block text-xs text-neutral-500 mt-1">If you cannot scan the QR code, manually input this secret into your app.</span>
                                                </label>
                                                <label className="block mb-5">
                                                    <span className={labelClass}>Authentication Code</span>
                                                    <input
                                                        type="text"
                                                        value={setupState.code}
                                                        maxLength={6}
                                                        onChange={(event) => setSetupState({ ...setupState, code: event.target.value.replace(/[^0-9]/g, '') })}
                                                        placeholder="000000"
                                                        className={`${inputClass} font-mono tracking-widest text-lg py-3`}
                                                    />
                                                </label>
                                                {setupState.error && <p className="text-red-400 text-sm mb-4 font-bold">{setupState.error}</p>}
                                                <div className="flex gap-3">
                                                    <button type="button" className="bg-neutral-700 hover:bg-neutral-600 text-white font-semibold py-2 px-6 rounded transition-colors text-sm" onClick={() => setSetupState({ loading: false, qrCodeUrl: '', secret: '', code: '', error: '' })}>
                                                        Cancel
                                                    </button>
                                                    <button type="button" className="bg-primary-600 hover:bg-primary-500 text-white font-semibold py-2 px-6 rounded transition-colors text-sm shadow-sm disabled:opacity-50" onClick={enable2FA} disabled={setupState.loading || setupState.code.length !== 6}>
                                                        {setupState.loading ? 'Verifying...' : 'Verify & Enable'}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                    {!setupState.qrCodeUrl && setupState.error && <p className="text-red-400 text-sm mt-4 font-bold">{setupState.error}</p>}
                                </div>
                            )}
                        </div>

                    </div>
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default AccountPage;

if (root) {
    root.render(<AccountPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
