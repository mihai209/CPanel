import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'afk';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

const compactFormatter = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });

export function AFKPage({ pageData = data }) {
    const [coins, setCoins] = React.useState(Number(pageData.user?.coins || 0));
    const [afkRemainingSeconds, setAfkRemainingSeconds] = React.useState(Number(pageData.afkRemainingSeconds || 0));
    const [status, setStatus] = React.useState('Initializing...');

    const pingAfk = async () => {
        if (!pageData.afkTimerEnabled) return;
        try {
            const response = await fetch('/afk/ping', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: '{}'
            });
            const payload = await response.json();
            
            if (!response.ok || !payload.success) {
                throw new Error(payload.error || 'AFK ping failed');
            }

            if (payload.remainingSeconds !== undefined) {
                setAfkRemainingSeconds(Math.max(0, payload.remainingSeconds));
            }
            if (payload.coins !== undefined) {
                setCoins(payload.coins);
            }

            if (payload.awarded && Number(payload.awardedCoins) > 0) {
                setStatus(`+${payload.awardedCoins} ${payload.economyUnit || pageData.economyUnit} awarded`);
                // Clear success message after 5s
                setTimeout(() => setStatus('AFK heartbeat synced'), 5000);
            } else {
                setStatus('AFK heartbeat synced');
            }
        } catch (error) {
            setStatus(error.message || 'AFK ping error');
        }
    };

    React.useEffect(() => {
        // Initial ping
        pingAfk();

        const tickInterval = setInterval(() => {
            setAfkRemainingSeconds((prev) => (prev > 0 ? prev - 1 : 0));
        }, 1000);

        const pingInterval = setInterval(() => {
            pingAfk();
        }, 10000); // Heartbeat every 10 seconds

        return () => {
            clearInterval(tickInterval);
            clearInterval(pingInterval);
        };
    }, []);

    return (
        <ReactAppShell pageData={pageData} subtitle="AFK Rewards">
            <PageContentBlock 
                title="AFK Timer" 
                description="Stay on this page to automatically earn coins at the configured interval."
                actions={
                    <div className="flex gap-2">
                        <Link to={ReactRoutes.rewards} className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2">
                            <i className="bi bi-coin"></i> Rewards
                        </Link>
                        <Link to={ReactRoutes.dashboard} className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2">
                            <i className="bi bi-house-door"></i> Home
                        </Link>
                    </div>
                }
            >
                {/* Metrics Row */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-6 shadow-sm">
                        <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Your Wallet</span>
                        <div className="text-3xl font-black text-white flex items-baseline gap-2">
                            {compactFormatter.format(coins)}
                            <span className="text-xs font-bold text-neutral-500 uppercase">{pageData.economyUnit}</span>
                        </div>
                    </div>
                    <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-6 shadow-sm ring-2 ring-primary-500/20">
                        <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Next Reward In</span>
                        <div className="text-3xl font-black text-primary-400 font-mono tracking-tighter">
                            {afkRemainingSeconds}s
                        </div>
                    </div>
                    <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-6 shadow-sm">
                        <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Reward Value</span>
                        <div className="text-3xl font-black text-neutral-200">
                            +{compactFormatter.format(pageData.afkTimerCoins || 0)}
                        </div>
                        <div className="text-[10px] text-neutral-500 mt-1 uppercase tracking-tight">Interval: {pageData.afkTimerCooldownSeconds || 60}s</div>
                    </div>
                </div>

                {/* Status Indicator */}
                <div className="bg-neutral-800 border border-neutral-700 rounded-2xl p-10 flex flex-col items-center justify-center text-center gap-6 relative overflow-hidden">
                    {/* Background Animation Decorations */}
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary-500 to-transparent opacity-20 animate-pulse"></div>
                    <div className="absolute -bottom-24 -right-24 w-64 h-64 bg-primary-500/5 rounded-full blur-3xl"></div>
                    <div className="absolute -top-24 -left-24 w-64 h-64 bg-primary-500/5 rounded-full blur-3xl"></div>

                    <div className="relative">
                        <div className="w-24 h-24 rounded-full bg-primary-500/10 border border-primary-500/20 flex items-center justify-center mb-2">
                            <i className="bi bi-hourglass-split text-4xl text-primary-400 animate-spin-slow"></i>
                        </div>
                        <div className="absolute -top-1 -right-1">
                            <div className="w-4 h-4 bg-green-500 rounded-full border-4 border-neutral-800 animate-pulse"></div>
                        </div>
                    </div>

                    <div>
                        <h2 className="text-xl font-bold text-white mb-2">AFK Monitoring Active</h2>
                        <p className="text-sm text-neutral-400 max-w-md mx-auto">
                            As long as this tab remains open and active, your session is being monitored. 
                            The heartbeat system confirms your presence every 10 seconds.
                        </p>
                    </div>

                    <div className="bg-neutral-900 px-6 py-2 rounded-full border border-neutral-700 shadow-inner">
                        <span className={`text-xs font-black uppercase tracking-widest ${status.includes('awarded') ? 'text-green-400' : 'text-neutral-500'}`}>
                            {status}
                        </span>
                    </div>

                    {!pageData.afkTimerEnabled && (
                        <div className="mt-4 bg-red-600/10 border border-red-600/20 text-red-400 px-4 py-2 rounded-lg text-xs font-bold">
                            <i className="bi bi-exclamation-triangle-fill mr-2"></i>
                            AFK Timer is currently disabled by administrator.
                        </div>
                    )}
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default AFKPage;

if (root) {
    root.render(<AFKPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
