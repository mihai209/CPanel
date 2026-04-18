import React from 'react';
import { createRoot } from 'react-dom/client';
import { Link } from 'react-router-dom';
import { ReactRoutes } from './ReactRoutes.js';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'rewards';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

const compactFormatter = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });

function formatRemaining(period, seconds) {
    if (seconds <= 0) return 'Ready';
    
    let s = seconds;
    const d = Math.floor(s / 86400);
    s -= d * 86400;
    const h = Math.floor(s / 3600);
    s -= h * 3600;
    const m = Math.floor(s / 60);
    s -= m * 60;
    
    if (period === 'minute') return `${m}m ${s}s`;
    if (period === 'hour') return `${h}h ${m}m ${s}s`;
    if (period === 'day') return `${d}d ${h}h ${m}m`;
    if (period === 'week') return `${d}d ${h}h`;
    if (period === 'month') return `${d}d ${h}h`;
    if (period === 'year') {
        const months = Math.floor(d / 30);
        const days = d % 30;
        return `${months}mo ${days}d`;
    }
    return `${d}d ${h}h ${m}m`;
}

export function RewardsPage({ pageData = data }) {
    const [coins, setCoins] = React.useState(Number(pageData.user?.coins || 0));
    const [dailyStreak, setDailyStreak] = React.useState(Number(pageData.dailyStreak || 0));
    const [streakResetSeconds, setStreakResetSeconds] = React.useState(Number(pageData.streakResetSeconds || 0));
    const [claimRemaining, setClaimRemaining] = React.useState(pageData.claimRemainingByPeriod || {});
    const [claiming, setClaiming] = React.useState(null);
    const [status, setStatus] = React.useState('Ready');

    React.useEffect(() => {
        const interval = setInterval(() => {
            setStreakResetSeconds((prev) => (prev > 0 ? prev - 1 : 0));
            setClaimRemaining((prev) => {
                const next = { ...prev };
                let changed = false;
                Object.keys(next).forEach((k) => {
                    if (next[k] > 0) {
                        next[k] -= 1;
                        changed = true;
                    }
                });
                return changed ? next : prev;
            });
        }, 1000);
        return () => clearInterval(interval);
    }, []);

    const handleClaim = async (period) => {
        setClaiming(period);
        try {
            const response = await fetch('/rewards/claim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ period })
            });
            const payload = await response.json();
            
            if (!response.ok || !payload.success) {
                if (payload.remainingSeconds !== undefined) {
                    setClaimRemaining(prev => ({ ...prev, [period]: Math.max(0, payload.remainingSeconds) }));
                }
                throw new Error(payload.error || 'Claim failed.');
            }

            if (payload.coins !== undefined) setCoins(payload.coins);
            if (payload.dailyStreak !== undefined) setDailyStreak(payload.dailyStreak);
            if (payload.remainingSeconds !== undefined) {
                setClaimRemaining(prev => ({ ...prev, [period]: Math.max(0, payload.remainingSeconds) }));
            }
            setStreakResetSeconds(86400); // Reset streak timeout
            setStatus(`Claimed +${compactFormatter.format(payload.awardedCoins || 0)} ${payload.economyUnit || pageData.economyUnit}`);
            
            // Auto hide status after 5s
            setTimeout(() => setStatus('Ready'), 5000);
        } catch (error) {
            setStatus(error.message);
        } finally {
            setClaiming(null);
        }
    };

    const cards = [
        { key: 'minute', label: 'Minutes' },
        { key: 'hour', label: 'Hours' },
        { key: 'day', label: 'Days' },
        { key: 'week', label: 'Weekly' },
        { key: 'month', label: 'Monthly' },
        { key: 'year', label: 'Yearly' }
    ];

    return (
        <ReactAppShell pageData={pageData} subtitle="Rewards Center">
            <PageContentBlock 
                title="Rewards" 
                description="Claim rewards at various intervals and keep your daily streak active."
                actions={
                    <div className="flex gap-2">
                        <Link to={ReactRoutes.afk} className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2">
                            <i className="bi bi-hourglass-split"></i> AFK Timer
                        </Link>
                        <Link to={ReactRoutes.dashboard} className="bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-bold py-1.5 px-3 rounded border border-neutral-700 transition-colors flex items-center gap-2">
                            <i className="bi bi-house-door"></i> Home
                        </Link>
                    </div>
                }
            >
                {/* Metrics Row */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-5 shadow-sm">
                        <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Total Balance</span>
                        <div className="text-2xl font-black text-white flex items-baseline gap-2">
                            {compactFormatter.format(coins)}
                            <span className="text-xs font-bold text-neutral-500">{pageData.economyUnit}</span>
                        </div>
                    </div>
                    <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-5 shadow-sm">
                        <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Daily Streak</span>
                        <div className="text-2xl font-black text-blue-400">{dailyStreak} Days</div>
                        <div className="text-[10px] text-neutral-500 mt-1 uppercase tracking-tight">Bonus: +{pageData.claimDailyStreakBonusCoins || 0} / day</div>
                    </div>
                    <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-5 shadow-sm">
                        <span className="block text-[10px] font-black text-neutral-500 uppercase tracking-widest mb-1">Streak Reset</span>
                        <div className="text-2xl font-black text-neutral-200">
                            {dailyStreak > 0 ? (streakResetSeconds > 0 ? formatRemaining('day', streakResetSeconds) : 'Expired') : 'No streak'}
                        </div>
                    </div>
                </div>

                {/* Status Bar */}
                <div className="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-3 mb-8 flex justify-between items-center">
                    <h2 className="text-xs font-black text-neutral-400 uppercase tracking-widest">Global Claim Status</h2>
                    <span className={`text-xs font-bold ${status.includes('Claimed') ? 'text-green-400' : 'text-neutral-500'}`}>{status}</span>
                </div>

                {/* Streak Calendar */}
                <div className="bg-neutral-800 border border-neutral-700 rounded-xl p-6 mb-8">
                    <h2 className="text-sm font-black text-neutral-200 uppercase tracking-[0.1em] mb-4">Streak Calendar</h2>
                    <div className="grid grid-cols-7 gap-3">
                        {Array.from({ length: 7 }).map((_, i) => (
                            <div key={i} className={`h-16 rounded-lg border-2 flex flex-col items-center justify-center gap-1 transition-all ${dailyStreak > i ? 'bg-blue-600/10 border-blue-600/50 text-blue-400 font-bold' : 'bg-neutral-900 border-neutral-700 text-neutral-600 opacity-50'}`}>
                                <span className={dailyStreak > i ? 'text-lg' : 'text-sm'}><i className={dailyStreak > i ? 'bi bi-check-circle-fill' : 'bi bi-circle'}></i></span>
                                <span className="text-[9px] uppercase font-black">Day {i + 1}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Claim Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                    {cards.map((card) => {
                        const remaining = claimRemaining[card.key] || 0;
                        const isReady = remaining <= 0;
                        const isClaiming = claiming === card.key;
                        const rewardValue = pageData.rewardsMap ? pageData.rewardsMap[card.key] : 0;

                        return (
                            <div key={card.key} className={`relative bg-neutral-800 border rounded-xl p-6 flex flex-col gap-4 transition-all ${isReady ? 'border-primary-500/50 shadow-md ring-1 ring-primary-500/10' : 'border-neutral-700 opacity-80 shadow-sm'}`}>
                                <div className="flex justify-between items-start">
                                    <h3 className="text-sm font-black text-neutral-100 uppercase tracking-widest">{card.label}</h3>
                                    {isReady && <span className="bg-green-500/20 text-green-400 text-[10px] font-black px-2 py-0.5 rounded animate-pulse">READY</span>}
                                </div>
                                
                                <div className="py-2">
                                    <div className="text-2xl font-black text-white">+{compactFormatter.format(rewardValue)} <span className="text-xs text-neutral-500 uppercase">{pageData.economyUnit}</span></div>
                                    <div className="text-xs text-neutral-400 mt-1">Remaining: <span className="font-mono text-neutral-200">{formatRemaining(card.key, remaining)}</span></div>
                                </div>

                                <button 
                                    onClick={() => handleClaim(card.key)}
                                    disabled={!isReady || isClaiming || rewardValue <= 0}
                                    className={`w-full py-2.5 rounded text-sm font-bold shadow-sm transition-all flex items-center justify-center gap-2 ${isReady ? 'bg-primary-600 hover:bg-primary-500 text-white' : 'bg-neutral-700 text-neutral-500 cursor-not-allowed'}`}
                                >
                                    {isClaiming ? (
                                        <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
                                    ) : (
                                        <><i className="bi bi-box-arrow-in-down"></i> Claim</>
                                    )}
                                </button>
                            </div>
                        );
                    })}
                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default RewardsPage;

if (root) {
    root.render(<RewardsPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
