import React, { useState, useEffect } from 'react';

export default function GlobalStatusModal() {
    const [payload, setPayload] = useState(null);
    const [isOpen, setIsOpen] = useState(false);

    useEffect(() => {
        // Detect status from URL
        const params = new URLSearchParams(window.location.search);
        const error = params.get('error');
        const warning = params.get('warning');
        const success = params.get('success');

        if (error || warning || success) {
            setPayload({
                type: error ? 'error' : (warning ? 'warning' : 'success'),
                message: error || warning || success
            });
            setIsOpen(true);

            // Clean URL to prevent re-triggering
            const url = new URL(window.location.href);
            url.searchParams.delete('error');
            url.searchParams.delete('warning');
            url.searchParams.delete('success');
            window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
        }

        // Global event listener for manual triggers
        const triggerHandler = (e) => {
            if (e.detail && e.detail.message) {
                setPayload({
                    type: e.detail.type || 'success',
                    message: e.detail.message
                });
                setIsOpen(true);
            }
        };

        window.addEventListener('cpanel:show-status', triggerHandler);
        return () => window.removeEventListener('cpanel:show-status', triggerHandler);
    }, []);

    if (!isOpen || !payload) return null;

    const config = {
        error: {
            title: 'Whoops! Something went wrong.',
            img: '/assets/sad-rocky.png',
            color: 'text-red-400',
            bar: 'bg-gradient-to-r from-red-600 to-red-900',
            bg: 'bg-red-500/10',
            border: 'border-red-500/30',
            btn: 'bg-red-600 hover:bg-red-500 shadow-red-900/40',
            btnLabel: 'I Understand'
        },
        warning: {
            title: 'Wait! One second.',
            img: '/assets/what-rocky.png',
            color: 'text-amber-400',
            bar: 'bg-gradient-to-r from-amber-500 to-amber-700',
            bg: 'bg-amber-500/10',
            border: 'border-amber-500/30',
            btn: 'bg-amber-600 hover:bg-amber-500 shadow-amber-900/40',
            btnLabel: 'Got It'
        },
        success: {
            title: 'Great! Success.',
            img: '/assets/happy-rocky.png',
            color: 'text-emerald-400',
            bar: 'bg-gradient-to-r from-emerald-500 to-emerald-700',
            bg: 'bg-emerald-500/10',
            border: 'border-emerald-500/30',
            btn: 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-900/40',
            btnLabel: 'Perfect, thanks!'
        }
    }[payload.type];

    return (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4">
            {/* Backdrop */}
            <div 
                className="absolute inset-0 bg-black/80 backdrop-blur-md transition-opacity"
                onClick={() => setIsOpen(false)}
            ></div>

            {/* Modal Content */}
            <div className="relative w-full max-w-md bg-neutral-900 border border-neutral-800 rounded-[2.5rem] overflow-hidden shadow-2xl animate-in zoom-in duration-300">
                {/* Top Status Bar */}
                <div className={`h-1.5 w-full ${config.bar}`}></div>

                <div className="p-8 pt-10 text-center">
                    <button 
                        onClick={() => setIsOpen(false)}
                        className="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors"
                    >
                        <i className="bi bi-x-lg"></i>
                    </button>

                    {/* Mascot Container */}
                    <div className={`relative w-32 h-32 mx-auto mb-6 rounded-full flex items-center justify-center border-2 border-dashed ${config.bg} ${config.border}`}>
                        <img 
                            src={config.img} 
                            alt="Rocky Mascot" 
                            className="w-24 h-24 object-contain relative z-10"
                        />
                        <div className={`absolute inset-0 rounded-full blur-2xl opacity-20 ${config.bg}`}></div>
                    </div>

                    <h3 className={`text-xl font-black uppercase tracking-[0.15em] mb-2 ${config.color}`}>
                        {config.title}
                    </h3>
                    
                    <p className="text-neutral-400 font-medium leading-relaxed mb-8 px-4">
                        {payload.message}
                    </p>

                    <div className="space-y-4">
                        {payload.type === 'error' && (
                            <div className="bg-red-500/5 border border-red-500/20 rounded-xl py-2 mb-4">
                                <span className="text-[10px] font-black uppercase tracking-widest text-red-400/80">
                                    <i className="bi bi-info-circle me-2"></i>
                                    If this persists, contact support
                                </span>
                            </div>
                        )}

                        <button 
                            onClick={() => setIsOpen(false)}
                            className={`w-full py-4 rounded-2xl text-[11px] font-black uppercase tracking-[0.25em] text-white transition-all transform hover:-translate-y-1 shadow-xl ${config.btn}`}
                        >
                            {config.btnLabel}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
