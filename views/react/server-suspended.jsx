import React from 'react';
import { createRoot } from 'react-dom/client';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-suspended';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerSuspendedPage({ pageData = data }) {
    const brandName = pageData.settings?.brandName || 'CPanel';
    const server = pageData.server || {};
    const suspendReason = server.suspendReason || null;

    return (
        <div className="min-h-screen bg-neutral-950 flex items-center justify-center p-6 font-sans text-neutral-200">
            <div className="max-w-lg w-full bg-neutral-900 border border-yellow-900/20 rounded-2xl p-10 text-center shadow-2xl relative overflow-hidden">
                {/* Decorative background element */}
                <div className="absolute -top-24 -right-24 w-48 h-48 bg-yellow-600/10 rounded-full blur-3xl"></div>
                
                <div className="relative z-10">
                    <div className="mb-6">
                        <img 
                            src="/assets/sad-rocky.png" 
                            alt="Suspended" 
                            className="w-40 h-40 mx-auto rounded-2xl shadow-lg border border-neutral-800"
                        />
                    </div>
                    
                    <div className="text-yellow-500 text-xs font-black uppercase tracking-[0.2em] mb-3">
                        {brandName}
                    </div>
                    
                    <h1 className="text-3xl font-extrabold text-white mb-2">Server Suspended</h1>
                    
                    <div className="inline-block px-3 py-1 bg-neutral-800 border border-neutral-700 rounded text-xs font-mono text-neutral-400 mb-6">
                        <i className="bi bi-server me-2"></i>
                        {server.name || 'Unknown Server'}
                    </div>

                    <p className="text-neutral-400 text-sm mb-6 leading-relaxed">
                        This server has been suspended by an administrator and is temporarily unavailable. 
                        All runtime resources have been halted.
                    </p>

                    <div className="bg-yellow-500/5 border border-yellow-500/10 rounded-xl p-5 mb-8 text-left">
                        <div className="text-[10px] font-bold text-yellow-500 uppercase tracking-widest mb-2 flex items-center">
                            <i className="bi bi-chat-left-text me-2"></i> Reason
                        </div>
                        <div className="text-sm text-neutral-300">
                            {suspendReason ? (
                                suspendReason
                            ) : (
                                <span className="text-neutral-500 italic">No specific reason was provided by the administrator.</span>
                            )}
                        </div>
                    </div>

                    <p className="text-neutral-500 text-xs mb-8">
                        Please contact support or an administrator for more information regarding this suspension.
                    </p>

                    <a 
                        href="/" 
                        className="inline-flex items-center justify-center px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-white font-bold rounded-xl transition-all hover:-translate-y-1 shadow-md border border-neutral-700"
                    >
                        <i className="bi bi-arrow-left me-2"></i>
                        Back to Dashboard
                    </a>
                </div>
            </div>
        </div>
    );
}

export default ServerSuspendedPage;

if (root) {
    root.render(<ServerSuspendedPage pageData={data} />);
}
