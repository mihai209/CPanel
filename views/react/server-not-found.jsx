import React from 'react';
import { createRoot } from 'react-dom/client';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-not-found';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

export function ServerNotFoundPage({ pageData = data }) {
    const brandName = pageData.settings?.brandName || 'CPanel';

    return (
        <div className="min-h-screen bg-neutral-950 flex items-center justify-center p-6 font-sans text-neutral-200">
            <div className="max-w-md w-full bg-neutral-900 border border-neutral-800 rounded-2xl p-10 text-center shadow-2xl relative overflow-hidden">
                {/* Decorative background element */}
                <div className="absolute -top-24 -right-24 w-48 h-48 bg-primary-600/10 rounded-full blur-3xl"></div>
                
                <div className="relative z-10">
                    <div className="mb-8">
                        <img 
                            src="/assets/sad-rocky.png" 
                            alt="Not Found" 
                            className="w-40 h-40 mx-auto rounded-2xl shadow-lg border border-neutral-800"
                        />
                    </div>
                    
                    <div className="text-primary-500 text-xs font-black uppercase tracking-[0.2em] mb-3">
                        {brandName}
                    </div>
                    
                    <h1 className="text-3xl font-extrabold text-white mb-4">Server Not Found</h1>
                    <p className="text-neutral-400 leading-relaxed mb-8">
                        The server you are looking for does not exist or has been deleted from our system.
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

export default ServerNotFoundPage;

if (root) {
    root.render(<ServerNotFoundPage pageData={data} />);
}
