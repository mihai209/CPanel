import React from 'react';

export default function ProvisioningBarrier({ status = 'installing', containerId }) {
    const isReinstall = status === 'reinstalling';

    return (
        <div className="flex flex-col items-center justify-center min-h-[500px] py-20 px-6 text-center">
            {/* Animated SVG Backdrop */}
            <div className="relative mb-8">
                <div className="absolute -inset-10 bg-primary-600/10 rounded-full blur-3xl animate-pulse"></div>
                <div className="relative w-32 h-32 flex items-center justify-center">
                    <svg className="w-full h-full text-primary-500 animate-[spin_3s_linear_infinite]" viewBox="0 0 100 100">
                        <circle 
                            cx="50" cy="50" r="45" 
                            fill="none" stroke="currentColor" 
                            strokeWidth="2" strokeDasharray="200 100" 
                            strokeLinecap="round"
                        />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center text-primary-400">
                        <i className={`bi ${isReinstall ? 'bi-arrow-clockwise' : 'bi-tools'} text-4xl`}></i>
                    </div>
                </div>
            </div>

            <h2 className="text-3xl font-black text-white uppercase tracking-[0.2em] mb-4">
                {isReinstall ? 'System Reinstall' : 'Server Provisioning'}
            </h2>
            
            <p className="text-neutral-500 font-bold uppercase tracking-widest text-xs max-w-md mx-auto leading-relaxed mb-8">
                Your server instance is currently being {isReinstall ? 'reinstalled' : 'set up'} on the node. 
                Administrative tools are temporarily disabled to ensure data integrity during file restoration.
            </p>

            <div className="flex flex-col items-center gap-4">
                <div className="flex items-center gap-2 bg-neutral-800/50 px-4 py-2 rounded-full border border-neutral-700/50">
                    <div className="w-2 h-2 bg-primary-500 rounded-full animate-ping"></div>
                    <span className="text-[10px] font-black text-neutral-300 uppercase tracking-widest">
                        Working on {containerId?.substring(0, 12) || 'unknown'}
                    </span>
                </div>

                <div className="mt-4 flex gap-4">
                    <a 
                        href={`/server/${containerId}`}
                        className="bg-neutral-800 hover:bg-neutral-700 text-neutral-100 px-6 py-3 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-all flex items-center gap-3 border border-neutral-700"
                    >
                        <i className="bi bi-terminal text-lg opacity-50"></i>
                        Open Console
                    </a>
                </div>
            </div>

            <div className="mt-16 grid grid-cols-1 sm:grid-cols-3 gap-8 w-full max-w-2xl opacity-40 grayscale group-hover:grayscale-0 transition-all">
                <div className="text-center">
                    <div className="text-xl text-neutral-400 mb-1 font-black">1</div>
                    <div className="text-[10px] text-neutral-600 uppercase font-black tracking-widest">Allocating Resources</div>
                </div>
                <div className="text-center">
                    <div className="text-xl text-white mb-1 font-black">2</div>
                    <div className="text-[10px] text-primary-400 uppercase font-black tracking-widest ring-1 ring-primary-500/20 rounded-full px-2 py-1">Running Install Script</div>
                </div>
                <div className="text-center">
                    <div className="text-xl text-neutral-400 mb-1 font-black">3</div>
                    <div className="text-[10px] text-neutral-600 uppercase font-black tracking-widest">Starting Instance</div>
                </div>
            </div>
        </div>
    );
}
