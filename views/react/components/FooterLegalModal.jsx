import React from 'react';

export default function FooterLegalModal({ isOpen, onClose }) {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-[10000] flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/80 backdrop-blur-xl transition-opacity" onClick={onClose}></div>
            
            <div className="relative w-full max-w-2xl bg-neutral-900 border border-neutral-800 rounded-[2.5rem] overflow-hidden shadow-2xl animate-in zoom-in duration-300 flex flex-col max-h-[90vh]">
                <div className="h-1.5 w-full bg-primary-600"></div>
                
                <div className="p-8 border-b border-neutral-800 flex justify-between items-center bg-neutral-900/50">
                    <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-2xl bg-primary-500/10 flex items-center justify-center border border-primary-500/20 shadow-inner">
                            <img src="/assets/rocky-security.png" alt="Security Rocky" className="w-10 h-10 object-contain" />
                        </div>
                        <div>
                            <h3 className="text-xl font-black uppercase tracking-[0.15em] text-white">Licensing & Support</h3>
                            <p className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest mt-1">Official Project Documentation</p>
                        </div>
                    </div>
                    <button 
                        onClick={onClose}
                        className="w-10 h-10 flex items-center justify-center rounded-xl bg-neutral-800 text-neutral-400 hover:text-white transition-colors"
                    >
                        <i className="bi bi-x-lg"></i>
                    </button>
                </div>

                <div className="p-8 overflow-y-auto custom-scrollbar space-y-8">
                    {/* MIT License Section */}
                    <section>
                        <div className="flex items-center gap-3 mb-3">
                            <div className="w-1.5 h-6 bg-primary-500 rounded-full"></div>
                            <h4 className="text-sm font-black uppercase tracking-[0.2em] text-primary-400">MIT License</h4>
                        </div>
                        <p className="text-sm text-neutral-300 leading-relaxed font-medium">
                            CPanel is distributed under the MIT License. You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, subject to the conditions of the license.
                        </p>
                    </section>

                    {/* Disclaimer Section */}
                    <section>
                        <div className="flex items-center gap-3 mb-3">
                            <div className="w-1.5 h-6 bg-yellow-500 rounded-full"></div>
                            <h4 className="text-sm font-black uppercase tracking-[0.2em] text-yellow-500">Disclaimer</h4>
                        </div>
                        <p className="text-sm text-neutral-300 leading-relaxed font-medium">
                            CPanel is not associated with <strong>pterodactyl.io</strong> or the Pterodactyl Panel. This software is merely inspired by its design and concepts, but remains an independent project.
                        </p>
                    </section>

                    {/* Support & Modification Policy Section */}
                    <section className="p-6 bg-neutral-800/50 border border-neutral-700/50 rounded-3xl relative overflow-hidden group">
                        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
                            <i className="bi bi-shield-lock-fill text-6xl"></i>
                        </div>
                        <div className="flex items-center gap-3 mb-4">
                            <div className="w-1.5 h-6 bg-red-500 rounded-full"></div>
                            <h4 className="text-sm font-black uppercase tracking-[0.2em] text-red-500">Support & Modification Policy</h4>
                        </div>
                        <div className="space-y-4 relative z-10">
                            <p className="text-sm text-neutral-200 leading-relaxed font-semibold">
                                You are free to modify any assets, styles, and logic within the panel and connector to suit your needs.
                            </p>
                            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-2xl">
                                <p className="text-sm text-red-400 leading-relaxed font-bold">
                                    IMPORTANT: Removing or modifying the copyright notices in the footer will result in the immediate and automatic termination of support from the developer.
                                </p>
                            </div>
                            <p className="text-sm text-neutral-400 leading-relaxed font-medium italic">
                                Support is provided solely by <strong>Mihai209</strong> to users who maintain the original branding in the footer. By using this software, you agree to keep the copyright links visible.
                            </p>
                        </div>
                    </section>
                </div>

                <div className="p-8 bg-neutral-800/50 flex justify-end">
                    <button 
                        onClick={onClose}
                        className="px-8 py-3 bg-neutral-800 hover:bg-neutral-700 text-neutral-300 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] border border-neutral-700 transition-all font-bold"
                    >
                        Close Document
                    </button>
                </div>
            </div>
        </div>
    );
}
