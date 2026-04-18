import React from 'react';

export default function SponsorModal({ isOpen, onClose }) {
    if (!isOpen) return null;

    const sponsorLinks = [
        {
            name: 'BuyMeACoffee',
            handle: 'mihai14launcher',
            url: 'https://www.buymeacoffee.com/mihai14launcher',
            icon: 'bi-cup-hot-fill',
            color: 'bg-[#FFDD00] text-black'
        },
        {
            name: 'Ko-fi',
            handle: 'mihai14launcher',
            url: 'https://ko-fi.com/mihai14launcher',
            icon: 'bi-patch-check-fill',
            color: 'bg-[#13C3FF] text-white'
        },
        {
            name: 'GitHub Sponsors',
            handle: 'mihai209',
            url: 'https://github.com/sponsors/mihai209',
            icon: 'bi-heart-fill',
            color: 'bg-[#ea4aaa] text-white'
        }
    ];

    return (
        <div className="fixed inset-0 z-[10000] flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/80 backdrop-blur-xl transition-opacity" onClick={onClose}></div>
            
            <div className="relative w-full max-w-lg bg-neutral-900 border border-neutral-800 rounded-[2.5rem] overflow-hidden shadow-2xl animate-in zoom-in duration-300">
                <div className="h-1.5 w-full bg-gradient-to-r from-primary-600 via-purple-500 to-pink-500"></div>
                
                <div className="p-8 pt-10 text-center">
                    <button 
                        onClick={onClose}
                        className="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors"
                    >
                        <i className="bi bi-x-lg"></i>
                    </button>

                    <div className="relative w-32 h-32 mx-auto mb-6 rounded-full flex items-center justify-center border-2 border-dashed border-primary-500/30 bg-primary-500/5">
                        <img 
                            src="/assets/happy-rocky.png" 
                            alt="Happy Rocky" 
                            className="w-24 h-24 object-contain relative z-10 animate-bounce group-hover:animate-none"
                        />
                        <div className="absolute inset-0 rounded-full blur-2xl opacity-20 bg-primary-500"></div>
                    </div>

                    <h3 className="text-2xl font-black uppercase tracking-[0.1em] mb-3 text-white">
                        Support the Creator
                    </h3>
                    
                    <p className="text-neutral-400 font-medium leading-relaxed mb-8 px-4 text-sm">
                        CPanel Rocky and the Connector are developed for <strong>free</strong> during my spare time. 
                        If you find this project useful, a small "thank you" gift would mean a lot!
                    </p>

                    <div className="grid grid-cols-1 gap-4 mb-4">
                        {sponsorLinks.map((link) => (
                            <a
                                key={link.name}
                                href={link.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className={`flex items-center justify-between p-4 rounded-2xl transition-all hover:-translate-y-1 shadow-lg group ${link.color}`}
                            >
                                <div className="flex items-center gap-4">
                                    <div className="w-10 h-10 rounded-xl bg-black/10 flex items-center justify-center">
                                        <i className={`bi ${link.icon} text-xl`}></i>
                                    </div>
                                    <div className="text-left">
                                        <div className="text-[10px] font-black uppercase tracking-widest opacity-80">{link.name}</div>
                                        <div className="font-bold">@{link.handle}</div>
                                    </div>
                                </div>
                                <i className="bi bi-arrow-right text-lg opacity-0 group-hover:opacity-100 transition-opacity"></i>
                            </a>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
