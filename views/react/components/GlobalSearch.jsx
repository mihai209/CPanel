import React, { useState, useRef, useEffect } from 'react';

export default function GlobalSearch() {
    const [isOpen, setIsOpen] = useState(false);
    const [query, setQuery] = useState('');
    const inputRef = useRef(null);
    const containerRef = useRef(null);

    // If we're on the dashboard and there's a search param, initialize it
    useEffect(() => {
        if (window.location.pathname === '/') {
            const params = new URLSearchParams(window.location.search);
            const sq = params.get('search');
            if (sq) {
                setQuery(sq);
                setIsOpen(true);
            }
        }
    }, []);

    // Also dispatch event when typing to live-filter dashboard if we are there
    useEffect(() => {
        if (window.location.pathname === '/') {
            window.dispatchEvent(new CustomEvent('dashboard-search', { detail: query }));
        }
    }, [query]);

    // Click outside to close
    useEffect(() => {
        function handleClickOutside(event) {
            if (containerRef.current && !containerRef.current.contains(event.target)) {
                if (!query) setIsOpen(false);
            }
        }
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [query]);

    const handleToggle = () => {
        if (isOpen && !query) {
            setIsOpen(false);
        } else {
            setIsOpen(true);
            setTimeout(() => inputRef.current?.focus(), 50);
        }
    };

    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            if (window.location.pathname !== '/') {
                // Redirect to dashboard with query
                window.location.href = `/?search=${encodeURIComponent(query)}`;
            } else {
                // Maybe blur to close keyboard on mobile
                inputRef.current?.blur();
            }
        } else if (e.key === 'Escape') {
            setQuery('');
            setIsOpen(false);
        }
    };

    return (
        <div ref={containerRef} className={`relative flex items-center transition-all duration-300 ease-in-out ${isOpen ? 'w-48 sm:w-64' : 'w-10'}`}>
            <button 
                type="button"
                onClick={handleToggle}
                className={`absolute left-0 z-10 w-10 h-10 flex items-center justify-center transition-colors ${isOpen ? 'text-primary-400' : 'text-neutral-400 hover:text-neutral-100 hover:bg-neutral-700/50 rounded-full'}`}
            >
                <i className="bi bi-search"></i>
            </button>
            <input
                ref={inputRef}
                type="text"
                placeholder="Search servers..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                className={`w-full bg-neutral-800 border transition-all duration-300 h-10 py-2 pl-10 pr-4 text-sm text-neutral-200 placeholder-neutral-500 focus:outline-none focus:border-primary-500/50 focus:ring-1 focus:ring-primary-500/50 ${isOpen ? 'border-neutral-700 rounded-xl opacity-100' : 'border-transparent rounded-full opacity-0 pointer-events-none bg-transparent'}`}
            />
            {isOpen && query && (
                <button 
                    type="button" 
                    onClick={() => { setQuery(''); inputRef.current?.focus(); }}
                    className="absolute right-3 text-neutral-500 hover:text-neutral-300"
                >
                    <i className="bi bi-x-circle-fill text-[11px]"></i>
                </button>
            )}
        </div>
    );
}
