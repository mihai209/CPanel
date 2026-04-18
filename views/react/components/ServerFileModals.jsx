import React, { useState, useEffect } from 'react';

export function CreateFolderModal({ isOpen, onClose, currentPath, serverId, onComplete }) {
    const [name, setName] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => { if (isOpen) { setName(''); setError(''); } }, [isOpen]);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!name.trim()) return;
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/create-folder`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, name: name.trim() })
            });
            const payload = await res.json();
            if (!res.ok || payload.error) throw new Error(payload.error || 'Failed to create folder');
            onComplete();
            onClose();
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-neutral-900 border border-neutral-700 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden animate-fade-in-up">
                <div className="px-6 py-4 border-b border-neutral-800 flex justify-between items-center bg-neutral-900/50">
                    <h3 className="text-lg font-bold text-white">Create Folder</h3>
                    <button onClick={onClose} className="text-neutral-500 hover:text-white transition-colors"><i className="bi bi-x-lg"></i></button>
                </div>
                <form onSubmit={handleSubmit} className="p-6">
                    {error && <div className="mb-4 p-3 bg-red-900/20 border border-red-900/50 text-red-400 rounded text-sm">{error}</div>}
                    <div className="mb-6">
                        <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Folder Name</label>
                        <input 
                            type="text" 
                            autoFocus
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            className="w-full bg-neutral-950 border border-neutral-700 rounded-lg py-2.5 px-4 text-neutral-200 focus:outline-none focus:border-primary-500"
                            placeholder="e.g. plugins or config/essentials"
                        />
                        <div className="text-[10px] text-neutral-500 mt-2">Folder will be created in {currentPath}</div>
                    </div>
                    <div className="flex justify-end gap-3">
                        <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-bold text-neutral-400 hover:text-white">Cancel</button>
                        <button type="submit" disabled={loading || !name.trim()} className="px-5 py-2 text-sm font-bold bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white rounded-lg transition-colors flex items-center gap-2">
                            {loading && <i className="bi bi-arrow-repeat animate-spin"></i>}
                            Create Folder
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

export function CreateFileModal({ isOpen, onClose, currentPath, onComplete }) {
    const [name, setName] = useState('');

    useEffect(() => { if (isOpen) setName(''); }, [isOpen]);

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!name.trim()) return;
        const normalized = (currentPath === '/' ? '' : currentPath) + '/' + name.trim();
        onComplete(normalized);
        onClose();
    };

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-neutral-900 border border-neutral-700 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden animate-fade-in-up">
                <div className="px-6 py-4 border-b border-neutral-800 flex justify-between items-center bg-neutral-900/50">
                    <h3 className="text-lg font-bold text-white">Create File</h3>
                    <button onClick={onClose} className="text-neutral-500 hover:text-white transition-colors"><i className="bi bi-x-lg"></i></button>
                </div>
                <form onSubmit={handleSubmit} className="p-6">
                    <div className="mb-6">
                        <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">File Name</label>
                        <input 
                            type="text" 
                            autoFocus
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            className="w-full bg-neutral-950 border border-neutral-700 rounded-lg py-2.5 px-4 text-neutral-200 focus:outline-none focus:border-primary-500"
                            placeholder="e.g. config.yml or script.js"
                        />
                        <div className="text-[10px] text-neutral-500 mt-2">Will open in editor immediately.</div>
                    </div>
                    <div className="flex justify-end gap-3">
                        <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-bold text-neutral-400 hover:text-white">Cancel</button>
                        <button type="submit" disabled={!name.trim()} className="px-5 py-2 text-sm font-bold bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white rounded-lg transition-colors">
                            Continue to Editor
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

export function RenameModal({ isOpen, onClose, currentPath, serverId, targetItem, onComplete }) {
    const [name, setName] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => { 
        if (isOpen && targetItem) { 
            setName(targetItem); 
            setError(''); 
        } 
    }, [isOpen, targetItem]);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!name.trim() || name === targetItem) return;
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/rename`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files: [{ from: targetItem, to: name.trim() }] })
            });
            const payload = await res.json();
            if (!res.ok || payload.error) throw new Error(payload.error || 'Failed to rename item');
            onComplete();
            onClose();
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-neutral-900 border border-neutral-700 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden animate-fade-in-up">
                <div className="px-6 py-4 border-b border-neutral-800 flex justify-between items-center bg-neutral-900/50">
                    <h3 className="text-lg font-bold text-white">Rename Item</h3>
                    <button onClick={onClose} className="text-neutral-500 hover:text-white transition-colors"><i className="bi bi-x-lg"></i></button>
                </div>
                <form onSubmit={handleSubmit} className="p-6">
                    {error && <div className="mb-4 p-3 bg-red-900/20 border border-red-900/50 text-red-400 rounded text-sm">{error}</div>}
                    <div className="mb-6">
                        <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">New Name</label>
                        <input 
                            type="text" 
                            autoFocus
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            className="w-full bg-neutral-950 border border-neutral-700 rounded-lg py-2.5 px-4 text-neutral-200 focus:outline-none focus:border-primary-500"
                        />
                    </div>
                    <div className="flex justify-end gap-3">
                        <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-bold text-neutral-400 hover:text-white">Cancel</button>
                        <button type="submit" disabled={loading || !name.trim() || name === targetItem} className="px-5 py-2 text-sm font-bold bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white rounded-lg transition-colors flex items-center gap-2">
                            {loading && <i className="bi bi-arrow-repeat animate-spin"></i>}
                            Rename
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

export function PermissionsModal({ isOpen, onClose, currentPath, serverId, targetItem, currentPerms, onComplete }) {
    const [perms, setPerms] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => { 
        if (isOpen && targetItem) { 
            setPerms(String(currentPerms).match(/[a-zA-Z]/) ? '755' : currentPerms); // default to 755 if parsing string perms failed initially
            setError(''); 
        } 
    }, [isOpen, targetItem, currentPerms]);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        const cleanPerms = String(perms).trim();
        if (!cleanPerms) return;
        setLoading(true);
        setError('');
        try {
            const res = await fetch(`/api/client/servers/${serverId}/files/chmod`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files: [{ file: targetItem, mode: cleanPerms }] })
            });
            const payload = await res.json();
            if (!res.ok || payload.error) throw new Error(payload.error || 'Failed to change permissions');
            onComplete();
            onClose();
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-neutral-900 border border-neutral-700 rounded-2xl w-full max-w-sm shadow-2xl overflow-hidden animate-fade-in-up">
                <div className="px-6 py-4 border-b border-neutral-800 flex justify-between items-center bg-neutral-900/50">
                    <h3 className="text-lg font-bold text-white">Chmod</h3>
                    <button onClick={onClose} className="text-neutral-500 hover:text-white transition-colors"><i className="bi bi-x-lg"></i></button>
                </div>
                <form onSubmit={handleSubmit} className="p-6">
                    {error && <div className="mb-4 p-3 bg-red-900/20 border border-red-900/50 text-red-400 rounded text-sm">{error}</div>}
                    <div className="mb-6">
                        <label className="block text-xs font-bold text-neutral-400 uppercase tracking-widest mb-2">Octal Mode</label>
                        <input 
                            type="text" 
                            autoFocus
                            value={perms}
                            onChange={(e) => setPerms(e.target.value.replace(/[^0-9]/g, ''))}
                            maxLength={4}
                            className="w-full bg-neutral-950 border border-neutral-700 rounded-lg py-2.5 px-4 text-neutral-200 font-mono focus:outline-none focus:border-primary-500"
                            placeholder="755"
                        />
                        <div className="text-[10px] text-neutral-500 mt-2 font-mono break-all">{targetItem}</div>
                    </div>
                    <div className="flex justify-end gap-3">
                        <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-bold text-neutral-400 hover:text-white">Cancel</button>
                        <button type="submit" disabled={loading} className="px-5 py-2 text-sm font-bold bg-primary-600 hover:bg-primary-500 disabled:bg-neutral-700 text-white rounded-lg transition-colors flex items-center gap-2">
                            {loading && <i className="bi bi-arrow-repeat animate-spin"></i>}
                            Apply
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
