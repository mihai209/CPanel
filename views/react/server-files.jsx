import React from 'react';
import { createRoot } from 'react-dom/client';
import ReactAppShell from './components/ReactAppShell.jsx';
import PageContentBlock from './components/PageContentBlock.jsx';

const data = window.__CPANEL_REACT_PAGE_DATA__ || {};
const standaloneEntry = ((window.__CPANEL_REACT_PAGE_META__ || {}).entry || '').trim() === 'server-files';
const root = standaloneEntry ? createRoot(document.getElementById('reactRoot')) : null;

function normalizePath(value) {
    const raw = String(value || '/').trim().replace(/\\/g, '/');
    if (!raw || raw === '/') return '/';
    const normalized = raw.startsWith('/') ? raw : `/${raw}`;
    return normalized.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
}

function formatBytes(value) {
    const bytes = Math.max(0, Number(value) || 0);
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let current = bytes;
    let index = 0;
    while (current >= 1024 && index < units.length - 1) {
        current /= 1024;
        index += 1;
    }
    return `${current >= 100 || index === 0 ? current.toFixed(0) : current.toFixed(2)} ${units[index]}`;
}

function formatDate(value) {
    if (!value) return '-';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString();
}

function buildSegments(pathname) {
    const normalized = normalizePath(pathname);
    if (normalized === '/') return [{ label: 'home', path: '/' }];
    const parts = normalized.split('/').filter(Boolean);
    const segments = [{ label: 'home', path: '/' }];
    let current = '';
    parts.forEach((part) => {
        current += `/${part}`;
        segments.push({ label: part, path: current });
    });
    return segments;
}

export function ServerFilesPage({ pageData = data }) {
    const manager = pageData.fileManager || {};
    const permissions = pageData.permissions || {};
    const [currentPath, setCurrentPath] = React.useState(() => normalizePath(pageData.initialPath || '/'));
    const [entries, setEntries] = React.useState([]);
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState(pageData.error || '');
    const [menuPath, setMenuPath] = React.useState('');
    const [isDragging, setIsDragging] = React.useState(false);
    const [fileQueue, setFileQueue] = React.useState([]);
    const [isQueueExpanded, setIsQueueExpanded] = React.useState(true);

    const reloadFiles = React.useCallback(() => {
        setLoading(true);
        setError('');
        fetch(`${manager.fetchUrlBase}?path=${encodeURIComponent(currentPath)}`, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' }
        })
            .then(async (response) => {
                const payload = await response.json().catch(() => ({}));
                const nextEntries = Array.isArray(payload.files) ? payload.files : [];
                nextEntries.sort((left, right) => {
                    if (left.isDirectory && !right.isDirectory) return -1;
                    if (!left.isDirectory && right.isDirectory) return 1;
                    return String(left.name || '').localeCompare(String(right.name || ''), undefined, { numeric: true, sensitivity: 'base' });
                });
                setEntries(nextEntries);
                setLoading(false);
            })
            .catch(() => {
                setLoading(false);
                setError('Failed to refresh files.');
            });
    }, [currentPath, manager.fetchUrlBase]);

    const uploadFile = (file, queueId) => {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            const url = `${manager.uploadUrlBase || `/server/${pageData.server?.containerId}/files/upload`}?path=${encodeURIComponent(currentPath)}&name=${encodeURIComponent(file.name)}`;
            
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    setFileQueue(prev => prev.map(item => item.id === queueId ? { ...item, progress: percent } : item));
                }
            });

            xhr.addEventListener('load', () => {
                try {
                    const payload = JSON.parse(xhr.responseText);
                    if (xhr.status >= 200 && xhr.status < 300 && !payload.error) {
                        setFileQueue(prev => prev.map(item => item.id === queueId ? { ...item, status: 'done', progress: 100 } : item));
                        resolve();
                    } else {
                        throw new Error(payload.error || 'Upload failed');
                    }
                } catch (err) {
                    setFileQueue(prev => prev.map(item => item.id === queueId ? { ...item, status: 'error', error: err.message } : item));
                    reject(err);
                }
            });

            xhr.addEventListener('error', () => {
                setFileQueue(prev => prev.map(item => item.id === queueId ? { ...item, status: 'error', error: 'Network error' } : item));
                reject(new Error('Network error'));
            });

            xhr.open('POST', url, true);
            xhr.setRequestHeader('x-file-name', file.name);
            xhr.withCredentials = true;
            xhr.send(file);
        });
    };

    const handleDrop = async (e) => {
        e.preventDefault();
        setIsDragging(false);
        if (permissions.filesWriteLocked) return;

        const droppedFiles = Array.from(e.dataTransfer.files);
        if (droppedFiles.length === 0) return;

        const newEntries = droppedFiles.map(f => ({
            id: Math.random().toString(36).substring(7),
            name: f.name,
            size: f.size,
            progress: 0,
            status: 'uploading'
        }));

        setFileQueue(prev => [...newEntries, ...prev]);
        setIsQueueExpanded(true);

        // Upload files (parallel)
        await Promise.allSettled(droppedFiles.map((file, idx) => uploadFile(file, newEntries[idx].id)));
        
        reloadFiles();
    };

    const handleArchive = async (fileName) => {
        if (!fileName) return;
        setLoading(true);
        try {
            const response = await fetch(`/api/client/servers/${pageData.server?.containerId}/files/archive`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, files: [fileName], name: `${fileName}.zip` })
            });
            const payload = await response.json();
            if (!response.ok || payload.error) throw new Error(payload.error || 'Archive failed');
            reloadFiles();
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    const handleUnarchive = async (fileName) => {
        setLoading(true);
        try {
            const response = await fetch(`/api/client/servers/${pageData.server?.containerId}/files/unarchive`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ directory: currentPath, name: fileName })
            });
            const payload = await response.json();
            if (!response.ok || payload.error) throw new Error(payload.error || 'Extraction failed');
            reloadFiles();
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        if (!permissions.filesWriteLocked) setIsDragging(true);
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        // Only disable if we actually left the container
        if (!e.currentTarget.contains(e.relatedTarget)) {
            setIsDragging(false);
        }
    };

    React.useEffect(() => {
        let cancelled = false;
        setLoading(true);
        setError('');
        fetch(`${manager.fetchUrlBase}?path=${encodeURIComponent(currentPath)}`, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' }
        })
            .then(async (response) => {
                const payload = await response.json().catch(() => ({}));
                if (!response.ok || payload.error) {
                    throw new Error(payload.error || `Failed to load ${currentPath}`);
                }
                if (cancelled) return;
                const nextEntries = Array.isArray(payload.files) ? payload.files : [];
                nextEntries.sort((left, right) => {
                    if (left.isDirectory && !right.isDirectory) return -1;
                    if (!left.isDirectory && right.isDirectory) return 1;
                    return String(left.name || '').localeCompare(String(right.name || ''), undefined, { numeric: true, sensitivity: 'base' });
                });
                setEntries(nextEntries);
                setLoading(false);
            })
            .catch((requestError) => {
                if (cancelled) return;
                setEntries([]);
                setLoading(false);
                setError(requestError && requestError.message ? requestError.message : 'Failed to load files.');
            });
        return () => {
            cancelled = true;
        };
    }, [currentPath, manager.fetchUrlBase]);

    const breadcrumbs = buildSegments(currentPath);
    const activeServer = pageData.server || {};

    return (
        <ReactAppShell pageData={pageData} subtitle="File manager">
            <PageContentBlock 
                title="File Manager" 
                description="Browse container files, jump into the editor, or fall back to the legacy manager for advanced actions." 
                eyebrow="Server Workspace"
            >
                <div className="flex justify-end gap-3 mb-6">
                    {manager.webUploadEnabled ? (
                        <span className="text-sm text-neutral-400 self-center mr-2">{`Uploads enabled up to ${manager.webUploadMaxMb} MB`}</span>
                    ) : null}
                    <a href={`${manager.legacyUrl}?legacy=1`} className="bg-neutral-700 hover:bg-neutral-600 text-white font-semibold flex-shrink-0 py-2 px-4 rounded transition-colors text-sm shadow-sm flex items-center gap-2">
                        <i className="bi bi-box-arrow-up-right"></i> Open Legacy View
                    </a>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
                    
                    {/* Sidebar / Info */}
                    <div className="lg:col-span-1 flex flex-col gap-6">
                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg p-6">
                            <h2 className="text-lg font-bold text-white mb-4">Storage Access</h2>
                            <div className="flex flex-col gap-3">
                                <div className="flex justify-between items-center border-b border-neutral-700/50 pb-2">
                                    <span className="text-sm font-semibold text-neutral-400">Server</span>
                                    <strong className="text-neutral-200">{activeServer.name || 'Server'}</strong>
                                </div>
                                <div className="flex justify-between items-center border-b border-neutral-700/50 pb-2">
                                    <span className="text-sm font-semibold text-neutral-400">Status</span>
                                    <strong className="text-neutral-200 capitalize">{activeServer.status || 'unknown'}</strong>
                                </div>
                                <div className="flex justify-between items-center border-b border-neutral-700/50 pb-2">
                                    <span className="text-sm font-semibold text-neutral-400">Writable</span>
                                    <strong className={permissions.canWriteFiles && !permissions.filesWriteLocked ? 'text-green-400' : 'text-red-400'}>
                                        {permissions.canWriteFiles && !permissions.filesWriteLocked ? 'Yes' : 'Read only'}
                                    </strong>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-sm font-semibold text-neutral-400">SFTP</span>
                                    <strong className="text-neutral-200">{pageData.sftpDetails && pageData.sftpDetails.available ? 'Available' : 'Unavailable'}</strong>
                                </div>
                            </div>
                            {permissions.filesWriteLocked ? (
                                <div className="mt-6 bg-yellow-900/20 border border-yellow-500/30 text-yellow-200 p-3 rounded text-sm flex items-start gap-2">
                                    <i className="bi bi-shield-lock text-yellow-500 mt-0.5"></i>
                                    File writes are locked by policy. Use editor and downloads in read-only mode.
                                </div>
                            ) : null}
                        </div>
                    </div>

                    {/* File Manager UI */}
                    <div 
                        className="lg:col-span-3 relative"
                        onDragOver={handleDragOver}
                        onDragLeave={handleDragLeave}
                        onDrop={handleDrop}
                    >
                        {isDragging && (
                            <div className="absolute inset-0 z-50 bg-primary-600/20 backdrop-blur-[2px] border-2 border-dashed border-primary-500 rounded-lg flex items-center justify-center pointer-events-none transition-all duration-300">
                                <div className="bg-neutral-900 px-8 py-10 rounded-2xl shadow-2xl border border-neutral-700 flex flex-col items-center animate-bounce">
                                    <i className="bi bi-cloud-arrow-up text-5xl text-primary-500 mb-4"></i>
                                    <span className="text-xl font-black text-white uppercase tracking-widest">Drop to Upload</span>
                                    <span className="text-sm text-neutral-400 mt-2">File(s) will be uploaded to {currentPath}</span>
                                </div>
                            </div>
                        )}

                        {fileQueue.length > 0 && (
                            <div className={`fixed bottom-6 right-6 z-[60] w-80 bg-neutral-900 border border-neutral-700 rounded-2xl shadow-2xl transition-all duration-300 ${isQueueExpanded ? 'translate-y-0 opacity-100' : 'translate-y-[calc(100%-50px)]'}`}>
                                <div 
                                    className="p-4 border-b border-neutral-800 flex items-center justify-between cursor-pointer hover:bg-neutral-800/50 transition-colors rounded-t-2xl"
                                    onClick={() => setIsQueueExpanded(!isQueueExpanded)}
                                >
                                    <div className="flex items-center gap-3">
                                        <div className="relative">
                                            <i className="bi bi-cloud-arrow-up text-xl text-primary-500"></i>
                                            {fileQueue.filter(f => f.status === 'uploading').length > 0 && (
                                                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-400 opacity-75"></span>
                                                    <span className="relative inline-flex rounded-full h-3 w-3 bg-primary-500"></span>
                                                </span>
                                            )}
                                        </div>
                                        <div>
                                            <div className="text-[10px] font-black text-neutral-500 uppercase tracking-widest leading-none mb-1">Queue Manager</div>
                                            <div className="text-xs font-bold text-white leading-none">
                                                {fileQueue.filter(f => f.status === 'done').length} of {fileQueue.length} files uploaded
                                            </div>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-4">
                                        <i className={`bi ${isQueueExpanded ? 'bi-chevron-down' : 'bi-chevron-up'} text-neutral-500`}></i>
                                        <button 
                                            className="text-neutral-500 hover:text-white transition-colors"
                                            onClick={(e) => { e.stopPropagation(); setFileQueue([]); }}
                                        >
                                            <i className="bi bi-x-lg text-xs"></i>
                                        </button>
                                    </div>
                                </div>

                                <div className={`overflow-y-auto max-h-64 flex flex-col divide-y divide-neutral-800 transition-all ${isQueueExpanded ? 'opacity-100' : 'opacity-0 h-0 pointer-events-none'}`}>
                                    {fileQueue.map(item => (
                                        <div key={item.id} className="p-4 hover:bg-white/[0.02] transition-colors">
                                            <div className="flex justify-between items-start mb-2 gap-3">
                                                <div className="min-w-0">
                                                    <div className="text-xs font-bold text-neutral-200 truncate">{item.name}</div>
                                                    <div className="text-[10px] text-neutral-500 font-mono mt-0.5">{formatBytes(item.size)}</div>
                                                </div>
                                                {item.status === 'done' ? (
                                                    <i className="bi bi-check-circle-fill text-green-500"></i>
                                                ) : item.status === 'error' ? (
                                                    <i className="bi bi-exclamation-circle-fill text-red-500"></i>
                                                ) : (
                                                    <span className="text-[10px] font-black text-primary-500">{item.progress}%</span>
                                                )}
                                            </div>
                                            
                                            {item.status === 'uploading' && (
                                                <div className="h-1 w-full bg-neutral-800 rounded-full overflow-hidden">
                                                    <div 
                                                        className="h-full bg-primary-500 transition-all duration-300 ease-out"
                                                        style={{ width: `${item.progress}%` }}
                                                    ></div>
                                                </div>
                                            )}
                                            {item.status === 'error' && (
                                                <div className="text-[10px] text-red-500 mt-1 truncate">{item.error}</div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div className="bg-neutral-800 border border-neutral-700 rounded-lg overflow-hidden flex flex-col">
                            
                            {/* Breadcrumbs Row */}
                            <div className="px-5 py-4 border-b border-neutral-700/70 bg-neutral-800 flex items-center flex-wrap gap-2">
                                {breadcrumbs.map((segment, index) => (
                                    <React.Fragment key={segment.path}>
                                        <button
                                            type="button"
                                            className={`font-semibold hover:text-white transition-colors ${index === breadcrumbs.length - 1 ? 'text-neutral-100 cursor-default' : 'text-neutral-400'}`}
                                            onClick={() => index !== breadcrumbs.length - 1 && setCurrentPath(segment.path)}
                                        >
                                            {segment.label === 'home' ? <i className="bi bi-house-door-fill text-lg relative top-[1px]"></i> : segment.label}
                                        </button>
                                        {index < breadcrumbs.length - 1 && (
                                            <span className="text-neutral-600 font-bold mx-1">/</span>
                                        )}
                                    </React.Fragment>
                                ))}
                            </div>

                            {error && (
                                <div className="bg-red-600/20 border-b border-red-600/50 text-red-100 p-3 px-5 text-sm flex items-center gap-2">
                                    <i className="bi bi-exclamation-triangle-fill text-red-500"></i> {error}
                                </div>
                            )}

                            {/* Table Header */}
                            <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-neutral-700/50 bg-neutral-900/30 text-xs font-bold text-neutral-400 uppercase tracking-widest hidden sm:grid">
                                <div className="col-span-6">Name</div>
                                <div className="col-span-3">Modified</div>
                                <div className="col-span-2 text-right">Size</div>
                                <div className="col-span-1 text-right">Actions</div>
                            </div>

                            {/* List Body */}
                            <div className="flex flex-col min-h-[400px]">
                                {loading && (
                                    <div className="flex-1 flex justify-center items-center py-16">
                                        <div className="flex flex-col items-center justify-center space-y-4">
                                            <div className="w-10 h-10 border-4 border-neutral-600 border-t-primary-500 rounded-full animate-spin"></div>
                                            <span className="text-neutral-400 text-sm">Loading directory...</span>
                                        </div>
                                    </div>
                                )}
                                {!loading && entries.length === 0 && (
                                    <div className="flex-1 flex justify-center items-center py-16">
                                        <div className="text-center">
                                            <i className="bi bi-folder2-open text-4xl text-neutral-600 block mb-3"></i>
                                            <span className="text-neutral-400 text-sm block">This directory is empty.</span>
                                        </div>
                                    </div>
                                )}
                                
                                {!loading && entries.map((entry) => {
                                    const entryPath = normalizePath(`${currentPath === '/' ? '' : currentPath}/${entry.name || ''}`);
                                    const isMenuOpen = menuPath === entryPath;
                                    
                                    return (
                                        <div key={entryPath} className="grid sm:grid-cols-12 gap-0 sm:gap-4 px-0 sm:px-6 py-0 border-b border-neutral-700/30 hover:bg-neutral-700/20 transition-colors group relative">
                                            
                                            <div className="sm:col-span-6 flex items-center">
                                                <button
                                                    type="button"
                                                    className="w-full text-left px-5 sm:px-0 py-4 flex items-center gap-4 hover:text-white transition-colors"
                                                    onClick={() => {
                                                        setMenuPath('');
                                                        if (entry.isDirectory) {
                                                            setCurrentPath(entryPath);
                                                        } else {
                                                            // For files, navigate to editor
                                                            window.location.href = `${manager.editUrlBase}?path=${encodeURIComponent(entryPath)}`;
                                                        }
                                                    }}
                                                >
                                                    <i className={`text-2xl ${entry.isDirectory ? 'bi bi-folder-fill text-primary-400 group-hover:text-primary-300' : 'bi bi-file-earmark-text text-neutral-400 group-hover:text-neutral-300'}`}></i>
                                                    <div className="overflow-hidden">
                                                        <strong className="block text-neutral-200 text-sm truncate font-semibold">{entry.name || 'Unnamed item'}</strong>
                                                        <span className="block text-xs text-neutral-500 sm:hidden mt-0.5">{entry.isDirectory ? 'Folder' : (entry.permissions || 'File')}</span>
                                                    </div>
                                                </button>
                                            </div>
                                            
                                            <div className="hidden sm:flex col-span-3 items-center">
                                                <div className="text-sm text-neutral-400 truncate">{formatDate(entry.modified)}</div>
                                            </div>
                                            
                                            <div className="hidden sm:flex col-span-2 items-center justify-end">
                                                <div className="text-sm text-neutral-400 font-mono">{entry.isDirectory ? 'Folder' : formatBytes(entry.size)}</div>
                                            </div>
                                            
                                            <div className="flex sm:col-span-1 items-center justify-end px-4 sm:px-0 py-2 sm:py-0">
                                                <button 
                                                    type="button" 
                                                    className="w-10 h-10 sm:w-8 sm:h-8 flex items-center justify-center rounded-lg sm:rounded text-neutral-400 hover:text-white hover:bg-neutral-700 sm:hover:bg-neutral-600 transition-colors border border-neutral-700 sm:border-0" 
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        setMenuPath(isMenuOpen ? '' : entryPath);
                                                    }}
                                                >
                                                    <i className="bi bi-three-dots"></i>
                                                </button>
                                                
                                                {isMenuOpen && (
                                                    <div className="absolute right-4 sm:right-6 top-14 sm:top-12 z-50 w-56 bg-neutral-900 border border-neutral-700 rounded-xl shadow-2xl py-2 transform origin-top-right transition-all overflow-hidden ring-1 ring-black/50">
                                                        {entry.isDirectory ? (
                                                            <button 
                                                                type="button" 
                                                                className="w-full text-left px-4 py-2.5 text-sm text-neutral-300 hover:text-white hover:bg-neutral-800 flex items-center gap-3 transition-colors" 
                                                                onClick={() => { setCurrentPath(entryPath); setMenuPath(''); }}
                                                            >
                                                                <i className="bi bi-folder-symlink text-primary-400"></i> Open Folder
                                                            </button>
                                                        ) : (
                                                            <>
                                                                <a className="flex items-center gap-3 px-4 py-2.5 text-sm text-neutral-300 hover:text-white hover:bg-neutral-800 transition-colors" href={`${manager.editUrlBase}?path=${encodeURIComponent(entryPath)}`}>
                                                                    <i className="bi bi-pencil text-neutral-400"></i> Edit File
                                                                </a>
                                                                <a className="flex items-center gap-3 px-4 py-2.5 text-sm text-neutral-300 hover:text-white hover:bg-neutral-800 transition-colors" href={`${manager.previewUrlBase}?path=${encodeURIComponent(entryPath)}`}>
                                                                    <i className="bi bi-eye text-neutral-400"></i> Preview
                                                                </a>
                                                                {permissions.canDownloadFiles && (
                                                                    <a className="flex items-center gap-3 px-4 py-2.5 text-sm text-neutral-300 hover:text-white hover:bg-neutral-800 mt-1 border-t border-neutral-800/50 pt-2 transition-colors" href={`${manager.downloadUrlBase}?path=${encodeURIComponent(entryPath)}`}>
                                                                        <i className="bi bi-cloud-arrow-down text-blue-400"></i> Download
                                                                    </a>
                                                                )}
                                                            </>
                                                        )}
                                                        
                                                        {/* Archive Actions */}
                                                        {!permissions.filesWriteLocked && (
                                                            <div className="mt-1 pt-1 border-t border-neutral-800/50">
                                                                <button 
                                                                    type="button"
                                                                    className="w-full text-left px-4 py-2.5 text-sm text-neutral-300 hover:text-white hover:bg-neutral-800 flex items-center gap-3 transition-colors"
                                                                    onClick={() => { handleArchive(entry.name); setMenuPath(''); }}
                                                                >
                                                                    <i className="bi bi-file-zip text-yellow-400"></i> Archive
                                                                </button>
                                                                {!entry.isDirectory && (entry.name.endsWith('.zip') || entry.name.endsWith('.tar.gz') || entry.name.endsWith('.tar')) && (
                                                                    <button 
                                                                        type="button"
                                                                        className="w-full text-left px-4 py-2.5 text-sm text-neutral-300 hover:text-white hover:bg-neutral-800 flex items-center gap-3 transition-colors"
                                                                        onClick={() => { handleUnarchive(entry.name); setMenuPath(''); }}
                                                                    >
                                                                        <i className="bi bi-file-earmark-zip text-green-400"></i> Unarchive
                                                                    </button>
                                                                )}
                                                            </div>
                                                        )}

                                                        <div className="border-t border-neutral-800/50 mt-1 pt-1">
                                                            <a className="flex items-center gap-3 px-4 py-2.5 text-xs text-neutral-500 hover:text-white hover:bg-neutral-800 transition-colors" href={`${manager.legacyUrl}?legacy=1&path=${encodeURIComponent(currentPath)}`}>
                                                                <i className="bi bi-box-arrow-up-right"></i> Legacy Mode
                                                            </a>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>

                </div>
            </PageContentBlock>
        </ReactAppShell>
    );
}

export default ServerFilesPage;

if (root) {
    root.render(<ServerFilesPage pageData={data} />);
    if (typeof window.__CPANEL_REACT_BOOTED__ === 'function') {
        window.__CPANEL_REACT_BOOTED__();
    }
}
