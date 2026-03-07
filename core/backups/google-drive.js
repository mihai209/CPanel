const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { PassThrough } = require('stream');
const axios = require('axios');

const GOOGLE_TOKEN_SETTINGS_PREFIX = 'oauth_google_tokens_user_';
const GOOGLE_DRIVE_BACKUP_DEST = 'google_drive';
const GOOGLE_DRIVE_SCOPE_FILE = 'https://www.googleapis.com/auth/drive.file';
const GOOGLE_DRIVE_SCOPE_FULL = 'https://www.googleapis.com/auth/drive';

function getGoogleTokenSettingKey(userId) {
    const parsed = Number.parseInt(userId, 10);
    if (!Number.isInteger(parsed) || parsed <= 0) return '';
    return `${GOOGLE_TOKEN_SETTINGS_PREFIX}${parsed}`;
}

function parseScopes(raw) {
    if (Array.isArray(raw)) {
        return raw
            .map((entry) => String(entry || '').trim())
            .filter(Boolean);
    }
    return String(raw || '')
        .split(/[\s,]+/)
        .map((entry) => entry.trim())
        .filter(Boolean);
}

function hasGoogleDriveScope(scopesRaw) {
    const scopes = parseScopes(scopesRaw);
    return scopes.includes(GOOGLE_DRIVE_SCOPE_FILE) || scopes.includes(GOOGLE_DRIVE_SCOPE_FULL);
}

function parseGoogleTokenPayload(rawValue) {
    if (!rawValue) return {};
    if (typeof rawValue === 'object' && rawValue !== null) return rawValue;
    try {
        return JSON.parse(String(rawValue));
    } catch {
        return {};
    }
}

async function getGoogleOAuthClientConfig(Settings) {
    if (!Settings || typeof Settings.findAll !== 'function') {
        return { clientId: '', clientSecret: '' };
    }
    const rows = await Settings.findAll({
        where: { key: ['authGoogleClientId', 'authGoogleClientSecret'] },
        attributes: ['key', 'value']
    });
    const map = {};
    rows.forEach((row) => {
        if (!row || !row.key) return;
        map[row.key] = String(row.value || '').trim();
    });
    return {
        clientId: String(map.authGoogleClientId || '').trim(),
        clientSecret: String(map.authGoogleClientSecret || '').trim()
    };
}

async function loadGoogleTokenState(Settings, userId) {
    const key = getGoogleTokenSettingKey(userId);
    if (!key || !Settings || typeof Settings.findByPk !== 'function') return { key, state: {} };
    const row = await Settings.findByPk(key);
    const state = parseGoogleTokenPayload(row && row.value ? row.value : '{}');
    return { key, state };
}

async function saveGoogleTokenState(Settings, userId, state) {
    const key = getGoogleTokenSettingKey(userId);
    if (!key || !Settings || typeof Settings.upsert !== 'function') return;
    await Settings.upsert({
        key,
        value: JSON.stringify(state || {})
    });
}

async function refreshGoogleAccessToken({ clientId, clientSecret, refreshToken }) {
    const params = new URLSearchParams();
    params.set('client_id', String(clientId || '').trim());
    params.set('client_secret', String(clientSecret || '').trim());
    params.set('refresh_token', String(refreshToken || '').trim());
    params.set('grant_type', 'refresh_token');

    const response = await axios.post('https://oauth2.googleapis.com/token', params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 20000,
        validateStatus: () => true
    });

    if (response.status < 200 || response.status >= 300) {
        const message = response && response.data && response.data.error_description
            ? String(response.data.error_description)
            : (response && response.data && response.data.error ? String(response.data.error) : `HTTP ${response.status}`);
        throw new Error(`Google token refresh failed: ${message}`);
    }

    return response.data || {};
}

function toIsoFromExpiresIn(expiresInRaw) {
    const expiresIn = Number.parseInt(expiresInRaw, 10);
    if (!Number.isInteger(expiresIn) || expiresIn <= 0) return null;
    return new Date(Date.now() + (expiresIn * 1000)).toISOString();
}

function isTokenStillValid(tokenExpiryRaw) {
    const ts = Date.parse(String(tokenExpiryRaw || ''));
    if (!Number.isFinite(ts)) return false;
    return ts - Date.now() > 60 * 1000;
}

async function getValidGoogleAccessToken({ Settings, userId, clientId, clientSecret }) {
    const { state } = await loadGoogleTokenState(Settings, userId);
    const accessToken = String(state.accessToken || '').trim();
    const refreshToken = String(state.refreshToken || '').trim();
    const tokenType = String(state.tokenType || 'Bearer').trim() || 'Bearer';
    const scopes = parseScopes(state.scopes || []);

    if (accessToken && isTokenStillValid(state.tokenExpiry)) {
        return {
            accessToken,
            tokenType,
            scopes,
            tokenExpiry: state.tokenExpiry || null,
            refreshToken
        };
    }

    if (!refreshToken) {
        throw new Error('Google Drive access is missing refresh token. Relink Google account with Drive permission.');
    }
    if (!clientId || !clientSecret) {
        throw new Error('Google OAuth is not configured on panel (missing client id/secret).');
    }

    const refreshed = await refreshGoogleAccessToken({
        clientId,
        clientSecret,
        refreshToken
    });

    const nextState = {
        provider: 'google',
        accessToken: String(refreshed.access_token || '').trim() || accessToken || null,
        refreshToken,
        tokenType: String(refreshed.token_type || tokenType || 'Bearer').trim() || 'Bearer',
        tokenExpiry: toIsoFromExpiresIn(refreshed.expires_in) || state.tokenExpiry || null,
        scopes: parseScopes(refreshed.scope || scopes),
        updatedAt: new Date().toISOString()
    };

    await saveGoogleTokenState(Settings, userId, nextState);

    return {
        accessToken: String(nextState.accessToken || ''),
        tokenType: String(nextState.tokenType || 'Bearer'),
        scopes: parseScopes(nextState.scopes || []),
        tokenExpiry: nextState.tokenExpiry || null,
        refreshToken
    };
}

function sanitizeNameForArchive(raw) {
    const text = String(raw || '').trim();
    if (!text) return 'server-backup';
    const normalized = text
        .replace(/[^a-zA-Z0-9._-]+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 64);
    return normalized || 'server-backup';
}

function emitProgress(onProgress, payload) {
    if (typeof onProgress !== 'function') return;
    try {
        onProgress(payload || {});
    } catch {
        // ignore progress callback errors
    }
}

async function getDirectorySizeBytes(sourceDir) {
    return new Promise((resolve) => {
        const child = spawn('du', ['-sb', sourceDir], {
            stdio: ['ignore', 'pipe', 'ignore']
        });

        let stdout = '';
        child.stdout.on('data', (chunk) => {
            stdout += String(chunk || '');
        });
        child.on('error', () => resolve(0));
        child.on('close', (code) => {
            if (code !== 0) return resolve(0);
            const firstToken = String(stdout || '').trim().split(/\s+/)[0];
            const parsed = Number.parseInt(firstToken, 10);
            if (!Number.isInteger(parsed) || parsed < 0) return resolve(0);
            resolve(parsed);
        });
    });
}

function driveAuthHeaders(accessToken) {
    return {
        Authorization: `Bearer ${String(accessToken || '').trim()}`
    };
}

async function ensureDriveFolder({ accessToken, folderName }) {
    const safeName = String(folderName || '').trim() || 'server-backup';
    const listResponse = await axios.get('https://www.googleapis.com/drive/v3/files', {
        headers: driveAuthHeaders(accessToken),
        params: {
            q: `mimeType = 'application/vnd.google-apps.folder' and trashed = false and name = '${safeName.replace(/'/g, "\\'")}' and 'root' in parents`,
            fields: 'files(id,name)',
            pageSize: 20,
            spaces: 'drive'
        },
        timeout: 20000,
        validateStatus: () => true
    });

    if (listResponse.status >= 200 && listResponse.status < 300) {
        const files = Array.isArray(listResponse.data && listResponse.data.files)
            ? listResponse.data.files
            : [];
        if (files.length > 0 && files[0].id) {
            return String(files[0].id);
        }
    } else {
        const message = listResponse && listResponse.data && listResponse.data.error && listResponse.data.error.message
            ? String(listResponse.data.error.message)
            : `HTTP ${listResponse.status}`;
        throw new Error(`Failed to query Google Drive folder: ${message}`);
    }

    const createResponse = await axios.post('https://www.googleapis.com/drive/v3/files', {
        name: safeName,
        mimeType: 'application/vnd.google-apps.folder',
        parents: ['root']
    }, {
        headers: {
            ...driveAuthHeaders(accessToken),
            'Content-Type': 'application/json'
        },
        params: { fields: 'id,name' },
        timeout: 20000,
        validateStatus: () => true
    });

    if (createResponse.status < 200 || createResponse.status >= 300 || !createResponse.data || !createResponse.data.id) {
        const message = createResponse && createResponse.data && createResponse.data.error && createResponse.data.error.message
            ? String(createResponse.data.error.message)
            : `HTTP ${createResponse.status}`;
        throw new Error(`Failed to create Google Drive folder: ${message}`);
    }

    return String(createResponse.data.id);
}

async function listDriveFilesInFolder({ accessToken, folderId }) {
    const result = [];
    let pageToken = '';

    while (true) {
        const response = await axios.get('https://www.googleapis.com/drive/v3/files', {
            headers: driveAuthHeaders(accessToken),
            params: {
                q: `'${String(folderId)}' in parents and trashed = false and mimeType != 'application/vnd.google-apps.folder'`,
                fields: 'nextPageToken,files(id,name,size,createdTime)',
                pageSize: 1000,
                spaces: 'drive',
                pageToken: pageToken || undefined
            },
            timeout: 25000,
            validateStatus: () => true
        });

        if (response.status < 200 || response.status >= 300) {
            const message = response && response.data && response.data.error && response.data.error.message
                ? String(response.data.error.message)
                : `HTTP ${response.status}`;
            throw new Error(`Failed to list old Google Drive backups: ${message}`);
        }

        const files = Array.isArray(response.data && response.data.files) ? response.data.files : [];
        result.push(...files);
        pageToken = String(response.data && response.data.nextPageToken ? response.data.nextPageToken : '');
        if (!pageToken) break;
    }

    return result;
}

async function deleteDriveFile({ accessToken, fileId }) {
    const response = await axios.delete(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(String(fileId))}`, {
        headers: driveAuthHeaders(accessToken),
        timeout: 20000,
        validateStatus: () => true
    });
    if (response.status >= 200 && response.status < 300) return;
    const message = response && response.data && response.data.error && response.data.error.message
        ? String(response.data.error.message)
        : `HTTP ${response.status}`;
    throw new Error(`Failed to delete old Google Drive backup: ${message}`);
}

async function cleanupFolderFiles({ accessToken, folderId, namePrefix = 'cpanel-backup-' }) {
    const oldFiles = await listDriveFilesInFolder({ accessToken, folderId });
    const filtered = oldFiles.filter((file) => String(file && file.name ? file.name : '').startsWith(String(namePrefix)));
    for (const file of filtered) {
        if (!file || !file.id) continue;
        await deleteDriveFile({ accessToken, fileId: file.id });
    }
    return filtered.length;
}

async function uploadTarStreamToDriveMultipart({ accessToken, sourceDir, fileName, parentFolderId, estimatedSourceBytes = 0, onProgress = null }) {
    const boundary = `cpanel_backup_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const metadata = {
        name: String(fileName || 'cpanel-backup.tar.gz'),
        parents: [String(parentFolderId)]
    };
    const preamble = [
        `--${boundary}`,
        'Content-Type: application/json; charset=UTF-8',
        '',
        JSON.stringify(metadata),
        `--${boundary}`,
        'Content-Type: application/gzip',
        '',
        ''
    ].join('\r\n');
    const epilogue = `\r\n--${boundary}--\r\n`;

    const bodyStream = new PassThrough();
    const hash = crypto.createHash('sha256');
    const child = spawn('tar', ['-czf', '-', '-C', sourceDir, '.'], {
        stdio: ['ignore', 'pipe', 'pipe']
    });
    const uploadStartedAt = Date.now();
    let uploadedBytes = 0;
    let estimatedTotalBytes = Math.max(Math.floor(Number(estimatedSourceBytes || 0) * 0.65), 64 * 1024 * 1024);
    let lastEmitMs = 0;
    let lastEmittedPercent = 0;

    const maybeEmitUploadProgress = (force = false) => {
        const now = Date.now();
        if (uploadedBytes >= estimatedTotalBytes * 0.98) {
            estimatedTotalBytes = Math.max(Math.floor(uploadedBytes * 1.2), uploadedBytes + 8 * 1024 * 1024);
        }
        const ratio = Math.min(0.995, uploadedBytes / Math.max(1, estimatedTotalBytes));
        const percent = 35 + (ratio * 60); // 35..95%
        const elapsedSec = Math.max(1, (now - uploadStartedAt) / 1000);
        const speedBytesPerSec = uploadedBytes / elapsedSec;
        const remainingBytes = Math.max(0, estimatedTotalBytes - uploadedBytes);
        const etaSeconds = speedBytesPerSec > 0 ? Math.round(remainingBytes / speedBytesPerSec) : null;

        if (!force && (now - lastEmitMs) < 1500 && Math.abs(percent - lastEmittedPercent) < 0.8) {
            return;
        }
        lastEmitMs = now;
        lastEmittedPercent = percent;
        emitProgress(onProgress, {
            stage: 'uploading',
            percent,
            etaSeconds,
            uploadedBytes,
            totalBytes: estimatedTotalBytes
        });
    };

    let stderr = '';
    child.stderr.on('data', (chunk) => {
        stderr += String(chunk || '');
    });

    const tarExitPromise = new Promise((resolve, reject) => {
        child.on('error', (error) => {
            bodyStream.destroy(error);
            reject(error);
        });
        child.on('close', (code) => {
            if (code === 0) {
                resolve();
                return;
            }
            const error = new Error(stderr.trim() || `tar exited with code ${code}`);
            bodyStream.destroy(error);
            reject(error);
        });
    });

    bodyStream.write(Buffer.from(preamble, 'utf8'));
    child.stdout.on('data', (chunk) => {
        uploadedBytes += chunk.length;
        hash.update(chunk);
        maybeEmitUploadProgress(false);
    });
    child.stdout.on('error', (error) => {
        bodyStream.destroy(error);
    });
    child.stdout.pipe(bodyStream, { end: false });
    child.stdout.on('end', () => {
        maybeEmitUploadProgress(true);
        bodyStream.end(Buffer.from(epilogue, 'utf8'));
    });

    let uploadResponse;
    try {
        [uploadResponse] = await Promise.all([
            axios.post('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', bodyStream, {
                headers: {
                    ...driveAuthHeaders(accessToken),
                    'Content-Type': `multipart/related; boundary=${boundary}`
                },
                params: {
                    fields: 'id,name,size,createdTime,webViewLink,webContentLink'
                },
                maxBodyLength: Infinity,
                maxContentLength: Infinity,
                timeout: 10 * 60 * 1000,
                validateStatus: () => true
            }),
            tarExitPromise
        ]);
    } catch (error) {
        try {
            child.kill('SIGKILL');
        } catch {
            // ignore
        }
        throw error;
    }

    if (!uploadResponse || uploadResponse.status < 200 || uploadResponse.status >= 300 || !uploadResponse.data || !uploadResponse.data.id) {
        const message = uploadResponse && uploadResponse.data && uploadResponse.data.error && uploadResponse.data.error.message
            ? String(uploadResponse.data.error.message)
            : `HTTP ${uploadResponse ? uploadResponse.status : 'unknown'}`;
        throw new Error(`Failed to upload backup to Google Drive: ${message}`);
    }

    return {
        uploadData: uploadResponse.data,
        checksum: hash.digest('hex'),
        uploadedBytes
    };
}

async function performGoogleDriveBackup({
    server,
    connector,
    Settings,
    onProgress = null
}) {
    if (!server || !connector) {
        throw new Error('Cannot run backup: missing server or connector details.');
    }

    const ownerId = Number.parseInt(server.ownerId, 10);
    if (!Number.isInteger(ownerId) || ownerId <= 0) {
        throw new Error('Cannot run backup: server owner is invalid.');
    }

    const { clientId, clientSecret } = await getGoogleOAuthClientConfig(Settings);
    if (!clientId || !clientSecret) {
        throw new Error('Google OAuth provider is not configured in panel settings.');
    }

    const tokenState = await getValidGoogleAccessToken({
        Settings,
        userId: ownerId,
        clientId,
        clientSecret
    });
    if (!tokenState.accessToken) {
        throw new Error('Google Drive access token is missing. Relink Google account.');
    }
    if (!hasGoogleDriveScope(tokenState.scopes)) {
        throw new Error('Google account is linked without Drive permission. Reconnect with Drive access.');
    }

    const baseDirectoryRaw = String(connector.fileDirectory || '/var/lib/cpanel/volumes').trim() || '/var/lib/cpanel/volumes';
    const sourceDir = path.resolve(baseDirectoryRaw, String(server.id));
    emitProgress(onProgress, {
        stage: 'scanning',
        percent: 10,
        etaSeconds: null,
        message: 'Scanning server files...'
    });
    let sourceStat;
    try {
        sourceStat = await fsp.stat(sourceDir);
    } catch {
        throw new Error(`Server files path not found on panel host: ${sourceDir}`);
    }
    if (!sourceStat.isDirectory()) {
        throw new Error(`Server files path is not a directory: ${sourceDir}`);
    }
    const sourceSizeBytes = await getDirectorySizeBytes(sourceDir);
    emitProgress(onProgress, {
        stage: 'preparing',
        percent: 18,
        etaSeconds: null,
        totalBytes: sourceSizeBytes || 0,
        message: 'Preparing Google Drive backup...'
    });

    emitProgress(onProgress, {
        stage: 'drive_folder',
        percent: 24,
        etaSeconds: null,
        message: 'Preparing Drive folder...'
    });
    const folderId = await ensureDriveFolder({
        accessToken: tokenState.accessToken,
        folderName: String(server.name || `server-${server.id}`)
    });

    emitProgress(onProgress, {
        stage: 'cleanup',
        percent: 30,
        etaSeconds: null,
        message: 'Removing old Drive backup...'
    });
    const deletedOldCount = await cleanupFolderFiles({
        accessToken: tokenState.accessToken,
        folderId,
        namePrefix: 'cpanel-backup-'
    });

    const archiveName = `cpanel-backup-${sanitizeNameForArchive(server.name || `server-${server.id}`)}-${server.id}-${Date.now()}.tar.gz`;
    const uploadResult = await uploadTarStreamToDriveMultipart({
        accessToken: tokenState.accessToken,
        sourceDir,
        fileName: archiveName,
        parentFolderId: folderId,
        estimatedSourceBytes: sourceSizeBytes,
        onProgress
    });
    const uploadData = uploadResult.uploadData || {};
    emitProgress(onProgress, {
        stage: 'finalizing',
        percent: 98,
        etaSeconds: 0,
        uploadedBytes: uploadResult.uploadedBytes || 0,
        totalBytes: sourceSizeBytes || 0,
        message: 'Finalizing backup metadata...'
    });

    return {
        sourceDir,
        sourceSizeBytes,
        folderId,
        deletedOldCount,
        fileId: String(uploadData.id),
        fileName: String(uploadData.name || archiveName),
        sizeBytes: Number(uploadData.size || 0),
        checksum: uploadResult.checksum || null,
        webViewLink: uploadData.webViewLink || null,
        webContentLink: uploadData.webContentLink || null
    };
}

module.exports = {
    GOOGLE_TOKEN_SETTINGS_PREFIX,
    GOOGLE_DRIVE_BACKUP_DEST,
    GOOGLE_DRIVE_SCOPE_FILE,
    GOOGLE_DRIVE_SCOPE_FULL,
    getGoogleTokenSettingKey,
    parseGoogleTokenPayload,
    parseScopes,
    hasGoogleDriveScope,
    getGoogleOAuthClientConfig,
    loadGoogleTokenState,
    saveGoogleTokenState,
    getValidGoogleAccessToken,
    performGoogleDriveBackup
};
