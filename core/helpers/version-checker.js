const axios = require('axios');
const fs = require('fs');
const path = require('path');

let versionCache = null;
let lastCheckTime = 0;
const CACHE_TTL = 3600 * 1000; // 1 hour

async function getPanelVersionStatus() {
    const now = Date.now();
    
    // Return cached value if it's still valid
    if (versionCache && (now - lastCheckTime < CACHE_TTL)) {
        return versionCache;
    }

    let currentVersion = 'unknown';
    try {
        const pkgPath = path.join(__dirname, '../../package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        currentVersion = pkg.version;
    } catch (err) {
        console.error('Error reading package.json version:', err.message);
    }

    let versionStatus = {
        message: `Panel up to date v${currentVersion}`,
        type: 'success',
        currentVersion,
        remoteVersion: currentVersion,
        lastChecked: now
    };

    try {
        // Fetch remote version from the project's homepage/API
        const response = await axios.get('https://cpanel-rocky.netlify.app/version.json', { timeout: 5000 });
        const remoteVersion = response.data.version;

        if (currentVersion !== remoteVersion) {
            versionStatus = {
                message: `Your panel is not up-to-date. You are running v${currentVersion}, and the latest version is v${remoteVersion}`,
                type: 'warning',
                currentVersion,
                remoteVersion,
                lastChecked: now
            };
        }
    } catch (error) {
        console.error('Error fetching remote version:', error.message);
        versionStatus = {
            message: "Unable to reach the update server. Please check your internet connection or try again later.",
            type: 'error',
            currentVersion,
            remoteVersion: 'unknown',
            lastChecked: now
        };
    }

    // Update cache
    versionCache = versionStatus;
    lastCheckTime = now;

    return versionStatus;
}

module.exports = { getPanelVersionStatus };
