#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const configPath = path.join(rootDir, 'security', 'supply-chain-blocklist.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

const manifestsToScan = new Set(Array.isArray(config.scanFiles) ? config.scanFiles : []);
const skipDirs = new Set(Array.isArray(config.skipDirectories) ? config.skipDirectories : []);
const blockedPackages = Array.isArray(config.blockedPackages) ? config.blockedPackages : [];

const blockedPackageMap = new Map(
    blockedPackages
        .filter((entry) => entry && typeof entry.name === 'string' && entry.name.trim())
        .map((entry) => [entry.name.trim(), {
            versions: new Set(Array.isArray(entry.blockedVersions) ? entry.blockedVersions.map((item) => String(item).trim()) : []),
            reason: String(entry.reason || '').trim(),
        }])
);

const findings = [];

function readText(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

function pushFinding(filePath, message) {
    findings.push({
        file: path.relative(rootDir, filePath),
        message,
    });
}

function isBlockedVersion(packageName, version) {
    const meta = blockedPackageMap.get(packageName);
    if (!meta) return false;
    return meta.versions.has('*') || meta.versions.has(String(version).trim());
}

function blockedReason(packageName) {
    const meta = blockedPackageMap.get(packageName);
    return meta && meta.reason ? ` (${meta.reason})` : '';
}

function scanDependencySpec(filePath, packageName, spec, trail) {
    const normalized = String(spec || '').trim();
    if (!normalized) return;
    const meta = blockedPackageMap.get(packageName);
    if (!meta) return;

    for (const blockedVersion of meta.versions) {
        if (blockedVersion === '*') {
            pushFinding(filePath, `blocked package "${packageName}" referenced at ${trail}${blockedReason(packageName)}`);
            return;
        }
        if (normalized === blockedVersion || normalized.includes(blockedVersion)) {
            pushFinding(filePath, `blocked version spec "${packageName}@${normalized}" at ${trail}${blockedReason(packageName)}`);
            return;
        }
    }
}

function scanJsonObject(filePath, node, trail = []) {
    if (Array.isArray(node)) {
        node.forEach((entry, index) => scanJsonObject(filePath, entry, trail.concat(String(index))));
        return;
    }
    if (!node || typeof node !== 'object') return;

    for (const [key, value] of Object.entries(node)) {
        const nextTrail = trail.concat(key);
        const trailText = nextTrail.join('.');

        if (
            ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'overrides', 'packages'].includes(key) &&
            value &&
            typeof value === 'object' &&
            !Array.isArray(value)
        ) {
            for (const [depName, depValue] of Object.entries(value)) {
                if (typeof depValue === 'string') {
                    scanDependencySpec(filePath, depName, depValue, `${trailText}.${depName}`);
                } else if (depValue && typeof depValue === 'object') {
                    const candidateVersion = typeof depValue.version === 'string' ? depValue.version : '';
                    if (candidateVersion && isBlockedVersion(depName, candidateVersion)) {
                        pushFinding(filePath, `blocked package object "${depName}@${candidateVersion}" at ${trailText}.${depName}${blockedReason(depName)}`);
                    }
                    scanJsonObject(filePath, depValue, nextTrail.concat(depName));
                }
            }
        }

        if (blockedPackageMap.has(key) && typeof value === 'string') {
            scanDependencySpec(filePath, key, value, trailText);
        }

        if (key === 'name' && typeof value === 'string' && blockedPackageMap.has(value)) {
            const packageName = value.trim();
            const version = typeof node.version === 'string' ? node.version.trim() : '';
            if (isBlockedVersion(packageName, version || '*')) {
                pushFinding(filePath, `blocked package "${packageName}${version ? '@' + version : ''}" at ${trailText}${blockedReason(packageName)}`);
            }
        }

        if (typeof value === 'object') {
            scanJsonObject(filePath, value, nextTrail);
        }
    }
}

function scanJsonFile(filePath) {
    try {
        const data = JSON.parse(readText(filePath));
        scanJsonObject(filePath, data);
    } catch (error) {
        pushFinding(filePath, `failed to parse JSON: ${error.message}`);
    }
}

function scanTextFile(filePath) {
    const content = readText(filePath);
    for (const [packageName, meta] of blockedPackageMap.entries()) {
        if (meta.versions.has('*') && content.includes(packageName)) {
            pushFinding(filePath, `blocked package "${packageName}" found in lockfile${blockedReason(packageName)}`);
            continue;
        }
        for (const blockedVersion of meta.versions) {
            if (blockedVersion === '*') continue;
            if (
                content.includes(`${packageName}@${blockedVersion}`) ||
                content.includes(`/${packageName}/${blockedVersion}`) ||
                content.includes(`"${packageName}": "${blockedVersion}"`) ||
                content.includes(`version: ${blockedVersion}`) ||
                content.includes(`version "${blockedVersion}"`)
            ) {
                pushFinding(filePath, `blocked version "${packageName}@${blockedVersion}" found in text lockfile${blockedReason(packageName)}`);
            }
        }
    }
}

function walk(dirPath) {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        if (entry.isDirectory()) {
            if (skipDirs.has(entry.name)) continue;
            walk(fullPath);
            continue;
        }
        if (!manifestsToScan.has(entry.name)) continue;
        if (entry.name.endsWith('.json')) {
            scanJsonFile(fullPath);
        } else {
            scanTextFile(fullPath);
        }
    }
}

walk(rootDir);

if (findings.length) {
    console.error('Blocked supply-chain indicators found:\n');
    for (const finding of findings) {
        console.error(`- ${finding.file}: ${finding.message}`);
    }
    process.exit(1);
}

console.log('Supply-chain security check passed. No blocked package indicators found.');
