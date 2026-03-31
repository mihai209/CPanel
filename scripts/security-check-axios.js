#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const blockedVersions = new Set(['1.14.1', '0.30.4']);
const blockedPackageNames = new Set(['plain-crypto-js']);
const manifestsToScan = ['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'npm-shrinkwrap.json'];
const skipDirs = new Set(['node_modules', '.git', 'storage', 'dist', 'build', '.next', 'coverage']);

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

function scanJsonObject(filePath, node, trail = []) {
    if (Array.isArray(node)) {
        node.forEach((entry, index) => scanJsonObject(filePath, entry, trail.concat(String(index))));
        return;
    }
    if (!node || typeof node !== 'object') return;

    for (const [key, value] of Object.entries(node)) {
        const nextTrail = trail.concat(key);

        if (blockedPackageNames.has(key)) {
            pushFinding(filePath, `blocked package reference "${key}" at ${nextTrail.join('.')}`);
        }

        if (key === 'axios' && typeof value === 'string') {
            const normalized = value.trim();
            for (const blocked of blockedVersions) {
                if (normalized === blocked || normalized.includes(blocked)) {
                    pushFinding(filePath, `blocked axios reference "${normalized}" at ${nextTrail.join('.')}`);
                }
            }
        }

        if (key === 'version' && typeof value === 'string' && blockedVersions.has(value.trim())) {
            const parentName = typeof node.name === 'string' ? node.name : null;
            if (parentName === 'axios' || trail.includes('node_modules/axios')) {
                pushFinding(filePath, `blocked axios version "${value.trim()}" at ${nextTrail.join('.')}`);
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
    if (content.includes('plain-crypto-js')) {
        pushFinding(filePath, 'blocked package reference "plain-crypto-js" found in lockfile');
    }
    for (const blocked of blockedVersions) {
        if (content.includes(`axios@${blocked}`) || content.includes(`version: ${blocked}`) || content.includes(`version "${blocked}"`)) {
            pushFinding(filePath, `blocked axios version "${blocked}" found in text lockfile`);
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
        if (!manifestsToScan.includes(entry.name)) continue;
        if (entry.name.endsWith('.json')) {
            scanJsonFile(fullPath);
        } else {
            scanTextFile(fullPath);
        }
    }
}

walk(rootDir);

if (findings.length) {
    console.error('Blocked axios supply-chain indicators found:\n');
    for (const finding of findings) {
        console.error(`- ${finding.file}: ${finding.message}`);
    }
    process.exit(1);
}

console.log('Axios security check passed. No blocked versions or package indicators found.');
