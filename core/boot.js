const fs = require('fs');
const os = require('os');
const path = require('path');
const figlet = require('figlet');
const ansiReset = '\x1b[0m';
const ansiBlue = '\x1b[34m';
const ansiCyan = '\x1b[36m';
const ansiYellow = '\x1b[33m';

/*const PANEL_BANNER = [
    '   ____ ____                  _ ',
    '  / ___|  _ \\ __ _ _ __   ___| |',
    ' | |   | |_) / _` | \'_ \\ / _ \\ |',
    ' | |___|  __/ (_| | | | |  __/ |',
    '  \\____|_|   \\__,_|_| |_|\\___|_|'
].join('\n');*/

function buildPanelBanner() {
    const textOptions = {
        horizontalLayout: 'default',
        verticalLayout: 'default',
        width: 80,
        whitespaceBreak: true
    };
    const customFontEnabled = ['1', 'true', 'yes', 'on'].includes(String(process.env.CUSTOM_FONT || '').trim().toLowerCase());

    if (!customFontEnabled) {
        try {
            return figlet.textSync('CPanel - Rocky', { ...textOptions, font: 'Standard' });
        } catch {
            return 'CPanel - Rocky';
        }
    }

    try {
        const localFontPath = path.resolve(__dirname, 'fonts', 'bubble.flf');
        if (fs.existsSync(localFontPath)) {
            const localFont = fs.readFileSync(localFontPath, 'utf8');
            figlet.parseFont('bubble', localFont);
        }
        return figlet.textSync('CPanel - Rocky', { ...textOptions, font: 'bubble' });
    } catch {
        try {
            return figlet.textSync('CPanel - Rocky', { ...textOptions, font: 'Bubble' });
        } catch {
            try {
                return figlet.textSync('CPanel - Rocky', { ...textOptions, font: 'Standard' });
            } catch {
                return 'CPanel - Rocky';
            }
        }
    }
}

const PANEL_BANNER = buildPanelBanner();

const PANEL_COPYRIGHT = 'Copyright (c) 2026 CPanel Mihai209';
const PANEL_WEBSITE = 'https://cpanel-rocky.netlify.app';
const PANEL_SOURCE = 'https://github.com/mihai209/CPanel';
const PANEL_LICENSE = 'MIT';
const DEFAULT_TIMEZONE = 'Europe/Bucharest';

const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function two(n) {
    return String(n).padStart(2, '0');
}

function three(n) {
    return String(n).padStart(3, '0');
}

function utcOffsetLabel(offsetMinutes) {
    const sign = offsetMinutes >= 0 ? '+' : '-';
    const abs = Math.abs(offsetMinutes);
    const hours = Math.floor(abs / 60);
    const minutes = abs % 60;
    return `${sign}${hours}:${two(minutes)}`;
}

function resolveTimezone(configuredTimezone) {
    const value = String(configuredTimezone || '').trim();
    if (!value) return DEFAULT_TIMEZONE;
    try {
        new Intl.DateTimeFormat('en-US', { timeZone: value }).format(new Date());
        return value;
    } catch {
        return DEFAULT_TIMEZONE;
    }
}

function getOffsetMinutesForTimezone(date, timezone) {
    try {
        const formatter = new Intl.DateTimeFormat('en-US', {
            timeZone: timezone,
            hour12: false,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });

        const parts = formatter.formatToParts(date);
        const values = {};
        for (const part of parts) {
            if (part.type !== 'literal') {
                values[part.type] = part.value;
            }
        }

        const asUtc = Date.UTC(
            Number.parseInt(values.year, 10),
            Number.parseInt(values.month, 10) - 1,
            Number.parseInt(values.day, 10),
            Number.parseInt(values.hour, 10),
            Number.parseInt(values.minute, 10),
            Number.parseInt(values.second, 10)
        );

        return Math.round((asUtc - date.getTime()) / 60000);
    } catch {
        return -date.getTimezoneOffset();
    }
}

function bootTimestamp() {
    const now = new Date();
    const month = monthNames[now.getMonth()];
    const day = two(now.getDate());
    const hh = two(now.getHours());
    const mm = two(now.getMinutes());
    const ss = two(now.getSeconds());
    const ms = three(now.getMilliseconds());
    return `${month} ${day} ${hh}:${mm}:${ss}.${ms}`;
}

function bootInfo(format, ...args) {
    console.log(`${ansiBlue}INFO${ansiReset}: [${bootTimestamp()}] ${formatString(format, args)}`);
}

function bootWarn(format, ...args) {
    console.warn(`${ansiYellow}WARN${ansiReset}: [${bootTimestamp()}] ${formatString(format, args)}`);
}

function formatString(format, args) {
    let index = 0;
    return String(format).replace(/%[sdj]/g, (token) => {
        if (index >= args.length) return token;
        const value = args[index++];
        if (token === '%j') {
            try {
                return JSON.stringify(value);
            } catch {
                return String(value);
            }
        }
        return String(value);
    });
}

function printBootBanner() {
    console.log('');
    for (const line of PANEL_BANNER.split('\n')) {
        console.log(`${ansiCyan}${line}${ansiReset}`);
    }
}

function printBootMetadata(options = {}) {
    const {
        appUrl,
        port,
        dbConnection,
        configFile = '.env',
        debugEnabled = false,
        timezone = process.env.TIMEZONE || process.env.TZ || DEFAULT_TIMEZONE
    } = options;

    const resolvedTimezone = resolveTimezone(timezone);
    if (String(timezone || '').trim() && resolvedTimezone !== String(timezone).trim()) {
        bootWarn('invalid timezone provided timezone=%s fallback=%s', String(timezone).trim(), resolvedTimezone);
    }
    const offsetLabel = utcOffsetLabel(getOffsetMinutesForTimezone(new Date(), resolvedTimezone));

    let username = 'unknown';
    let uid = 'unknown';
    let gid = 'unknown';
    try {
        const info = os.userInfo();
        username = info.username || 'unknown';
        uid = typeof info.uid === 'number' ? info.uid : 'unknown';
        gid = typeof info.gid === 'number' ? info.gid : 'unknown';
    } catch {
        // ignore
    }

    console.log(PANEL_COPYRIGHT);
    console.log(`Website:  ${PANEL_WEBSITE}`);
    console.log(`Source:   ${PANEL_SOURCE}`);
    console.log(`License:  ${PANEL_LICENSE}`);
    console.log('');

    const resolvedUrl = String(appUrl || '').trim() || `http://localhost:${port || process.env.APP_PORT || 3000}`;

    bootInfo('loading configuration from file config_file=%s', path.resolve(configFile));
    bootInfo('configured panel endpoint url=%s', resolvedUrl);
    bootInfo('configured system timezone timezone=%s utc_offset=%s', resolvedTimezone, offsetLabel);
    bootInfo('configured runtime node_version=%s os=%s arch=%s', process.version, process.platform, process.arch);
    bootInfo('configured system user success uid=%s gid=%s username=%s', uid, gid, username);
    bootInfo('configured database connection=%s', dbConnection || process.env.DB_CONNECTION || 'sqlite');
    bootInfo('configured debug mode=%s', debugEnabled ? 'enabled' : 'disabled');
}

function printStartupBoot(options = {}) {
    printBootBanner();
    printBootMetadata(options);
    console.log('');
}

module.exports = {
    printStartupBoot,
    bootInfo,
    bootWarn
};
