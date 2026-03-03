(function themeLoader() {
    let lifecycleBound = false;
    const THEME_PALETTES = {
        'default': {
            '--bg-dark': '#0f0f12',
            '--bg-sidebar': '#121216',
            '--border-color': '#2d2d35',
            '--text-primary': '#e1e1e6',
            '--text-secondary': '#8b8b9a',
            '--accent-blue': '#3b82f6',
            '--cp-panel-surface': 'rgba(26, 26, 32, 0.9)',
            '--cp-panel-surface-2': 'rgba(24, 24, 30, 0.88)',
            '--cp-panel-input': 'rgba(20, 20, 26, 0.9)'
        },
        'minecraft': {
            '--bg-dark': '#0b180b',
            '--bg-sidebar': '#102010',
            '--border-color': 'rgba(114, 179, 82, 0.42)',
            '--text-primary': '#e9fbe2',
            '--text-secondary': '#b8d8ae',
            '--accent-blue': '#9ce45f',
            '--cp-panel-surface': 'rgba(21, 30, 17, 0.84)',
            '--cp-panel-surface-2': 'rgba(17, 25, 14, 0.86)',
            '--cp-panel-input': 'rgba(12, 19, 10, 0.9)'
        },
        'gothic': {
            '--bg-dark': '#140b13',
            '--bg-sidebar': '#1a1019',
            '--border-color': 'rgba(147, 102, 174, 0.42)',
            '--text-primary': '#f5eafb',
            '--text-secondary': '#cfb6df',
            '--accent-blue': '#d7a3ff',
            '--cp-panel-surface': 'rgba(28, 15, 24, 0.86)',
            '--cp-panel-surface-2': 'rgba(24, 13, 22, 0.88)',
            '--cp-panel-input': 'rgba(20, 11, 18, 0.92)'
        },
        'azure': {
            '--bg-dark': '#082038',
            '--bg-sidebar': '#0b2a44',
            '--border-color': 'rgba(107, 185, 255, 0.36)',
            '--text-primary': '#e5f6ff',
            '--text-secondary': '#a8cde4',
            '--accent-blue': '#77d0ff',
            '--cp-panel-surface': 'rgba(13, 35, 54, 0.86)',
            '--cp-panel-surface-2': 'rgba(10, 29, 46, 0.88)',
            '--cp-panel-input': 'rgba(8, 24, 38, 0.92)'
        },
        'light': {
            '--bg-dark': '#eef3fb',
            '--bg-sidebar': '#eaf1fb',
            '--border-color': '#cfdaea',
            '--text-primary': '#16253b',
            '--text-secondary': '#526179',
            '--accent-blue': '#1f5fbf',
            '--cp-panel-surface': 'rgba(255, 255, 255, 0.92)',
            '--cp-panel-surface-2': 'rgba(248, 252, 255, 0.96)',
            '--cp-panel-input': '#f7faff'
        },
        'discord-l': {
            '--bg-dark': '#171c2d',
            '--bg-sidebar': '#1f2439',
            '--border-color': 'rgba(132, 142, 255, 0.34)',
            '--text-primary': '#f1f3ff',
            '--text-secondary': '#b8bfdc',
            '--accent-blue': '#a5b2ff',
            '--cp-panel-surface': 'rgba(34, 39, 62, 0.86)',
            '--cp-panel-surface-2': 'rgba(28, 33, 52, 0.88)',
            '--cp-panel-input': 'rgba(24, 28, 44, 0.92)'
        },
        'tropical-island': {
            '--bg-dark': '#082532',
            '--bg-sidebar': '#0b2f3f',
            '--border-color': 'rgba(56, 217, 169, 0.4)',
            '--text-primary': '#efffff',
            '--text-secondary': '#a9d8de',
            '--accent-blue': '#2ad1c9',
            '--cp-panel-surface': 'rgba(10, 34, 46, 0.86)',
            '--cp-panel-surface-2': 'rgba(9, 30, 40, 0.88)',
            '--cp-panel-input': 'rgba(8, 29, 39, 0.9)'
        },
        'ocean-deep-sea': {
            '--bg-dark': '#031025',
            '--bg-sidebar': '#041734',
            '--border-color': 'rgba(0, 219, 255, 0.36)',
            '--text-primary': '#dffcff',
            '--text-secondary': '#8ec7df',
            '--accent-blue': '#39efff',
            '--cp-panel-surface': 'rgba(3, 18, 42, 0.88)',
            '--cp-panel-surface-2': 'rgba(2, 16, 36, 0.9)',
            '--cp-panel-input': 'rgba(2, 13, 31, 0.9)'
        },
        'jurassic-summer': {
            '--bg-dark': '#122a12',
            '--bg-sidebar': '#17351a',
            '--border-color': 'rgba(238, 137, 45, 0.4)',
            '--text-primary': '#effbe8',
            '--text-secondary': '#b8cf9f',
            '--accent-blue': '#ffb155',
            '--cp-panel-surface': 'rgba(20, 46, 20, 0.86)',
            '--cp-panel-surface-2': 'rgba(18, 40, 17, 0.88)',
            '--cp-panel-input': 'rgba(15, 35, 14, 0.9)'
        },
        'sunset-gamer': {
            '--bg-dark': '#311642',
            '--bg-sidebar': '#381a4f',
            '--border-color': 'rgba(255, 121, 182, 0.38)',
            '--text-primary': '#ffe8f7',
            '--text-secondary': '#d8a9c8',
            '--accent-blue': '#ff8ecf',
            '--cp-panel-surface': 'rgba(28, 14, 39, 0.84)',
            '--cp-panel-surface-2': 'rgba(25, 13, 35, 0.88)',
            '--cp-panel-input': 'rgba(23, 11, 32, 0.9)'
        },
        'minimal-summer-clean': {
            '--bg-dark': '#f3fbf8',
            '--bg-sidebar': '#e9f6f2',
            '--border-color': '#cde7e2',
            '--text-primary': '#223139',
            '--text-secondary': '#547079',
            '--accent-blue': '#ff7f6b',
            '--cp-panel-surface': 'rgba(255, 255, 255, 0.9)',
            '--cp-panel-surface-2': 'rgba(248, 255, 253, 0.95)',
            '--cp-panel-input': '#f8fffd'
        },
        'dino-cartoon-fun': {
            '--bg-dark': '#153146',
            '--bg-sidebar': '#1a3f58',
            '--border-color': 'rgba(120, 219, 115, 0.4)',
            '--text-primary': '#efffff',
            '--text-secondary': '#b0cfe1',
            '--accent-blue': '#83e3ff',
            '--cp-panel-surface': 'rgba(23, 45, 62, 0.86)',
            '--cp-panel-surface-2': 'rgba(20, 40, 56, 0.88)',
            '--cp-panel-input': 'rgba(17, 35, 50, 0.9)'
        },
        'sky-islands-fantasy': {
            '--bg-dark': '#0f2b4e',
            '--bg-sidebar': '#14355f',
            '--border-color': 'rgba(131, 243, 104, 0.34)',
            '--text-primary': '#efffff',
            '--text-secondary': '#b1d3e4',
            '--accent-blue': '#9be8ff',
            '--cp-panel-surface': 'rgba(18, 38, 72, 0.82)',
            '--cp-panel-surface-2': 'rgba(15, 34, 64, 0.86)',
            '--cp-panel-input': 'rgba(11, 27, 52, 0.72)'
        }
    };

    function getActiveThemeId() {
        const link = document.getElementById('cpanel-theme-css');
        return String((link && link.dataset && link.dataset.theme) || 'default').trim().toLowerCase() || 'default';
    }

    function applyThemePalette(themeId) {
        const palette = THEME_PALETTES[themeId] || THEME_PALETTES.default;
        const root = document.documentElement;
        root.setAttribute('data-theme', themeId);
        Object.entries(palette).forEach(([cssVar, value]) => {
            root.style.setProperty(cssVar, value);
        });
        if (document.body) {
            document.body.setAttribute('data-theme', themeId);
        }
    }

    function reorderThemeStylesheets() {
        if (!document.head) return;
        const themeLink = document.getElementById('cpanel-theme-css');
        const bridgeLink = document.getElementById('cpanel-theme-bridge-css');
        if (themeLink) document.head.appendChild(themeLink);
        if (bridgeLink) document.head.appendChild(bridgeLink);
    }

    function applyThemeEverywhere() {
        reorderThemeStylesheets();
        applyThemePalette(getActiveThemeId());
    }

    function bindLifecycleEvents() {
        if (lifecycleBound) return;
        lifecycleBound = true;
        document.addEventListener('turbo:load', applyThemeEverywhere);
    }

    bindLifecycleEvents();
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyThemeEverywhere, { once: true });
    } else {
        applyThemeEverywhere();
    }
})();
