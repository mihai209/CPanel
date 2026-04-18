import React, { createContext, useContext, useEffect, useState } from 'react';

const ThemeContext = createContext();

export function ThemeProvider({ children, pageData = {} }) {
    const [activeTheme, setActiveTheme] = useState(pageData.activeTheme || 'default');
    const [previewTheme, setPreviewTheme] = useState(null);
    const [customTheme, setCustomTheme] = useState(pageData.customTheme || { enabled: false });

    const applyTheme = (themeId, isPreview = false) => {
        if (isPreview) {
            setPreviewTheme(themeId);
        } else {
            setActiveTheme(themeId || activeTheme);
            setPreviewTheme(null);
        }
    };

    const toggleCustomTheme = (enabled) => {
        setCustomTheme(prev => ({ ...prev, enabled }));
    };

    const restoreTheme = () => {
        setPreviewTheme(null);
    };

    // Reflect server-provided state on mount or pageData change
    useEffect(() => {
        if (pageData.activeTheme) {
            setActiveTheme(pageData.activeTheme);
        }
        if (pageData.customTheme) {
            setCustomTheme(pageData.customTheme);
        }
    }, [pageData]);

    // Apply theme to document whenever state changes
    useEffect(() => {
        const themeToApply = previewTheme || activeTheme;
        
        // Use the common theme link ID injected by loader.ejs
        let themeLink = document.getElementById('cpanel-theme-css');
        if (!themeLink) {
            themeLink = document.createElement('link');
            themeLink.id = 'cpanel-theme-css';
            themeLink.rel = 'stylesheet';
            document.head.appendChild(themeLink);
        }

        const href = `/themes-react/${themeToApply}.css`;
        if (themeLink.getAttribute('href') !== href) {
            themeLink.setAttribute('href', href);
        }

        document.documentElement.setAttribute('data-theme', themeToApply);
        
        // Global Body Application
        // We set these directly to ensure they override any stubborn CSS in legacy sheets
        document.body.style.background = 'var(--cp-body-background)';
        document.body.style.backgroundSize = 'cover';
        document.body.style.backgroundPosition = 'center';
        document.body.style.backgroundAttachment = 'fixed';

        // Handle custom theme overrides
        const customEnabled = previewTheme ? false : customTheme.enabled;
        document.documentElement.setAttribute('data-user-custom-theme', customEnabled ? 'on' : 'off');
        
        // Reactive Custom Theme Styles
        let customStyle = document.getElementById('cpanel-custom-theme-overrides');
        if (customEnabled) {
            if (!customStyle) {
                customStyle = document.createElement('style');
                customStyle.id = 'cpanel-custom-theme-overrides';
                document.head.appendChild(customStyle);
            }
            customStyle.textContent = `
                :root {
                    --neutral-900: ${customTheme.panelSurface || '#141419'};
                    --neutral-800: ${customTheme.cardBackground || '#1f2023'};
                    --neutral-700: ${customTheme.cardBorder || '#2e3036'};
                    --primary-500: ${customTheme.accentColor || '#3b82f6'};
                    --neutral-100: ${customTheme.textColor || '#ffffff'};
                    --neutral-400: ${customTheme.mutedTextColor || '#a1a1aa'};
                    --cp-body-background: ${customTheme.backgroundImageUrl ? `linear-gradient(rgba(0,0,0,0.4), rgba(0,0,0,0.4)), url('${customTheme.backgroundImageUrl}'), ${customTheme.backgroundColor || '#0d0d0f'}` : (customTheme.backgroundColor || '#0d0d0f')};
                }
            `;
        } else if (customStyle) {
            customStyle.textContent = '';
        }
    }, [activeTheme, previewTheme, customTheme]);

    const value = {
        activeTheme,
        previewTheme,
        customTheme,
        applyTheme,
        toggleCustomTheme,
        restoreTheme
    };

    return (
        <ThemeContext.Provider value={value}>
            {children}
        </ThemeContext.Provider>
    );
}

export const useTheme = () => {
    const context = useContext(ThemeContext);
    if (!context) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }
    return context;
};

export default ThemeProvider;
