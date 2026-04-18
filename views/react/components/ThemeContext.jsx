import React, { createContext, useContext, useEffect, useState } from 'react';

const ThemeContext = createContext();

export function ThemeProvider({ children, pageData = {} }) {
    const [activeTheme, setActiveTheme] = useState(pageData.activeTheme || 'default');
    const [previewTheme, setPreviewTheme] = useState(null);
    const [customTheme, setCustomTheme] = useState(pageData.customTheme || { enabled: false });

    const applyTheme = (themeId, isPreview = false) => {
        const themeToApply = isPreview ? themeId : (themeId || activeTheme);
        
        // Dynamically manage the React theme stylesheet
        let themeLink = document.getElementById('cpanel-react-theme-css');
        if (!themeLink) {
            themeLink = document.createElement('link');
            themeLink.id = 'cpanel-react-theme-css';
            themeLink.rel = 'stylesheet';
            document.head.appendChild(themeLink);
        }

        // Load the React-specific theme stylesheet
        themeLink.setAttribute('href', `/themes-react/${themeToApply}.css`);

        document.documentElement.setAttribute('data-theme', themeToApply);
        
        // Handle custom theme overrides
        const customEnabled = isPreview ? false : customTheme.enabled;
        document.documentElement.setAttribute('data-user-custom-theme', customEnabled ? 'on' : 'off');
        
        if (isPreview) {
            setPreviewTheme(themeId);
        } else {
            setActiveTheme(themeId);
            setPreviewTheme(null);
        }
    };

    const toggleCustomTheme = (enabled) => {
        setCustomTheme(prev => ({ ...prev, enabled }));
        document.documentElement.setAttribute('data-user-custom-theme', enabled ? 'on' : 'off');
    };

    const restoreTheme = () => {
        applyTheme(activeTheme, false);
        setPreviewTheme(null);
    };

    // Reflect server-provided state on mount
    useEffect(() => {
        if (pageData.activeTheme) {
            setActiveTheme(pageData.activeTheme);
        }
        if (pageData.customTheme) {
            setCustomTheme(pageData.customTheme);
        }
    }, [pageData]);

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
