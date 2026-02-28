const helmet = require('helmet');
const cors = require('cors');
const express = require('express');

function registerSecurityMiddleware(app) {
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                ...helmet.contentSecurityPolicy.getDefaultDirectives(),
                "img-src": ["'self'", "data:", "https:", "http:", "blob:"],
                "script-src": ["'self'", "'unsafe-inline'", "blob:", "https://cdn.jsdelivr.net"],
                "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
                "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
                "connect-src": ["'self'", "https://cdn.jsdelivr.net", "ws:", "wss:"],
                "worker-src": ["'self'", "blob:"],
            },
        },
    }));

    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
}

module.exports = {
    registerSecurityMiddleware
};
