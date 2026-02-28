const express = require('express');
const http = require('http');

const app = express();
// Enable trust proxy for rate limiting behind reverse proxies.
app.set('trust proxy', 1);

const server = http.createServer(app);

module.exports = {
    app,
    server
};
