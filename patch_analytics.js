const fs = require('fs');
const path = 'routes/legacy/server-pages.js';
let content = fs.readFileSync(path, 'utf8');

function injectReact(content, regex, pageDataBuilder, title, entry, routePath) {
    return content.replace(regex, (match, p1, p2) => {
        const indent = p1;
        const renderStart = p2;
        return `${indent}const reactPageData = ${pageDataBuilder};
${indent}if (wantsReactPageData(req)) {
${indent}    return res.json(reactPageData);
${indent}}
${indent}if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
${indent}    return res.render('react/loader', {
${indent}        title: ${title},
${indent}        reactEntry: 'app',
${indent}        reactPageData
${indent}    });
${indent}
}
${indent}${renderStart}`;
    });
}

// 1. Overview
content = injectReact(
    content,
    /(\s+)(res\.render\('server\/overview', \{)/,
    `{
        routePath: \`/server/\$\{server.containerId\}/overview\`,
        brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
        faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
        success: req.query.success || null,
        error: req.query.error || null,
        user: buildReactUserSummary(req.session.user),
        server: { ...server.toJSON(), folder: normalizeServerFolderName(server.folder), tags: normalizeServerTags(server.tags) },
        serverNavItems: buildReactServerNavItems(server, access, 'overview'),
        wsToken,
        resolvedStartup,
        healthScore,
        serverCost,
        configDrift,
        minecraftProfileCard
    }`,
    `\`Overview \$\{server.name\}\``,
    'app',
    '/overview'
);

// 2. Activity
content = injectReact(
    content,
    /(\s+)(return res\.render\('server\/activity', \{)/,
    `{
        routePath: \`/server/\$\{server.containerId\}/activity\`,
        brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
        faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
        success: req.query.success || null,
        error: req.query.error || null,
        user: buildReactUserSummary(req.session.user),
        server: server.toJSON(),
        serverNavItems: buildReactServerNavItems(server, access, 'activity'),
        logs,
        changeLogs
    }`,
    `\`Activity \$\{server.name\}\``,
    'app',
    '/activity'
);

// 3. Timeline
content = injectReact(
    content,
    /(\s+)(return res\.render\('server\/timeline', \{)/,
    `{
        routePath: \`/server/\$\{server.containerId\}/timeline\`,
        brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
        faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
        success: req.query.success || null,
        error: req.query.error || null,
        user: buildReactUserSummary(req.session.user),
        server: server.toJSON(),
        serverNavItems: buildReactServerNavItems(server, access, 'timeline'),
        wsToken,
        samples
    }`,
    `\`Resource Timeline \$\{server.name\}\``,
    'app',
    '/timeline'
);

// 4. Not Found
content = content.replace(
    /(\s+)(res\.render\('server\/notfound', \{)/,
    `$1const reactPageData = {
$1    routePath: '/server/notfound',
$1    brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
$1    faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
$1    user: buildReactUserSummary(req.session.user)
$1};
$1if (wantsReactPageData(req)) {
$1    return res.json(reactPageData);
$1}
$1if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
$1    return res.render('react/loader', {
$1        title: 'Server Not Found',
$1        reactEntry: 'app',
$1        reactPageData
$1    });
$1}
$1$2`
);

// 5. No Permissions
content = content.replace(
    /(\s+)(res\.render\('server\/no-permissions', \{)/,
    `$1const reactPageData = {
$1    routePath: '/server/no-permissions',
$1    brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
$1    faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
$1    user: buildReactUserSummary(req.session.user)
$1};
$1if (wantsReactPageData(req)) {
$1    return res.json(reactPageData);
$1}
$1if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
$1    return res.render('react/loader', {
$1        title: 'Access Denied',
$1        reactEntry: 'app',
$1        reactPageData
$1    });
$1}
$1$2`
);

// 6. Suspended
content = content.replace(
    /(\s+)(res\.render\('server\/suspended', \{)/,
    `$1const reactPageData = {
$1    routePath: \`/server/\$\{server.containerId\}/suspended\`,
$1    brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
$1    faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
$1    user: buildReactUserSummary(req.session.user),
$1    server: server.toJSON()
$1};
$1if (wantsReactPageData(req)) {
$1    return res.json(reactPageData);
$1}
$1if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
$1    return res.render('react/loader', {
$1        title: 'Server Suspended',
$1        reactEntry: 'app',
$1        reactPageData
$1    });
$1}
$1$2`
);

fs.writeFileSync(path, content);
console.log('patched successfully!');
