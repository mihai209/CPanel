const fs = require('fs');
const content = fs.readFileSync('routes/legacy/server-pages.js', 'utf8');

let newContent = content;

// Users
newContent = newContent.replace(
    /(\s*)(return\s+res\.render\('server\/users',\s*\{)/,
    `$1const reactPageData = {
$1    routePath: \`/server/\$\{server.containerId\}/users\`,
$1    brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
$1    faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
$1    success: req.query.success || null,
$1    error: req.query.error || null,
$1    user: buildReactUserSummary(req.session.user),
$1    server: {
$1        id: server.id,
$1        containerId: server.containerId,
$1        name: server.name,
$1        description: server.description || '',
$1        status: server.status || 'unknown'
$1    },
$1    serverNavItems: buildReactServerNavItems(server, access, 'users'),
$1    owner,
$1    memberships,
$1    candidateUsers,
$1    permissionCatalog: SERVER_PERMISSIONS,
$1    permissionPresets: SUBUSER_PERMISSION_PRESETS,
$1    canManageUsers: hasServerPermission(access, 'server.users.manage')
$1};
$1if (wantsReactPageData(req)) {
$1    return res.json(reactPageData);
$1}
$1if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
$1    return res.render('react/loader', {
$1        title: \`Users \$\{server.name\}\`,
$1        reactEntry: 'app',
$1        reactPageData
$1    });
$1}
$1$2`
);

// Databases
newContent = newContent.replace(
    /(\s*)(return\s+res\.render\('server\/databases',\s*\{)/,
    `$1const reactPageData = {
$1    routePath: \`/server/\$\{state.server.containerId\}/databases\`,
$1    brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
$1    faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
$1    success: req.query.success || null,
$1    error: req.query.error || null,
$1    user: buildReactUserSummary(req.session.user),
$1    server: {
$1        id: state.server.id,
$1        containerId: state.server.containerId,
$1        name: state.server.name,
$1        description: state.server.description || '',
$1        status: state.server.status || 'unknown',
$1        databaseLimit
$1    },
$1    serverNavItems: buildReactServerNavItems(state.server, access, 'dbs'),
$1    hosts: state.hosts,
$1    databases: state.databases,
$1    locationId: state.locationId,
$1    databaseLimit,
$1    canManageDatabases: hasServerPermission(access, 'server.databases.manage')
$1};
$1if (wantsReactPageData(req)) {
$1    return res.json(reactPageData);
$1}
$1if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
$1    return res.render('react/loader', {
$1        title: \`Databases \$\{state.server.name\}\`,
$1        reactEntry: 'app',
$1        reactPageData
$1    });
$1}
$1$2`
);

// Schedules
newContent = newContent.replace(
    /(\s*)(return\s+res\.render\('server\/schedules',\s*\{)/,
    `$1const reactPageData = {
$1    routePath: \`/server/\$\{server.containerId\}/schedules\`,
$1    brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
$1    faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
$1    success: req.query.success || null,
$1    error: req.query.error || null,
$1    user: buildReactUserSummary(req.session.user),
$1    server: {
$1        id: server.id,
$1        containerId: server.containerId,
$1        name: server.name,
$1        description: server.description || '',
$1        status: server.status || 'unknown'
$1    },
$1    serverNavItems: buildReactServerNavItems(server, access, 'schedules'),
$1    schedules,
$1    canManageSchedules: hasServerPermission(access, 'server.schedules.manage')
$1};
$1if (wantsReactPageData(req)) {
$1    return res.json(reactPageData);
$1}
$1if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
$1    return res.render('react/loader', {
$1        title: \`Schedules \$\{server.name\}\`,
$1        reactEntry: 'app',
$1        reactPageData
$1    });
$1}
$1$2`
);

// Startup
newContent = newContent.replace(
    /(\s*)(res\.render\('server\/startup',\s*\{)/,
    `$1const reactPageData = {
$1    routePath: \`/server/\$\{server.containerId\}/startup\`,
$1    brandName: (res.locals.settings && res.locals.settings.brandName) || 'CPanel',
$1    faviconUrl: (res.locals.settings && res.locals.settings.faviconUrl) || '/assets/rocky.png',
$1    success: req.query.success || null,
$1    error: req.query.error || null,
$1    user: buildReactUserSummary(req.session.user),
$1    server: {
$1        id: server.id,
$1        containerId: server.containerId,
$1        name: server.name,
$1        description: server.description || '',
$1        status: server.status || 'unknown',
$1        startup: server.startup,
$1        dockerImage: server.dockerImage,
$1        variables: server.variables
$1    },
$1    serverNavItems: buildReactServerNavItems(server, access, 'startup'),
$1    image: image,
$1    dockerChoices,
$1    variableDefinitions,
$1    resolvedVariables,
$1    selectedDockerImage,
$1    resolvedStartup,
$1    startupPresets,
$1    selectedStartupPresetId,
$1    startupWriteLocked
$1};
$1if (wantsReactPageData(req)) {
$1    return res.json(reactPageData);
$1}
$1if (!wantsLegacyReactBypass(req) && String(req.session && req.session.user ? req.session.user.experimentalViewMode || 'ejs' : 'ejs').trim().toLowerCase() === 'react') {
$1    return res.render('react/loader', {
$1        title: \`Startup \$\{server.name\}\`,
$1        reactEntry: 'app',
$1        reactPageData
$1    });
$1}
$1$2`
);

fs.writeFileSync('routes/legacy/server-pages.js', newContent);
console.log('patched successfully!');
