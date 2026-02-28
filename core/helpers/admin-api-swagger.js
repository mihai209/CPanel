function buildAdminApiSwaggerSpec(baseUrl = '') {
    const resolvedBaseUrl = String(baseUrl || '').trim().replace(/\/+$/, '');

    const authSchemes = [
        {
            id: 'admin-api-key',
            title: 'Admin API Key',
            header: 'Authorization: Bearer cp_adm_<token>',
            notes: 'Create keys from /admin/api and assign granular admin.* permissions.'
        },
        {
            id: 'server-api-key',
            title: 'Server API Key',
            header: 'Authorization: Bearer cp_srv_<token>',
            notes: 'Create per-server keys from /server/:containerId/api with server.* permissions.'
        },
        {
            id: 'jwt-token',
            title: 'Legacy JWT',
            header: 'Authorization: Bearer <jwt>',
            notes: 'Token is returned by POST /api/auth/login and used by legacy /api/servers endpoints.'
        },
        {
            id: 'session-admin',
            title: 'Admin Session Cookie',
            header: 'Cookie: connect.sid=<session>',
            notes: 'Browser/admin-session based endpoints. Not intended for third-party long-lived integrations.'
        },
        {
            id: 'connector-token',
            title: 'Connector Body Token',
            header: 'JSON body fields: { id/connectorId, token }',
            notes: 'Private connector-to-panel endpoints only.'
        }
    ];

    const routeGroups = [
        {
            title: 'Authentication & Legacy API',
            description: 'Legacy token endpoints and basic server list/create integration.',
            routes: [
                {
                    method: 'POST',
                    path: '/api/auth/login',
                    auth: 'none',
                    permission: '-',
                    summary: 'Return legacy JWT token.',
                    payload: '{ "username": "admin", "password": "secret" }'
                },
                {
                    method: 'GET',
                    path: '/api/servers',
                    auth: 'jwt-token',
                    permission: '-',
                    summary: 'List servers (legacy endpoint).',
                    payload: 'No body'
                },
                {
                    method: 'POST',
                    path: '/api/servers',
                    auth: 'jwt-token',
                    permission: 'JWT user must be admin',
                    summary: 'Create server through connector bridge (legacy endpoint).',
                    payload: '{ "name": "my-server", "image": "ghcr.io/ptero-eggs/yolks:java_17" }'
                }
            ]
        },
        {
            title: 'Admin API (Platform Ops)',
            description: 'Primary admin automation API. Supports admin session or admin API key auth.',
            routes: [
                {
                    method: 'GET',
                    path: '/api/admin/jobs',
                    auth: 'admin-api-key',
                    permission: 'admin.jobs.view',
                    summary: 'List queued/processed jobs.',
                    payload: 'Query: ?limit=50'
                },
                {
                    method: 'GET',
                    path: '/api/admin/jobs/:id',
                    auth: 'admin-api-key',
                    permission: 'admin.jobs.view',
                    summary: 'Get one job by id.',
                    payload: 'Path param: :id'
                },
                {
                    method: 'POST',
                    path: '/api/admin/jobs',
                    auth: 'admin-api-key',
                    permission: 'admin.jobs.manage',
                    summary: 'Enqueue a new job.',
                    payload: '{ "type": "server.reinstall", "payload": { "serverId": 1 }, "priority": 0, "maxAttempts": 3 }'
                },
                {
                    method: 'GET',
                    path: '/api/admin/audit-logs',
                    auth: 'admin-api-key',
                    permission: 'admin.audit.view',
                    summary: 'Fetch audit logs.',
                    payload: 'Query: ?limit=100'
                },
                {
                    method: 'GET',
                    path: '/api/admin/rbac/users',
                    auth: 'admin-api-key',
                    permission: 'admin.rbac.view',
                    summary: 'List users with RBAC fields.',
                    payload: 'No body'
                },
                {
                    method: 'POST',
                    path: '/api/admin/rbac/users/:id',
                    auth: 'admin-api-key',
                    permission: 'admin.rbac.manage',
                    summary: 'Set permissions for a non-admin user.',
                    payload: '{ "permissions": ["server.view", "server.console"] }'
                },
                {
                    method: 'GET',
                    path: '/api/admin/backups/policies',
                    auth: 'admin-api-key',
                    permission: 'admin.backups.view',
                    summary: 'Returns 410 (built-in backups disabled; SFTP workflow).',
                    payload: 'No body'
                },
                {
                    method: 'POST',
                    path: '/api/admin/backups/policies/:serverId',
                    auth: 'admin-api-key',
                    permission: 'admin.backups.manage',
                    summary: 'Returns 410 (built-in backups disabled; SFTP workflow).',
                    payload: '{...} (ignored)'
                },
                {
                    method: 'POST',
                    path: '/api/admin/backups/run/:serverId',
                    auth: 'admin-api-key',
                    permission: 'admin.backups.manage',
                    summary: 'Returns 410 (built-in backups disabled; SFTP workflow).',
                    payload: 'No body'
                },
                {
                    method: 'GET',
                    path: '/api/admin/backups/history/:serverId',
                    auth: 'admin-api-key',
                    permission: 'admin.backups.view',
                    summary: 'Returns 410 (built-in backups disabled; SFTP workflow).',
                    payload: 'No body'
                },
                {
                    method: 'GET',
                    path: '/api/admin/metrics',
                    auth: 'admin-api-key',
                    permission: 'admin.observability.view',
                    summary: 'Get node, queue and totals metrics snapshot.',
                    payload: 'No body'
                }
            ]
        },
        {
            title: 'Admin Session API (UI support)',
            description: 'Used mainly by admin UI pages and migration wizard.',
            routes: [
                {
                    method: 'GET',
                    path: '/api/admin/packages',
                    auth: 'session-admin',
                    permission: 'admin session required',
                    summary: 'List package records for admin modals/pages.',
                    payload: 'No body'
                },
                {
                    method: 'GET',
                    path: '/api/admin/migrations/pterodactyl/status',
                    auth: 'session-admin',
                    permission: 'admin session required',
                    summary: 'Check Pterodactyl migration job + file import status.',
                    payload: 'Query: ?serverId=1&jobId=12'
                }
            ]
        },
        {
            title: 'Server Client API (per-server keys)',
            description: 'Automate power, console and files with per-server API keys.',
            routes: [
                {
                    method: 'GET',
                    path: '/api/client/servers/:containerId',
                    auth: 'server-api-key',
                    permission: 'server.view',
                    summary: 'Get server metadata/resources/allocation.',
                    payload: 'Path param: :containerId'
                },
                {
                    method: 'POST',
                    path: '/api/client/servers/:containerId/power',
                    auth: 'server-api-key',
                    permission: 'server.power',
                    summary: 'Send power signal: start/stop/restart/kill.',
                    payload: '{ "signal": "restart" }'
                },
                {
                    method: 'POST',
                    path: '/api/client/servers/:containerId/command',
                    auth: 'server-api-key',
                    permission: 'server.console',
                    summary: 'Send one console command.',
                    payload: '{ "command": "say hello from api" }'
                },
                {
                    method: 'GET',
                    path: '/api/client/servers/:containerId/files/list',
                    auth: 'server-api-key',
                    permission: 'server.files.read',
                    summary: 'List files for directory.',
                    payload: 'Query: ?directory=/plugins'
                },
                {
                    method: 'GET',
                    path: '/api/client/servers/:containerId/files/content',
                    auth: 'server-api-key',
                    permission: 'server.files.read',
                    summary: 'Read file content.',
                    payload: 'Query: ?file=/server.properties'
                },
                {
                    method: 'POST',
                    path: '/api/client/servers/:containerId/files/write',
                    auth: 'server-api-key',
                    permission: 'server.files.write',
                    summary: 'Write file content (max 2 MiB).',
                    payload: '{ "file": "/notes.txt", "content": "hello" }'
                },
                {
                    method: 'GET',
                    path: '/api/client/servers/:containerId/files/download',
                    auth: 'server-api-key',
                    permission: 'server.files.download',
                    summary: 'Download file stream.',
                    payload: 'Query: ?file=/world.zip'
                },
                {
                    method: 'POST',
                    path: '/api/client/servers/:containerId/files/create-folder',
                    auth: 'server-api-key',
                    permission: 'server.files.write',
                    summary: 'Create folder in directory.',
                    payload: '{ "directory": "/", "name": "backups" }'
                },
                {
                    method: 'POST',
                    path: '/api/client/servers/:containerId/files/rename',
                    auth: 'server-api-key',
                    permission: 'server.files.write',
                    summary: 'Rename file/folder in directory.',
                    payload: '{ "directory": "/", "name": "old.txt", "newName": "new.txt" }'
                },
                {
                    method: 'POST',
                    path: '/api/client/servers/:containerId/files/delete',
                    auth: 'server-api-key',
                    permission: 'server.files.write',
                    summary: 'Delete one or more files/folders.',
                    payload: '{ "directory": "/", "files": ["a.txt", "logs"] }'
                },
                {
                    method: 'POST',
                    path: '/api/client/servers/:containerId/files/chmod',
                    auth: 'server-api-key',
                    permission: 'server.files.write',
                    summary: 'Set octal permissions on file/folder.',
                    payload: '{ "directory": "/", "name": "run.sh", "permissions": "755" }'
                }
            ]
        },
        {
            title: 'Connector Private API',
            description: 'Internal routes used by connector-go / legacy connector; not for public integrations.',
            routes: [
                {
                    method: 'POST',
                    path: '/api/connector/heartbeat',
                    auth: 'connector-token',
                    permission: '-',
                    summary: 'Connector heartbeat and live usage push.',
                    payload: '{ "id": 1, "token": "connector_token", "status": "online", "usage": {...} }'
                },
                {
                    method: 'POST',
                    path: '/api/connector/sftp-auth',
                    auth: 'connector-token',
                    permission: '-',
                    summary: 'Connector asks panel to validate SFTP username/password per server.',
                    payload: '{ "connectorId": 1, "token": "connector_token", "username": "user.ab123", "password": "..." }'
                }
            ]
        }
    ];

    const examples = {
        curl: `# Admin API key (jobs list)\ncurl -sS \\\n  -H "Authorization: Bearer cp_adm_your_key_here" \\\n  "${resolvedBaseUrl}/api/admin/jobs?limit=20"\n\n# Server API key (send power)\ncurl -sS -X POST \\\n  -H "Authorization: Bearer cp_srv_your_key_here" \\\n  -H "Content-Type: application/json" \\\n  -d '{"signal":"restart"}' \\\n  "${resolvedBaseUrl}/api/client/servers/<containerId>/power"\n\n# Server API key (list files)\ncurl -sS \\\n  -H "Authorization: Bearer cp_srv_your_key_here" \\\n  "${resolvedBaseUrl}/api/client/servers/<containerId>/files/list?directory=/"`,
        nodejs: `// Node.js 18+ (native fetch)\nconst baseUrl = "${resolvedBaseUrl}";\nconst adminKey = "cp_adm_your_key_here";\nconst serverKey = "cp_srv_your_key_here";\n\nasync function run() {\n  const jobsRes = await fetch(baseUrl + "/api/admin/jobs?limit=10", {\n    headers: { Authorization: \`Bearer \${adminKey}\` }\n  });\n  const jobs = await jobsRes.json();\n  console.log("jobs:", jobs);\n\n  const commandRes = await fetch(baseUrl + "/api/client/servers/<containerId>/command", {\n    method: "POST",\n    headers: {\n      Authorization: \`Bearer \${serverKey}\`,\n      "Content-Type": "application/json"\n    },\n    body: JSON.stringify({ command: "say hello from node" })\n  });\n  console.log("command:", await commandRes.json());\n}\n\nrun().catch(console.error);`,
        python: `# Python 3 + requests\nimport requests\n\nbase_url = "${resolvedBaseUrl}"\nadmin_key = "cp_adm_your_key_here"\nserver_key = "cp_srv_your_key_here"\n\njobs = requests.get(\n    f"{base_url}/api/admin/jobs",\n    params={"limit": 10},\n    headers={"Authorization": f"Bearer {admin_key}"},\n    timeout=15,\n)\nprint("jobs:", jobs.status_code, jobs.json())\n\npower = requests.post(\n    f"{base_url}/api/client/servers/<containerId>/power",\n    json={"signal": "start"},\n    headers={\n        "Authorization": f"Bearer {server_key}",\n        "Content-Type": "application/json",\n    },\n    timeout=15,\n)\nprint("power:", power.status_code, power.json())`
    };

    return {
        generatedAt: new Date().toISOString(),
        baseUrl: resolvedBaseUrl,
        authSchemes,
        routeGroups,
        examples
    };
}

function buildOpenApiOperationId(method, path) {
    const rawMethod = String(method || 'get').trim().toLowerCase();
    const rawPath = String(path || '/')
        .replace(/^\//, '')
        .replace(/[{}]/g, '')
        .replace(/[:/]+/g, '_')
        .replace(/[^a-zA-Z0-9_]/g, '_')
        .replace(/_+/g, '_')
        .replace(/^_+|_+$/g, '');
    return `${rawMethod}_${rawPath || 'root'}`;
}

function extractPathParameters(path) {
    const text = String(path || '');
    const named = [];
    const colonMatches = text.match(/:[a-zA-Z0-9_]+/g) || [];
    colonMatches.forEach((token) => {
        const value = token.slice(1).trim();
        if (value) named.push(value);
    });
    const braceMatches = text.match(/{[a-zA-Z0-9_]+}/g) || [];
    braceMatches.forEach((token) => {
        const value = token.slice(1, -1).trim();
        if (value) named.push(value);
    });
    return Array.from(new Set(named));
}

function normalizeOpenApiPath(path) {
    return String(path || '/').replace(/:([a-zA-Z0-9_]+)/g, '{$1}');
}

function buildRequestBodyFromPayload(payload) {
    const text = String(payload || '').trim();
    if (!text || text.toLowerCase() === 'no body') return null;
    if (!text.startsWith('{') && !text.startsWith('[')) return null;

    let parsed = null;
    try {
        parsed = JSON.parse(text);
    } catch {
        return {
            required: true,
            content: {
                'application/json': {
                    schema: { type: 'object' },
                    example: text
                }
            }
        };
    }

    const schema = Array.isArray(parsed)
        ? { type: 'array' }
        : { type: 'object' };

    return {
        required: true,
        content: {
            'application/json': {
                schema,
                example: parsed
            }
        }
    };
}

function resolveSecurityForAuth(authLabel) {
    const auth = String(authLabel || '').trim().toLowerCase();
    if (!auth || auth === 'none') return [];
    if (auth === 'session-admin') return [{ sessionCookie: [] }];
    if (auth === 'connector-token') return [{ connectorBodyToken: [] }];
    return [{ bearerAuth: [] }];
}

function buildAdminApiOpenApiSpec(baseUrl = '') {
    const swagger = buildAdminApiSwaggerSpec(baseUrl);
    const paths = {};

    (swagger.routeGroups || []).forEach((group) => {
        (group.routes || []).forEach((route) => {
            const method = String(route.method || 'GET').trim().toLowerCase();
            if (!['get', 'post', 'put', 'patch', 'delete'].includes(method)) return;

            const openApiPath = normalizeOpenApiPath(route.path);
            if (!paths[openApiPath]) paths[openApiPath] = {};

            const parameters = [];
            const pathParams = extractPathParameters(route.path);
            pathParams.forEach((name) => {
                parameters.push({
                    name,
                    in: 'path',
                    required: true,
                    schema: { type: 'string' }
                });
            });

            const payloadText = String(route.payload || '');
            if (payloadText.toLowerCase().startsWith('query:')) {
                parameters.push({
                    name: 'query',
                    in: 'query',
                    required: false,
                    schema: { type: 'string' },
                    description: payloadText.replace(/^query:\s*/i, '')
                });
            }

            const operation = {
                tags: [String(group.title || 'API')],
                summary: String(route.summary || '').trim() || `${String(route.method || '').toUpperCase()} ${route.path}`,
                description: `Auth: ${route.auth || '-'}\nPermission: ${route.permission || '-'}`,
                operationId: buildOpenApiOperationId(method, route.path),
                security: resolveSecurityForAuth(route.auth),
                responses: {
                    200: {
                        description: 'Successful response.'
                    },
                    400: {
                        description: 'Bad request.'
                    },
                    401: {
                        description: 'Unauthorized.'
                    },
                    403: {
                        description: 'Forbidden.'
                    },
                    500: {
                        description: 'Internal server error.'
                    }
                }
            };

            if (parameters.length > 0) {
                operation.parameters = parameters;
            }

            const requestBody = buildRequestBodyFromPayload(route.payload);
            if (requestBody) {
                operation.requestBody = requestBody;
            }

            paths[openApiPath][method] = operation;
        });
    });

    return {
        openapi: '3.1.0',
        info: {
            title: 'CPanel Rocky API',
            version: '1.0.0',
            description: 'Auto-generated API reference from admin swagger helper.'
        },
        servers: [
            { url: swagger.baseUrl || '' }
        ],
        tags: (swagger.routeGroups || []).map((group) => ({
            name: String(group.title || 'API'),
            description: String(group.description || '')
        })),
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'Token'
                },
                sessionCookie: {
                    type: 'apiKey',
                    in: 'cookie',
                    name: 'connect.sid'
                },
                connectorBodyToken: {
                    type: 'apiKey',
                    in: 'query',
                    name: 'token'
                }
            }
        },
        paths
    };
}

module.exports = {
    buildAdminApiSwaggerSpec,
    buildAdminApiOpenApiSpec
};
