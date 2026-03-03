# CPanel Panel

## English

Web panel for provisioning and managing Docker-based game/app servers.

- Repo: https://github.com/mihai209/CPanel
- License: MIT

### Stack

- Node.js + Express
- EJS templates
- Sequelize (SQLite by default, MySQL/PostgreSQL supported)
- WebSocket bridge for connector communication

### Requirements

- Node.js 20+
- npm 10+
- Docker host with at least one `connector-go` node

### Quick Start

```bash
cd /home/mihai/Desktop/cpanel/panel
cp .env.example .env
npm ci
npm run upgrade-db
npm run dev
```

Default URL: `http://localhost:3000`

### MySQL via Docker (Port 5757)

```bash
cd /home/mihai/Desktop/cpanel/panel
cp .env.mysql-docker.example .env
docker compose -f docker-compose.mysql.yml up -d
npm run upgrade-db
npm run create-user
npm run dev
```

Use `docker compose -f docker-compose.mysql.yml ps` to check DB health.

Default Docker DB credentials are defined in `docker-compose.mysql.yml`.
Change all passwords before production use.

### Main Scripts

- `npm run dev` - start with nodemon
- `npm start` - start in normal mode
- `npm run upgrade-db` - apply schema/data upgrades
- `npm run create-user` - create initial user/admin
- `npm run lang:sync` - sync `espanol.json` and `romana.json` from `english.json` (auto-translate only missing/unchanged keys)

Language sync options:

- `npm run lang:sync -- --force` - re-translate all keys
- `npm run lang:sync -- --only=es` - sync only Spanish
- `npm run lang:sync -- --only=ro` - sync only Romanian
- `npm run lang:sync -- --limit=50` - translate only first 50 pending keys (test mode)

Language runtime:

- `/admin/lang` manages JSON files from `public/lang`.
- UI language is resolved from session/cookie/query (`lang`) with fallback to `english`.
- `POST /language` changes active language (`languageCode` + optional `redirect`).

### Core Features

- Multi-connector and multi-location orchestration
- Power/console/files management
- SFTP integration (toggleable from admin settings)
- Schedules, smart alerts, scaling, inventory/store/redeem/deals
- Admin API keys + audit
- Migration flows from Pterodactyl
- Extensions system (announcer, incidents, maintenance, security tools)

### Environment

Check `.env.example`. Common keys:

- `APP_PORT`
- `APP_URL`
- `APP_SECRET`
- `CONNECTOR_SECRET`
- `DEBUG`
- `TIMEZONE`

### Connector Endpoints Used

- `GET/WS /ws/connector`
- `GET/WS /ws/server/:containerId`
- `POST /api/connector/sftp-auth`

Connector repo: https://github.com/mihai209/Connector

### Production Notes

- Use `panel/conf/nginx.conf` or `panel/conf/apache2.conf`, or standalone mode.
- Run panel and connector processes with `systemd` or `pm2`.
- Keep secrets private and rotate tokens/keys on compromise.

## Romana

Panel web pentru provisionare si administrare de servere game/app bazate pe Docker.

- Repo: https://github.com/mihai209/CPanel
- Licenta: MIT

### Stack

- Node.js + Express
- Template-uri EJS
- Sequelize (implicit SQLite, suport si pentru MySQL/PostgreSQL)
- Bridge WebSocket pentru comunicarea cu connector-ele

### Cerinte

- Node.js 20+
- npm 10+
- Host Docker cu cel putin un nod `connector-go`

### Pornire Rapida

```bash
cd /home/mihai/Desktop/cpanel/panel
cp .env.example .env
npm ci
npm run upgrade-db
npm run dev
```

URL implicit: `http://localhost:3000`

### Scripturi Principale

- `npm run dev` - pornire cu nodemon
- `npm start` - pornire normala
- `npm run upgrade-db` - aplica upgrade-uri de schema/date
- `npm run create-user` - creeaza utilizator initial/admin
- `npm run lang:sync` - sincronizeaza `espanol.json` si `romana.json` din `english.json` (traduce doar cheile lipsa/nesincronizate)

Optiuni pentru sincronizare limbi:

- `npm run lang:sync -- --force` - retraduce toate cheile
- `npm run lang:sync -- --only=es` - sincronizeaza doar spaniola
- `npm run lang:sync -- --only=ro` - sincronizeaza doar romana
- `npm run lang:sync -- --limit=50` - traduce doar primele 50 chei pendinte (test)

Runtime limbi:

- `/admin/lang` administreaza fisierele JSON din `public/lang`.
- Limba UI este rezolvata din session/cookie/query (`lang`), cu fallback la `english`.
- `POST /language` schimba limba activa (`languageCode` + `redirect` optional).

### Functionalitati

- Orchestrare multi-connector si multi-location
- Management power/consola/fisiere
- Integrare SFTP (toggle din admin settings)
- Schedules, smart alerts, scaling, inventory/store/redeem/deals
- Chei API de admin + audit
- Fluxuri de migrare din Pterodactyl
- Sistem de extensii (announcer, incidents, maintenance, security tools)

### Mediu

Verifica `.env.example`. Chei uzuale:

- `APP_PORT`
- `APP_URL`
- `APP_SECRET`
- `CONNECTOR_SECRET`
- `DEBUG`
- `TIMEZONE`

### Endpoint-uri Folosite pentru Connector

- `GET/WS /ws/connector`
- `GET/WS /ws/server/:containerId`
- `POST /api/connector/sftp-auth`

Repo connector: https://github.com/mihai209/Connector

### Note Productie

- Foloseste `panel/conf/nginx.conf` sau `panel/conf/apache2.conf`, ori modul standalone.
- Ruleaza panelul si connector-ele cu `systemd` sau `pm2`.
- Pastreaza secretele private si roteste token-urile/cheile compromise.
