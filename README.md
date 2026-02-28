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

### Main Scripts

- `npm run dev` - start with nodemon
- `npm start` - start in normal mode
- `npm run upgrade-db` - apply schema/data upgrades
- `npm run create-user` - create initial user/admin

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
