#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_DIR="$BASE_DIR/panel"
COMPOSE_FILE="$PANEL_DIR/docker-compose.mysql.yml"
ENV_FILE="$PANEL_DIR/.env.mysql-auto"

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker is not installed or not in PATH." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[ERROR] docker compose plugin is missing. Install docker compose plugin and retry." >&2
  exit 1
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "[ERROR] docker-compose.mysql.yml not found at $COMPOSE_FILE" >&2
  exit 1
fi

echo "CPanel Rocky - Auto MySQL Docker Setup"
echo "This will create a MySQL container using the panel compose file."
echo

read -rsp "MySQL root password (required): " ROOT_PASS
echo
while [[ -z "$ROOT_PASS" ]]; do
  read -rsp "MySQL root password (required): " ROOT_PASS
  echo
done

echo
read -r -p "Panel database name [panel]: " PANEL_DB
PANEL_DB="${PANEL_DB:-panel}"

read -r -p "Panel database user [cpanel]: " PANEL_USER
PANEL_USER="${PANEL_USER:-cpanel}"

read -rsp "Panel database password (required): " PANEL_PASS
echo
while [[ -z "$PANEL_PASS" ]]; do
  read -rsp "Panel database password (required): " PANEL_PASS
  echo
done

echo
read -r -p "Host DB user (for per-server DBs) [cpanelhost]: " HOST_USER
HOST_USER="${HOST_USER:-cpanelhost}"

read -rsp "Host DB user password (required): " HOST_PASS
echo
while [[ -z "$HOST_PASS" ]]; do
  read -rsp "Host DB user password (required): " HOST_PASS
  echo
done

echo
read -r -p "MySQL TCP port [5757]: " MYSQL_PORT
MYSQL_PORT="${MYSQL_PORT:-5757}"

cat > "$ENV_FILE" <<ENV
MYSQL_ROOT_PASSWORD=$ROOT_PASS
MYSQL_DATABASE=$PANEL_DB
MYSQL_USER=$PANEL_USER
MYSQL_PASSWORD=$PANEL_PASS
MYSQL_TCP_PORT=$MYSQL_PORT
DB_HOST_USER=$HOST_USER
DB_HOST_PASSWORD=$HOST_PASS
ENV

echo
echo "[INFO] Starting MySQL container via docker compose..."
(cd "$PANEL_DIR" && docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d)

echo
(cd "$PANEL_DIR" && docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps)

echo
cat <<INFO
[OK] MySQL container started.

Panel .env values to use:
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=$MYSQL_PORT
DB_DATABASE=$PANEL_DB
DB_USERNAME=$PANEL_USER
DB_PASSWORD=$PANEL_PASS

Database Host values (Admin > Databases):
Type: mysql
Host: 127.0.0.1
Port: $MYSQL_PORT
Username: $HOST_USER
Password: $HOST_PASS
INFO
