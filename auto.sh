#!/usr/bin/env bash
set -euo pipefail

if ! command -v mysql >/dev/null 2>&1; then
  echo "[ERROR] mysql client is not installed. Install mysql-client/mariadb-client first."
  exit 1
fi

random_secret() {
  local len="${1:-24}"
  local bytes=$(( (len + 1) / 2 + 8 ))
  local raw
  raw="$(od -An -N "$bytes" -tx1 /dev/urandom 2>/dev/null || true)"
  raw="${raw//[[:space:]]/}"
  if [[ ${#raw} -lt "$len" ]]; then
    raw="${raw}$(date +%s%N)"
    raw="${raw//[[:space:]]/}"
  fi
  printf '%s' "${raw:0:len}"
}

escape_sql_string() {
  local input="$1"
  input="${input//\\/\\\\}"
  input="${input//\'/\'\'}"
  printf '%s' "$input"
}

escape_sql_identifier() {
  local input="$1"
  input="${input//\`/\`\`}"
  printf '%s' "$input"
}

validate_identifier() {
  local value="$1"
  local field="$2"
  if [[ ! "$value" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "[ERROR] $field must match ^[A-Za-z0-9_]+$ (letters, numbers, underscore)."
    exit 1
  fi
}

validate_host_pattern() {
  local value="$1"
  local field="$2"
  if [[ ! "$value" =~ ^[A-Za-z0-9.%:_-]+$ ]]; then
    echo "[ERROR] $field contains invalid characters."
    exit 1
  fi
}

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
PANEL_DB="${PANEL_DB:-rockypanel}"
PANEL_USER="${PANEL_USER:-rockyuser}"
PANEL_USER_HOST="${PANEL_USER_HOST:-%}"
DBHOST_USER="${DBHOST_USER:-cpaneldbadmin}"
DBHOST_USER_HOST="${DBHOST_USER_HOST:-%}"
DBHOST_DISPLAY_NAME="${DBHOST_DISPLAY_NAME:-RockyDB}"
DBHOST_DEFAULT_DATABASE="${DBHOST_DEFAULT_DATABASE:-$PANEL_DB}"
DBHOST_TYPE="${DBHOST_TYPE:-mysql}"
DBHOST_HOST="${DBHOST_HOST:-$MYSQL_HOST}"
DBHOST_PORT="${DBHOST_PORT:-$MYSQL_PORT}"
PANEL_PASS="${PANEL_PASS:-$(random_secret 24)}"
DBHOST_PASS="${DBHOST_PASS:-$(random_secret 24)}"

validate_identifier "$PANEL_DB" "Panel database name"
validate_identifier "$PANEL_USER" "Panel database user"
validate_identifier "$DBHOST_USER" "DB Host admin user"
validate_host_pattern "$PANEL_USER_HOST" "Panel user host pattern"
validate_host_pattern "$DBHOST_USER_HOST" "DB Host user host pattern"

if [[ ! "$MYSQL_PORT" =~ ^[0-9]+$ ]] || (( MYSQL_PORT < 1 || MYSQL_PORT > 65535 )); then
  echo "[ERROR] MYSQL_PORT must be between 1 and 65535."
  exit 1
fi
if [[ ! "$DBHOST_PORT" =~ ^[0-9]+$ ]] || (( DBHOST_PORT < 1 || DBHOST_PORT > 65535 )); then
  echo "[ERROR] DBHOST_PORT must be between 1 and 65535."
  exit 1
fi

MYSQL_ADMIN_CMD=()
if mysql --protocol=socket -u root -e "SELECT 1;" >/dev/null 2>&1; then
  MYSQL_ADMIN_CMD=(mysql --protocol=socket -u root)
elif command -v sudo >/dev/null 2>&1 && sudo -n mysql --protocol=socket -u root -e "SELECT 1;" >/dev/null 2>&1; then
  MYSQL_ADMIN_CMD=(sudo mysql --protocol=socket -u root)
elif [[ -n "${MYSQL_ADMIN_USER:-}" && -n "${MYSQL_ADMIN_PASS:-}" ]]; then
  MYSQL_ADMIN_CMD=(mysql --protocol=tcp -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_ADMIN_USER" "-p$MYSQL_ADMIN_PASS")
else
  echo "[ERROR] Could not connect as MySQL root automatically."
  echo "Run as root/sudo on DB host OR set env MYSQL_ADMIN_USER + MYSQL_ADMIN_PASS."
  exit 1
fi

panel_db_esc="$(escape_sql_identifier "$PANEL_DB")"
panel_user_esc="$(escape_sql_string "$PANEL_USER")"
panel_user_host_esc="$(escape_sql_string "$PANEL_USER_HOST")"
panel_pass_esc="$(escape_sql_string "$PANEL_PASS")"
dbhost_user_esc="$(escape_sql_string "$DBHOST_USER")"
dbhost_user_host_esc="$(escape_sql_string "$DBHOST_USER_HOST")"
dbhost_pass_esc="$(escape_sql_string "$DBHOST_PASS")"

echo "[INFO] Auto provisioning MySQL users and grants..."
"${MYSQL_ADMIN_CMD[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${panel_db_esc}\`;

DROP USER IF EXISTS '${panel_user_esc}'@'${panel_user_host_esc}';
CREATE USER '${panel_user_esc}'@'${panel_user_host_esc}' IDENTIFIED BY '${panel_pass_esc}';
GRANT ALL PRIVILEGES ON \`${panel_db_esc}\`.* TO '${panel_user_esc}'@'${panel_user_host_esc}';

DROP USER IF EXISTS '${dbhost_user_esc}'@'${dbhost_user_host_esc}';
CREATE USER '${dbhost_user_esc}'@'${dbhost_user_host_esc}' IDENTIFIED BY '${dbhost_pass_esc}';
GRANT ALL PRIVILEGES ON *.* TO '${dbhost_user_esc}'@'${dbhost_user_host_esc}' WITH GRANT OPTION;

FLUSH PRIVILEGES;
SQL

echo
echo "[OK] Auto setup complete."
echo
echo "=== Panel .env ==="
echo "DB_CONNECTION=mysql"
echo "DB_HOST=${MYSQL_HOST}"
echo "DB_PORT=${MYSQL_PORT}"
echo "DB_DATABASE=${PANEL_DB}"
echo "DB_USERNAME=${PANEL_USER}"
echo "DB_PASSWORD=${PANEL_PASS}"
echo
echo "=== /admin/databases -> Create/Edit Host ==="
echo "Display Name: ${DBHOST_DISPLAY_NAME}"
echo "Host / IP: ${DBHOST_HOST}"
echo "Port: ${DBHOST_PORT}"
echo "Username: ${DBHOST_USER}"
echo "Password: ${DBHOST_PASS}"
echo "Default Database: ${DBHOST_DEFAULT_DATABASE}"
echo "Host Type: ${DBHOST_TYPE}"
echo "Location: select your node location (example: Germany)"
echo
echo "=== Verify Grants (optional) ==="
echo "SHOW GRANTS FOR '${PANEL_USER}'@'${PANEL_USER_HOST}';"
echo "SHOW GRANTS FOR '${DBHOST_USER}'@'${DBHOST_USER_HOST}';"

