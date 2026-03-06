#!/usr/bin/env bash
set -euo pipefail

if ! command -v mysql >/dev/null 2>&1; then
  echo "[ERROR] mysql client is not installed. Install mysql-client/mariadb-client first."
  exit 1
fi

random_secret() {
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}"
}

prompt() {
  local label="$1"
  local default_value="${2:-}"
  local value=""
  if [[ -n "$default_value" ]]; then
    read -r -p "$label [$default_value]: " value
    value="${value:-$default_value}"
  else
    read -r -p "$label: " value
  fi
  printf '%s' "$value"
}

prompt_secret() {
  local label="$1"
  local default_value="${2:-}"
  local value=""
  if [[ -n "$default_value" ]]; then
    read -r -s -p "$label [$default_value]: " value
    echo
    value="${value:-$default_value}"
  else
    read -r -s -p "$label: " value
    echo
  fi
  printf '%s' "$value"
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

echo "CPanel Rocky - MySQL Provision Auto Setup"
echo "This script configures:"
echo "  1) panel database user (limited to panel DB)"
echo "  2) database host admin user (for per-server DB provisioning)"
echo

MYSQL_HOST="$(prompt "MySQL admin host" "127.0.0.1")"
MYSQL_PORT="$(prompt "MySQL admin port" "3306")"
MYSQL_ADMIN_USER="$(prompt "MySQL admin user" "root")"
MYSQL_ADMIN_PASS="$(prompt_secret "MySQL admin password (leave empty for socket/no-password auth)")"

PANEL_DB="$(prompt "Panel database name" "rockypanel")"
PANEL_USER="$(prompt "Panel database user" "rockyuser")"
PANEL_USER_HOST="$(prompt "Panel database user host pattern" "%")"
PANEL_PASS_DEFAULT="$(random_secret 24)"
PANEL_PASS="$(prompt_secret "Panel database user password" "$PANEL_PASS_DEFAULT")"

DBHOST_USER="$(prompt "DB Host admin user (used in /admin/databases)" "cpaneldbadmin")"
DBHOST_USER_HOST="$(prompt "DB Host admin user host pattern" "%")"
DBHOST_PASS_DEFAULT="$(random_secret 24)"
DBHOST_PASS="$(prompt_secret "DB Host admin user password" "$DBHOST_PASS_DEFAULT")"

validate_identifier "$PANEL_DB" "Panel database name"
validate_identifier "$PANEL_USER" "Panel database user"
validate_identifier "$DBHOST_USER" "DB Host admin user"
validate_host_pattern "$PANEL_USER_HOST" "Panel user host pattern"
validate_host_pattern "$DBHOST_USER_HOST" "DB Host user host pattern"

if [[ ! "$MYSQL_PORT" =~ ^[0-9]+$ ]] || (( MYSQL_PORT < 1 || MYSQL_PORT > 65535 )); then
  echo "[ERROR] MySQL port must be between 1 and 65535."
  exit 1
fi

panel_db_esc="$(escape_sql_identifier "$PANEL_DB")"
panel_user_esc="$(escape_sql_string "$PANEL_USER")"
panel_user_host_esc="$(escape_sql_string "$PANEL_USER_HOST")"
panel_pass_esc="$(escape_sql_string "$PANEL_PASS")"
dbhost_user_esc="$(escape_sql_string "$DBHOST_USER")"
dbhost_user_host_esc="$(escape_sql_string "$DBHOST_USER_HOST")"
dbhost_pass_esc="$(escape_sql_string "$DBHOST_PASS")"

mysql_admin_args=(-h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_ADMIN_USER" --protocol=tcp)
if [[ -n "$MYSQL_ADMIN_PASS" ]]; then
  mysql_admin_args+=(-p"$MYSQL_ADMIN_PASS")
fi

echo
echo "[INFO] Applying grants..."
mysql "${mysql_admin_args[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${panel_db_esc}\`;

CREATE USER IF NOT EXISTS '${panel_user_esc}'@'${panel_user_host_esc}' IDENTIFIED BY '${panel_pass_esc}';
ALTER USER '${panel_user_esc}'@'${panel_user_host_esc}' IDENTIFIED BY '${panel_pass_esc}';
GRANT ALL PRIVILEGES ON \`${panel_db_esc}\`.* TO '${panel_user_esc}'@'${panel_user_host_esc}';

CREATE USER IF NOT EXISTS '${dbhost_user_esc}'@'${dbhost_user_host_esc}' IDENTIFIED BY '${dbhost_pass_esc}';
ALTER USER '${dbhost_user_esc}'@'${dbhost_user_host_esc}' IDENTIFIED BY '${dbhost_pass_esc}';
GRANT ALL PRIVILEGES ON *.* TO '${dbhost_user_esc}'@'${dbhost_user_host_esc}' WITH GRANT OPTION;

FLUSH PRIVILEGES;
SQL

echo "[INFO] Grants applied. Verifying with smoke test as DB Host admin user..."

suffix="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 6)"
test_db="cpanel_test_${suffix}"
test_user="cp_test_${suffix}"
test_pass="$(random_secret 18)"
test_db_esc="$(escape_sql_identifier "$test_db")"
test_user_esc="$(escape_sql_string "$test_user")"
test_pass_esc="$(escape_sql_string "$test_pass")"

mysql_dbhost_args=(-h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$DBHOST_USER" --protocol=tcp -p"$DBHOST_PASS")
mysql "${mysql_dbhost_args[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${test_db_esc}\`;
CREATE USER IF NOT EXISTS '${test_user_esc}'@'%' IDENTIFIED BY '${test_pass_esc}';
ALTER USER '${test_user_esc}'@'%' IDENTIFIED BY '${test_pass_esc}';
GRANT ALL PRIVILEGES ON \`${test_db_esc}\`.* TO '${test_user_esc}'@'%';
DROP DATABASE IF EXISTS \`${test_db_esc}\`;
DROP USER IF EXISTS '${test_user_esc}'@'%';
FLUSH PRIVILEGES;
SQL

echo
echo "[OK] Setup complete."
echo
echo "Use these in panel .env:"
echo "DB_CONNECTION=mysql"
echo "DB_HOST=${MYSQL_HOST}"
echo "DB_PORT=${MYSQL_PORT}"
echo "DB_DATABASE=${PANEL_DB}"
echo "DB_USERNAME=${PANEL_USER}"
echo "DB_PASSWORD=${PANEL_PASS}"
echo
echo "Use these in /admin/databases (Database Host):"
echo "Type: mysql"
echo "Host: ${MYSQL_HOST}"
echo "Port: ${MYSQL_PORT}"
echo "Username: ${DBHOST_USER}"
echo "Password: ${DBHOST_PASS}"
echo
echo "Grant verification commands:"
echo "SHOW GRANTS FOR '${PANEL_USER}'@'${PANEL_USER_HOST}';"
echo "SHOW GRANTS FOR '${DBHOST_USER}'@'${DBHOST_USER_HOST}';"

