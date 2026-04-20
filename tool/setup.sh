#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# W3GathrVulns — setup.sh
#
# Creates a .env file from .env.example with cryptographically secure
# randomly generated secrets.
#
# Usage:
#   ./setup.sh                  # first-time installation
#   ./setup.sh --rotate-secrets # regenerate secrets only (keeps existing IPs)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

ENV_FILE=".env"
EXAMPLE_FILE=".env.example"
ROTATE_ONLY=false

# ── Parse args ────────────────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --rotate-secrets) ROTATE_ONLY=true ;;
    *) echo "Usage: $0 [--rotate-secrets]"; exit 1 ;;
  esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
info() { echo -e "${CYAN}→${NC}  $*"; }
err()  { echo -e "${RED}✗${NC}  $*" >&2; }

echo -e "\n${BOLD}W3GathrVulns — Setup${NC}\n"

# ── Check dependencies ────────────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
  err "openssl is required. Install it: apt install openssl"
  exit 1
fi

# ── Generate a cryptographically secure random string ─────────────────────────
gen_secret() {
  local length="${1:-64}"
  openssl rand -base64 "$length" | tr -d '\n/+=' | cut -c1-"$length"
}

gen_password() {
  # Alphanumeric only — safe for connection strings
  openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | cut -c1-32
}

# ── Rotate mode: update SECRET_KEY and POSTGRES_PASSWORD in existing .env ────
if $ROTATE_ONLY; then
  if [[ ! -f "$ENV_FILE" ]]; then
    err ".env not found. Run ./setup.sh first."
    exit 1
  fi

  echo ""
  echo -e "  ${BOLD}What this command rotates${NC}"
  echo    "  ┌─────────────────────────────────────────────────────────────────────┐"
  echo    "  │  SECRET_KEY        → updated in .env, effective after restart       │"
  echo    "  │  POSTGRES_PASSWORD → updated in .env only (see note below)          │"
  echo    "  └─────────────────────────────────────────────────────────────────────┘"
  echo    ""
  echo -e "  ${BOLD}Out of scope — manage these from the Settings page in the UI${NC}"
  echo    "  ┌─────────────────────────────────────────────────────────────────────┐"
  echo    "  │  API_TOKEN_READ    → Settings → API Tokens → Regenerate             │"
  echo    "  │  API_TOKEN_WRITE   → Settings → API Tokens → Regenerate             │"
  echo    "  │  Admin password    → Settings → Change password                     │"
  echo    "  └─────────────────────────────────────────────────────────────────────┘"
  echo    "  These values are stored in the database and are not read from .env"
  echo    "  after first startup. Changing them here would have no effect."
  echo    ""

  NEW_PG_PASS=$(gen_password)
  NEW_SECRET=$(gen_secret 64)
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${NEW_PG_PASS}|" "$ENV_FILE"
  sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${NEW_SECRET}|" "$ENV_FILE"
  ok "SECRET_KEY rotated"
  ok "POSTGRES_PASSWORD rotated in .env"

  echo ""
  echo -e "  ${YELLOW}Note: POSTGRES_PASSWORD${NC}"
  echo    "  The new password is written to .env but the running PostgreSQL instance"
  echo    "  still uses the old one. To apply it without data loss, run:"
  echo    "      docker compose exec db psql -U w3gathrvulns -c \"ALTER USER w3gathrvulns WITH PASSWORD 'NEW_PASSWORD'\""
  echo    "  Replace NEW_PASSWORD with the value now in .env."
  echo    "  Alternatively, 'docker compose down -v' will recreate the volume (data loss)."
  echo ""
  echo -e "  ${YELLOW}Note: SECRET_KEY${NC}"
  echo    "  Changing SECRET_KEY invalidates all active web UI sessions."
  echo    "  Users will need to log in again after restart."
  echo ""
  echo -e "  Restart the backend to apply SECRET_KEY:"
  echo -e "  ${CYAN}docker compose up -d --build backend${NC}"
  echo ""
  exit 0
fi

# ── Fresh install ─────────────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
  warn ".env already exists."
  read -rp "   Overwrite? (y/N): " confirm
  if [[ "${confirm,,}" != "y" ]]; then
    info "Cancelled. To regenerate secrets only: $0 --rotate-secrets"
    exit 0
  fi
fi

if [[ ! -f "$EXAMPLE_FILE" ]]; then
  err ".env.example not found. Make sure you are in the src/ directory."
  exit 1
fi

# ── Ask for SERVER_IP ─────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Server IP / hostname${NC}"
echo    "  This value is embedded in the self-signed TLS certificate (SAN) and"
echo    "  used to configure CORS. Use 'localhost' for local testing, or the"
echo    "  IP / domain your team will use to reach the instance."
read -rp "$(echo -e "${CYAN}→${NC}  Server IP or hostname [localhost]: ")" SERVER_IP
SERVER_IP="${SERVER_IP:-localhost}"

echo ""
echo -e "  ${BOLD}Ports${NC}"
echo    "  HTTP redirects to HTTPS automatically. Change only if 80/443 are taken."
read -rp "$(echo -e "${CYAN}→${NC}  HTTP port  [80]:  ")" HTTP_PORT
HTTP_PORT="${HTTP_PORT:-80}"

read -rp "$(echo -e "${CYAN}→${NC}  HTTPS port [443]: ")" HTTPS_PORT
HTTPS_PORT="${HTTPS_PORT:-443}"

# ── Ask for admin password ────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Admin password${NC}"
echo    "  Password for the web UI login (username: admin)."
echo    "  Min 8 characters recommended."
read -rsp "$(echo -e "${CYAN}→${NC}  Admin password: ")" UI_PASSWORD
echo ""
if [[ -z "$UI_PASSWORD" ]]; then
  err "UI_PASSWORD cannot be empty."
  exit 1
fi

# ── Demo mode ────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Demo mode${NC}"
echo    "  Disables token/password changes and resets all data every hour with"
echo    "  sample findings. Use only for a public demonstration instance."
echo    "  Credentials will be set to: admin / demo"
read -rp "$(echo -e "${CYAN}→${NC}  Enable demo mode? (y/N): ")" ENABLE_DEMO
DEMO_MODE=false
if [[ "${ENABLE_DEMO,,}" == "y" ]]; then
  DEMO_MODE=true
  UI_PASSWORD="W3Gathr!Demo"
  warn "Demo mode enabled — UI_PASSWORD set to 'W3Gathr!Demo'"
fi

# ── Generate secrets ──────────────────────────────────────────────────────────
info "Generating cryptographic secrets..."
PG_PASSWORD=$(gen_password)
SECRET_KEY=$(gen_secret 64)
API_TOKEN_READ=$(gen_secret 48)
API_TOKEN_WRITE=$(gen_secret 48)

ok "POSTGRES_PASSWORD:  ${PG_PASSWORD:0:8}... (${#PG_PASSWORD} chars)"
ok "SECRET_KEY:         ${SECRET_KEY:0:8}... (${#SECRET_KEY} chars)"
ok "API_TOKEN_READ:     ${API_TOKEN_READ:0:8}... (${#API_TOKEN_READ} chars)"
ok "API_TOKEN_WRITE:    ${API_TOKEN_WRITE:0:8}... (${#API_TOKEN_WRITE} chars)"

# ── Write .env ────────────────────────────────────────────────────────────────
cat > "$ENV_FILE" << EOF
# ─────────────────────────────────────────────────────────────────────────────
# W3GathrVulns — .env
# Generated by setup.sh on $(date '+%Y-%m-%d %H:%M:%S')
# WARNING: Do not commit this file to git
# ─────────────────────────────────────────────────────────────────────────────

# ── Network / TLS ─────────────────────────────────────────────────────────────
SERVER_IP=${SERVER_IP}
HTTP_PORT=${HTTP_PORT}
HTTPS_PORT=${HTTPS_PORT}

# ── PostgreSQL ────────────────────────────────────────────────────────────────
POSTGRES_USER=w3gathrvulns
POSTGRES_PASSWORD=${PG_PASSWORD}
POSTGRES_DB=w3gathrvulns

# ── Backend FastAPI ───────────────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}
CORS_ORIGINS=["https://${SERVER_IP}","http://localhost"]
DEBUG=false

# ── Authentication ─────────────────────────────────────────────────────────────
UI_USERNAME=admin
UI_PASSWORD=${UI_PASSWORD}
API_TOKEN_READ=${API_TOKEN_READ}
API_TOKEN_WRITE=${API_TOKEN_WRITE}
JWT_EXPIRE_HOURS=24

# ── Demo mode ──────────────────────────────────────────────────────────────────
# When true: disables token/password changes and resets data hourly
DEMO_MODE=${DEMO_MODE}
EOF

chmod 600 "$ENV_FILE"
ok ".env created with permissions 600"

# ── Check .gitignore ──────────────────────────────────────────────────────────
if [[ -f ".gitignore" ]]; then
  if ! grep -qE "^\.env$" ".gitignore" 2>/dev/null; then
    warn ".env is not in .gitignore!"
    echo '    Add these lines to .gitignore:'
    echo '      .env'
    echo '      certs/*.pem'
    echo '      certs/*.crt'
    echo '      certs/*.key'
  else
    ok ".env is in .gitignore"
  fi
else
  warn ".gitignore not found — creating with essential entries..."
  cat > .gitignore << 'GITEOF'
# Secrets — never commit
.env
*.pem
*.crt
*.key
certs/

# Python
__pycache__/
*.pyc
*.pyo
.venv/
venv/

# Node
node_modules/
dist/
build/
.npm/

# OS
.DS_Store
Thumbs.db
GITEOF
  ok ".gitignore created"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Setup complete!${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo ""
echo "  Next step:"
echo -e "  ${CYAN}docker compose up --build -d${NC}"
echo ""
echo "  Application available at:"
echo -e "  ${CYAN}https://${SERVER_IP}:${HTTPS_PORT}${NC}"
echo ""
echo "  To rotate secrets later:"
echo -e "  ${CYAN}./setup.sh --rotate-secrets${NC}"
echo ""
