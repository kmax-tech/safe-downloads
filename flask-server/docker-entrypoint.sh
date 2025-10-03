#!/usr/bin/env sh
set -euo pipefail

# Defaults (override via env)
: "${WORKERS:=2}"
: "${BIND:=0.0.0.0:5000}"     # must be 0.0.0.0 so Caddy can reach it
: "${APP_IMPORT:=app:app}"   # module:object that exposes your Flask app
: "${FLASK_ENV:=development}" # "production" or "development"

HOST="${BIND%%:*}"
PORT="${BIND##*:}"

if [ "$FLASK_ENV" = "production" ]; then
  echo "Starting Gunicorn (${WORKERS} workers) on ${BIND} -> ${APP_IMPORT}"
  # You can use 'gunicorn' or 'python -m gunicorn'; using the binary is simpler
  exec gunicorn -w "$WORKERS" -b "$BIND" "$APP_IMPORT"
else
  echo "Starting Flask dev server on ${HOST}:${PORT} -> ${APP_IMPORT}"
  # Use flask's built-in runner and pass host/port explicitly
  export FLASK_APP="$APP_IMPORT"      
  export FLASK_RUN_HOST="$HOST"
  export FLASK_RUN_PORT="$PORT"
  exec flask run 
fi
