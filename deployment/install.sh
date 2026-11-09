#!/usr/bin/env bash
#
# ThreatPulse backend installer — schedules the pipeline to run unattended.
#
# Idempotent and non-interactive: safe to re-run after an upgrade. It never
# overwrites an existing secrets file, and it does not touch the database, the
# website or the frontend.
#
# Usage:
#   sudo ./deployment/install.sh                 # install and schedule
#   sudo ./deployment/install.sh --skip-tests    # schedule without the test gate
#   sudo ./deployment/install.sh --dry-run-only  # install, verify, do not schedule
#
# The backend is standard-library only, so there is nothing to pip install and no
# virtual environment to maintain. That is deliberate: fewer moving parts on a
# small VM, and no dependency that can rot.

set -euo pipefail

APP_ROOT="${THREATPULSE_APP_ROOT:-/home/ubnt/ThreatPulse}"
CONFIG_DIR="${THREATPULSE_CONFIG_DIR:-/etc/threatpulse}"
ENV_FILE="$CONFIG_DIR/threatpulse.env"
# The units are installed verbatim, not templated, so this must match User= and
# Group= in deployment/systemd/threatpulse.service. The step after installation
# checks that it does, rather than letting the two drift apart silently.
SERVICE_USER="${THREATPULSE_SERVICE_USER:-ubnt}"
PYTHON="${THREATPULSE_PYTHON:-/usr/bin/python3}"
UNIT_DIR="/etc/systemd/system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUN_TESTS=1
SCHEDULE=1

for argument in "$@"; do
    case "$argument" in
        --skip-tests)    RUN_TESTS=0 ;;
        --dry-run-only)  SCHEDULE=0 ;;
        -h|--help)
            sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$argument" >&2
            exit 2
            ;;
    esac
done

step() { printf '\n== %s\n' "$*"; }
log()  { printf '   %s\n' "$*"; }
fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run this with sudo"

step "Checking prerequisites"

command -v systemctl >/dev/null 2>&1 \
    || fail "systemd is not available on this host"

SYSTEMD_VERSION="$(systemctl --version 2>/dev/null | head -n 1 | awk '{print $2}')"

if [ -n "${SYSTEMD_VERSION:-}" ] && [ "$SYSTEMD_VERSION" -lt 245 ] 2>/dev/null; then
    log "systemd $SYSTEMD_VERSION is older than 245: ProtectClock, ProtectKernelLogs and"
    log "a few other hardening directives will be ignored with a warning. The pipeline"
    log "still runs; the unit is simply less confined. Check the output of"
    log "'systemd-analyze verify' below."
else
    log "systemd ${SYSTEMD_VERSION:-unknown}"
fi

[ -x "$PYTHON" ] || fail "$PYTHON not found; set THREATPULSE_PYTHON"

log "python: $($PYTHON -V 2>&1)"

# Every module the pipeline imports at start-up. A host with a trimmed Python
# (a minimal container or an appliance image) is missing some of these, and the
# failure otherwise surfaces much later as a confusing ImportError mid-run.
"$PYTHON" - <<'PYTHON' || fail "the Python standard library is incomplete — install the full package (Debian/Ubuntu: apt-get install -y python3-full)"
import csv        # noqa: F401  exploit catalogue
import html       # noqa: F401  RSS/Atom normalisation
import http.client  # noqa: F401
import json       # noqa: F401
import unittest   # noqa: F401  the test suite
import urllib.request  # noqa: F401  every collector
import xml.etree.ElementTree  # noqa: F401  feeds
PYTHON

log "standard library present (no third-party packages required)"

step "Checking the application directory"

[ -f "$APP_ROOT/run_pipeline.py" ] \
    || fail "$APP_ROOT/run_pipeline.py not found — upload the contents of backend/ there first (see DEPLOYMENT.md)"

[ -f "$APP_ROOT/config/settings.json" ] \
    || fail "$APP_ROOT/config/settings.json not found"

log "application: $APP_ROOT"

step "Creating the service account"

if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "user $SERVICE_USER already exists"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    log "created system user $SERVICE_USER"
fi

step "Preparing directories"

for directory in state data logs; do
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$APP_ROOT/$directory"
done

chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_ROOT"
chmod 0750 "$APP_ROOT"
log "state, data and logs are writable by $SERVICE_USER"

step "Preparing the secrets file"

install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"

if [ -f "$ENV_FILE" ]; then
    log "existing $ENV_FILE kept — never overwritten"
else
    printf 'THREATPULSE_PUBLISHER_TOKEN=\n' > "$ENV_FILE"
    log "created $ENV_FILE"
fi

chown "$SERVICE_USER:$SERVICE_USER" "$ENV_FILE"
chmod 0600 "$ENV_FILE"

token_present=no

if grep -qE '^THREATPULSE_PUBLISHER_TOKEN=.+$' "$ENV_FILE"; then
    token_present=yes
    log "publisher token is present"
else
    log "publisher token is MISSING"
fi

step "Running the test suite"

if [ "$RUN_TESTS" -eq 0 ]; then
    log "skipped (--skip-tests)"
elif ( cd "$APP_ROOT" && "$PYTHON" -m unittest discover -s tests -t . > /tmp/threatpulse-tests.log 2>&1 ); then
    log "$(tail -n 1 /tmp/threatpulse-tests.log)"
    log "the suite passes; the code that will be scheduled is the code that was tested"
else
    log "the test suite FAILED:"
    tail -n 20 /tmp/threatpulse-tests.log | sed 's/^/   /'
    fail "refusing to schedule a pipeline whose tests do not pass (re-run with --skip-tests to override)"
fi

step "Installing systemd units"

install -m 0644 "$SCRIPT_DIR/systemd/threatpulse.service" "$UNIT_DIR/threatpulse.service"
install -m 0644 "$SCRIPT_DIR/systemd/threatpulse.timer" "$UNIT_DIR/threatpulse.timer"

systemctl daemon-reload

log "installed $UNIT_DIR/threatpulse.service"
log "installed $UNIT_DIR/threatpulse.timer"

# The units are copied verbatim, so the paths and the service account are baked
# into them. If this script's APP_ROOT/SERVICE_USER disagree with the unit file,
# the install would look successful and then run the wrong tree — or fail at 05:20
# with a WorkingDirectory error that names nothing useful. Fail here instead.
step "Checking the units match this installation"

unit_working_directory="$(sed -n 's/^WorkingDirectory=//p' "$UNIT_DIR/threatpulse.service")"
unit_user="$(sed -n 's/^User=//p' "$UNIT_DIR/threatpulse.service")"

if [ "$unit_working_directory" != "$APP_ROOT" ]; then
    fail "the unit's WorkingDirectory ($unit_working_directory) does not match APP_ROOT ($APP_ROOT); edit deployment/systemd/threatpulse.service or set THREATPULSE_APP_ROOT to the value it carries"
fi

if [ "$unit_user" != "$SERVICE_USER" ]; then
    fail "the unit's User ($unit_user) does not match SERVICE_USER ($SERVICE_USER); edit deployment/systemd/threatpulse.service or set THREATPULSE_SERVICE_USER to the value it carries"
fi

log "unit paths and service account agree with APP_ROOT=$APP_ROOT and SERVICE_USER=$SERVICE_USER"

# Reports unit-file problems such as an unknown directive before they are hit at
# 05:20 in the morning. Warnings are reported, not fatal: verify is stricter than
# the runtime.
systemd-analyze verify "$UNIT_DIR/threatpulse.service" 2>&1 \
    | sed 's/^/   /' || true

step "Verifying the pipeline runs as the service account"

if ( cd "$APP_ROOT" \
        && sudo -u "$SERVICE_USER" "$PYTHON" run_pipeline.py --dry-run --log-level WARNING \
           > /tmp/threatpulse-dryrun.log 2>&1 ); then
    log "$(grep -E '^Threats:' /tmp/threatpulse-dryrun.log | head -n 1)"
    log "dry run succeeded; nothing was transmitted"
else
    log "the dry run did not succeed:"
    tail -n 15 /tmp/threatpulse-dryrun.log | sed 's/^/   /'
    log "the timer will not be started until this passes"
    SCHEDULE=0
fi

step "Scheduling"

if [ "$SCHEDULE" -eq 0 ]; then
    systemctl enable threatpulse.timer >/dev/null 2>&1 || true
    log "timer enabled but NOT started"
    log "start it once the dry run and the token are in place: sudo systemctl start threatpulse.timer"
elif [ "$token_present" = no ]; then
    systemctl enable threatpulse.timer >/dev/null 2>&1 || true
    log "timer enabled but NOT started — the publisher token is empty"
    log "set it, then start the timer:"
    log "  sudo editor $ENV_FILE      # THREATPULSE_PUBLISHER_TOKEN=..."
    log "  sudo systemctl start threatpulse.timer"
else
    systemctl enable --now threatpulse.timer >/dev/null 2>&1
    log "timer enabled and started"
    systemctl list-timers threatpulse.timer --no-pager 2>/dev/null | sed 's/^/   /' || true
fi

step "Installed"

cat <<EOF

   The pipeline will run daily at 05:20 UTC (with up to 20 minutes of jitter)
   as the unprivileged user '$SERVICE_USER'. It publishes over outbound HTTPS
   only; no inbound port is opened.

   Watch a run              journalctl -u threatpulse.service -f
   Run one now              sudo systemctl start threatpulse.service
   Last run's outcome       systemctl status threatpulse.service
   Next scheduled run       systemctl list-timers threatpulse.timer
   Verify the publication   $PYTHON $APP_ROOT/scripts/verify_publication.py
   Stop publishing          sudo systemctl disable --now threatpulse.timer

   A failed run exits non-zero and is visible in the journal; the timer retries
   at most three times within the hour and then waits for the next day.

   If the run fails with a permission or "failed to execute" error, the two most
   restrictive hardening directives in the unit are MemoryDenyWriteExecute and
   SystemCallFilter — see the comment block in $UNIT_DIR/threatpulse.service.

EOF
