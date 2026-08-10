#!/bin/sh
# Railway mounts the persistent volume over /app/storage, replacing the image
# directory along with the ownership set at build time. A container that starts
# unprivileged cannot repair that mount, and every cache write then fails with
# PermissionError. So the container starts as root, corrects the mount, and drops
# to the unprivileged runtime user before any application code runs.
set -eu

NETRA_UID=10001
NETRA_GID=10001
STORAGE_ROOT="${NETRA_STORAGE_ROOT:-/app/storage}"
TEMP_ROOT="${NETRA_TEMP_ROOT:-/app/.netra-tmp}"

if [ "$(id -u)" = "0" ]; then
    for directory in "$STORAGE_ROOT" "$TEMP_ROOT"; do
        mkdir -p "$directory"
        owner="$(stat -c '%u:%g' "$directory" 2>/dev/null || echo '')"
        if [ "$owner" != "${NETRA_UID}:${NETRA_GID}" ]; then
            echo "netra-entrypoint: correcting ownership of ${directory} (was ${owner:-unknown})"
            chown -R "${NETRA_UID}:${NETRA_GID}" "$directory"
        fi
    done
    exec setpriv --reuid="$NETRA_UID" --regid="$NETRA_GID" --clear-groups "$@"
fi

# Already unprivileged, for example because RAILWAY_RUN_UID pinned the user.
# Run as-is and let the cache preflight report if the volume is not writable.
echo "netra-entrypoint: running as uid $(id -u); skipping ownership correction"
exec "$@"
