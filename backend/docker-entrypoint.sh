#!/bin/sh
# Railway mounts the persistent volume over /app/storage, replacing the image
# directory along with the ownership set at build time. A container that starts
# unprivileged cannot repair that mount, and every cache write then fails with
# PermissionError. So the container starts as root, corrects the mount, and drops
# to the unprivileged runtime user before any application code runs.
#
# This entrypoint belongs only on the worker image, which is the service that
# mounts the volume. It must reproduce the environment a `USER 10001:10001`
# directive would have produced -- same uid, same gid, same supplementary
# groups, and the same HOME. Dropping privileges without restoring HOME leaves
# it pointing at root's home, which the runtime user cannot even read.
set -eu

NETRA_UID=10001
NETRA_GID=10001
STORAGE_ROOT="${NETRA_STORAGE_ROOT:-/app/storage}"
TEMP_ROOT="${NETRA_TEMP_ROOT:-/app/.netra-tmp}"

# Resolve HOME from the passwd database rather than assuming a path, so this
# keeps matching the image if the account is ever moved.
NETRA_HOME="$(getent passwd "$NETRA_UID" | cut -d: -f6)"
[ -n "$NETRA_HOME" ] || NETRA_HOME=/home/netra
export HOME="$NETRA_HOME"

if [ "$(id -u)" = "0" ]; then
    for directory in "$STORAGE_ROOT" "$TEMP_ROOT"; do
        mkdir -p "$directory"
        owner="$(stat -c '%u:%g' "$directory" 2>/dev/null || echo '')"
        if [ "$owner" != "${NETRA_UID}:${NETRA_GID}" ]; then
            echo "netra-entrypoint: correcting ownership of ${directory} (was ${owner:-unknown})"
            chown -R "${NETRA_UID}:${NETRA_GID}" "$directory"
        fi
    done
    # --init-groups mirrors the supplementary groups a USER directive grants.
    # --clear-groups would drop them and is not equivalent.
    exec setpriv --reuid="$NETRA_UID" --regid="$NETRA_GID" --init-groups "$@"
fi

# Already unprivileged, for example because RAILWAY_RUN_UID pinned the user.
# Run as-is and let the cache preflight report if the volume is not writable.
echo "netra-entrypoint: running as uid $(id -u); skipping ownership correction"
exec "$@"
