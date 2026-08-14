#!/bin/sh
set -e

# Railway (and other platforms) mount persistent volumes over /data at
# runtime, which overrides the ownership we set during the image build.
# Re-apply ownership before dropping privileges so the kontor user can
# write to its own storage directory.
if [ "$(id -u)" = "0" ]; then
    chown -R kontor:kontor /data
    exec gosu kontor /app/kontor-storage-node "$@"
fi

exec /app/kontor-storage-node "$@"
