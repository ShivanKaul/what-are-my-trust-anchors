#!/bin/sh
set -eu
umask 077
find /data -xdev -type d -exec chown app:app {} \;
find /data -xdev -type f -exec chown app:app {} \;
find /data -xdev -type d -exec chmod 700 {} \;
find /data -xdev -type f -exec chmod 600 {} \;
exec su app -s /bin/sh -c 'exec /usr/local/bin/what-are-my-trust-anchors'
