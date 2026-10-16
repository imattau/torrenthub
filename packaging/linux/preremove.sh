#!/bin/sh
# deb passes "remove" or "upgrade"; rpm passes the number of copies left (0 = removal)
set -e
if [ "$1" = remove ] || [ "$1" = 0 ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop torrenthub 2>/dev/null || true
        systemctl disable torrenthub 2>/dev/null || true
    fi
fi
