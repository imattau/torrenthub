#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
# Data under /var/lib/torrenthub, the torrenthub user and /etc/torrenthub/hub.env are left in place on purpose.
