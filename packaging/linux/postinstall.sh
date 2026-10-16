#!/bin/sh
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/torrenthub.conf || true
fi
if ! getent passwd torrenthub >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/torrenthub --shell /usr/sbin/nologin --user-group torrenthub 2>/dev/null || \
    adduser --system --group --home /var/lib/torrenthub --shell /usr/sbin/nologin torrenthub
fi
chown root:torrenthub /etc/torrenthub /etc/torrenthub/hub.env
chmod 750 /etc/torrenthub
chmod 640 /etc/torrenthub/hub.env
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
echo "torrenthub is installed but not running. Edit /etc/torrenthub/hub.env (THUB_PUBLIC_URL, THUB_ROOTS), then: systemctl enable --now torrenthub"
