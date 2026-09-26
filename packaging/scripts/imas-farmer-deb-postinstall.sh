#!/bin/bash
# Create farmer user if it doesn't exist
if ! id -u farmer >/dev/null 2>&1; then
  useradd -r -s /bin/false -d /var/cache/imas/farmer farmer
fi
# Set ownership
chown -R farmer:farmer /etc/imas/pki/farmer /var/cache/imas/farmer
# Enable and start service
systemctl daemon-reload
systemctl enable imas-farmer.service 