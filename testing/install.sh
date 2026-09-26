#!/usr/bin/env bash
wget https://github.com/yogzblr/imas/releases/download/v0.0.4/sprout
chmod +x sprout
sudo systemctl stop imas-sprout.service
sudo rm /etc/imas/pki/sprout/tls-rootca.pem
sudo mv sprout /usr/bin/imas-sprout
sudo systemctl start imas-sprout.service
