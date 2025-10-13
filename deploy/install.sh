#!/usr/bin/env bash
# Simple install script to copy binary, config, and systemd files (posix systems)
set -euo pipefail

BINARY_PATH=target/release/aiviania
INSTALL_DIR=/opt/aiviania
SERVICE_FILE=deploy/systemd/aiviania.service
ENV_FILE=deploy/systemd/aiviania.env
NGINX_CONF=deploy/nginx/aiviania.conf
LOGROTATE=deploy/logrotate/aiviania

if [ ! -f "$BINARY_PATH" ]; then
  echo "Release binary not found. Build first: cargo build --release"
  exit 1
fi

sudo mkdir -p "$INSTALL_DIR"
sudo cp "$BINARY_PATH" "$INSTALL_DIR/aiviania"
sudo mkdir -p /etc/aiviania
sudo cp config.yml /etc/aiviania/config.yml || true
sudo cp "$ENV_FILE" /etc/default/aiviania
sudo cp "$SERVICE_FILE" /etc/systemd/system/aiviania.service
sudo cp "$NGINX_CONF" /etc/nginx/sites-available/aiviania.conf
sudo ln -sf /etc/nginx/sites-available/aiviania.conf /etc/nginx/sites-enabled/aiviania.conf
sudo cp "$LOGROTATE" /etc/logrotate.d/aiviania

sudo systemctl daemon-reload
sudo systemctl enable --now aiviania
sudo systemctl restart nginx || true

echo "Installed and started aiviania service"
