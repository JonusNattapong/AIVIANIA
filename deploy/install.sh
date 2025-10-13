#!/usr/bin/env bash
# Install helper: copies binary, config, systemd unit and NGINX config.
# Supports simple systemd/sysv detection and can produce a minimal .deb package.
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

echo "Detected init system: $(/sbin/init --version 2>/dev/null || true)"

sudo mkdir -p "$INSTALL_DIR"
sudo cp "$BINARY_PATH" "$INSTALL_DIR/aiviania"
sudo mkdir -p /etc/aiviania
sudo cp config.yml /etc/aiviania/config.yml || true

if command -v systemctl >/dev/null 2>&1; then
  echo "Installing systemd unit"
  sudo cp "$ENV_FILE" /etc/default/aiviania
  sudo cp "$SERVICE_FILE" /etc/systemd/system/aiviania.service
  sudo systemctl daemon-reload
  sudo systemctl enable --now aiviania
else
  echo "Systemd not detected; attempting legacy init script placement"
  # Fallback: create a simple init.d script
  sudo tee /etc/init.d/aiviania >/dev/null <<'EOF'
#!/bin/sh
# /etc/init.d/aiviania - simple sysv init script
case "$1" in
  start)
    echo "Starting aiviania"
    nohup /opt/aiviania/aiviania --config /etc/aiviania/config.yml >/var/log/aiviania/aiviania.log 2>&1 &
    ;;
  stop)
    echo "Stopping aiviania"
    pkill -f /opt/aiviania/aiviania || true
    ;;
  restart)
    $0 stop || true
    $0 start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac
EOF
  sudo chmod +x /etc/init.d/aiviania
fi

if [ -f "$NGINX_CONF" ]; then
  sudo cp "$NGINX_CONF" /etc/nginx/sites-available/aiviania.conf
  sudo ln -sf /etc/nginx/sites-available/aiviania.conf /etc/nginx/sites-enabled/aiviania.conf
  sudo systemctl restart nginx || true
fi

sudo mkdir -p /var/log/aiviania
sudo cp "$LOGROTATE" /etc/logrotate.d/aiviania

echo "Installed aiviania to $INSTALL_DIR"

if [ "${1:-}" = "--package" ]; then
  echo "Building minimal .deb package"
  PKGDIR=package_deb
  rm -rf "$PKGDIR"
  mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/opt/aiviania"
  cp "$BINARY_PATH" "$PKGDIR/opt/aiviania/aiviania"
  cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: aiviania
Version: 0.1.0
Section: web
Priority: optional
Architecture: amd64
Maintainer: AIVIANIA <dev@aiviania.example>
Description: AIVIANIA Rust web framework
EOF
  dpkg-deb --build "$PKGDIR" aiviania_0.1.0_amd64.deb
  echo "Built aiviania_0.1.0_amd64.deb"
fi

echo "Done."
