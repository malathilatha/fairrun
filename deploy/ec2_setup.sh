#!/usr/bin/env bash
# Run ONCE on a fresh Amazon Linux 2023 EC2 instance, from inside the fairrun folder.
# Installs Docker, builds the MOCK-ONLY demo image and starts it on port 80.
set -euo pipefail
sudo dnf install -y docker
sudo systemctl enable --now docker
sudo docker build -t fairrun-demo .
sudo docker rm -f fairrun 2>/dev/null || true
# --restart unless-stopped: comes back after a reboot. No env vars, no keys: mock mode only.
sudo docker run -d --name fairrun --restart unless-stopped -p 80:8501 fairrun-demo
echo "Done. Open: http://$(curl -s http://checkip.amazonaws.com)"
