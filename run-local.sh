#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-5500}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "Gecersiz port: $PORT"
  echo "Kullanim: ./run-local.sh [port]"
  exit 1
fi

cd "$ROOT_DIR"

echo "Web uygulamasi baslatiliyor: http://127.0.0.1:$PORT"
echo "Durdurmak icin Ctrl+C"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet bulunamadi. .NET 8 SDK kurulu olmali."
  exit 1
fi

ASPNETCORE_URLS="http://127.0.0.1:$PORT" exec dotnet run --no-launch-profile
