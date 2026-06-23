#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ADAPTER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SDK_DIR="$(cd "$ADAPTER_DIR/../core" && pwd)"
REPO_DIR="$(cd "$ADAPTER_DIR/.." && pwd)"

# Demo defaults — override by setting the variable in your shell before running.
export ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
export RESOURCE_URL="${RESOURCE_URL:-http://localhost:8080/mcp}"
if [[ -z "${CLIENT_ID:-}" && -f /tmp/authserver-demo.client-id ]]; then
  export CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
fi
if [[ -z "${CLIENT_SECRET:-}" && -f /tmp/authserver-demo.key ]]; then
  export CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"
fi

echo "==> Installing Authplane parent POM to local Maven repo..."
mvn -f "$REPO_DIR/pom.xml" install -N -DskipTests -Djacoco.skip=true -q

echo "==> Installing Authplane SDK to local Maven repo..."
mvn -f "$SDK_DIR/pom.xml" install -DskipTests -Djacoco.skip=true -q

echo "==> Installing Authplane MCP adapter to local Maven repo..."
mvn -f "$ADAPTER_DIR/pom.xml" install -DskipTests -Djacoco.skip=true -q

echo "==> Starting MathServer on http://localhost:8080/mcp ..."
cd "$SCRIPT_DIR"
mvn compile exec:exec@run
