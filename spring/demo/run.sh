#!/usr/bin/env bash
# Usage:
#   ./run.sh            — transport-level auth (no Spring Security)
#   ./run.sh security   — Spring Security filter-chain auth
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ADAPTER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SDK_DIR="$(cd "$ADAPTER_DIR/../core" && pwd)"
REPO_DIR="$(cd "$ADAPTER_DIR/.." && pwd)"

PROFILE="${1:-transport}"

if [[ "$PROFILE" == "transport" ]]; then
  echo "==> Running in transport mode. Use './run.sh security' for Spring Security mode."
else
  echo "==> Running in security mode. Use './run.sh' for transport mode."
fi

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
mvn -f "$SDK_DIR/pom.xml" install -DskipTests -Djacoco.skip=true -Dcheckstyle.skip=true -q

echo "==> Installing Authplane Spring adapter to local Maven repo..."
mvn -f "$ADAPTER_DIR/pom.xml" install -DskipTests -Djacoco.skip=true -Dcheckstyle.skip=true -q

echo "==> Starting MathServer (profile: $PROFILE) on http://localhost:8080/mcp ..."
cd "$SCRIPT_DIR"
# SsrfSafeFetcher pins DNS and sets the Host header explicitly; the JDK HttpClient
# blocks that "restricted" header unless this property is set (see core/docs/user-guide.md).
mvn spring-boot:run -P"$PROFILE" \
  -Dspring-boot.run.jvmArguments="-Djdk.httpclient.allowRestrictedHeaders=host"
