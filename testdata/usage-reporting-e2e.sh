#!/usr/bin/env bash
# End-to-end test of usage reporting against a real Yivi Portal.
#
# Starts the Portal from a yivi-portal checkout and the irmago test image on one Docker network,
# then: creates the account key with `yivi irma server usage-key`, registers it in the Portal, runs IRMA
# sessions with the irmago wallet against a production-mode server (TestUsageReportingE2E), starts
# and stops the `irma server` binary itself, and checks what the Portal stored.
#
# Usage: testdata/usage-reporting-e2e.sh <path to yivi-portal checkout>
set -euo pipefail

# pwd -W gives the Windows path Docker Desktop expects under Git Bash; plain pwd elsewhere.
PORTAL_DIR=$(cd "${1:?usage: $0 <path to yivi-portal checkout>}" && (pwd -W 2>/dev/null || pwd))
IRMAGO_DIR=$(cd "$(dirname "$0")/.." && (pwd -W 2>/dev/null || pwd))
NET=usage-e2e
PORTAL=usage-e2e-portal
IRMAGO=usage-e2e-irmago
DIRECTORY=http://portal:8000/usage/v1/directory
export MSYS_NO_PATHCONV=1 # keep container paths intact under Git Bash on Windows

cleanup() {
  docker rm -f "$PORTAL" "$IRMAGO" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" >/dev/null

echo "== Building images"
docker build -q -f "$PORTAL_DIR/Dockerfile.django.dev" -t usage-e2e-portal "$PORTAL_DIR" >/dev/null
docker build -q -f "$IRMAGO_DIR/Dockerfile.test" -t usage-e2e-irmago "$IRMAGO_DIR" >/dev/null

echo "== Starting the Portal with a fresh database and organization 'e2e'"
docker run -d --name "$PORTAL" --network "$NET" --network-alias portal \
  --env-file "$PORTAL_DIR/.env.testing" -e DJANGO_ALLOWED_HOSTS=portal,localhost \
  usage-e2e-portal sh -c '
    python manage.py migrate --noinput >/dev/null &&
    python manage.py shell -c "from portal_backend.models.models import Organization; Organization.objects.create(name_en=\"E2E\", name_nl=\"E2E\", slug=\"e2e\")" &&
    python manage.py runserver 0.0.0.0:8000' >/dev/null

docker run -d --name "$IRMAGO" --network "$NET" -v "$IRMAGO_DIR:/src" -w /src \
  -v irmago-gomod:/go/pkg/mod -v irmago-gocache:/root/.cache/go-build \
  usage-e2e-irmago sleep infinity >/dev/null

for _ in $(seq 60); do
  if docker exec "$PORTAL" python -c "import urllib.request; urllib.request.urlopen('$DIRECTORY')" 2>/dev/null; then
    break
  fi
  sleep 1
done

echo "== Creating the account key with the irma CLI and registering it in the Portal"
docker exec "$IRMAGO" go build -o /tmp/yivi ./yivi
PUBLIC_KEY=$(docker exec "$IRMAGO" /tmp/yivi irma server usage-key --usage-reporting-state-dir /state)
echo "$PUBLIC_KEY"
echo "$PUBLIC_KEY" | docker exec -i "$PORTAL" sh -c 'cat > /tmp/key.pem && python manage.py register_usage_key e2e /tmp/key.pem --label e2e'

echo "== Running IRMA sessions against a production-mode server that reports to the Portal"
docker exec -e USAGE_E2E_PORTAL_URL="$DIRECTORY" -e USAGE_E2E_STATE_DIR=/state "$IRMAGO" \
  go test ./internal/sessiontest/ -run '^TestUsageReportingE2E$' -count=1 -v | grep -E '^(=== RUN|--- |ok|FAIL|PASS)'

echo "== Starting and stopping the irma server binary"
docker exec "$IRMAGO" sh -c "
  /tmp/yivi irma server --production --no-tls --no-auth --url http://localhost:8088 \
    --schemes-path testdata/irma_configuration --schemes-update 0 \
    --usage-reporting-portal-url $DIRECTORY --usage-reporting-state-dir /state \
    --usage-reporting-server-instance e2e-cli > /tmp/server.log 2>&1 &
  pid=\$!
  for i in \$(seq 30); do grep -q 'is registered in the Yivi Portal' /tmp/server.log && break; sleep 1; done
  kill -TERM \$pid; wait \$pid || true
  grep -E 'is registered in the Yivi Portal|Sent usage report' /tmp/server.log"

echo "== Checking what the Portal stored"
docker exec -i "$PORTAL" python manage.py shell <<'EOF'
from django.db.models import Sum
from portal_backend.models.models import Organization, UsageDisclosureCount, UsageReport, UsageSessionCount
from portal_backend.services.usage import find_gaps

org = Organization.objects.get(slug="e2e")
reports = UsageReport.objects.filter(server_key__organization=org)

sessiontest = reports.filter(server_instance="e2e-sessiontest").order_by("sequence")
assert sessiontest.count() >= 2, f"expected a delta and a final report, got {sessiontest.count()}"
assert [r.sequence for r in sessiontest] == list(range(1, sessiontest.count() + 1)), "sequence has a gap"
assert sessiontest.last().final, "the last report of the run is not final"

def disclosed(action):
    return UsageDisclosureCount.objects.filter(
        report__in=sessiontest, requestor="requestor1", action=action,
        credential_type="irma-demo.RU.studentCard", outcome="done",
    ).aggregate(n=Sum("count"))["n"]

assert disclosed("disclosing") == 2, f"disclosing: {disclosed('disclosing')}"
assert disclosed("signing") == 1, f"signing: {disclosed('signing')}"
sessions = UsageSessionCount.objects.filter(report__in=sessiontest, outcome="done").aggregate(n=Sum("count"))["n"]
assert sessions == 3, f"sessions: {sessions}"

cli = reports.filter(server_instance="e2e-cli")
assert cli.filter(final=True).count() == 1, "the irma server binary sent no final report on SIGTERM"

assert find_gaps(reports) == [], f"unexpected gaps: {find_gaps(reports)}"
print(f"OK: {reports.count()} reports stored; 2 disclosures and 1 signature of irma-demo.RU.studentCard "
      f"counted for requestor1 over {sessiontest.count()} reports; the CLI server closed its run; no gaps")
EOF
