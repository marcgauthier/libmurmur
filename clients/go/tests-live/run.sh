#!/usr/bin/env bash
# Live libmurmur multi-node scenario checks: hybrid harness (in-process driver
# nodes + tests-live/node child binary nodes).
# Port agents NEVER run this (single-package skip-gated `go test` only); it is
# the CI/operator runner. Each scenario is a standalone Go test package and
# runs alone.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
gomod="$root/clients/go"
live="$gomod/tests-live"
scenario=${1:-all}
if [[ "${MURMUR_ENGINE_INTEGRATION:-}" != "1" ]]; then
  echo "Live scenarios are opt-in. Set MURMUR_ENGINE_INTEGRATION=1 to run the real-engine scenarios." >&2
  exit 1
fi

runtime_root=${MURMUR_LIVE_RUNTIME:-"$live/runtime"}
started_at=$SECONDS

echo "======================================================================"
echo "  LIBMURMUR GO CLIENT / LIVE SCENARIO RUNNER"
echo "======================================================================"

# Native library prerequisites: build libmurmur.a so the go bindings link.
if [[ ! -f "$root/libmurmur.a" ]]; then
  echo "Building libmurmur.a..."
  (cd "$root" && make -j"$(nproc 2>/dev/null || echo 4)")
fi

# Managed profiles use their own child and controlled original-record
# delivery. They do not depend on the legacy network driver's binary.
case "$scenario" in
  managed|managed-profiles|managed-durability)
    managed_count=${MURMUR_MANAGED_TEST_COUNT:-1}
    if [[ ! "$managed_count" =~ ^[1-9][0-9]*$ ]]; then
      echo "MURMUR_MANAGED_TEST_COUNT must be a positive integer" >&2
      exit 1
    fi
    managed_packages=("./tests-live/managed-profiles/" "./tests-live/managed-durability/")
    if [[ "$scenario" != managed ]]; then
      managed_packages=("./tests-live/$scenario/")
    fi
    (cd "$gomod" && CGO_ENABLED=1 \
      CGO_CXXFLAGS="${CGO_CXXFLAGS:-} -DMURMUR_TEST_LIBRARY_REV=$(stat -c %Y "$root/libmurmur.a")" \
      go test -race -count="$managed_count" -timeout 20m "${managed_packages[@]}")
    exit 0
    ;;
esac

# Reap node processes rooted at OUR runtime dir on the way out (Ctrl-C,
# inter-scenario kills, CI cancel). Scoped by the --root path so parallel
# runs with their own MURMUR_LIVE_RUNTIME roots are never touched. No-op on
# clean runs (in-test cleanup already reaped everything).
sweep_runtime_servers() {
  local pids
  pids=$(pgrep -f "tests-live/node.*$runtime_root" 2>/dev/null || true)
  if [[ -z "$pids" ]]; then
    return 0
  fi
  # shellcheck disable=SC2086
  kill -TERM $pids 2>/dev/null || true
  sleep 2
  pids=$(pgrep -f "tests-live/node.*$runtime_root" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    kill -KILL $pids 2>/dev/null || true
  fi
}
trap sweep_runtime_servers EXIT INT TERM

if [[ -z "${MURMUR_NODE_BIN:-}" ]]; then
  echo "Building tests-live node binary..."
  mkdir -p "$gomod/bin"
  (cd "$gomod" && CGO_ENABLED=1 go build -o bin/tests-live-node ./tests-live/node)
  export MURMUR_NODE_BIN="$gomod/bin/tests-live-node"
fi
if [[ ! -x "$MURMUR_NODE_BIN" ]]; then
  echo "MURMUR_NODE_BIN is not executable: $MURMUR_NODE_BIN" >&2
  exit 1
fi

scenario_timeout_secs() {
  # Per-scenario caps for the `timeout(1)` wrapper (also passed to go test).
  case "$1" in
    endurance-chaos) echo "273600" ;;       # 76h
    soak-slo) echo "10800" ;;               # 3h
    long-running-five-node) echo "4500" ;;  # 75m
    files-soak|compression) echo "900" ;;   # 15m
    allow-nodes) echo "480" ;;              # 8m
    crash-recovery|chaos-load) echo "600" ;;  # 10m
    snapshot-resync) echo "1200" ;;             # 20m (3 sequential GC-wait legs)
    abuse) echo "1800" ;;                   # 30m
    resource-exhaustion) echo "1500" ;;     # 25m
    *) echo "600" ;;                        # 10m
  esac
}

run_scenario() {
  local scn=$1
  local go_tests=( "$live/$scn"/*_test.go )
  if [[ ! -f "${go_tests[0]}" ]]; then
    echo ""
    echo ">>> MISSING LIVE SCENARIO: $scn" >&2
    return 1
  fi
  if [[ "$scn" == "downgrade-guard" && -z "${MURMUR_FORMAT_FIXTURE_BIN:-}" ]]; then
    echo "downgrade-guard needs MURMUR_FORMAT_FIXTURE_BIN set to the engine-owned future-format injector test binary; refusing to run without it." >&2
    return 1
  fi
  echo ""
  echo ">>> RUNNING LIVE SCENARIO: $scn"
  ( cd "$gomod" && CGO_ENABLED=1 timeout -s TERM "$(scenario_timeout_secs "$scn")s" \
    go test -count=1 -timeout "$(scenario_timeout_secs "$scn")s" "./tests-live/$scn/" )
  echo ">>> SCENARIO COMPLETED: $scn"
}

ALL_SCENARIOS="three-node-sync partition chaos-load flap-partition three-way-heal tail-repair partial-mesh swim-discovery plumtree-live scale-mesh long-running-five-node txchunk-resume corrupt-snapshot large-payload crdt-contention typed-records typed-bridge bridge-two-streams merge-policies delete-pruning views schema-evolution migration-concurrency migration-crash clock-skew crash-recovery crash-loop rejoin-storm rolling-restart graceful-shutdown pause-resume churn-retirement snapshot-resync open-progress compression gc-balance log-boundedness maintenance-under-load overload-budgets loadshare write-priority soak-slo api-mtls tls-floor cert-lifecycle allow-nodes addrpolicy dbid-isolation version-skew unlock-abuse hostile-peer hostile-schema encryption plaintext-audit rekey file-permissions backup-restore backup-under-fire tampered-backup downgrade-guard files-bridge files-soak files-crash files-corrupt-source fetch-restart highlow origin-signatures abuse endurance-chaos resource-exhaustion dos-client diskfull-live impaired-network sqli-api search-mesh snaprejoin"

# Release-gate subset (excludes downgrade-guard, which needs an externally
# built injector binary). Missing scenario packages fail the run.
GATE_SCENARIOS="merge-policies origin-signatures open-progress api-mtls three-node-sync typed-records typed-bridge views rekey encryption backup-restore partition version-skew schema-evolution highlow files-bridge files-soak scale-mesh loadshare pause-resume partial-mesh rolling-restart snapshot-resync gc-balance crash-recovery migration-crash chaos-load graceful-shutdown tampered-backup files-crash file-permissions plaintext-audit unlock-abuse rejoin-storm migration-concurrency sqli-api crash-loop swim-discovery txchunk-resume hostile-peer hostile-schema tail-repair three-way-heal flap-partition delete-pruning corrupt-snapshot backup-under-fire bridge-two-streams tls-floor dbid-isolation cert-lifecycle files-corrupt-source maintenance-under-load search-mesh"

case "$scenario" in
  all)
    for scn in $ALL_SCENARIOS; do
      run_scenario "$scn"
    done
    ;;
  gate)
    for scn in $GATE_SCENARIOS; do
      run_scenario "$scn"
    done
    ;;
  soak)
    MURMUR_FILES_SOAK_DURATION_SECONDS=${MURMUR_FILES_SOAK_DURATION_SECONDS:-600} \
    MURMUR_FILES_SOAK_INTERVAL_SECONDS=${MURMUR_FILES_SOAK_INTERVAL_SECONDS:-60} \
      run_scenario "files-soak"
    MURMUR_SLO_DURATION_SECONDS=${MURMUR_SLO_DURATION_SECONDS:-7200} \
    MURMUR_SLO_SETTLE_SECONDS=${MURMUR_SLO_SETTLE_SECONDS:-300} \
      run_scenario "soak-slo"
    MURMUR_FIVE_NODE_DURATION_SECONDS=${MURMUR_FIVE_NODE_DURATION_SECONDS:-3600} \
    MURMUR_FIVE_NODE_SETTLE_SECONDS=${MURMUR_FIVE_NODE_SETTLE_SECONDS:-300} \
      run_scenario "long-running-five-node"
    ;;
  stress)
    stress_count=${MURMUR_STRESS_COUNT:-5}
    for scn in rolling-restart partial-mesh crash-recovery partition snapshot-resync; do
      echo ""
      echo ">>> STRESS $scn x$stress_count"
      for ((i = 1; i <= stress_count; i++)); do
        run_scenario "$scn"
      done
    done
    ;;
  *)
    if [[ " $ALL_SCENARIOS " == *" $scenario "* ]]; then
      run_scenario "$scenario"
    else
      echo "Unknown scenario: $scenario" >&2
      echo "Available scenarios: $ALL_SCENARIOS all gate soak stress managed managed-profiles managed-durability" >&2
      exit 1
    fi
    ;;
esac

echo ""
echo "======================================================================"
echo "  ALL REQUESTED LIVE SCENARIOS PASSED (Elapsed: $((SECONDS - started_at))s)"
echo "======================================================================"
