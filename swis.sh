#!/usr/bin/env bash
set -euo pipefail

SWIS_TOOL="${SWIS_TOOL:-all}"          # trivy|grype|kics|sbom|all
SWIS_IMAGE="${SWIS_IMAGE:-}"
SWIS_PATH="${SWIS_PATH:-.}"
SWIS_IAC_PATH="${SWIS_IAC_PATH:-.}"
SWIS_PROFILE="${SWIS_PROFILE:-balanced}"   # strict|balanced|lenient
SWIS_OUTPUT="${SWIS_OUTPUT:-table}"        # table|json|sarif
SWIS_SBOM_FORMAT="${SWIS_SBOM_FORMAT:-spdx-json}" # for syft

case "$SWIS_PROFILE" in
  strict)
    SWIS_SEVERITY="HIGH,CRITICAL"
    SWIS_IGNORE_UNFIXED="false"
    ;;
  balanced)
    SWIS_SEVERITY="MEDIUM,HIGH,CRITICAL"
    SWIS_IGNORE_UNFIXED="true"
    ;;
  lenient)
    SWIS_SEVERITY="LOW,MEDIUM,HIGH,CRITICAL"
    SWIS_IGNORE_UNFIXED="true"
    ;;
  *)
    echo "[swis] Unknown profile: $SWIS_PROFILE"
    exit 1
    ;;
esac

format_flag() {
  case "$SWIS_OUTPUT" in
    json) echo "--format json" ;;
    sarif) echo "--format sarif" ;;
    table) echo "" ;;
    *) echo "" ;;
  esac
}

EXIT_CODE=0

run_trivy_image() {
  trivy image \
    --severity "$SWIS_SEVERITY" \
    $( [[ "$SWIS_IGNORE_UNFIXED" == "true" ]] && echo "--ignore-unfixed" ) \
    $(format_flag) \
    --exit-code 1 \
    "$SWIS_IMAGE" || EXIT_CODE=$?
}

run_trivy_fs() {
  trivy fs \
    --severity "$SWIS_SEVERITY" \
    $( [[ "$SWIS_IGNORE_UNFIXED" == "true" ]] && echo "--ignore-unfixed" ) \
    $(format_flag) \
    --exit-code 1 \
    "$SWIS_PATH" || EXIT_CODE=$?
}

run_grype_image() {
  grype "$SWIS_IMAGE" \
    $(format_flag) \
    --fail-on "$(echo "$SWIS_SEVERITY" | cut -d',' -f1 | tr '[:upper:]' '[:lower:]')" \
    || EXIT_CODE=$?
}

run_kics() {
  kics scan \
    -p "$SWIS_IAC_PATH" \
    --no-progress \
    $( [[ "$SWIS_OUTPUT" == "json" ]] && echo "--report-formats json" ) \
    $( [[ "$SWIS_OUTPUT" == "sarif" ]] && echo "--report-formats sarif" ) \
    || EXIT_CODE=$?
}

run_sbom() {
  if [[ -z "$SWIS_IMAGE" ]]; then
    echo "[swis] SWIS_IMAGE required for SBOM"
    EXIT_CODE=1
    return
  fi
  syft "$SWIS_IMAGE" -o "$SWIS_SBOM_FORMAT" || EXIT_CODE=$?
}

case "$SWIS_TOOL" in
  trivy)
    [[ -n "$SWIS_IMAGE" ]] && run_trivy_image || run_trivy_fs
    ;;
  grype)
    run_grype_image
    ;;
  kics)
    run_kics
    ;;
  sbom)
    run_sbom
    ;;
  all)
    [[ -n "$SWIS_IMAGE" ]] && run_trivy_image || run_trivy_fs
    run_grype_image
    run_kics
    run_sbom
    ;;
  *)
    echo "[swis] Unknown SWIS_TOOL: $SWIS_TOOL"
    EXIT_CODE=1
    ;;
esac

exit "$EXIT_CODE"
