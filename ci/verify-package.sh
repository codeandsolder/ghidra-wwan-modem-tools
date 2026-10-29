#!/usr/bin/env bash
set -euo pipefail

zip_path=${1:?usage: verify-package.sh EXTENSION.zip}
[[ -f "$zip_path" ]] || { echo "missing extension zip: $zip_path" >&2; exit 1; }

members=$(unzip -Z1 "$zip_path")
for required in \
  VnaolteFirmware/extension.properties \
  VnaolteFirmware/lib/VnaolteFirmware.jar \
  VnaolteFirmware/docs/PACKED_REGRESSION_MATRIX.md \
  VnaolteFirmware/docs/GCT_GDM7243_RF.md \
  VnaolteFirmware/ghidra_scripts/ProbeQualcommPacked.java \
  VnaolteFirmware/ghidra_scripts/GctRfSurvey.java \
  VnaolteFirmware/ghidra_scripts/DecompileFunctions.java \
  VnaolteFirmware/ghidra_scripts/DisassembleRanges.java \
  VnaolteFirmware/ghidra_scripts/FindAddressUses.java \
  VnaolteFirmware/ghidra_scripts/FindScalarUses.java \
  VnaolteFirmware/ghidra_scripts/DumpGctPamProfiles.java; do
  grep -Fxq "$required" <<<"$members" || {
    echo "missing package member: $required" >&2
    exit 1
  }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
unzip -p "$zip_path" VnaolteFirmware/lib/VnaolteFirmware.jar > "$work/VnaolteFirmware.jar"
jar_bin=${JAVA_HOME:+$JAVA_HOME/bin/jar}
if [[ ! -x "$jar_bin" ]]; then
  jar_bin=$(command -v jar || true)
fi
[[ -n "$jar_bin" && -x "$jar_bin" ]] || { echo "jar tool not found" >&2; exit 1; }
jar_members=$("$jar_bin" tf "$work/VnaolteFirmware.jar")
for required in \
  vnaolte/ghidra/q6zip/Q6ZipDecoder.class \
  vnaolte/ghidra/qcom/QualcommCladeMappingAnalyzer.class \
  vnaolte/ghidra/qcom/QualcommZlibDebugOverlayAnalyzer.class; do
  grep -Fxq "$required" <<<"$jar_members" || {
    echo "missing jar member: $required" >&2
    exit 1
  }
done

echo "extension package structure OK: $zip_path"
