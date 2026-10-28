#!/usr/bin/env bash
set -euo pipefail

zip_path=${1:?usage: run-packed-regression.sh EXTENSION.zip}
fixture_root=${VNAOLTE_FIXTURE_ROOT:-/srv/ci/vnaolte-fixtures}
qcom_loaders=${VNAOLTE_QCOM_LOADERS:-$fixture_root/QualcommLoaders}
ghidra=${GHIDRA_INSTALL_DIR:?GHIDRA_INSTALL_DIR must point at Ghidra 12.2}
analyze="$ghidra/support/analyzeHeadless"
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
script_dir="$repo_root/ghidra/VnaolteFirmware/ghidra_scripts"

[[ -x "$analyze" ]] || { echo "missing analyzeHeadless: $analyze" >&2; exit 1; }
[[ -f "$zip_path" ]] || { echo "missing extension package: $zip_path" >&2; exit 1; }
[[ -f "$qcom_loaders/lib/QualcommLoaders.jar" ]] || {
  echo "missing QualcommLoaders fixture dependency: $qcom_loaders" >&2
  exit 1
}

expect_hash() {
  local expected=$1 path=$2 actual
  [[ -f "$path" ]] || { echo "missing fixture: $path" >&2; exit 1; }
  actual=$(sha256sum "$path" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || {
    echo "fixture hash mismatch: $path" >&2
    echo "  expected $expected" >&2
    echo "  actual   $actual" >&2
    exit 1
  }
}

# Pin the exact fixture generation and the split segments that exercise each
# packed representation. The importer will load all sibling .bNN files.
expect_hash 94d3d18eaca50c854753dfaeafb4c17cbeacd51483ef6798eef28d8d545c1a5b "$fixture_root/em7455/modem.mdt"
expect_hash c666b00730573ce4f818645462e726aa0ea7740b0ee1f08430749a8708011c53 "$fixture_root/em7455/modem.b17"
expect_hash f959f7516285f30e372f90c750b39a24fd7406f3c597d714b210619a4de42227 "$fixture_root/em7455/modem.b18"
expect_hash ea7eccd655405a77d1937bab83d16e30c578de6c7daeeb1d205cb3c418357b00 "$fixture_root/eg25/modem.mdt"
expect_hash 45c44272dd1be9e72cbb284c08e6262a6406c95ab7a7f32b40f37fcd24159110 "$fixture_root/eg25/modem.b18"
expect_hash ca7fadeb7258c0bcf13cf7afa7c2a9e7ca50a5c83f004293a43be2bd335b8ebf "$fixture_root/eg25/modem.b19"
expect_hash e372ca9cdab4dfa929521684e7998ec2fe8a85d0c00f4bd07cea982e136c6ffc "$fixture_root/rm500q/modem.mdt"
expect_hash db0c5ed5cd06b5c9de7f57b4124b95a49064fe534f76a2208f006d678b9b25e4 "$fixture_root/rm500q/modem.b24"
expect_hash 08242266407bc1b01bddd7db838540632740969c46fa7d65dafc9616547363e4 "$fixture_root/rm500q/modem.b25"
expect_hash 2864ee9b96f5303ba359fb8fb918e51503be657bc4a8510dd51be71b1ac8685e "$fixture_root/ln920/modem.mdt"
expect_hash f6c7f16133226bb355aa23e5299787a838b35954d79184605119a34afd8da149 "$fixture_root/ln920/modem.b18"
expect_hash d51249b6d53311532ad04509d118129fed4f1463c3c2c327be8310c3b06876f1 "$fixture_root/ln920/modem.b19"
expect_hash fb13eaf44de0712f1d73d7221244e7301c6dce010ba31ce838915ba6dde3262f "$fixture_root/fn990/modem.mdt"
expect_hash bacb9e48a025eb9b6ecca1cc8d6b4806941c373ea7b789b9f03bf261740de5e9 "$fixture_root/fn990/modem.b24"
expect_hash 72c3ae709407081ab79ffe671ef89c97a134ad934adbc1e65784cd70870dbdd4 "$fixture_root/fn990/modem.b26"
expect_hash d2a822d2f571d318d37291ab9050bad4da0e47221fdd564f59348875d38ea7a4 "$qcom_loaders/lib/QualcommLoaders.jar"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ci_home="$work/home"
config_dir="$ci_home/.config/ghidra/$(basename "$ghidra")/Extensions"
mkdir -p "$config_dir" "$work/projects" "$work/logs"
cp -a "$qcom_loaders" "$config_dir/QualcommLoaders"
unzip -q "$zip_path" -d "$config_dir"

assert_log() {
  local log=$1 expected=$2
  grep -Fq -- "$expected" "$log" || {
    echo "missing expected regression output:" >&2
    echo "  $expected" >&2
    echo "--- tail of $log ---" >&2
    tail -200 "$log" >&2
    exit 1
  }
}

run_fixture() {
  local name=$1 mdt=$2
  shift 2
  local project_dir="$work/projects/$name" log="$work/logs/$name.log"
  mkdir -p "$project_dir"
  echo "== packed regression: $name =="
  (
    export HOME="$ci_home"
    export XDG_CONFIG_HOME="$ci_home/.config"
    export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=$ci_home"
    "$analyze" "$project_dir" "$name" \
      -import "$mdt" -noanalysis \
      -scriptPath "$script_dir" -postScript ProbeQualcommPacked.java
  ) >"$log" 2>&1
  for expected in "$@"; do
    assert_log "$log" "$expected"
  done
  grep -E 'PACKED_PROBE_SUMMARY|VNAOLTE Qualcomm (q6zip|zlib|CLADE)' "$log" | tail -12
}

run_fixture em7455 "$fixture_root/em7455/modem.mdt" \
  'dict=10/12, lookback=9, pages=3763 (3762 exact, 1 short)' \
  '48672 debug records (369 RF-interest)' \
  'PACKED_PROBE_SUMMARY q6zip_blocks=1 zlib_blocks=1 clade_bookmarks=0'

run_fixture eg25 "$fixture_root/eg25/modem.mdt" \
  'dict=10/14, lookback=8, pages=4473 (4473 exact, 0 short)' \
  '5911 debug records (39 RF-interest)' \
  'PACKED_PROBE_SUMMARY q6zip_blocks=1 zlib_blocks=1 clade_bookmarks=0'

run_fixture rm500q "$fixture_root/rm500q/modem.mdt" \
  'no new q6zip runtime blocks mapped' \
  'dense diagnostic string pool: 94644 strings, 77481 diagnostic (879 RF-interest)' \
  'compressed 0xcc4c0000..0xce891000 -> runtime 0xd4800000..0xd6bd0000' \
  'PACKED_PROBE_SUMMARY q6zip_blocks=0 zlib_blocks=1 clade_bookmarks=2'

run_fixture ln920 "$fixture_root/ln920/modem.mdt" \
  'dict=10/12, lookback=4, pages=3599 (3286 exact, 313 short)' \
  '898 debug records (0 RF-interest)' \
  'PACKED_PROBE_SUMMARY q6zip_blocks=1 zlib_blocks=1 clade_bookmarks=0'

run_fixture fn990 "$fixture_root/fn990/modem.mdt" \
  'no new q6zip runtime blocks mapped' \
  'no new Qualcomm zlib debug overlay mounted' \
  'self-described .clade.comp packed region at 0xc8890000 (size 0x274a040' \
  'runtime mapping not recovered' \
  'PACKED_PROBE_SUMMARY q6zip_blocks=0 zlib_blocks=0 clade_bookmarks=2'

echo 'five-firmware packed regression matrix OK'
