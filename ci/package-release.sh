#!/usr/bin/env bash
set -euo pipefail
ghidra=${1:?usage: package-release.sh GHIDRA_DIR OUTPUT_DIR [GRADLE_OPTIONS...]}
output=${2:?specify a new output directory}
shift 2
cd "$(dirname "$0")/.."
version=$(sed -n 's/^releaseVersion=//p' gradle.properties)
sdk=$(sed -n 's/^application.version=//p' "$ghidra/Ghidra/application.properties")
mkdir -p "$output"
test -z "$(ls -A "$output")"
./gradlew --no-daemon "$@" check :cli:distZip -ProcksdbPlatform=linux64
./gradlew --no-daemon "$@" -PghidraInstallDir="$ghidra" -ProcksdbPlatform=linux64 packageExtensions
cp "qualcomm/dist/VnaolteFirmware-$version-ghidra-$sdk.zip" "$output/"
for platform in linux64 win64 osx; do
  if [[ "$platform" != linux64 ]]; then
    ./gradlew --no-daemon "$@" -PghidraInstallDir="$ghidra" -ProcksdbPlatform="$platform" :mtk-mddb-tools:packageExtension :cli:distZip -x :mtk-mddb-tools:test -x :core:test -x :cli:test
  fi
  cp "mediatek/dist/mtk-mddb-tools-$version-ghidra-$sdk-$platform.zip" \
    "cli/build/distributions/mtk-mddb-cli-$platform-$version.zip" "$output/"
done
for archive in "$output"/*.zip; do
  unzip -tq "$archive"
  members=$(unzip -Z1 "$archive")
  for notice in LICENSE LICENSE-MIT LICENSE-APACHE THIRD-PARTY-NOTICES.md; do
    rg -q "^[^/]+/$notice$" <<<"$members"
  done
  case "$(basename "$archive")" in
    VnaolteFirmware-*) if rg -q 'rocksdbjni' <<<"$members"; then exit 1; fi ;;
    *-linux64*|*-win64*|*-osx*)
      platform=$(basename "$archive" | sed -E 's/.*-(linux64|win64|osx)(-.*)?\.zip/\1/')
      rocks=$(rg '/lib/rocksdbjni-.*\.jar$' <<<"$members")
      [[ "$rocks" == *"-$platform.jar" && "$rocks" != *$'\n'* ]]
      ;;
    *) exit 1 ;;
  esac
done
(cd "$output" && sha256sum -- *.zip > SHA256SUMS && sha256sum -c SHA256SUMS)
test "$(find "$output" -maxdepth 1 -name '*.zip' | wc -l)" -eq 7
