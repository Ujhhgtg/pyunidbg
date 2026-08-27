#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
jar_dir="$project_dir/src/pyunidbg/_vendor/jars"
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

classpath=$(find "$jar_dir" -maxdepth 1 -name '*.jar' ! -name 'pyunidbg-bridge.jar' -printf '%p:' | sed 's/:$//')
javac --release 17 -cp "$classpath" -d "$build_dir" "$project_dir"/java/io/pyunidbg/bridge/*.java
jar --create --date=1980-01-01T00:00:02Z --file "$jar_dir/pyunidbg-bridge.jar" -C "$build_dir" .
sha256sum "$jar_dir/pyunidbg-bridge.jar"
