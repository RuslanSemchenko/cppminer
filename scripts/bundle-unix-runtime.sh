#!/usr/bin/env bash
set -euo pipefail

platform="${1:?usage: bundle-unix-runtime.sh linux|macos staging-dir}"
staging="${2:?usage: bundle-unix-runtime.sh linux|macos staging-dir}"
binary="$staging/bin/cppminer"
libdir="$staging/lib"
mkdir -p "$libdir"

if [[ "$platform" == "linux" ]]; then
    declare -A seen=()

    bundle_linux() {
        local file="$1"
        local dep path base
        [[ -f "$file" ]] || return 0
        while IFS= read -r dep; do
            path="$dep"
            [[ -f "$path" ]] || continue
            base="$(basename "$path")"
            case "$base" in
                linux-vdso*|ld-linux*|libc.so*|libm.so*|libpthread.so*|libdl.so*|librt.so*|libresolv.so*|libnsl.so*|libutil.so*)
                    continue
                    ;;
            esac
            [[ "${seen[$path]+yes}" == yes ]] && continue
            seen["$path"]=1
            cp -L "$path" "$libdir/$base"
            bundle_linux "$path"
        done < <(ldd "$file" | awk '/=> \/|^[[:space:]]*\// { for (i = 1; i <= NF; ++i) if ($i ~ /^\//) { print $i; break } }')
    }

    bundle_linux "$binary"
elif [[ "$platform" == "macos" ]]; then
    seen_file="$libdir/.bundled-files"
    : > "$seen_file"

    bundle_macos() {
        local file="$1"
        local dep base dest
        [[ -f "$file" ]] || return 0
        grep -Fqx "$file" "$seen_file" && return 0
        printf '%s\n' "$file" >> "$seen_file"
        while IFS= read -r dep; do
            case "$dep" in
                /usr/local/*|/opt/homebrew/*)
                    [[ -f "$dep" ]] || continue
                    base="$(basename "$dep")"
                    dest="$libdir/$base"
                    if [[ ! -e "$dest" ]]; then
                        cp -fL "$dep" "$dest"
                        install_name_tool -id "@loader_path/../lib/$base" "$dest" 2>/dev/null || true
                    fi
                    install_name_tool -change "$dep" "@loader_path/../lib/$base" "$file" 2>/dev/null || true
                    bundle_macos "$dep"
                    ;;
            esac
        done < <(otool -L "$file" | tail -n +2 | sed 's/^[[:space:]]*//' | awk '{print $1}')
    }

    bundle_macos "$binary"
    rm -f "$seen_file"
else
    echo "unsupported platform: $platform" >&2
    exit 2
fi
