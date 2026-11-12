#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
API_LEVEL="${API_LEVEL:-31}"
FOD_DELAY_US="${FOD_DELAY_US:-30000}"
PATCH_STRICT="${PATCH_STRICT:-0}"
PREBUILT_BIN="${PREBUILT_BIN:-}"

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

show_help() {
    cat <<EOF
Usage: $(basename "$0") [COMMAND|PROFILE]

Commands:
  release    Build optimized release binaries (default)
  debug      Build unoptimized debug binaries with debug symbols
  clean      Remove build artifacts (target/ and out/)
  help       Show this help message

Environment variables:
  ANDROID_NDK_HOME  Path to Android NDK toolchain
  API_LEVEL         Target Android API level (default: 31)
  CARGO             Path to cargo binary
  FOD_DELAY_US      Jeda pengganti uevent di libgf_hal (us, default 30000). Lebih kecil = FOD lebih responsif
  PATCH_STRICT=1    Tolak libgf_hal.so yang hash-nya belum dikenal patcher
  PREBUILT_BIN      (test) lewati cargo dan pakai biner ini
EOF
    exit 0
}

# Command dispatching
CMD="${1:-release}"
case "$CMD" in
    help|-h|--help)
        show_help
        ;;
    clean)
        log_info "Cleaning build artifacts..."
        rm -rf "${OUT_DIR}" "${SCRIPT_DIR}/target" "${SCRIPT_DIR}/libsl_fp_impl.so.patched"
        log_success "Clean completed."
        exit 0
        ;;
    release|debug)
        PROFILE="$CMD"
        ;;
    *)
        log_error "Unknown argument: '$CMD'"
        show_help
        ;;
esac

if [ -z "$PREBUILT_BIN" ]; then
# Locate Android NDK
find_ndk() {
    for var in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "${ANDROID_NDK_LATEST_HOME:-}" "${NDK_HOME:-}"; do
        if [ -n "$var" ] && [ -d "$var" ]; then
            echo "$var"
            return 0
        fi
    done

    local sdk_dirs=(
        "${ANDROID_HOME:-}"
        "${ANDROID_SDK_ROOT:-}"
        "/usr/local/lib/android/sdk"
        "$HOME/Android/Sdk"
        "$HOME/Library/Android/sdk"
        "/opt/android-sdk"
    )

    for sdk in "${sdk_dirs[@]}"; do
        if [ -n "$sdk" ] && [ -d "$sdk/ndk" ]; then
            local ndk_match
            ndk_match=$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d -name "*26*" 2>/dev/null | sort -V | tail -n1 || true)
            if [ -n "$ndk_match" ] && [ -d "$ndk_match" ]; then
                echo "$ndk_match"
                return 0
            fi
            ndk_match=$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -n1 || true)
            if [ -n "$ndk_match" ] && [ -d "$ndk_match" ]; then
                echo "$ndk_match"
                return 0
            fi
        fi
    done

    local standalone_dirs=(
        "/home/rapli/android-ndk-r26b"
        "$HOME/android-ndk-r26b"
        "$HOME/android-ndk"*
        "/opt/android-ndk"*
    )

    for c in "${standalone_dirs[@]}"; do
        if [ -d "$c" ]; then
            echo "$c"
            return 0
        fi
    done

    return 1
}

if ! ANDROID_NDK_HOME="$(find_ndk)"; then
    log_error "Android NDK not found. Please export ANDROID_NDK_HOME=/path/to/ndk"
    exit 1
fi

find_ndk_bin() {
    local ndk="$1"
    for p in "$ndk/toolchains/llvm/prebuilt/"*/bin; do
        if [ -d "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

if ! NDK_BIN="$(find_ndk_bin "$ANDROID_NDK_HOME")"; then
    log_error "Unable to locate prebuilt LLVM toolchain in $ANDROID_NDK_HOME"
    exit 1
fi

CLANG="$NDK_BIN/aarch64-linux-android${API_LEVEL}-clang"
CLANGXX="$NDK_BIN/aarch64-linux-android${API_LEVEL}-clang++"
AR="$NDK_BIN/llvm-ar"
STRIP="$NDK_BIN/llvm-strip"

if [ ! -x "$CLANG" ]; then
    log_warn "Target Clang $CLANG not found. Searching for alternative clang in $NDK_BIN..."
    CLANG_ALT=$(find "$NDK_BIN" -name "aarch64-linux-android*-clang" -executable 2>/dev/null | head -n1 || true)
    if [ -n "$CLANG_ALT" ] && [ -x "$CLANG_ALT" ]; then
        CLANG="$CLANG_ALT"
        CLANGXX="${CLANG_ALT}++"
        log_info "Fallback to: $CLANG"
    else
        log_error "Clang compiler for aarch64-linux-android not found in $NDK_BIN"
        exit 1
    fi
fi

# Export NDK cross-compilation environment
export CC_aarch64_linux_android="$CLANG"
export CXX_aarch64_linux_android="$CLANGXX"
export AR_aarch64_linux_android="$AR"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"
export RUSTFLAGS="-C link-arg=-llog"

# Locate Cargo & ensure target is installed
CARGO_BIN="${CARGO:-cargo}"
if ! command -v "$CARGO_BIN" &>/dev/null && [ -x "$HOME/.cargo/bin/cargo" ]; then
    CARGO_BIN="$HOME/.cargo/bin/cargo"
fi

if ! command -v "$CARGO_BIN" &>/dev/null; then
    log_error "Cargo not found. Please install Rust toolchain."
    exit 1
fi

RUSTUP_BIN="$(command -v rustup 2>/dev/null || echo "$HOME/.cargo/bin/rustup")"
if [ -x "$RUSTUP_BIN" ]; then
    if ! "$RUSTUP_BIN" target list --installed 2>/dev/null | grep -qx "aarch64-linux-android"; then
        log_info "Adding Rust target 'aarch64-linux-android' via rustup..."
        "$RUSTUP_BIN" target add aarch64-linux-android
    fi
fi

echo -e "${BOLD}=== Building Fingerprint AIDL Bridge for Transsion ($PROFILE, aarch64) ===${NC}"
log_info "Using NDK: $ANDROID_NDK_HOME (API $API_LEVEL)"
log_info "Using Cargo: $CARGO_BIN"

cd "$SCRIPT_DIR"

if [ "$PROFILE" = "release" ]; then
    "$CARGO_BIN" build --target aarch64-linux-android --release
    BIN="target/aarch64-linux-android/release/android-hardware-biometrics-fingerprint-service-transsion"
    if [ -x "$STRIP" ]; then
        log_info "Stripping release binary..."
        "$STRIP" "$BIN"
    elif command -v llvm-strip &>/dev/null; then
        log_info "Stripping release binary with system llvm-strip..."
        llvm-strip "$BIN"
    fi
else
    "$CARGO_BIN" build --target aarch64-linux-android
    BIN="target/aarch64-linux-android/debug/android-hardware-biometrics-fingerprint-service-transsion"
fi
else
    PROFILE="${PROFILE:-release}"
    BIN="$PREBUILT_BIN"
    log_warn "PREBUILT_BIN diset: melewati cargo/NDK ($BIN)"
    cd "$SCRIPT_DIR"
fi

log_info "Assembling output package in ${OUT_DIR}..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/vendor/bin/hw"
mkdir -p "$OUT_DIR/vendor/etc/init"
mkdir -p "$OUT_DIR/vendor/etc/vintf/manifest"

cp -f "$BIN" "$OUT_DIR/vendor/bin/hw/android.hardware.biometrics.fingerprint-service.transsion"
chmod 0755 "$OUT_DIR/vendor/bin/hw/android.hardware.biometrics.fingerprint-service.transsion"

cp -f "$BIN" "$OUT_DIR/vendor/bin/hw/android.hardware.biometrics.fingerprint-service"
chmod 0755 "$OUT_DIR/vendor/bin/hw/android.hardware.biometrics.fingerprint-service"

cp -f "${SCRIPT_DIR}/android.hardware.biometrics.fingerprint-service.transsion.rc" "$OUT_DIR/vendor/etc/init/"
chmod 0644 "$OUT_DIR/vendor/etc/init/android.hardware.biometrics.fingerprint-service.transsion.rc"

cp -f "${SCRIPT_DIR}/manifest_fingerprint_transsion.xml" "$OUT_DIR/vendor/etc/vintf/manifest/"
chmod 0644 "$OUT_DIR/vendor/etc/vintf/manifest/manifest_fingerprint_transsion.xml"

echo '<manifest version="1.0" type="device"/>' > "$OUT_DIR/vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint@2.1-service-mediatek.xml"
echo '<manifest version="1.0" type="device"/>' > "$OUT_DIR/vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint@2.3-service.transsion.xml"
echo '<manifest version="1.0" type="device"/>' > "$OUT_DIR/vendor/etc/vintf/manifest/manifest_fingerprint.xml"
chmod 0644 "$OUT_DIR/vendor/etc/vintf/manifest/"*.xml

echo "# Disabled in favor of AIDL Fingerprint HAL" > "$OUT_DIR/vendor/etc/init/android.hardware.biometrics.fingerprint@2.1-service-mediatek.rc"
echo "# Disabled in favor of AIDL Fingerprint HAL" > "$OUT_DIR/vendor/etc/init/android.hardware.biometrics.fingerprint@2.3-service.transsion.rc"
chmod 0644 "$OUT_DIR/vendor/etc/init/"*.rc

if [ -f "${SCRIPT_DIR}/libsl_fp_impl.so" ] && [ -f "${SCRIPT_DIR}/patch_libsl_fp.py" ]; then
    log_info "Generating pre-patched libsl_fp_impl.so for Camon 30 Pro (KJ7)..."
    python3 "${SCRIPT_DIR}/patch_libsl_fp.py" "${SCRIPT_DIR}/libsl_fp_impl.so"
    if [ -f "${SCRIPT_DIR}/libsl_fp_impl.so.patched" ]; then
        mkdir -p "$OUT_DIR/vendor/lib64"
        cp -f "${SCRIPT_DIR}/libsl_fp_impl.so.patched" "$OUT_DIR/vendor/lib64/libsl_fp_impl.so"
        chmod 0644 "$OUT_DIR/vendor/lib64/libsl_fp_impl.so"
        rm -f "${SCRIPT_DIR}/libsl_fp_impl.so.patched"
    fi
fi

cp -f "${SCRIPT_DIR}/patch_libgf_hal.py" "$OUT_DIR/" 2>/dev/null || true

ODM_SRC="${SCRIPT_DIR}/prebuilt"
if [ -d "$ODM_SRC" ]; then
    log_info "Assembling odm layout (delay ${FOD_DELAY_US}us)..."
    for f in lib64/libgf_hal.so lib64/hw/gf_fingerprint.default.so; do
        [ -f "$ODM_SRC/$f" ] || { log_error "prebuilt/$f tidak ada"; exit 1; }
    done
    mkdir -p "$OUT_DIR/odm/lib64/hw"

    PATCH_ARGS=(--delay-us "$FOD_DELAY_US")
    [ "$PATCH_STRICT" = "1" ] && PATCH_ARGS+=(--strict)
    python3 -I "${SCRIPT_DIR}/patch_libgf_hal.py" "$ODM_SRC/lib64/libgf_hal.so" \
        -o "$OUT_DIR/odm/lib64/libgf_hal.so" "${PATCH_ARGS[@]}"

    if cmp -s "$ODM_SRC/lib64/libgf_hal.so" "$OUT_DIR/odm/lib64/libgf_hal.so"; then
        log_error "libgf_hal.so hasil patch identik dengan aslinya"; exit 1
    fi
    python3 -I "${SCRIPT_DIR}/patch_libgf_hal.py" "$OUT_DIR/odm/lib64/libgf_hal.so" \
        --delay-us "$FOD_DELAY_US" --check | grep -q "0 instruksi akan diubah" \
        || { log_error "verifikasi ulang patch gagal"; exit 1; }

    cp -f "$ODM_SRC/lib64/hw/gf_fingerprint.default.so" "$OUT_DIR/odm/lib64/hw/"
    if [ -f "$ODM_SRC/etc/init/fingerprint-default.rc" ]; then
        mkdir -p "$OUT_DIR/odm/etc/init"
        cp -f "$ODM_SRC/etc/init/fingerprint-default.rc" "$OUT_DIR/odm/etc/init/"
    fi
    find "$OUT_DIR/odm" -type f -exec chmod 0644 {} +
else
    log_warn "prebuilt/ tidak ada; paket hanya berisi vendor/"
fi

log_info "Packaging distribution archives (vendor + odm)..."
PKG_DIRS=(vendor)
[ -d "${OUT_DIR}/odm" ] && PKG_DIRS+=(odm)

tar -czf "${OUT_DIR}/transsion-vendor-fod-package.tar.gz" -C "${OUT_DIR}" "${PKG_DIRS[@]}"

if command -v zip &>/dev/null; then
    (cd "${OUT_DIR}" && zip -rq "transsion-vendor-fod-package.zip" "${PKG_DIRS[@]}")
else
    PKG_DIRS_CSV="${PKG_DIRS[*]}" python3 -c '
import zipfile, os
os.chdir("'"${OUT_DIR}"'")
with zipfile.ZipFile("transsion-vendor-fod-package.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for d in os.environ["PKG_DIRS_CSV"].split():
        for root, _, files in os.walk(d):
            for f in files:
                z.write(os.path.join(root, f))
'
fi

echo ""
log_success "Build completed successfully!"
echo -e "${BOLD}Output Files (${OUT_DIR}):${NC}"
ls -lh "${OUT_DIR}" | grep -E '\.(tar\.gz|zip)$' || true
echo ""
echo -e "${BOLD}Package Files Structure:${NC}"
find "${OUT_DIR}/vendor" "${OUT_DIR}/odm" -type f -exec ls -lh {} + 2>/dev/null
