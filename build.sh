#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
API_LEVEL="${API_LEVEL:-31}"

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
        rm -rf "${OUT_DIR}" "${SCRIPT_DIR}/target"
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

# 1. Compile via Cargo
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

# 2. Prepare output layout
log_info "Assembling output package in ${OUT_DIR}..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/vendor/bin/hw"
mkdir -p "$OUT_DIR/vendor/etc/init"
mkdir -p "$OUT_DIR/vendor/etc/vintf/manifest"

# 3. Copy files and enforce standard permissions
cp -f "$BIN" "$OUT_DIR/vendor/bin/hw/android.hardware.biometrics.fingerprint-service.transsion"
chmod 0755 "$OUT_DIR/vendor/bin/hw/android.hardware.biometrics.fingerprint-service.transsion"

cp -f "${SCRIPT_DIR}/android.hardware.biometrics.fingerprint-service.transsion.rc" "$OUT_DIR/vendor/etc/init/"
chmod 0644 "$OUT_DIR/vendor/etc/init/android.hardware.biometrics.fingerprint-service.transsion.rc"

cp -f "${SCRIPT_DIR}/manifest_fingerprint_transsion.xml" "$OUT_DIR/vendor/etc/vintf/manifest/"
chmod 0644 "$OUT_DIR/vendor/etc/vintf/manifest/manifest_fingerprint_transsion.xml"

# Automatically mask and disable obsolete legacy HIDL HAL services and manifests
echo '<manifest version="1.0" type="device"/>' > "$OUT_DIR/vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint@2.1-service-mediatek.xml"
echo '<manifest version="1.0" type="device"/>' > "$OUT_DIR/vendor/etc/vintf/manifest/android.hardware.biometrics.fingerprint@2.3-service.transsion.xml"
echo '<manifest version="1.0" type="device"/>' > "$OUT_DIR/vendor/etc/vintf/manifest/manifest_fingerprint.xml"
chmod 0644 "$OUT_DIR/vendor/etc/vintf/manifest/"*.xml

echo "# Disabled in favor of AIDL Fingerprint HAL" > "$OUT_DIR/vendor/etc/init/android.hardware.biometrics.fingerprint@2.1-service-mediatek.rc"
echo "# Disabled in favor of AIDL Fingerprint HAL" > "$OUT_DIR/vendor/etc/init/android.hardware.biometrics.fingerprint@2.3-service.transsion.rc"
chmod 0644 "$OUT_DIR/vendor/etc/init/"*.rc

# 4. Copy utility scripts to out
cp -f "${SCRIPT_DIR}/patch_libgf_hal.py" "$OUT_DIR/" 2>/dev/null || true

# 6. Package archives
log_info "Packaging distribution archives..."
tar -czf "${OUT_DIR}/transsion-vendor-fod-package.tar.gz" -C "${OUT_DIR}" vendor

if command -v zip &>/dev/null; then
    (cd "${OUT_DIR}" && zip -rq "transsion-vendor-fod-package.zip" vendor patch_*.py 2>/dev/null || zip -rq "transsion-vendor-fod-package.zip" vendor)
else
    python3 -c '
import zipfile, os
os.chdir("'"${OUT_DIR}"'")
with zipfile.ZipFile("transsion-vendor-fod-package.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk("vendor"):
        for f in files:
            z.write(os.path.join(root, f))
    for f in ["patch_libgf_hal.py"]:
        if os.path.exists(f):
            z.write(f)
'
fi

echo ""
log_success "Build completed successfully!"
echo -e "${BOLD}Output Files (${OUT_DIR}):${NC}"
ls -lh "${OUT_DIR}" | grep -E '\.(tar\.gz|zip)$' || true
echo ""
echo -e "${BOLD}Vendor Files Structure:${NC}"
find "${OUT_DIR}/vendor" -type f -exec ls -lh {} +
