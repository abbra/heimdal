#!/bin/bash
#
# Build Heimdal with Rust PKINIT and run integration tests.
#
# This script performs the complete build-and-test cycle:
#   1. Install build dependencies (Fedora/RHEL)
#   2. Build the Rust pkinit-core adapter (cargo build --release)
#   3. Run pkinit-core's own test suite
#   4. Bootstrap Heimdal's autotools
#   5. Configure Heimdal with --enable-pkinit-rust
#   6. Build Heimdal
#   7. Run the PKINIT integration tests
#
# Usage:
#   ./build-and-test.sh [options]
#
# Options:
#   --skip-deps       Skip system dependency installation
#   --skip-rust       Skip Rust library build (use existing)
#   --skip-heimdal    Skip Heimdal build (use existing install)
#   --prefix PATH     Heimdal install prefix (default: /tmp/heimdal-pkinit-test)
#   --mit-prefix PATH MIT krb5 prefix for cross-tests (optional)
#   --verbose         Show full build and test output
#   --jobs N          Parallel make jobs (default: nproc)
#
# Environment:
#   KURBU5_DIR        Path to kurbu5-pkinit checkout (for pkinit-core tests)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOP_SRCDIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────

PREFIX="/tmp/heimdal-pkinit-test"
MIT_PREFIX=""
SKIP_DEPS=0
SKIP_RUST=0
SKIP_HEIMDAL=0
VERBOSE=0
JOBS="$(nproc 2>/dev/null || echo 4)"
KURBU5_DIR="${KURBU5_DIR:-$(cd "$TOP_SRCDIR/../kurbu5-pkinit" 2>/dev/null && pwd || echo "")}"

# ── Parse arguments ──────────────────────────────────────────────────

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-deps)     SKIP_DEPS=1; shift ;;
        --skip-rust)     SKIP_RUST=1; shift ;;
        --skip-heimdal)  SKIP_HEIMDAL=1; shift ;;
        --prefix)        PREFIX="$2"; shift 2 ;;
        --prefix=*)      PREFIX="${1#*=}"; shift ;;
        --mit-prefix)    MIT_PREFIX="$2"; shift 2 ;;
        --mit-prefix=*)  MIT_PREFIX="${1#*=}"; shift ;;
        --verbose)       VERBOSE=1; shift ;;
        --jobs)          JOBS="$2"; shift 2 ;;
        --jobs=*)        JOBS="${1#*=}"; shift ;;
        -h|--help)
            awk '/^#!/{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (use --help)"
            exit 1
            ;;
    esac
done

BUILDDIR="$TOP_SRCDIR/build-pkinit-rust"

# ── Helpers ──────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

step() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
}

run_quiet() {
    local logfile="$1"; shift
    if [ "$VERBOSE" = "1" ]; then
        "$@" 2>&1 | tee "$logfile"
    else
        "$@" > "$logfile" 2>&1
    fi
}

check_result() {
    local desc="$1"
    local rc="$2"
    if [ "$rc" -eq 0 ]; then
        echo "  ✓ $desc"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $desc"
        FAIL=$((FAIL + 1))
    fi
}

# ── Step 1: Dependencies ─────────────────────────────────────────────

step "Step 1: Build dependencies"

if [ "$SKIP_DEPS" = "1" ]; then
    echo "  (skipped)"
    SKIP=$((SKIP + 1))
else
    NEEDED_RPMS=(
        autoconf automake libtool bison flex texinfo
        openssl-devel ncurses-devel readline-devel
        libdb-devel e2fsprogs-devel json-c-devel
        heimdal-devel
    )

    if command -v dnf > /dev/null 2>&1; then
        echo "  Installing via dnf..."
        rc=0
        run_quiet "$BUILDDIR/deps.log" \
            sudo dnf install -y "${NEEDED_RPMS[@]}" || rc=$?
        check_result "system dependencies installed" $rc
    elif command -v apt-get > /dev/null 2>&1; then
        echo "  Installing via apt-get..."
        NEEDED_DEBS=(
            autoconf automake libtool bison flex texinfo
            libssl-dev libncurses-dev libreadline-dev
            libdb-dev libsqlite3-dev libjson-c-dev
        )
        rc=0
        run_quiet "$BUILDDIR/deps.log" \
            sudo apt-get install -y "${NEEDED_DEBS[@]}" || rc=$?
        check_result "system dependencies installed" $rc
    else
        echo "  WARNING: Unknown package manager — install dependencies manually"
        SKIP=$((SKIP + 1))
    fi

    # Verify Rust toolchain
    if ! command -v cargo > /dev/null 2>&1; then
        echo "  ERROR: Rust toolchain (cargo) not found"
        echo "  Install from https://rustup.rs/"
        exit 1
    fi
    RUST_VER="$(rustc --version 2>/dev/null || echo "unknown")"
    echo "  Rust: $RUST_VER"
fi

# ── Step 2: Build Rust library ───────────────────────────────────────

step "Step 2: Build Rust PKINIT adapter"

mkdir -p "$BUILDDIR"

if [ "$SKIP_RUST" = "1" ]; then
    echo "  (skipped)"
    SKIP=$((SKIP + 1))
else
    echo "  Building rust/heimdal-pkinit (release)..."
    rc=0
    run_quiet "$BUILDDIR/cargo-build.log" \
        cargo build --release --manifest-path="$TOP_SRCDIR/rust/Cargo.toml" || rc=$?
    check_result "cargo build --release" $rc

    if [ $rc -ne 0 ]; then
        echo "  Build log: $BUILDDIR/cargo-build.log"
        tail -20 "$BUILDDIR/cargo-build.log"
        exit 1
    fi

    # Verify the static library
    RUST_LIB="$TOP_SRCDIR/rust/target/release/libheimdal_pkinit.a"
    if [ -f "$RUST_LIB" ]; then
        NSYMS=$(nm "$RUST_LIB" 2>/dev/null | grep -c " T heimdal_pkinit_" || echo 0)
        check_result "libheimdal_pkinit.a: $NSYMS FFI symbols" 0
    else
        check_result "libheimdal_pkinit.a exists" 1
        exit 1
    fi
fi

# ── Step 3: pkinit-core tests ────────────────────────────────────────

step "Step 3: Run pkinit-core tests"

if [ -n "$KURBU5_DIR" ] && [ -f "$KURBU5_DIR/Cargo.toml" ]; then
    echo "  Running cargo test in $KURBU5_DIR..."
    rc=0
    run_quiet "$BUILDDIR/pkinit-core-test.log" \
        cargo test --workspace --manifest-path="$KURBU5_DIR/Cargo.toml" || rc=$?
    if [ $rc -eq 0 ]; then
        NTESTS=$(grep -c "^test .* ok$" "$BUILDDIR/pkinit-core-test.log" 2>/dev/null || echo "?")
        check_result "pkinit-core tests ($NTESTS passed)" 0
    else
        check_result "pkinit-core tests" 1
        echo "  Log: $BUILDDIR/pkinit-core-test.log"
        tail -10 "$BUILDDIR/pkinit-core-test.log"
    fi
else
    echo "  SKIP: kurbu5-pkinit not found (set KURBU5_DIR)"
    SKIP=$((SKIP + 1))
fi

# ── Step 4: Bootstrap Heimdal autotools ──────────────────────────────

step "Step 4: Bootstrap Heimdal autotools"

if [ "$SKIP_HEIMDAL" = "1" ]; then
    echo "  (skipped)"
    SKIP=$((SKIP + 1))
else
    echo "  Running autoreconf -fi..."
    rc=0
    (cd "$TOP_SRCDIR" && run_quiet "$BUILDDIR/autoreconf.log" autoreconf -fi) || rc=$?
    check_result "autoreconf" $rc
    if [ $rc -ne 0 ]; then
        echo "  Log: $BUILDDIR/autoreconf.log"
        tail -20 "$BUILDDIR/autoreconf.log"
        exit 1
    fi
fi

# ── Step 5: Configure Heimdal ────────────────────────────────────────

step "Step 5: Configure Heimdal (--enable-pkinit-rust)"

if [ "$SKIP_HEIMDAL" = "1" ]; then
    echo "  (skipped)"
    SKIP=$((SKIP + 1))
else
    mkdir -p "$BUILDDIR"
    echo "  Build dir: $BUILDDIR"
    echo "  Prefix: $PREFIX"
    rc=0
    (cd "$BUILDDIR" && run_quiet "$BUILDDIR/configure.log" \
        "$TOP_SRCDIR/configure" \
            --prefix="$PREFIX" \
            --enable-pkinit-rust \
            --with-openssl \
            ) || rc=$?
    check_result "configure" $rc
    if [ $rc -ne 0 ]; then
        echo "  Log: $BUILDDIR/configure.log"
        tail -30 "$BUILDDIR/configure.log"
        exit 1
    fi

    # Verify PKINIT_RUST was picked up
    if grep -q "PKINIT_RUST_TRUE=''" "$BUILDDIR/Makefile" 2>/dev/null || \
       grep -q "PKINIT_RUST" "$BUILDDIR/config.log" 2>/dev/null; then
        check_result "PKINIT_RUST enabled in config" 0
    else
        echo "  WARNING: PKINIT_RUST may not be active — check config.log"
    fi
fi

# ── Step 6: Build Heimdal ────────────────────────────────────────────

step "Step 6: Build Heimdal"

if [ "$SKIP_HEIMDAL" = "1" ]; then
    echo "  (skipped)"
    SKIP=$((SKIP + 1))
else
    echo "  make -j$JOBS ..."
    rc=0
    (cd "$BUILDDIR" && run_quiet "$BUILDDIR/make.log" make -j"$JOBS") || rc=$?
    check_result "make" $rc
    if [ $rc -ne 0 ]; then
        echo "  Build log tail:"
        tail -30 "$BUILDDIR/make.log"
        exit 1
    fi

    echo "  make install ..."
    rc=0
    (cd "$BUILDDIR" && run_quiet "$BUILDDIR/make-install.log" make install) || rc=$?
    check_result "make install → $PREFIX" $rc
    if [ $rc -ne 0 ]; then
        tail -20 "$BUILDDIR/make-install.log"
        exit 1
    fi

    # Verify key binaries exist
    for bin in kinit kadmin; do
        found=0
        for dir in bin sbin libexec; do
            if [ -x "$PREFIX/$dir/$bin" ]; then
                check_result "$PREFIX/$dir/$bin exists" 0
                found=1
                break
            fi
        done
        [ "$found" -eq 0 ] && check_result "$bin not found" 1
    done
    # KDC is special — may be in libexec
    if [ -x "$PREFIX/libexec/kdc" ] || [ -x "$PREFIX/sbin/kdc" ]; then
        check_result "kdc binary exists" 0
    else
        check_result "kdc binary exists" 1
    fi
fi

# ── Step 7: Integration tests ────────────────────────────────────────

step "Step 7: Integration tests"

HEIMDAL_PREFIX="$PREFIX"
if [ "$SKIP_HEIMDAL" = "1" ] && [ -n "${HEIMDAL_PREFIX:-}" ]; then
    echo "  Using existing install: $HEIMDAL_PREFIX"
fi

if [ ! -x "$HEIMDAL_PREFIX/sbin/kdc" ] && [ ! -x "$HEIMDAL_PREFIX/libexec/kdc" ]; then
    echo "  ERROR: KDC binary not found at $HEIMDAL_PREFIX"
    echo "  Cannot run integration tests without a working Heimdal install"
    FAIL=$((FAIL + 1))
else
    MIT_ARG=()
    if [ -n "$MIT_PREFIX" ]; then
        MIT_ARG=(--mit-prefix="$MIT_PREFIX")
    fi

    rc=0
    HEIMDAL_PREFIX="$HEIMDAL_PREFIX" \
    VERBOSE="${VERBOSE}" \
        "$SCRIPT_DIR/check-pkinit-rust.sh" "${MIT_ARG[@]}" || rc=$?

    check_result "check-pkinit-rust.sh" $rc
fi

# ── Summary ──────────────────────────────────────────────────────────

step "Summary"

echo ""
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
echo ""
echo "  Build directory:   $BUILDDIR"
echo "  Install prefix:    $PREFIX"
echo "  Rust library:      $TOP_SRCDIR/rust/target/release/libheimdal_pkinit.a"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "  ✗ SOME TESTS FAILED"
    echo ""
    echo "  Logs:"
    ls -1 "$BUILDDIR"/*.log 2>/dev/null | sed 's/^/    /' || true
    exit 1
else
    echo "  ✓ ALL TESTS PASSED"
    exit 0
fi
