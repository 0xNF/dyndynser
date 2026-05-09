#!/bin/bash
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
ARCH="${1:-amd64}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PACKAGE="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "${REPO_ROOT}/Cargo.toml" | head -1)"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "${REPO_ROOT}/Cargo.toml" | head -1)"
BINARY="${REPO_ROOT}/target/release/${PACKAGE}"
OUTPUT_DIR="${REPO_ROOT}/packaging"
OUTPUT="${OUTPUT_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb"
# ─────────────────────────────────────────────────────────────────────────────

# ── Preflight ─────────────────────────────────────────────────────────────────
if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR: Release binary not found at ${BINARY}" >&2
    echo "       Run 'cargo build --release' first." >&2
    exit 1
fi
# ─────────────────────────────────────────────────────────────────────────────

STAGING="$(mktemp -d -t "${PACKAGE}.XXXXXX")"
cleanup() { rm -rf "${STAGING}"; }
trap cleanup EXIT

echo "[1/8] Creating staging layout"
# Use 'install -d -m' instead of mkdir to guarantee 0755 regardless of umask.
# This prevents the W: non-standard-dir-perm lintian warning.
install -d -m 0755 "${STAGING}/DEBIAN"
install -d -m 0755 "${STAGING}/usr/bin"
install -d -m 0755 "${STAGING}/usr/share/doc/${PACKAGE}"
install -d -m 0755 "${STAGING}/usr/share/man/man1"
install -d -m 0755 "${STAGING}/etc/${PACKAGE}"
# ↑ 0755 here; postinst will chown root:dyndynser + chmod 770 after install

echo "[2/8] Installing binary"
install -m 0755 "${BINARY}" "${STAGING}/usr/bin/${PACKAGE}"

echo "[3/8] Installing documentation"
# Substitute version in changelog before compressing
sed "s/^${PACKAGE} ([^)]*)/&/" "${SCRIPT_DIR}/changelog" \
    | sed "1s/([^)]*)/(${VERSION})/" \
    | gzip -9 --no-name \
    > "${STAGING}/usr/share/doc/${PACKAGE}/changelog.gz"
chmod 0644 "${STAGING}/usr/share/doc/${PACKAGE}/changelog.gz"

install -m 0644 "${SCRIPT_DIR}/copyright" \
    "${STAGING}/usr/share/doc/${PACKAGE}/copyright"

echo "[4/8] Installing man page"
# Substitute version in the .TH header
sed "s/\"${PACKAGE} [^\"]*\"/\"${PACKAGE} ${VERSION}\"/" "${SCRIPT_DIR}/${PACKAGE}.1" \
    | gzip -9 --no-name \
    > "${STAGING}/usr/share/man/man1/${PACKAGE}.1.gz"
chmod 0644 "${STAGING}/usr/share/man/man1/${PACKAGE}.1.gz"

echo "[5/8] Writing control file"
INSTALLED_SIZE=$(du -sk "${STAGING}" | cut -f1)
sed -e "s/^Version: .*/Version: ${VERSION}/" \
    -e "s/^Architecture: .*/Architecture: ${ARCH}/" \
    "${SCRIPT_DIR}/control" > "${STAGING}/DEBIAN/control"
printf "Installed-Size: %s\n" "${INSTALLED_SIZE}" >> "${STAGING}/DEBIAN/control"

echo "[6/8] Installing maintainer scripts"
install -m 0755 "${SCRIPT_DIR}/postinst" "${STAGING}/DEBIAN/postinst"
install -m 0755 "${SCRIPT_DIR}/prerm"    "${STAGING}/DEBIAN/prerm"
install -m 0755 "${SCRIPT_DIR}/postrm"   "${STAGING}/DEBIAN/postrm"

echo "[7/8] Building package → ${OUTPUT}"
dpkg-deb --build --root-owner-group "${STAGING}" "${OUTPUT}"

echo ""
dpkg-deb --info "${OUTPUT}"

echo "[8/8] Linting package"
if command -v lintian &>/dev/null; then
    lintian "${OUTPUT}" || true
else
    echo "NOTICE: lintian is not installed — full package linting was skipped." >&2
    echo "        Install it with: sudo apt install lintian" >&2
fi

echo ""
echo "Built: ${OUTPUT}"
