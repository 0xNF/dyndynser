#!/bin/bash
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
PACKAGE="dyndynser"
VERSION="1.1.0"
ARCH="amd64"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BINARY="${REPO_ROOT}/target/release/${PACKAGE}"
OUTPUT_DIR="${REPO_ROOT}/packaging"
OUTPUT="${OUTPUT_DIR}/${PACKAGE}_${VERSION}_${ARCH}.deb"
# ─────────────────────────────────────────────────────────────────────────────

STAGING="$(mktemp -d -t "${PACKAGE}.XXXXXX")"
cleanup() { rm -rf "${STAGING}"; }
trap cleanup EXIT

echo "[1/7] Creating staging layout"
# Use 'install -d -m' instead of mkdir to guarantee 0755 regardless of umask.
# This prevents the W: non-standard-dir-perm lintian warning.
install -d -m 0755 "${STAGING}/DEBIAN"
install -d -m 0755 "${STAGING}/usr/bin"
install -d -m 0755 "${STAGING}/usr/share/doc/${PACKAGE}"
install -d -m 0755 "${STAGING}/usr/share/man/man1"
install -d -m 0755 "${STAGING}/etc/${PACKAGE}"
# ↑ 0755 here; postinst will chown root:dyndynser + chmod 770 after install

echo "[2/7] Installing binary"
install -m 0755 "${BINARY}" "${STAGING}/usr/bin/${PACKAGE}"

echo "[3/7] Installing documentation"
gzip -9 --no-name -c "${SCRIPT_DIR}/changelog" \
    > "${STAGING}/usr/share/doc/${PACKAGE}/changelog.gz"
chmod 0644 "${STAGING}/usr/share/doc/${PACKAGE}/changelog.gz"   # ← add

install -m 0644 "${SCRIPT_DIR}/copyright" \
    "${STAGING}/usr/share/doc/${PACKAGE}/copyright"

echo "[4/7] Installing man page"
gzip -9 --no-name -c "${SCRIPT_DIR}/${PACKAGE}.1" \
    > "${STAGING}/usr/share/man/man1/${PACKAGE}.1.gz"
chmod 0644 "${STAGING}/usr/share/man/man1/${PACKAGE}.1.gz"      # ← add

echo "[5/7] Writing control file"
INSTALLED_SIZE=$(du -sk "${STAGING}" | cut -f1)
cat "${SCRIPT_DIR}/control" > "${STAGING}/DEBIAN/control"
printf "Installed-Size: %s\n" "${INSTALLED_SIZE}" >> "${STAGING}/DEBIAN/control"

echo "[6/7] Installing maintainer scripts"
install -m 0755 "${SCRIPT_DIR}/postinst" "${STAGING}/DEBIAN/postinst"
install -m 0755 "${SCRIPT_DIR}/prerm"    "${STAGING}/DEBIAN/prerm"
install -m 0755 "${SCRIPT_DIR}/postrm"   "${STAGING}/DEBIAN/postrm"

echo "[7/7] Building package → ${OUTPUT}"
dpkg-deb --build --root-owner-group "${STAGING}" "${OUTPUT}"

echo ""
dpkg-deb --info "${OUTPUT}"
echo ""
echo "✓  Built: ${OUTPUT}"