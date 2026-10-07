#!/usr/bin/env bash
# Build the release archives from a Linux host.
#
# Produces:
#   bluecli-<VERSION>-linux-x64.tar.gz      (always)
#   bluecli-<VERSION>-windows-x64.zip       (when Windows binaries are present
#                                           under bin/ — they always are in
#                                           this repo, so by default both are
#                                           built)
#
# Both archives are source-mode: the launcher script inside creates a Python
# venv on first run. End user needs Python 3.10-3.14 on PATH and nothing else.

set -euo pipefail

cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.."

VERSION=$(grep -oE '__version__\s*=\s*"[^"]+"' src/bluecli/__init__.py | grep -oE '"[^"]+"' | tr -d '"')
[ -z "$VERSION" ] && { echo "ERROR: could not read __version__"; exit 1; }
echo "Building BlueCLI v$VERSION"

# Sanity-check: required Linux binaries must be present.
for f in bin/wireguard/wg bin/wireguard/wg-quick bin/v2ray/v2ray bin/v2ray/tun2socks \
         bin/v2ray/geoip.dat bin/v2ray/geosite.dat \
         bin/amneziawg/amneziawg-go bin/amneziawg/awg \
         bin/xray/xray bin/hysteria2/hysteria; do
    [ -f "$f" ] || { echo "ERROR: missing required Linux binary: $f"; exit 1; }
done

# --- Linux archive --------------------------------------------------------
PKG_LINUX=bluecli-linux-x64
rm -rf "$PKG_LINUX"
mkdir "$PKG_LINUX"

cp -r src wheels wheelhouse_src "$PKG_LINUX/"
cp pyproject.toml bluecli.sh cleanup.sh LICENSE "$PKG_LINUX/"

mkdir -p "$PKG_LINUX/bin/wireguard" "$PKG_LINUX/bin/v2ray" "$PKG_LINUX/bin/amneziawg" \
         "$PKG_LINUX/bin/xray" "$PKG_LINUX/bin/hysteria2"
cp bin/wireguard/wg bin/wireguard/wg-quick "$PKG_LINUX/bin/wireguard/"
cp bin/v2ray/v2ray bin/v2ray/tun2socks "$PKG_LINUX/bin/v2ray/"
cp bin/v2ray/geoip.dat bin/v2ray/geosite.dat "$PKG_LINUX/bin/v2ray/"
cp bin/amneziawg/amneziawg-go bin/amneziawg/awg "$PKG_LINUX/bin/amneziawg/"
cp bin/xray/xray bin/xray/LICENSE "$PKG_LINUX/bin/xray/"
cp bin/hysteria2/hysteria bin/hysteria2/LICENSE "$PKG_LINUX/bin/hysteria2/"

cat > "$PKG_LINUX/README.txt" << READMEEOF
BlueCLI v$VERSION  --  Sentinel dVPN client (Linux x86-64)
============================================================

Requirements
------------
  - Python 3.10-3.14 (most Linux distros have it preinstalled;
    if not: 'sudo apt install python3' or your distro's equivalent)
  - sudo
  - That's it. WireGuard tools, v2ray, tun2socks, the AmneziaWG
    userspace engine, Xray, and Hysteria2 are bundled.

Quick start
-----------
  ./bluecli.sh

On first run the launcher sets up a local Python virtual environment
inside this folder (takes ~30 seconds, only once). Launches after that
are instant.

To remove everything
--------------------
  ./cleanup.sh   (wipes the venv and your wallet/sessions data)
  cd .. && rm -rf bluecli-linux-x64

Documentation & issues:
  https://github.com/YOUR-ORG/bluecli
READMEEOF

chmod +x "$PKG_LINUX/bluecli.sh" "$PKG_LINUX/cleanup.sh"
chmod +x "$PKG_LINUX/bin/wireguard/wg" "$PKG_LINUX/bin/wireguard/wg-quick"
chmod +x "$PKG_LINUX/bin/v2ray/v2ray" "$PKG_LINUX/bin/v2ray/tun2socks"
chmod +x "$PKG_LINUX/bin/amneziawg/amneziawg-go" "$PKG_LINUX/bin/amneziawg/awg"
chmod +x "$PKG_LINUX/bin/xray/xray" "$PKG_LINUX/bin/hysteria2/hysteria"

ARCHIVE_LINUX="bluecli-${VERSION}-linux-x64.tar.gz"
rm -f "$ARCHIVE_LINUX"
tar czf "$ARCHIVE_LINUX" "$PKG_LINUX"
sha256sum "$ARCHIVE_LINUX" | tee "${ARCHIVE_LINUX}.sha256"
echo "✓ $ARCHIVE_LINUX  ($(du -h "$ARCHIVE_LINUX" | cut -f1))"
echo

# --- Windows archive (built from Linux — just file copies + zip) ----------
WIN_BINS_PRESENT=true
for f in bin/wireguard/wireguard.exe bin/v2ray/v2ray.exe bin/v2ray/tun2socks.exe \
         bin/v2ray/wintun.dll bin/v2ray/geoip.dat bin/v2ray/geosite.dat \
         bin/amneziawg/amneziawg.exe bin/xray/xray.exe bin/hysteria2/hysteria.exe; do
    [ -f "$f" ] || WIN_BINS_PRESENT=false
done

if [ "$WIN_BINS_PRESENT" = "true" ]; then
    PKG_WIN=bluecli-windows-x64
    rm -rf "$PKG_WIN"
    mkdir "$PKG_WIN"

    cp -r src wheels wheelhouse_src "$PKG_WIN/"
    cp pyproject.toml bluecli.bat cleanup.bat LICENSE "$PKG_WIN/"

    mkdir -p "$PKG_WIN/bin/wireguard" "$PKG_WIN/bin/v2ray" "$PKG_WIN/bin/amneziawg" \
             "$PKG_WIN/bin/xray" "$PKG_WIN/bin/hysteria2"
    cp bin/wireguard/wireguard.exe "$PKG_WIN/bin/wireguard/"
    cp bin/v2ray/v2ray.exe bin/v2ray/tun2socks.exe "$PKG_WIN/bin/v2ray/"
    cp bin/v2ray/wintun.dll bin/v2ray/geoip.dat bin/v2ray/geosite.dat "$PKG_WIN/bin/v2ray/"
    cp bin/amneziawg/amneziawg.exe "$PKG_WIN/bin/amneziawg/"
    cp bin/xray/xray.exe bin/xray/LICENSE "$PKG_WIN/bin/xray/"
    cp bin/hysteria2/hysteria.exe bin/hysteria2/LICENSE "$PKG_WIN/bin/hysteria2/"

    cat > "$PKG_WIN/README.txt" << READMEEOF
BlueCLI v$VERSION  --  Sentinel dVPN client (Windows x86-64)
============================================================

Requirements
------------
  - Python 3.10-3.14 (install from https://www.python.org/,
    tick "Add Python to PATH" during setup)
  - Administrator rights (the launcher requests them automatically)
  - That's it. WireGuard, v2ray, tun2socks, wintun, the AmneziaWG
    client, Xray, and Hysteria2 are bundled.

Quick start
-----------
  Double-click bluecli.bat

On first run the launcher sets up a local Python virtual environment
inside this folder (takes ~60 seconds, only once). Launches after that
are instant.

To remove everything
--------------------
  Double-click cleanup.bat (wipes the venv and your wallet/sessions data)
  Then delete this folder.

Documentation & issues:
  https://github.com/YOUR-ORG/bluecli
READMEEOF

    ARCHIVE_WIN="bluecli-${VERSION}-windows-x64.zip"
    rm -f "$ARCHIVE_WIN"
    # zip with -X = no extra file metadata, -r = recurse
    (cd . && zip -qrX "$ARCHIVE_WIN" "$PKG_WIN")
    sha256sum "$ARCHIVE_WIN" | tee "${ARCHIVE_WIN}.sha256"
    echo "✓ $ARCHIVE_WIN  ($(du -h "$ARCHIVE_WIN" | cut -f1))"
else
    echo "Skipped Windows archive (some .exe / .dll binaries missing under bin/)."
fi

echo
echo "Done."
echo "Cleanup intermediate dirs:  rm -rf bluecli-linux-x64 bluecli-windows-x64"
