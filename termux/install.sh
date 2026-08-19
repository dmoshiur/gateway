#!/data/data/com.termux/files/usr/bin/bash
# =============================================================================
# MFS Gateway — Termux listener installer
# Run inside Termux on the phone that receives the MFS payment SMS:
#     bash install.sh
# =============================================================================
set -euo pipefail

echo "==> Updating Termux packages"
pkg update -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

echo "==> Installing python + termux-api"
pkg install -y python termux-api

LISTENER_DIR="$HOME/.mfs_gateway"
mkdir -p "$LISTENER_DIR"

echo "==> Installing listener to $LISTENER_DIR/termux_listener.py"
cp "$(dirname "$0")/termux_listener.py" "$LISTENER_DIR/termux_listener.py"
chmod 700 "$LISTENER_DIR"

# --- interactive config -----------------------------------------------------
if [ ! -f "$LISTENER_DIR/config.json" ]; then
    echo
    read -rp "Gateway base URL (e.g. https://pay.yourdomain.com): " SERVER_URL
    read -rp "Device ID (Admin panel -> Devices -> Register): "    DEVICE_ID
    read -rp "Device Secret: "                                     DEVICE_SECRET
    cat > "$LISTENER_DIR/config.json" <<EOF
{
  "server_url": "${SERVER_URL%/}",
  "device_id": "$DEVICE_ID",
  "device_secret": "$DEVICE_SECRET",
  "interval_seconds": 10,
  "source": "sms"
}
EOF
    chmod 600 "$LISTENER_DIR/config.json"
    echo "==> Config written (chmod 600)."
else
    echo "==> Existing config found, keeping it."
fi

# --- boot persistence (optional, needs Termux:Boot app) ---------------------
BOOT_DIR="$HOME/.termux/boot"
if [ -d "$HOME/.termux" ]; then
    mkdir -p "$BOOT_DIR"
    cat > "$BOOT_DIR/mfs-listener.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
nohup python "$HOME/.mfs_gateway/termux_listener.py" >> "$HOME/.mfs_gateway/listener.log" 2>&1 &
EOF
    chmod +x "$BOOT_DIR/mfs-listener.sh"
    echo "==> Boot hook installed at $BOOT_DIR/mfs-listener.sh (requires Termux:Boot app)."
fi

echo
echo "======================================================================"
echo " DONE. Permissions checklist on the phone:"
echo "   1. Install the 'Termux:API' companion app from F-Droid/GitHub."
echo "   2. Android Settings -> Apps -> Termux:API -> Permissions -> SMS: ALLOW"
echo "   3. Android Settings -> Battery -> Termux: set to 'Unrestricted'"
echo "      (prevents Android from killing the listener)."
echo
echo " Start listening now with:"
echo "     termux-wake-lock"
echo "     python $LISTENER_DIR/termux_listener.py"
echo
echo " Quick regex sanity check (no network):"
echo "     python $LISTENER_DIR/termux_listener.py --test \\"
echo "       'You have received Tk 1,500.00 from 01712345678. TrxID 9HK8A2X1LM'"
echo "======================================================================"
