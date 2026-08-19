#!/data/data/com.termux/files/usr/bin/bash
# ---------------------------------------------------------------------------
# Termux setup for the MFS Gateway SMS listener.
# Run on the Android device inside Termux:
#     bash install.sh
# ---------------------------------------------------------------------------
set -e

echo "==> Updating Termux packages"
pkg update -y && pkg upgrade -y

echo "==> Installing dependencies"
pkg install -y python termux-api openssh 2>/dev/null || true
pip install requests

echo "==> Setting up Termux:Boot autostart (optional, needs Termux:Boot app)"
BOOT_DIR="$HOME/.termux/boot"
mkdir -p "$BOOT_DIR"
cat > "$BOOT_DIR/start-mfs-listener" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
cd "$HOME/mfs-gateway/termux" 2>/dev/null || cd "$HOME"
python "$HOME/mfs-gateway/termux/termux_listener.py" >> "$HOME/.mfs-gateway-listener.log" 2>&1 &
EOF
chmod +x "$BOOT_DIR/start-mfs-listener"

echo
echo "==> Done. Next steps:"
echo "    1. Copy the listener:  scp -r termux_listener.py config.example.json \\"
echo "                            <phone-ip>:\$HOME/mfs-gateway/termux/"
echo "    2. cd ~/mfs-gateway/termux && cp config.example.json config.json"
echo "    3. Edit config.json: set backend_url, device_id, device_secret"
echo "       (get device_id/device_secret from the gateway admin panel)"
echo "    4. python termux_listener.py --once   # test one poll"
echo "    5. python termux_listener.py          # run continuously"
echo
echo "    Grant SMS permission when Termux:API prompts (termux-sms-list)."
