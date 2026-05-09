#!/system/bin/sh

# Standalone Scene connect-probe hiding script.
# Keep this separate from the eBPF loader; it is packaged into service.d.

SCRIPT_DIR=${0%/*}
case "$SCRIPT_DIR" in
    */service.d) MODDIR=${SCRIPT_DIR%/service.d} ;;
    *) MODDIR="$SCRIPT_DIR" ;;
esac

PKG_NAME="com.omarea.vtools"
PORTS="8765 8788"
LOG_FILE="$MODDIR/hide_scene.log"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SceneHidePort] $1" >> "$LOG_FILE"
    echo "[SceneHidePort] $1" > /dev/kmsg
}

> "$LOG_FILE"
chmod 666 "$LOG_FILE" 2>/dev/null

log_msg "Waiting for system boot completion..."
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 2
done

log_msg "System booted. Extracting UID for $PKG_NAME..."
SCENE_UID=$(stat -c %u /data/data/$PKG_NAME 2>/dev/null)
if [ -z "$SCENE_UID" ] || ! echo "$SCENE_UID" | grep -qE '^[0-9]+$'; then
    SCENE_UID=$(cmd package list packages -U | grep "package:$PKG_NAME" | grep -oE 'uid:[0-9]+' | head -n 1 | cut -d':' -f2)
fi
if [ -z "$SCENE_UID" ] || ! echo "$SCENE_UID" | grep -qE '^[0-9]+$'; then
    SCENE_UID=$(dumpsys package $PKG_NAME | grep -E '^ *userId=[0-9]+' | head -n 1 | awk -F'=' '{print $2}' | awk '{print $1}')
fi

if [ -z "$SCENE_UID" ] || ! echo "$SCENE_UID" | grep -qE '^[0-9]+$'; then
    log_msg "Failed to get a valid UID for $PKG_NAME. Got: '$SCENE_UID'. Is the app installed? Exiting."
    exit 1
fi

log_msg "Successfully extracted valid UID: $SCENE_UID. Applying iptables rules..."

for PORT in $PORTS; do
    for cmd in iptables ip6tables; do
        for iface in "-o lo " ""; do
            while $cmd -D OUTPUT ${iface}-p tcp --dport $PORT -m owner --uid-owner 0 -j ACCEPT 2>/dev/null; do :; done
            while $cmd -D OUTPUT ${iface}-p tcp --dport $PORT -m owner --uid-owner 2000 -j ACCEPT 2>/dev/null; do :; done
            while $cmd -D OUTPUT ${iface}-p tcp --dport $PORT -m owner --uid-owner $SCENE_UID -j ACCEPT 2>/dev/null; do :; done
            while $cmd -D OUTPUT ${iface}-p tcp --dport $PORT -j REJECT --reject-with tcp-reset 2>/dev/null; do :; done
        done
    done
done

for PORT in $PORTS; do
    for cmd in iptables ip6tables; do
        $cmd -I OUTPUT 1 -p tcp --dport $PORT -j REJECT --reject-with tcp-reset
        $cmd -I OUTPUT 1 -p tcp --dport $PORT -m owner --uid-owner $SCENE_UID -j ACCEPT
        $cmd -I OUTPUT 1 -p tcp --dport $PORT -m owner --uid-owner 2000 -j ACCEPT
        $cmd -I OUTPUT 1 -p tcp --dport $PORT -m owner --uid-owner 0 -j ACCEPT
    done
done

log_msg "Port hiding applied successfully. Ports $PORTS are blocked for unauthorized apps across all interfaces."
