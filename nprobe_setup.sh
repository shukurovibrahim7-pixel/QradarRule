#!/usr/bin/env bash
# =============================================================================
# nprobe_setup.sh
# QRadar Network Flow üçün Nprobe quraşdırma və konfiqurasiya skripti
# Task 15 - Network Flow bölməsinin aktivləşdirilməsi
#
# İstifadə:
#   sudo bash nprobe_setup.sh
#
# Tələblər:
#   - Ubuntu/Debian əsaslı sistem
#   - Root icazəsi
#   - QRadar Flow Collector IP-si (QRADAR_FLOW_IP dəyişəni)
# =============================================================================

set -euo pipefail

# ─── Rəng kodları ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }

# ─── Konfiqurasiya ─────────────────────────────────────────────────────────────
QRADAR_FLOW_IP="${QRADAR_FLOW_IP:-172.31.28.30}"   # QRadar Flow Collector IP
QRADAR_FLOW_PORT="${QRADAR_FLOW_PORT:-2055}"         # NetFlow/IPFIX port
LISTEN_INTERFACE="${LISTEN_INTERFACE:-eth0}"          # Dinlənəcək interfeys
NPROBE_TEMPLATE="${NPROBE_TEMPLATE:-V9}"             # NetFlow V5, V9 və ya IPFIX
NPROBE_LOG="/var/log/nprobe/nprobe.log"
NPROBE_PID="/var/run/nprobe/nprobe.pid"
NPROBE_CONF="/etc/nprobe/nprobe.conf"

# ─── Root yoxlaması ────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    log_error "Bu skript root icazəsi tələb edir. 'sudo bash $0' ilə işə salın."
    exit 1
fi

# ─── Addım 1: Sistem yeniləməsi ────────────────────────────────────────────────
log_step "1. Sistem yeniləməsi"
apt-get update -qq
apt-get install -y -qq wget curl net-tools lsb-release gnupg2
log_info "Sistem yeniləndi"

# ─── Addım 2: Nprobe PPA əlavə etmək ─────────────────────────────────────────
log_step "2. Nprobe repozitoriyası əlavə edilir"

# ntop GPG açarını əlavə et
wget -qO - https://packages.ntop.org/apt-stable/ntop.key | \
    gpg --dearmor -o /usr/share/keyrings/ntop.gpg

# Repozitoriya əlavə et
CODENAME=$(lsb_release -cs)
echo "deb [signed-by=/usr/share/keyrings/ntop.gpg] \
https://packages.ntop.org/apt-stable/${CODENAME}/ x86_64/" \
    > /etc/apt/sources.list.d/ntop.list

apt-get update -qq
log_info "Nprobe repozitoriyası əlavə edildi"

# ─── Addım 3: Nprobe quraşdırılması ────────────────────────────────────────────
log_step "3. Nprobe quraşdırılır"
apt-get install -y nprobe 2>/dev/null || {
    log_warn "APT ilə quraşdırma uğursuz oldu, .deb paketi ilə cəhd edilir..."
    NPROBE_PKG="nprobe_amd64.deb"
    wget -q "https://packages.ntop.org/apt-stable/nprobe/${NPROBE_PKG}" -O "/tmp/${NPROBE_PKG}"
    dpkg -i "/tmp/${NPROBE_PKG}"
    apt-get install -f -y -qq
}
log_info "Nprobe quraşdırıldı: $(nprobe --version 2>&1 | head -1)"

# ─── Addım 4: Konfiqurasiya faylı ─────────────────────────────────────────────
log_step "4. Nprobe konfiqurasiyası yaradılır"

mkdir -p "$(dirname "$NPROBE_CONF")"
mkdir -p "$(dirname "$NPROBE_LOG")"
mkdir -p "$(dirname "$NPROBE_PID")"

cat > "$NPROBE_CONF" <<EOF
# Nprobe Konfiqurasiya Faylı
# QRadar Network Flow üçün - Task 15
# Yaradılma tarixi: $(date '+%Y-%m-%d %H:%M:%S')

# Dinlənəcək interfeys
-i=${LISTEN_INTERFACE}

# NetFlow göndəriləcək yer (QRadar Flow Collector)
-n=${QRADAR_FLOW_IP}:${QRADAR_FLOW_PORT}

# NetFlow versiyası (V5, V9, IPFIX)
-V=${NPROBE_TEMPLATE}

# Flow keşleme intervalı (saniyə)
--lifetime-timeout=120
--idle-timeout=30

# Maksimum flow sayı
--max-num-flows=2000000

# Log faylı
--log-to-file=${NPROBE_LOG}

# PID faylı
--pid-file=${NPROBE_PID}

# Əlavə sahələr (QRadar üçün faydalı)
--collector-port=2056

# Şəbəkə statistikaları
--dump-stats=60

# DNS reverse lookup (hostname üçün)
--dont-reforge-timestamps

# Flow aggregation
--flow-version=${NPROBE_TEMPLATE}
EOF

log_info "Konfiqurasiya faylı yaradıldı: $NPROBE_CONF"

# ─── Addım 5: Interfeysi yoxla ─────────────────────────────────────────────────
log_step "5. Şəbəkə interfeysləri yoxlanılır"

echo ""
log_info "Mövcud şəbəkə interfeysləri:"
ip -br link show | grep -v lo | while read -r name state _; do
    ip_addr=$(ip -br addr show "$name" 2>/dev/null | awk '{print $3}' | head -1)
    printf "  %-15s %-10s %s\n" "$name" "$state" "${ip_addr:-IP yoxdur}"
done

if ! ip link show "$LISTEN_INTERFACE" &>/dev/null; then
    log_warn "Seçilmiş interfeys ($LISTEN_INTERFACE) mövcud deyil!"
    log_warn "Aşağıdaki interfeysdən birini LISTEN_INTERFACE dəyişəni ilə seçin:"
    ip -br link show | grep -v lo | awk '{print "  " $1}'
else
    log_info "Seçilmiş interfeys: $LISTEN_INTERFACE ✓"
fi

# ─── Addım 6: Systemd servis faylı ────────────────────────────────────────────
log_step "6. Systemd servis yaradılır"

cat > /etc/systemd/system/nprobe.service <<EOF
[Unit]
Description=Nprobe NetFlow/IPFIX Probe (QRadar Network Flow)
After=network.target
Wants=network.target

[Service]
Type=forking
User=root
ExecStart=/usr/bin/nprobe --config-file=${NPROBE_CONF}
ExecReload=/bin/kill -HUP \$MAINPID
PIDFile=${NPROBE_PID}
Restart=on-failure
RestartSec=10
StandardOutput=append:${NPROBE_LOG}
StandardError=append:${NPROBE_LOG}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nprobe
log_info "Systemd servis yaradıldı və aktivləşdirildi"

# ─── Addım 7: Nprobe-u başlat ─────────────────────────────────────────────────
log_step "7. Nprobe başladılır"

# Əvvəlki prosesi dayandır
systemctl stop nprobe 2>/dev/null || true
sleep 2

systemctl start nprobe
sleep 3

if systemctl is-active --quiet nprobe; then
    log_info "Nprobe uğurla başladıldı ✓"
    systemctl status nprobe --no-pager -l
else
    log_error "Nprobe başlamadı! Log faylını yoxlayın: $NPROBE_LOG"
    journalctl -u nprobe -n 20 --no-pager
    exit 1
fi

# ─── Addım 8: Test ────────────────────────────────────────────────────────────
log_step "8. Flow göndərilməsi test edilir"

log_info "QRadar Flow Collector bağlantısı yoxlanılır..."
if nc -zu "$QRADAR_FLOW_IP" "$QRADAR_FLOW_PORT" 2>/dev/null; then
    log_info "QRadar Flow Collector əlçatandır: ${QRADAR_FLOW_IP}:${QRADAR_FLOW_PORT} ✓"
else
    log_warn "QRadar Flow Collector əlçatan deyil: ${QRADAR_FLOW_IP}:${QRADAR_FLOW_PORT}"
    log_warn "QRadar-da Flow Source konfiqurasiyasını yoxlayın."
fi

# ─── Nəticə ────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_info "Nprobe quraşdırılması tamamlandı!"
echo ""
echo "  Dinlənən interfeys : $LISTEN_INTERFACE"
echo "  Flow göndərilir    : $QRADAR_FLOW_IP:$QRADAR_FLOW_PORT"
echo "  NetFlow versiyası  : $NPROBE_TEMPLATE"
echo "  Log faylı          : $NPROBE_LOG"
echo ""
echo "  Servis idarəetməsi:"
echo "    systemctl status nprobe    # Vəziyyət"
echo "    systemctl restart nprobe   # Yenidən başlat"
echo "    tail -f $NPROBE_LOG        # Canlı log"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── Faydalı nprobe komandaları ────────────────────────────────────────────────
cat <<'CMDS'

Faydalı komandalar:
  # Dinlənən interfeysləri göstər:
  nprobe --list-interfaces

  # Test rejimində işə sal (konsola çıxar):
  nprobe -i eth0 -n none --dont-reforge-timestamps -V 9

  # Flow statistikasını izlə:
  nprobe --dump-stats=10 -i eth0 -n 192.168.1.100:2055 -V 9

CMDS
