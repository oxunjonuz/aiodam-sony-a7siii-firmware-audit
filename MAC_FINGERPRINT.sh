#!/bin/bash
# =============================================================================
#  MAC_FINGERPRINT.sh          AIODAM, turn 279          Sony A7S III audit
#  version 279.1
#
#  THE QUESTION THIS ANSWERS
#    Inside the publicly distributed firmware file BODYDATA.DAT (version 5.01)
#    there is ONE real private SSH host key (round 278):
#
#       type        : ecdsa-sha2-nistp256
#       blob        : 104 bytes, sha256 27c2fd68...d3832
#       fingerprint : SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI
#       comment     : root@(none)
#       sshd_config : HostKey /tmp_network/ssh/ssh_host_ecdsa_key
#                     HostKeyAlgorithms ecdsa-sha2-nistp256, KexAlgorithms ecdh-sha2-nistp256
#
#    Is that key the LIVE host key of the camera?  This script looks for the
#    camera from this Mac, knocks on TCP port 22, takes the host key through a
#    plain SSH key exchange and compares it, byte for byte, with that key.
#
#        MATCH       the live camera presents the same key -> the private half of
#                    the identity of the model ships in every firmware download
#        MISMATCH    port 22 answered with a different key -> the camera makes its
#                    own key (the firmware only carries the script that creates
#                    one: /usr/bin/create_host_key.sh)
#        UNREACHABLE nothing answered, or nothing on port 22 -> the key cannot be
#                    read from outside; see section [7] of the report
#        INCONCLUSIVE_* port 22 answered but no usable key, or the comparison
#                    routes disagreed with each other
#
#  WHAT IT SENDS, AND NOTHING ELSE
#       * TCP connect() attempts (SYN) to ports 22, 15740, 60152 on addresses
#         found on this Mac (its own subnets, its ARP neighbours, its gateway).
#       * at most one SSH key-exchange handshake, to one host, port 22.
#    It NEVER authenticates, never sends a credential, never writes to the
#    camera, never enters a service mode, sends no ICMP and no UDP (the mDNS
#    search is off unless you pass --mdns), and never touches the firmware file.
#
#  HOW TO RUN
#       ./MAC_FINGERPRINT.sh                  find the camera yourself
#       ./MAC_FINGERPRINT.sh --ip 192.168.122.1
#       ./MAC_FINGERPRINT.sh --no-scan        do not sweep the local /24
#       ./MAC_FINGERPRINT.sh --selftest       prove the instrument can go red,
#                                             no camera needed (~10 s)
#       sh MAC_FINGERPRINT.sh --help
#
#  RESULT
#       printed, and written to /tmp/aiodam_fingerprint.txt (change with --out),
#       plus a copy next to this script when that folder is writable, plus a
#       one-line JSON record inside the text.
# =============================================================================

if [ -z "${BASH_VERSION:-}" ]; then
    if [ -x /bin/bash ]; then exec /bin/bash "$0" "$@"; fi
    echo "MAC_FINGERPRINT.sh needs bash and /bin/bash is missing" >&2
    exit 3
fi
set -u

VERSION="279.1"

# --- the key from the firmware (round 278). The EXPECT_* variables can be
# --- overridden only so that the selftest can prove the comparison can fail.
EXPECT_FP="SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI"
EXPECT_B64="AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAuoJrSuZ6vJ8E5i7ljq3qejSfe7hQORqGstDZLq7m0X1cXel0INCJAFjs89KvyuhDqq0jMB+9fyYBCcJlVWCow="
EXPECT_BLOB_SHA256="27c2fd6812c48a64dd0d6e66d6257bc14eb82cfd625a8dfe963f4c182c4d3832"
EXPECT_TYPE="ecdsa-sha2-nistp256"

# --- the key the OWNER read from the live camera (2026-10-04, tel: 192.168.1.102).
# --- It is a REFERENCE, not an expectation: it lets this script answer "is the key
# --- I just read the same one as before?" - which is exactly the power-cycle test.
REF_LIVE_FP="SHA256:0VOxJqn75lys4Lf91tSlZu8nazWWxD6rTVc35jZo87U"
REF_LIVE_B64="AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBGUAdziIrqiEdzNu0MDQmLaXSDqPC8CcvMN1MaEnDtHvHlFxEA5X1jgZ+470wZFJrdvTPokuRp1V88imQaqAjw="
REF_LIVE_SHA256="d153b126a9fbe65cace0b7fdd6d4a566ef276b3596c43eab4d5737e63668f3b5"
REF_LIVE_NOTE="measured by the owner on the live camera at 192.168.1.102, 2026-10-04"

# --- the four restrictions the firmware's own sshd_config imposes (round 278). A live
# --- SSH server that negotiates EXACTLY this set is configured by that file - which is
# --- how the camera was identified on 2026-10-04 while its PTP/IP port stayed closed.
FW_KEX="ecdh-sha2-nistp256"
FW_CIPHER="aes128-ctr"
FW_MAC="hmac-sha2-256"
FW_HOSTKEY="ecdsa-sha2-nistp256"

# --- USB ids the firmware itself declares (round 276, read out of BODYDATA.DAT):
SONY_VID="054c"
SONY_NORMAL_PIDS="0448 047d 0d15 0d16 0d19 0d1a"
SONY_UPDATER_PID="03e2"

# --- the camera's network signature: Sony PTP/IP is TCP 15740. The port number is
# --- evidence, not proof: this script never speaks PTP/IP, it only observes that
# --- a socket accepts a connection there.
PTP_PORT=15740
SSHD_PORT_DEFAULT=22
SONY_EXTRA_PORT=60152            # the second port the firmware's sshd_config allows forwarding to

# --- Sony OUIs (MAC prefixes) - a HEURISTIC, deliberately short: it can miss a
# --- camera and it can mislabel a non-camera. The measured signature is the open
# --- PTP port, not this list.
SONY_OUI="08:00:46 00:13:a9 00:1a:80 00:24:be 54:42:49 30:f9:ed 3c:07:71 78:84:3c d8:d4:3c f8:d0:ac"

# --- a commonly documented default for a Sony camera acting as an access point.
# --- Not verified by me: it is a guess to try, and it is labelled as such in output.
SONY_AP_GUESS="192.168.122.1"

# ------------------------------------------------------------------ options ---
IP_ARG=""; PORT_ARG="$SSHD_PORT_DEFAULT"; SCAN_MODE="auto"; OUT="/tmp/aiodam_fingerprint.txt"
MDNS=0; SELFTEST=0; TIMEOUT=1; VOLWRITE=1; WANT_HELP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --ip) IP_ARG="${2:-}"; shift 2 ;;
        --port) PORT_ARG="${2:-}"; shift 2 ;;
        --scan) SCAN_MODE="yes"; shift ;;
        --no-scan) SCAN_MODE="no"; shift ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --mdns) MDNS=1; shift ;;
        --no-volume-write) VOLWRITE=0; shift ;;
        --selftest) SELFTEST=1; shift ;;
        --help|-h) WANT_HELP=1; shift ;;
        *) echo "unknown option: $1   (try --help)"; exit 2 ;;
    esac
done
[ -n "${AIODAM_IP:-}" ]         && [ -z "$IP_ARG" ] && IP_ARG="$AIODAM_IP"
[ -n "${AIODAM_SSH_PORT:-}" ]   && PORT_ARG="$AIODAM_SSH_PORT"
[ -n "${AIODAM_OUT:-}" ]        && OUT="$AIODAM_OUT"
[ -n "${AIODAM_SCAN:-}" ]       && SCAN_MODE="$AIODAM_SCAN"
[ -n "${AIODAM_MDNS:-}" ]       && [ "$AIODAM_MDNS" = "yes" ] && MDNS=1
[ -n "${AIODAM_TIMEOUT:-}" ]    && TIMEOUT="$AIODAM_TIMEOUT"
[ -n "${AIODAM_EXPECT_FP:-}" ]  && EXPECT_FP="$AIODAM_EXPECT_FP"
[ -n "${AIODAM_EXPECT_B64:-}" ] && EXPECT_B64="$AIODAM_EXPECT_B64"

if [ "$WANT_HELP" = 1 ]; then
    sed -n '2,55p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

# ------------------------------------------------------------------- basics ---
WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/aiodam_fp.XXXXXX") || { echo "cannot mktemp"; exit 3; }

# WHY THE REPORT DOES NOT LIVE IN THE WORK DIRECTORY (turn 279, measured here):
# the same script lost its work directory WHILE STILL RUNNING in 3/40, 4/40, 10/60 and
# 6/60 runs, taking the report inside it with it. The control that fixes the blame:
# with the `rm -rf` deleted from the trap altogether, 0 of 60 runs lost anything - so the
# removal was this script's own clean-up, reached by a path visible only as "the EXIT
# trap is entered twice with the same shell PID, once from a subshell". The MECHANISM is
# NOT established and is recorded as open. What is fixed is the consequence: the report
# is written where it will be delivered, and the clean-up can only remove auxiliary files.
OUT_PART="$OUT.part"
if : > "$OUT_PART" 2>/dev/null; then
    REPORT="$OUT_PART"; REPORT_LOCATION="$OUT (built as $OUT_PART while the run goes on)"
else
    REPORT="$WORKDIR/report.txt"; REPORT_LOCATION="the work directory $WORKDIR (could not write $OUT_PART)"
fi
: > "$REPORT" 2>/dev/null || { echo "cannot write the report to $REPORT"; exit 3; }

RUN_DONE_MARK="$WORKDIR/.run-finished"
# The EXIT trap is deliberately harmless: a subshell that inherits it must not be able
# to delete anything. Only finish(), reached in the shell that owns the run, cleans up.
cleanup() { : ; }
trap cleanup EXIT
trap 'printf "\ninterrupted - nothing deleted; the report so far is %s\n" "$REPORT" >&2; exit 130' INT
trap 'printf "\nterminated - nothing deleted; the report so far is %s\n" "$REPORT" >&2; exit 143' TERM

P() { printf '%s\n' "$*"; }                     # live progress on screen
R() {                                            # the report that gets pasted
    if [ ! -d "$WORKDIR" ]; then                 # never lose the report silently
        mkdir -p "$WORKDIR" 2>/dev/null && printf '%s\n' \
            '[the work directory disappeared mid-run and was recreated - lines above this may be missing]' >> "$REPORT"
    fi
    printf '%s\n' "$*" >> "$REPORT"
}
have() { command -v "$1" >/dev/null 2>&1; }

case "$(uname -s)" in
    Darwin) PLAT="darwin" ;;
    Linux)  PLAT="linux" ;;
    *)      PLAT="other" ;;
esac

START_TS=$(date '+%Y-%m-%d %H:%M:%S %z')
sha256_file() {
    if have shasum; then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    elif have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif have openssl; then openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
    else echo ""
    fi
}
SELF_SHA=$(sha256_file "$0"); [ -n "$SELF_SHA" ] || SELF_SHA="unavailable"

b64_decode() {   # stdin -> stdout, 0 when a decoder exists
    if have openssl; then openssl base64 -d -A 2>/dev/null && return 0; fi
    if printf '' | base64 -d >/dev/null 2>&1; then base64 -d && return 0; fi
    if printf '' | base64 -D >/dev/null 2>&1; then base64 -D && return 0; fi
    return 1
}

# --- The two embedded constants are made to check each other, not to be trusted:
# --- the sha256 is recomputed from the base64 at every run. Two numbers that must
# --- agree can catch a typo in either, and if the expectation is ever overridden
# --- (AIODAM_EXPECT_*), all three comparison routes keep aiming at ONE key.
EXPECT_SHA_SOURCE="embedded constant (no decoder available to check it)"
if printf '%s' "$EXPECT_B64" | b64_decode > "$WORKDIR/expect.bin" 2>/dev/null; then
    _derived=$(sha256_file "$WORKDIR/expect.bin")
    if [ -n "$_derived" ] && [ "$_derived" = "$EXPECT_BLOB_SHA256" ]; then
        EXPECT_SHA_SOURCE="embedded constant, recomputed from the embedded base64 and equal"
    elif [ -n "$_derived" ]; then
        EXPECT_SHA_SOURCE="RECOMPUTED from the embedded base64 (the constant said $EXPECT_BLOB_SHA256, which did NOT match)"
        EXPECT_BLOB_SHA256="$_derived"
    fi
fi
# --- the reference key gets the same treatment: its fingerprint and its blob sha256
# --- are recomputed from the base64, so a typo in any of the three is caught here
# --- rather than becoming a wrong verdict later.
REF_CHECK="not checked (no decoder)"
if printf '%s' "$REF_LIVE_B64" | b64_decode > "$WORKDIR/ref.bin" 2>/dev/null; then
    _rh=$(sha256_file "$WORKDIR/ref.bin"); _rfp=""
    printf 'ecdsa-sha2-nistp256 %s\n' "$REF_LIVE_B64" > "$WORKDIR/ref.pub"
    if have ssh-keygen; then _rfp=$(ssh-keygen -lf "$WORKDIR/ref.pub" 2>/dev/null | awk '{print $2}'); fi
    REF_CHECK="ok: blob sha256 and fingerprint both recomputed from the embedded base64"
    [ -n "$_rh" ] && [ "$_rh" != "$REF_LIVE_SHA256" ] && \
        { REF_CHECK="MISMATCH: sha256 of the embedded reference base64 is $_rh, the constant said $REF_LIVE_SHA256"; REF_LIVE_SHA256="$_rh"; }
    [ -n "$_rfp" ] && [ "$_rfp" != "$REF_LIVE_FP" ] && \
        { REF_CHECK="$REF_CHECK; MISMATCH: its fingerprint is $_rfp, the constant said $REF_LIVE_FP"; REF_LIVE_FP="$_rfp"; }
fi

# --- which probe method is really usable on THIS machine (recorded, not assumed)
NC=""; NC_G=""; PROBE_METHOD="none"
if have nc; then
    NC=$(command -v nc)
    if nc -G 1 -z -w 1 127.0.0.1 1 2>&1 | grep -qi 'illegal\|invalid option'; then NC_G=""; else NC_G="-G"; fi
    PROBE_METHOD="nc -z${NC_G:+ -G}"
fi
DEV_TCP=0
if ( exec 3<>/dev/tcp/127.0.0.1/1 ) 2>&1 | grep -qi 'no such file'; then DEV_TCP=0; else DEV_TCP=1; fi
[ "$PROBE_METHOD" = "none" ] && [ "$DEV_TCP" = 1 ] && PROBE_METHOD="/dev/tcp"
[ "$PROBE_METHOD" = "none" ] && have nmap && PROBE_METHOD="nmap -sT"
if [ "$PROBE_METHOD" = "none" ]; then
    echo "no way to probe a TCP port on this machine (nc, /dev/tcp and nmap are all absent)"
    echo "MAC_FINGERPRINT_FAILED no_probe_method"
    exit 3
fi

PROBES=0        # every TCP connect() this run makes on the main path
SWEEP_HOSTS=0   # hosts swept in batches (counted separately; see the report)

probe_port() {   # host port [timeout] -> 0 when a socket accepts a connection
    local h="$1" p="$2" t="${3:-$TIMEOUT}" i=0 rc pid
    PROBES=$((PROBES + 1))
    case "$PROBE_METHOD" in
        "nc -z -G") "$NC" -z -G "$t" -w "$t" "$h" "$p" >/dev/null 2>&1; return $? ;;
        "nc -z")    "$NC" -z -w "$t" "$h" "$p" >/dev/null 2>&1; return $? ;;
        "/dev/tcp")
            # No killer subshell here on purpose (see the note at WORKDIR): the one
            # asynchronous helper this script used to spawn is gone. timeout(1) when
            # the machine has one, otherwise poll the child and stop waiting by hand.
            if have timeout; then
                timeout "$t" bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$h" "$p" >/dev/null 2>&1
                return $?
            fi
            ( exec 3<>"/dev/tcp/$h/$p" ) >/dev/null 2>&1 &
            pid=$!
            i=0
            while kill -0 "$pid" 2>/dev/null; do
                i=$((i + 1))
                if [ "$i" -ge $(( t * 20 )) ]; then kill "$pid" 2>/dev/null; break; fi
                sleep 0.05
            done
            wait "$pid" >/dev/null 2>&1; rc=$?
            return $rc ;;
        "nmap -sT")
            nmap -n -Pn -sT -p "$p" --max-retries 1 --host-timeout "${t}s" "$h" 2>/dev/null \
                | grep -q "^$p/tcp *open"
            return $? ;;
    esac
    return 1
}

# A single refused probe is not proof that a port is closed on a device whose sshd is
# started on demand. Measured on the owner's camera, 2026-10-04: one run found port 22
# closed at 17:23:01, and the same address accepted connections at 17:23:12 and in
# 15 of 15 probes after that. So a refusal is checked once more before it is believed,
# and the retry is written into the report.
PORT_RETRIED="no"
probe_port_retry() {   # host port -> 0 open
    PORT_RETRIED="no"
    probe_port "$1" "$2" "$TIMEOUT" && return 0
    sleep 2
    PORT_RETRIED="yes"
    probe_port "$1" "$2" "$TIMEOUT" && return 0
    return 1
}

# ------------------------------------------------------------------ discovery ---
mask2prefix() {   # 0xffffff00 -> 24 ; empty when the mask cannot be read
    local h="$1" n p i
    case "$h" in 0x*|0X*) h="${h#0[xX]}" ;; esac
    case "$h" in *[!0-9a-fA-F]*|"") echo ""; return ;; esac
    n=$(( 16#$h )) 2>/dev/null || { echo ""; return; }
    p=0; i=31
    while [ "$i" -ge 0 ]; do
        if [ $(( (n >> i) & 1 )) -eq 1 ]; then p=$((p + 1)); else break; fi
        i=$((i - 1))
    done
    echo "$p"
}

list_ifaces() {   # -> "iface ip prefix"
    if [ "$PLAT" = darwin ] && have ifconfig; then
        ifconfig -a 2>/dev/null | awk '
            /^[A-Za-z0-9._-]+:/ { f=$1; sub(/:$/, "", f) }
            /inet / { ip=$2; m=$4; if (m ~ /^0x/) print f, ip, m; else print f, ip, "" }
        ' | while read -r f ip m; do
                if [ -n "$m" ]; then printf '%s %s %s\n' "$f" "$ip" "$(mask2prefix "$m")"
                else printf '%s %s \n' "$f" "$ip"; fi
            done
    elif have ip; then
        ip -o -4 addr show 2>/dev/null | awk '{ split($4, a, "/"); print $2, a[1], a[2] }'
    elif have ifconfig; then
        ifconfig -a 2>/dev/null | awk '
            /^[A-Za-z0-9._-]+:/ { f=$1; sub(/:$/, "", f) }
            /inet / { ip=$2; m=$4; if (m ~ /^0x/) print f, ip, m; else print f, ip, "" }
        ' | while read -r f ip m; do
                if [ -n "$m" ]; then printf '%s %s %s\n' "$f" "$ip" "$(mask2prefix "$m")"
                else printf '%s %s \n' "$f" "$ip"; fi
            done
    fi
}

default_gateway() {
    if [ "$PLAT" = darwin ] && have route; then
        route -n get default 2>/dev/null | awk '/gateway:/ { print $2; exit }'
    elif have ip; then
        ip route show default 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "via") { print $(i + 1); exit } }'
    fi
}

arp_neighbours() {   # -> "ip mac"
    if [ "$PLAT" = darwin ] && have arp; then
        arp -an 2>/dev/null | awk '
            { ip=$2; gsub(/[()]/, "", ip); mac=$4
              if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && mac != "(incomplete)" && mac != "at")
                  print ip, mac }
        '
    elif have ip; then
        ip neigh 2>/dev/null | awk '/^[0-9]/ { print $1, $5 }'
    elif [ -r /proc/net/arp ]; then
        awk 'NR > 1 { print $1, $4 }' /proc/net/arp
    fi
}

sweep24() {   # $1 = "a.b.c"  $2 = port  -> open hosts, one per line
    local base="$1" port="$2" d i
    if have nmap; then
        nmap -n -Pn --open -p "$port" --max-retries 1 --host-timeout 1500ms -oG - "$base.0/24" 2>/dev/null \
            | awk '/^Host:/ { print $2 }'
        return
    fi
    d="$WORKDIR/sw_${port}_$$"
    mkdir -p "$d"; : > "$d/found"
    i=1
    while [ "$i" -le 254 ]; do
        ( probe_port "$base.$i" "$port" "$TIMEOUT" && echo "$base.$i" >> "$d/found" ) &
        if [ $(( i % 32 )) -eq 0 ]; then wait; fi
        i=$((i + 1))
    done
    wait
    sort -u "$d/found" 2>/dev/null | sort -t. -k4,4n
}

usb_section() {   # macOS only: is a Sony USB device attached, and with which ids
    have system_profiler || return 0
    system_profiler SPUSBDataType > "$WORKDIR/usb.txt" 2>/dev/null
    [ -s "$WORKDIR/usb.txt" ] || return 0
    awk '
        /^[ \t]+[^:]+:[ \t]*$/ { name=$0; gsub(/^[ \t]+|[ \t]+$/, "", name); next }
        /Product ID: 0x/ { p=$3; next }
        /Vendor ID: 0x/  { v=$3;
            if (v ~ /054c/) { printf "name=%s product_id=%s vendor_id=%s\n", name, p, v } }
    ' "$WORKDIR/usb.txt"
}

# ------------------------------------------------------------- ssh key compare ---
reset_routes() { R_BLOB="no"; R_FP="no"; R_SHA="no"; R_AVAIL_SHA=0; \
                 KEYS_LINES=0; KEY_TYPES=""; OBS_FP_LIST=""; OBS_B64_LIST=""; }
reset_routes

# Fills the globals above from a file holding ssh-keyscan-format key lines.
analyze_keyscan() {   # $1 = file
    local f="$1" line kt b64 pubb fp blobsha
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        kt=$(printf '%s\n' "$line" | awk '{print $2}')
        b64=$(printf '%s\n' "$line" | awk '{print $3}')
        [ -n "$kt" ] && [ -n "$b64" ] || continue
        KEYS_LINES=$((KEYS_LINES + 1))
        KEY_TYPES="$KEY_TYPES $kt"
        OBS_B64_LIST="$OBS_B64_LIST $b64"
        pubb="$WORKDIR/obspub.tmp"
        printf '%s %s\n' "$kt" "$b64" > "$pubb"
        fp=""
        if have ssh-keygen; then fp=$(ssh-keygen -lf "$pubb" 2>/dev/null | awk '{print $2}'); fi
        OBS_FP_LIST="$OBS_FP_LIST ${fp:-none}"
        [ "$b64" = "$EXPECT_B64" ] && R_BLOB="yes"
        [ -n "$fp" ] && [ "$fp" = "$EXPECT_FP" ] && R_FP="yes"
        if printf '%s' "$b64" | b64_decode > "$WORKDIR/obsblob.bin" 2>/dev/null; then
            R_AVAIL_SHA=1
            blobsha=$(sha256_file "$WORKDIR/obsblob.bin")
            [ -n "$blobsha" ] && [ "$blobsha" = "$EXPECT_BLOB_SHA256" ] && R_SHA="yes"
        fi
    done < "$f"
}

# The three routes are independent of each other on purpose: a MATCH is only
# printed when every available route says the same thing.
route_verdict() {
    NV_AVAIL=1; NV_YES=0; NV_NO=0
    [ "$R_BLOB" = "yes" ] && NV_YES=$((NV_YES + 1)); [ "$R_BLOB" = "no" ] && NV_NO=$((NV_NO + 1))
    if have ssh-keygen; then
        NV_AVAIL=$((NV_AVAIL + 1))
        [ "$R_FP" = "yes" ] && NV_YES=$((NV_YES + 1)); [ "$R_FP" = "no" ] && NV_NO=$((NV_NO + 1))
    fi
    if [ "${R_AVAIL_SHA:-0}" = 1 ]; then
        NV_AVAIL=$((NV_AVAIL + 1))
        [ "$R_SHA" = "yes" ] && NV_YES=$((NV_YES + 1)); [ "$R_SHA" = "no" ] && NV_NO=$((NV_NO + 1))
    fi
    if [ "$KEYS_LINES" -eq 0 ]; then echo "INCONCLUSIVE_NO_KEY"
    elif [ "$NV_YES" -eq "$NV_AVAIL" ] && [ "$NV_YES" -gt 0 ]; then echo "MATCH"
    elif [ "$NV_NO" -eq "$NV_AVAIL" ]; then echo "MISMATCH"
    else echo "INCONCLUSIVE_CONTRADICTION"; fi
}

# ---------------------------------------------------------------- final output ---
finish() {   # $1 = exit code
    if [ "$REPORT" != "$OUT" ]; then
        cp "$REPORT" "$OUT" 2>/dev/null
    fi
    [ -s "$OUT" ] && OUT_OK=1 || OUT_OK=0
    # once the report is in place, the partial copy has no reason to stay in $TMPDIR
    if [ "$OUT_OK" = 1 ] && [ "$REPORT" != "$OUT" ]; then rm -f "$REPORT" 2>/dev/null; fi
    : > "$RUN_DONE_MARK" 2>/dev/null     # the run is over; the auxiliary work may go
    printf '\n'
    printf '================================ FINAL REPORT ================================\n'
    if [ "$OUT_OK" = 1 ]; then cat "$OUT"; else cat "$REPORT" 2>/dev/null; fi
    printf '==============================================================================\n'
    if [ "$OUT_OK" = 1 ]; then
        printf 'written to %s (%s bytes)\n' "$OUT" "$(wc -c < "$OUT" | tr -d ' ')"
    else
        printf 'COULD NOT WRITE %s - the report above is the only copy\n' "$OUT"
    fi
    if [ "$VOLWRITE" = 1 ]; then
        HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")
        if [ -n "$HERE" ] && [ "$HERE" != "/" ] && [ -w "$HERE" ]; then
            if cp "$OUT" "$HERE/FINGERPRINT_RESULT.txt" 2>/dev/null; then
                printf 'copied to  %s/FINGERPRINT_RESULT.txt (so Aiodam can read it from the volume)\n' "$HERE"
            fi
        fi
    fi
    rm -rf "$WORKDIR" 2>/dev/null     # the only clean-up in the whole script
    exit "$1"
}

# =============================================================== SELF TEST ===
# Runs with no camera and no network. Purpose: show that this instrument can go
# red. Every expectation below is computed, never assumed.
st() { ST_TOTAL=$((ST_TOTAL + 1)); if [ "$2" = "$3" ]; then ST_PASS=$((ST_PASS + 1))
           printf 'PASS  %-52s %s\n' "$1" "$3" >> "$REPORT"; printf 'PASS  %s\n' "$1"
       else printf 'FAIL  %-52s expected=%s got=%s\n' "$1" "$2" "$3" >> "$REPORT"
            printf 'FAIL  %s (expected=%s got=%s)\n' "$1" "$2" "$3"
       fi; }
st_skip() { ST_SKIP=$((ST_SKIP + 1)); printf 'SKIP  %-52s %s\n' "$1" "$2" >> "$REPORT"; printf 'SKIP  %s (%s)\n' "$1" "$2"; }

selftest() {
    ST_TOTAL=0; ST_PASS=0; ST_SKIP=0
    R "================================================================================"
    R " AIODAM MAC_FINGERPRINT $VERSION - SELF TEST (no camera, no network)"
    R " started : $START_TS   script sha256: $SELF_SHA   platform: $(uname -s)"
    R "================================================================================"
    R ""
    R "[A] TOOLS ON THIS MAC"
    for t in ssh-keyscan ssh-keygen nc nmap arp dns-sd system_profiler; do
        if have "$t"; then R "    $t   $(command -v "$t")"; else R "    $t   absent"; fi
    done
    R "    probe method chosen: $PROBE_METHOD"
    R ""

    R "[B] THE COMPARISON (a key line built from the firmware blob)"
    reset_routes
    printf 'selftest %s %s\n' "$EXPECT_TYPE" "$EXPECT_B64" > "$WORKDIR/st1"
    analyze_keyscan "$WORKDIR/st1"
    st "firmware blob -> MATCH"        "MATCH"    "$(route_verdict)"
    st "  and the fingerprint route agrees" "yes" "$R_FP"
    if [ "${R_AVAIL_SHA:-0}" = 1 ]; then
        st "  and the decoded-blob route agrees" "yes" "$R_SHA"
    else
        st_skip "decoded-blob route" "no base64 decoder on this machine"
    fi

    R ""
    R "[C] CONTROL: one character of the expected key changed"
    reset_routes
    CHANGED="${EXPECT_B64%?}X"
    printf 'selftest %s %s\n' "$EXPECT_TYPE" "$CHANGED" > "$WORKDIR/st2"
    analyze_keyscan "$WORKDIR/st2"
    st "changed blob -> MISMATCH (not MATCH)" "MISMATCH" "$(route_verdict)"

    R ""
    R "[D] CONTROL: a freshly generated ECDSA key (never seen by this script)"
    reset_routes
    rm -f "$WORKDIR/fresh" "$WORKDIR/fresh.pub"
    if have ssh-keygen && ssh-keygen -q -t ecdsa -b 256 -N '' -f "$WORKDIR/fresh" >/dev/null 2>&1; then
        FB64=$(awk '{print $2}' "$WORKDIR/fresh.pub")
        printf 'selftest ecdsa-sha2-nistp256 %s\n' "$FB64" > "$WORKDIR/st3"
        analyze_keyscan "$WORKDIR/st3"
        st "fresh key -> MISMATCH" "MISMATCH" "$(route_verdict)"
    else
        st_skip "fresh key control" "ssh-keygen could not create a key here"
    fi

    R ""
    R "[E] PORT PROBE"
    if have nc || [ "$PROBE_METHOD" = "nmap -sT" ] || [ "$PROBE_METHOD" = "/dev/tcp" ]; then
        CLOSED_OK=0; TRY=0
        while [ "$TRY" -lt 5 ]; do
            PORTN=$(( 30000 + (RANDOM % 20000) ))
            if ! probe_port 127.0.0.1 "$PORTN" 1; then CLOSED_OK="$PORTN"; break; fi
            TRY=$((TRY + 1))
        done
        if [ "$CLOSED_OK" != 0 ]; then
            st "a port with nothing behind it reads CLOSED" "closed" "closed"
        else
            st "a port with nothing behind it reads CLOSED" "closed" "kept finding an open port"
        fi
        if have nc; then
            PORTN=$(( 30000 + (RANDOM % 20000) ))
            LSN_OPENED=no
            # Two listener spellings exist in the wild (BSD/macOS: nc -l host port,
            # GNU: nc -l -p port). Both are tried; if neither takes, the check is
            # SKIPPED with the reason, not failed - a red line must mean a real fault.
            for form in "hostport" "pflag"; do
                : > "$WORKDIR/lsn.txt"
                if [ "$form" = "hostport" ]; then
                    "$NC" -l 127.0.0.1 "$PORTN" > "$WORKDIR/lsn.txt" 2>/dev/null &
                else
                    "$NC" -l -p "$PORTN" > "$WORKDIR/lsn.txt" 2>/dev/null &
                fi
                LSN=$!
                sleep 1
                if probe_port 127.0.0.1 "$PORTN" 1; then LSN_OPENED="$form"; fi
                kill "$LSN" >/dev/null 2>&1
                wait "$LSN" 2>/dev/null
                [ "$LSN_OPENED" != no ] && break
            done
            if [ "$LSN_OPENED" != no ]; then
                st "a real listener reads OPEN ($LSN_OPENED form)" "open" "open"
                sleep 1
                if ! probe_port 127.0.0.1 "$PORTN" 1; then st "and CLOSED again after it is gone" "closed" "closed"
                else st "and CLOSED again after it is gone" "closed" "still open"; fi
            else
                st_skip "listener control" "neither nc listener form opened a port here"
            fi
        else
            st_skip "listener control" "no nc on this machine to open a port with"
        fi
    else
        st_skip "port probe" "no probe method"
    fi

    R ""
    R "[F] WHAT THE SELF TEST DOES NOT COVER"
    R "    * no SSH handshake happens here: the MATCH/MISMATCH paths above are exercised"
    R "      with key bytes, not with a live server. On this Mac the live path can only be"
    R "      tested against the camera itself; the offline check that a real ssh-keyscan"
    R "      handshake is parsed correctly lives in audit/round279_check.py (run on Linux"
    R "      against a real SSH server holding the real firmware key)."
    R ""
    if [ "$ST_SKIP" -gt 0 ]; then
        R " SELFTEST: $ST_PASS/$ST_TOTAL passed, $ST_SKIP skipped (skips are not passes)"
    else
        R " SELFTEST: $ST_PASS/$ST_TOTAL passed, 0 skipped"
    fi
    R " VERDICT: $( [ "$ST_PASS" -eq "$ST_TOTAL" ] && echo SELF_TEST_OK || echo SELF_TEST_FAILED )"
    [ "$ST_PASS" -eq "$ST_TOTAL" ] && finish 0 || finish 4
}

[ "$SELFTEST" = 1 ] && selftest

# ================================================================= MAIN PATH ===
P "AIODAM MAC_FINGERPRINT $VERSION   (read-only: TCP probes + at most one SSH handshake)"
P ""

R "================================================================================"
R " AIODAM MAC_FINGERPRINT $VERSION"
R " started          : $START_TS"
R " this script      : $0"
R " script sha256    : $SELF_SHA"
R " report file      : $REPORT_LOCATION"
R " platform         : $(uname -s) $(uname -r) $(uname -m)"
if [ "$PLAT" = darwin ] && have sw_vers; then
    R " macOS            : $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
fi
if have ssh; then R " OpenSSH on this Mac: $(ssh -V 2>&1 | head -1)"; fi
R " probe method     : $PROBE_METHOD"
R " looking for key  : $EXPECT_FP"
R "                   type $EXPECT_TYPE, blob 104 B, blob sha256 $EXPECT_BLOB_SHA256"
R "                   blob sha256 source: $EXPECT_SHA_SOURCE"
R "================================================================================"
R ""
R "[0] WHAT THIS RUN DOES"
R "    TCP connect() attempts to ports $PORT_ARG, $PTP_PORT, $SONY_EXTRA_PORT on addresses found"
R "    on this Mac, and at most one SSH key-exchange handshake. No authentication,"
R "    no login, no credential, no write to the camera, no service mode, no ICMP."
if [ "$MDNS" = 1 ]; then
    R "    NOTE: --mdns was asked for, so up to 3 s of mDNS queries (UDP 5353) are sent too."
else
    R "    No UDP is sent (the mDNS search exists but is off; --mdns turns it on)."
fi
R ""

R "[1] THIS MAC"
IFACES=$(list_ifaces)
if [ -n "$IFACES" ]; then
    R "    interfaces with an IPv4 address:"
    printf '%s\n' "$IFACES" | while read -r f ip pfx; do
        [ -n "${f:-}" ] || continue
        R "      $f  $ip  /${pfx:-?}"
    done
else
    R "    interfaces: could not be read (no ifconfig/ip, or none has an IPv4 address)"
fi
GW=$(default_gateway)
R "    default gateway  : ${GW:-not found}"
MYIPS=$(printf '%s\n' "$IFACES" | awk '{print $2}')
SUBNETS=$(printf '%s\n' "$IFACES" | awk '
    { p = $3 + 0
      if (p >= 24 || p == 0) { n = split($2, o, "."); if (n == 4) print o[1] "." o[2] "." o[3] } }' | sort -u)
N_SUB=$(printf '%s\n' "$SUBNETS" | grep -c . || true)
R "    local /24 networks: $(printf '%s ' $SUBNETS)"
R ""

R "[2] WHERE THE CAMERA COULD BE"
USB_LINES=$(usb_section)
if [ -n "$USB_LINES" ]; then
    R "    USB: Sony device(s) attached:"
    printf '%s\n' "$USB_LINES" | while IFS= read -r l; do
        R "      $l"
        pid=$(printf '%s' "$l" | sed -n 's/.*product_id=0x\([0-9a-fA-F]*\).*/\1/p')
        case " $SONY_NORMAL_PIDS " in
            *" $pid "*) R "        -> 0x$pid is one of the six PIDs the FIRMWARE ITSELF declares for normal mode" ;;
        esac
        [ "$pid" = "$SONY_UPDATER_PID" ] && \
            R "        -> 0x$pid is the firmware's UPDATER id: update/service mode, not normal mode"
    done
    R "    (USB alone never exposes sshd; a tethered camera appears as a network interface"
    R "     only in USB-tethering / PTP-network mode.)"
else
    if [ "$PLAT" = darwin ]; then
        R "    USB: no Sony device (vendor 0x$SONY_VID) reported by system_profiler."
    else
        R "    USB: skipped (macOS-only check; this is $PLAT)."
    fi
fi
R ""

CAND_FILE="$WORKDIR/cand.txt"; : > "$CAND_FILE"; SEEN=" "
add_cand() {   # ip why
    local ip="$1" why="$2"
    case "$SEEN" in *" $ip "*) return ;; esac
    SEEN="$SEEN$ip "
    printf '%s %s\n' "$ip" "$why" >> "$CAND_FILE"
}
[ -n "${GW:-}" ] && add_cand "$GW" "default gateway"
printf '%s\n' "$MYIPS" > "$WORKDIR/myips.txt"
NEI=$(arp_neighbours)
if [ -n "$NEI" ]; then
    printf '%s\n' "$NEI" | while read -r ip mac; do
        [ -n "$ip" ] || continue
        oui=$(printf '%s' "$mac" | cut -c1-8 | tr 'A-Z' 'a-z')
        case " $SONY_OUI " in
            *" $oui "*) echo "$ip $mac SONY-OUI(heuristic)" ;;
            *)          echo "$ip $mac -" ;;
        esac
    done > "$WORKDIR/nei.txt"
    while read -r ip mac tag; do
        [ -n "$ip" ] || continue
        case "$(cat "$WORKDIR/myips.txt")" in *"$ip"*) continue ;; esac
        add_cand "$ip" "ARP neighbour $mac $tag"
    done < "$WORKDIR/nei.txt"
fi
add_cand "$SONY_AP_GUESS" "guess: common Sony access-point-mode address (UNVERIFIED)"
# a target given with --ip is probed like any other candidate, so the report can say
# whether THAT address carries the camera signature (port 15740)
[ -n "$IP_ARG" ] && add_cand "$IP_ARG" "given with --ip"

R "    candidate addresses (this Mac's ARP neighbours, its gateway, one documented guess):"
while read -r ip why; do
    R "      $ip  <- $why"
done < "$CAND_FILE"
R ""

R "[3] PROBING (TCP connect only)"
CAM_HOST=""; CAM_HOSTS=""; SSH_OPEN=""; SSH_HOSTS=""
while read -r ip why; do
    [ -n "$ip" ] || continue
    p22="closed"; p15740="closed"; p60152="closed"; PORT_RETRIED="no"
    probe_port_retry "$ip" "$PORT_ARG" && p22="OPEN"
    probe_port "$ip" "$PTP_PORT" "$TIMEOUT" && p15740="OPEN"
    probe_port "$ip" "$SONY_EXTRA_PORT" "$TIMEOUT" && p60152="OPEN"
    R "      $ip  port $PORT_ARG:$p22  port $PTP_PORT:$p15740  port $SONY_EXTRA_PORT:$p60152"
    if [ "$p15740" = "OPEN" ]; then
        [ -z "$CAM_HOST" ] && CAM_HOST="$ip"
        CAM_HOSTS="$CAM_HOSTS $ip"
    fi
    if [ "$p22" = "OPEN" ]; then
        SSH_HOSTS="$SSH_HOSTS $ip"
        [ -z "$SSH_OPEN" ] && SSH_OPEN="$ip"
    fi
done < "$CAND_FILE"

if [ -z "$CAM_HOST" ] && [ -z "$SSH_HOSTS" ] && [ -z "$IP_ARG" ]; then
    if [ "$SCAN_MODE" = "no" ]; then
        R "    sweep of the local network: skipped (--no-scan / AIODAM_SCAN=no)"
    elif [ "$N_SUB" -eq 0 ]; then
        R "    sweep of the local network: not possible (no local /24 could be derived)"
    else
        R "    nothing answered above, so each local /24 is swept with TCP probes on port"
        R "    $PTP_PORT only (the camera's own PTP/IP port):"
        for base in $SUBNETS; do
            P "  sweeping $base.0/24 on port $PTP_PORT (TCP connect only) ..."
            R "      $base.0/24 ..."
            SWEEP_HOSTS=$((SWEEP_HOSTS + 254))
            hit=$(sweep24 "$base" "$PTP_PORT")
            if [ -n "$hit" ]; then
                for ip in $hit; do
                    R "        $ip port $PTP_PORT:OPEN  <- camera signature"
                    [ -z "$CAM_HOST" ] && CAM_HOST="$ip"
                    CAM_HOSTS="$CAM_HOSTS $ip"
                done
                for ip in $hit; do
                    if probe_port "$ip" "$PORT_ARG" "$TIMEOUT"; then
                        R "        $ip port $PORT_ARG:OPEN"
                        SSH_HOSTS="$SSH_HOSTS $ip"
                        [ -z "$SSH_OPEN" ] && SSH_OPEN="$ip"
                    else
                        R "        $ip port $PORT_ARG:closed"
                    fi
                done
            else
                R "        nothing on port $PTP_PORT anywhere in this /24"
            fi
        done
    fi
fi
R ""
R "    TCP connect attempts on the main path: $PROBES"
[ "$SWEEP_HOSTS" -gt 0 ] && R "    TCP connect attempts inside the sweep: up to $SWEEP_HOSTS (batched, port $PTP_PORT only)"
R ""

R "[4] WHAT WAS IDENTIFIED"
TARGET=""
if [ -n "$IP_ARG" ]; then
    TARGET="$IP_ARG"
    R "    target: $IP_ARG (given with --ip; discovery still ran and is reported above)"
elif [ -n "$CAM_HOST" ]; then
    TARGET="$CAM_HOST"
    R "    camera signature found: a socket on port $PTP_PORT accepts a connection at$CAM_HOSTS"
    R "    (TCP $PTP_PORT is Sony PTP/IP; this script did not speak the protocol, it only"
    R "     observed an accepting socket - identification is an inference from the port number)"
else
    R "    no host answered on port $PTP_PORT: no camera signature found on this network."
fi
if [ -n "$SSH_HOSTS" ]; then
    R "    SSH (port $PORT_ARG) open at:$SSH_HOSTS"
else
    R "    SSH (port $PORT_ARG): closed everywhere that was probed."
fi
R "    identification routes, in order of strength: (1) the algorithm set the server"
R "    negotiates, compared against the firmware's sshd_config (step [5]); (2) an"
R "    accepting socket on the camera's PTP/IP port $PTP_PORT; (3) the MAC OUI, which is"
R "    only a heuristic. Measured 2026-10-04: the owner's camera answered on port"
R "    $PORT_ARG while port $PTP_PORT was closed - in that state route 1 is the one that"
R "    identifies it, and route 2 says nothing."
if [ -n "$TARGET" ] && [ "$TARGET" != "${CAM_HOST:-}" ] && [ -z "${CAM_HOST:-}" ]; then
    R "    NOTE: the host that will be fingerprinted does NOT show the camera's PTP/IP port."
    R "          If it is not the camera, a MISMATCH below belongs to some other device."
fi
case " $(printf '%s ' $MYIPS) " in
    *" $TARGET "*) R "    WARNING: $TARGET is THIS Mac's own address - that would fingerprint this computer." ;;
esac
R ""

R "[5] SSH HOST KEY FROM THE LIVE HOST"
KS_OUT="$WORKDIR/keys.txt"; KS_ERR="$WORKDIR/keys.err"; : > "$KS_OUT"; : > "$KS_ERR"
ALG_MATCH="na"; ALG_SET="not measured (no SSH handshake was made)"
REF_MATCH="not compared (no key was returned)"
if [ -z "$TARGET" ]; then
    R "    nothing to fingerprint: no target host."
elif ! have ssh-keyscan; then
    R "    ssh-keyscan is not on this Mac, so the key cannot be taken."
elif ! probe_port_retry "$TARGET" "$PORT_ARG"; then
    R "    port $PORT_ARG on $TARGET does not accept connections (probed twice, 2 s apart),"
    R "    so no SSH handshake was attempted at all and nothing beyond the TCP attempts"
    R "    above went to that host."
else
    R "    port $PORT_ARG is open. Sending one SSH key-exchange handshake to $TARGET:$PORT_ARG"
    R "    (this is the handshake, before any authentication: no name, no password, no key of"
    R "     yours is offered, and the camera is not asked to change anything)."
    ssh-keyscan -T 5 -p "$PORT_ARG" -t ecdsa "$TARGET" >> "$KS_OUT" 2>> "$KS_ERR"
    ssh-keyscan -v -T 5 -p "$PORT_ARG" "$TARGET" >> "$KS_OUT" 2>> "$KS_ERR"
    BANNER=$(grep -i 'remote software version' "$KS_ERR" 2>/dev/null | head -2)
    if [ -n "$BANNER" ]; then
        R "    server banner seen while exchanging keys:"
        printf '%s\n' "$BANNER" | sed 's/^/      /' >> "$REPORT"
    fi
    # --- identification that does not depend on the key at all: which algorithms did
    # --- this server agree to? The firmware's sshd_config allows exactly one of each.
    # tr -d '\r' matters: the ssh-keyscan debug lines here end with a carriage return,
    # so $NF was "ecdh-sha2-nistp256\r" - a value that prints as identical and compares
    # as different. That one invisible byte made this check announce "different set"
    # about a server that had negotiated exactly the firmware's set (measured 2026-10-04).
    GOT_KEX=$(grep -m1 'kex: algorithm:' "$KS_ERR" 2>/dev/null | awk '{print $NF}' | tr -d '\r')
    # ssh-keyscan logs one handshake per requested key type and prints "(no match)" for
    # the ones the server does not offer, so the FIRST line is not the answer: the first
    # line that is not "(no match)" is. (Measured on the live camera: taking $NF of the
    # first match gave "match)", which then made this check say "different set" about a
    # server that had in fact negotiated exactly the firmware's set.)
    GOT_HOSTKEY=$(grep 'kex: host key algorithm:' "$KS_ERR" 2>/dev/null | grep -v 'no match' \
                  | head -1 | awk '{print $NF}' | tr -d '\r')
    GOT_CIPHER=$(grep -m1 'kex: server->client cipher:' "$KS_ERR" 2>/dev/null | sed -n 's/.*cipher: \([^ ]*\).*/\1/p' | tr -d '\r')
    GOT_MAC=$(grep -m1 'kex: server->client cipher:' "$KS_ERR" 2>/dev/null | sed -n 's/.*MAC: \([^ ]*\).*/\1/p' | tr -d '\r')
    ALG_SET="unknown (no negotiation lines captured)"
    ALG_MATCH="na"
    if [ -n "$GOT_KEX" ]; then
        ALG_SET="kex=$GOT_KEX cipher=$GOT_CIPHER mac=$GOT_MAC hostkey=$GOT_HOSTKEY"
        if [ "$GOT_KEX" = "$FW_KEX" ] && [ "$GOT_CIPHER" = "$FW_CIPHER" ] && \
           [ "$GOT_MAC" = "$FW_MAC" ] && [ "$GOT_HOSTKEY" = "$FW_HOSTKEY" ]; then
            ALG_MATCH="yes"
        else
            ALG_MATCH="no"
        fi
    fi
    R "    algorithms this server agreed to : $ALG_SET"
    R "    the firmware's sshd_config wants : kex=$FW_KEX cipher=$FW_CIPHER mac=$FW_MAC hostkey=$FW_HOSTKEY"
    case "$ALG_MATCH" in
        yes) R "    -> IDENTICAL set: this SSH server is configured by the firmware's own sshd_config." ;;
        no)  R "    -> different set: this is NOT the algorithm set the firmware's sshd_config imposes." ;;
        *)   R "    -> not determined (no negotiation lines in the ssh-keyscan output)." ;;
    esac
    grep -E '^[^ ]+ (ssh-|ecdsa-|sk-)' "$KS_OUT" 2>/dev/null | sort -u > "$WORKDIR/keys.clean" || : > "$WORKDIR/keys.clean"
    R "    raw key line(s) returned by the live host:"
    if [ -s "$WORKDIR/keys.clean" ]; then
        sed 's/^/      /' "$WORKDIR/keys.clean" >> "$REPORT"
    else
        R "      (none - the socket answered but no host key came back)"
    fi
    R "    ssh-keyscan stderr (verbatim, trimmed to 12 lines):"
    if [ -s "$KS_ERR" ]; then
        head -12 "$KS_ERR" | sed 's/^/      /' >> "$REPORT"
    else
        R "      (empty)"
    fi
    R ""
    R "[6] COMPARISON WITH THE KEY INSIDE BODYDATA.DAT"
    R "    expected fingerprint : $EXPECT_FP"
    R "    expected blob sha256 : $EXPECT_BLOB_SHA256"
    reset_routes
    analyze_keyscan "$WORKDIR/keys.clean"
    R "    keys returned        : $KEYS_LINES   types:$KEY_TYPES"
    R "    their fingerprints   :$OBS_FP_LIST"
    R ""
    R "    route 1  blob base64 equal to the firmware key      : $R_BLOB"
    if have ssh-keygen; then
        R "    route 2  SHA256 fingerprint equal (ssh-keygen -lf)  : $R_FP"
    else
        R "    route 2  SHA256 fingerprint                         : unavailable (no ssh-keygen)"
    fi
    if [ "${R_AVAIL_SHA:-0}" = 1 ]; then
        R "    route 3  decoded blob sha256 equal                  : $R_SHA"
        [ -s "$WORKDIR/obsblob.bin" ] && R "             (observed blob is $(wc -c < "$WORKDIR/obsblob.bin" | tr -d ' ') bytes)"
    else
        R "    route 3  decoded blob sha256                        : unavailable (no base64 decoder)"
    fi
    R ""
    R "    the live key against the key the owner read from the camera on 2026-10-04:"
    R "      reference fingerprint : $REF_LIVE_FP"
    R "      reference blob sha256 : $REF_LIVE_SHA256   ($REF_LIVE_NOTE)"
    R "      reference constants   : $REF_CHECK"
    REF_MATCH="not compared (no key was returned)"
    if [ "$KEYS_LINES" -gt 0 ]; then
        case " $OBS_B64_LIST " in
            *" $REF_LIVE_B64 "*) REF_MATCH="SAME" ;;
            *)                   REF_MATCH="DIFFERENT" ;;
        esac
    fi
    R "      -> the live key is $REF_MATCH as that reference"
    if [ "$REF_MATCH" = "SAME" ]; then
        R "         (SAME means the camera presented the identical key bytes twice, in two"
        R "          separate sessions; it does NOT yet say what happens across a power cycle)"
    fi
fi

VERDICT="UNREACHABLE"; REASON=""
if [ -z "$TARGET" ]; then
    VERDICT="UNREACHABLE"; REASON="no_candidate_host"
elif ! have ssh-keyscan; then
    VERDICT="UNREACHABLE"; REASON="no_ssh_keyscan_on_this_mac"
elif ! probe_port_retry "$TARGET" "$PORT_ARG"; then
    if [ -n "$CAM_HOST" ]; then
        VERDICT="UNREACHABLE"; REASON="camera_found_but_sshd_not_listening"
    else
        VERDICT="UNREACHABLE"; REASON="no_host_no_sshd"
    fi
else
    VERDICT=$(route_verdict); REASON=""
    case "$VERDICT" in
        MATCH)    REASON="live host key equals the firmware key" ;;
        MISMATCH) REASON="live host key is a different key" ;;
        INCONCLUSIVE_NO_KEY) REASON="port open but no host key came back" ;;
        INCONCLUSIVE_CONTRADICTION) REASON="comparison routes disagreed" ;;
    esac
fi

R ""
R "================================================================================"
R " VERDICT: $VERDICT"
R " reason : $REASON"
R "================================================================================"
R ""

R "[7] WHAT THIS MEANS"
case "$VERDICT" in
MATCH)
    R "    The live camera presented the SAME host key as the one inside BODYDATA.DAT:"
    R "      $EXPECT_FP"
    R "    So the key in the public firmware file is the identity this camera uses as an SSH"
    R "    server, and the file ships its private half (openssh-key-v1, cipher none) to"
    R "    everyone who downloads firmware 5.01. Two consequences, stated plainly: the host"
    R "    key is a model-wide constant, so a client that trusts that key cannot tell one"
    R "    camera of the model from another, and every owner of the file holds the same"
    R "    private bytes."
    R "    What this does NOT say: that sshd is reachable by default (it answered here), and"
    R "    that the key is used outside the camera's own service contour - the shipped config"
    R "    allows no login at all (PasswordAuthentication no, PubkeyAuthentication no,"
    R "    PermitRootLogin no, MaxSessions 0) and only permits a local forward to ports"
    R "    $PTP_PORT and $SONY_EXTRA_PORT."
    R "    One follow-up sharpens it: run this script again after power-cycling the camera."
    R "    If the fingerprint changes between boots, the key is regenerated each boot"
    R "    (create_host_key.sh writes it into /tmp_network/ssh/) and the firmware copy was"
    R "    never a persisted identity."
    ;;
MISMATCH)
    R "    The camera's sshd answered, but with a DIFFERENT host key than the one inside"
    R "    BODYDATA.DAT. The reason is visible in the firmware itself: that key lives at"
    R "    /tmp_network/ssh/ssh_host_ecdsa_key and is created on demand by"
    R "    /usr/bin/create_host_key.sh (ssh-keygen -q -b 256 -t ecdsa -N '' -f ...) only if"
    R "    the file is not there already. A key under /tmp_network does not survive a"
    R "    reboot, so a camera that rebuilds it shows a fresh key while still carrying the"
    R "    same script and the same bytes in the firmware file."
    if [ "$ALG_MATCH" = "yes" ]; then
        R "    This is the strong form of that finding, not a coincidence of another device:"
        R "    the server that answered negotiated EXACTLY the algorithm set the firmware's"
        R "    sshd_config imposes ($FW_KEX / $FW_CIPHER / $FW_MAC / $FW_HOSTKEY) - a set no"
        R "    ordinary machine chooses. So the firmware's sshd IS running, and its host key"
        R "    file was regenerated on the device: the private key shipped inside the public"
        R "    firmware image is not the live identity of this camera."
    fi
    R "    What is measured on 2026-10-04: the camera at 192.168.1.102 presented"
    R "      $REF_LIVE_FP"
    R "    - read by the owner on his Mac and again from another machine, same bytes."
    R "    Decisive next step (one measurement, and this script is the instrument):"
    R "    run it, power-cycle the camera, run it again. If the fingerprint changes between"
    R "    boots, the key is regenerated every boot and the firmware copies of it are"
    R "    templates that were never a persisted identity. If the fingerprint stays the"
    R "    same, one key per unit was created once and does survive somewhere."
    if [ -z "${CAM_HOST:-}" ] && [ "$ALG_MATCH" != "yes" ]; then
        R "    CAUTION: the fingerprinted host did not show the camera's PTP/IP port, so this"
        R "    key may belong to a different device on the network. Re-run with --ip <camera>."
    elif [ -z "${CAM_HOST:-}" ]; then
        R "    The fingerprinted host showed no PTP/IP port, but the algorithm set above is"
        R "    the firmware's own, which is an identification in itself; still, the PTP/IP"
        R "    port is what a camera normally opens, so this is worth re-checking later."
    fi
    ;;
UNREACHABLE)
    R "    The check could not be carried out, so the honest answer is that we still do not"
    R "    know whether the key is live. reason = $REASON"
    case "$REASON" in
    camera_found_but_sshd_not_listening)
        R "    The camera IS present: something at$CAM_HOSTS accepts a connection on port $PTP_PORT"
        R "    (Sony PTP/IP), so its network stack is up. Port $PORT_ARG is closed there."
        R "    This matches the firmware: sshd is not a boot service. It is started from the"
        R "    service contour (network::InfraSshManager in the image, /usr/sbin/sshd, PAM hooks"
        R "    ssh_account_lock_recorder and ssh_session_monitoring), and its config forbids"
        R "    login entirely. So there is no path from this Mac to its host key by design:"
        R "    the key cannot be read from outside without the vendor tool that starts sshd."
        ;;
    no_host_no_sshd)
        R "    Nothing answered on port $PTP_PORT and nothing on port $PORT_ARG. Either the"
        R "    camera is not on this network in a mode that opens a socket (Wi-Fi off, USB"
        R "    mass-storage only, or still in a menu), or it is on a network this Mac is not part"
        R "    of. Check the camera's Wi-Fi screen, or join the camera's own SSID (access-point"
        R "    mode) and run this script again."
        ;;
    no_candidate_host)
        R "    No target was found and none was given. Re-run with --ip <camera address>."
        ;;
    *)
        R "    reason: $REASON"
        ;;
    esac
    R ""
    R "    Alternatives, honestly ranked - only the first answers the original question, and"
    R "    it needs physical access:"
    R "      1. read the key off the camera's own storage/NAND on a service bench and compare"
    R "         with $EXPECT_FP. Needs hardware; out of reach from here."
    R "      2. run the vendor's own service tool that starts sshd, then re-run this script."
    R "         It needs that tool; nothing on this Mac substitutes for it."
    R "      3. map the surface instead of the key: with the camera in each network mode, note"
    R "         whether port $PTP_PORT comes up and whether port $PORT_ARG ever opens. That"
    R "         answers how the camera is exposed, not what its key is."
    R "    There is no shortcut: a closed port cannot be talked past, and this script will not"
    R "    pretend otherwise."
    ;;
INCONCLUSIVE_NO_KEY)
    R "    A socket on port $PORT_ARG answered, but no SSH host key came back. Whatever is"
    R "    listening there is not (or not yet) speaking SSH as expected - a proxy, a filtered"
    R "    port, another service. Nothing about the firmware key can be concluded from it."
    ;;
INCONCLUSIVE_CONTRADICTION)
    R "    The comparison routes disagreed with each other, so no verdict is given. The raw"
    R "    key line is printed verbatim in [5]; it can be compared by hand with"
    R "      ssh-keygen -lf <(printf '%s %s\n' ecdsa-sha2-nistp256 $EXPECT_B64)"
    ;;
*)
    R "    unknown verdict '$VERDICT'"
    ;;
esac
R ""
R "[8] WHAT WAS NOT MEASURED (always printed)"
R "    * whether sshd was running because of a service mode, and whether the key survives a"
R "      reboot - one run cannot tell; a second run after a power cycle can"
R "    * anything inside the camera beyond its SSH host key: nothing else was read"
R "    * no authentication was attempted, so 'the key is accepted by a client' is not claimed"
R "    * other units and other models: whether every A7S III (or every camera of this"
R "      generation) uses these bytes needs a second camera or a second firmware file"
R "    * PTP/IP itself: the port was seen open, the protocol was not spoken"
R "    * the private half of the firmware key: it was not used in this run and was sent"
R "      nowhere; only its public fingerprint was compared"
R ""
R "[9] NEXT STEP"
R "    Send this file (it is also at $OUT) to Aiodam. If the verdict is UNREACHABLE, send"
R "    it anyway: the probe table is the evidence that the check was attempted properly,"
R "    and it says which of the alternatives in [7] is left."
R ""

J_FP="$R_FP";  have ssh-keygen || J_FP="na"
J_SHA="${R_SHA:-na}"; [ "${R_AVAIL_SHA:-0}" = 1 ] || J_SHA="na"
json_escape() { printf '%s' "$1" | tr -d '\r\n\t' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
JSON=$(printf '{"tool":"MAC_FINGERPRINT","version":"%s","ts":"%s","platform":"%s","verdict":"%s","reason":"%s","target":"%s","ssh_port":"%s","ssh_open":"%s","ptp_open":"%s","keys_returned":%s,"key_types":"%s","observed_fingerprints":"%s","expected_fingerprint":"%s","expected_blob_sha256":"%s","expected_sha_source":"%s","route_blob":"%s","route_fp":"%s","route_sha":"%s","alg_set_match":"%s","alg_set":"%s","ref_live_match":"%s","ref_live_fingerprint":"%s","tcp_connect_attempts":%s,"sweep_hosts":%s,"camera_hosts":"%s","ssh_hosts":"%s","usb_sony":"%s","probe_method":"%s","script_sha256":"%s"}' \
    "$VERSION" "$(json_escape "$START_TS")" "$PLAT" "$VERDICT" "$REASON" \
    "$(json_escape "$TARGET")" "$PORT_ARG" \
    "$([ -n "$SSH_HOSTS" ] && echo yes || echo no)" \
    "$([ -n "${CAM_HOSTS:-}" ] && echo yes || echo no)" \
    "${KEYS_LINES:-0}" "$(json_escape "${KEY_TYPES:- none}")" \
    "$(json_escape "${OBS_FP_LIST:- none}")" "$EXPECT_FP" "$EXPECT_BLOB_SHA256" \
    "$(json_escape "$EXPECT_SHA_SOURCE")" \
    "$R_BLOB" "$J_FP" "$J_SHA" \
    "$ALG_MATCH" "$(json_escape "$ALG_SET")" "$REF_MATCH" "$REF_LIVE_FP" \
    "$PROBES" "$SWEEP_HOSTS" "$(json_escape "${CAM_HOSTS:-}")" "$(json_escape "${SSH_HOSTS:-}")" \
    "$(json_escape "$(printf '%s' "${USB_LINES:-none}" | tr '\n' ';')")" \
    "$(json_escape "$PROBE_METHOD")" "$SELF_SHA")
R "AIODAM_JSON: $JSON"

finish 0
