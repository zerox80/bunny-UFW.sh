#!/usr/bin/env bash
# =============================================================================
#  bunny-guard – Port 443 (und optional weitere Ports) nur noch für BunnyCDN
# =============================================================================
#
#  Was das Tool macht
#    * Lädt die offiziellen Bunny-Edge-IP-Listen (IPv4 + IPv6) per curl und
#      prüft sie auf Plausibilität, bevor sie benutzt werden.
#    * Legt eine eigene nftables-Tabelle "inet bunny_guard" an (Hooks input und
#      forward, Priorität -10, also vor UFW/firewalld/Docker). Auf den
#      geschützten Ports wird alles verworfen, was nicht von Bunny, einer
#      erlaubten Quelle oder an eine freigegebene Ziel-IP geht.
#      TCP und UDP (HTTP/3) werden beide gefiltert.
#    * UFW, firewalld, nftables.conf und Docker bleiben unangetastet. Per DNAT
#      weitergeleitete Docker-Ports werden über den ursprünglichen Zielport
#      ebenfalls geschützt.
#    * Ein systemd-Dienst lädt die Regeln beim Booten aus dem Cache (kein Netz
#      nötig). Ein Timer aktualisiert die Liste und stellt die Tabelle wieder
#      her, falls sie jemand gelöscht hat.
#    * Interaktiver Assistent: erkennt Domains (nginx, Apache, Caddy, Let's
#      Encrypt), prüft deren DNS, fragt nach Domains, die OHNE Bunny erreichbar
#      sein sollen, testet danach alles und setzt automatisch zurück, wenn du
#      nicht bestätigst.
#
#  Aufruf
#    sudo bash bunny-guard.sh              Assistent (installiert sich selbst)
#    sudo bunny-guard help                 alle Befehle
# =============================================================================
set -Eeuo pipefail
umask 022
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

readonly VERSION="2.0.0"
readonly INSTALL_BIN="/usr/local/sbin/bunny-guard"
readonly CONF_DIR="/etc/bunny-guard"
readonly CONF_FILE="$CONF_DIR/bunny-guard.conf"
readonly STATE_DIR="/var/lib/bunny-guard"
readonly LIST4="$STATE_DIR/bunny-ipv4.txt"
readonly LIST6="$STATE_DIR/bunny-ipv6.txt"
readonly RULESET="$STATE_DIR/ruleset.nft"
readonly STAMP_FILE="$STATE_DIR/last-update"
readonly ADDED_RULES="$STATE_DIR/added-firewall-rules"
readonly RB_DIR="$STATE_DIR/rollback"
readonly LOCK_FILE="/run/bunny-guard.lock"
readonly TABLE="bunny_guard"
readonly UNIT_DIR="/etc/systemd/system"
readonly SVC="bunny-guard.service"
readonly UPD_SVC="bunny-guard-update.service"
readonly UPD_TIMER="bunny-guard-update.timer"
readonly RB_UNIT="bunny-guard-rollback"
readonly NGINX_GEO="/etc/nginx/conf.d/bunny-guard-geo.conf"
readonly NGINX_SNIPPET="/etc/nginx/snippets/bunny-guard-only.conf"
readonly ROLLBACK_SECS=300
readonly MIN4=100
readonly MIN6=50
readonly PRIVATE_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7"
readonly UA="bunny-guard/$VERSION"
readonly -a URLS4=(
  "https://api.bunny.net/system/edgeserverlist/plain"
  "https://bunnycdn.com/api/system/edgeserverlist/plain"
  "https://api.bunny.net/system/edgeserverlist"
)
readonly -a URLS6=(
  "https://api.bunny.net/system/edgeserverlist/ipv6/plain"
  "https://bunnycdn.com/api/system/edgeserverlist/ipv6/plain"
  "https://api.bunny.net/system/edgeserverlist/ipv6"
)

# --- Konfiguration (Standardwerte, werden aus $CONF_FILE überschrieben) -------
PORTS="443"
ALLOW_PRIVATE="1"
ALLOW_SRC=""
EXEMPT_DST=""
DIRECT_DOMAINS=""
TEST_DOMAINS=""
NGINX_MODE="0"
UPDATE_HOURS="6"

# --- Laufzeitvariablen ---------------------------------------------------------
TMPD=""
TTY_IN="${BUNNY_GUARD_INPUT:-/dev/tty}"
LISTS_CHANGED=0
N_OK=0 N_WARN=0 N_BAD=0
declare -a LOCAL_IPS=() LOCAL_IFS=()
declare -a DOM_NAME=() DOM_SRC=() DOM_STAT=() DOM_TGT=() DOM_LOCAL=() DOM_IPS=()
declare -A BASELINE=()
CL_STAT="" CL_TGT="" CL_LOCAL="" CL_IPS=""
PROBE_RES="" PROBE_MSG=""
EXT_OK=0 EXT_FAIL=0 EXT_TOTAL=0
RB_ARMED=0

# --- Ausgabe -------------------------------------------------------------------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  C0=$'\e[0m' CB=$'\e[1m' CR=$'\e[31m' CG=$'\e[32m' CY=$'\e[33m' CC=$'\e[36m' CD=$'\e[2m'
else
  C0="" CB="" CR="" CG="" CY="" CC="" CD=""
fi
say()  { printf '%s\n' "$*"; }
ok()   { N_OK=$((N_OK + 1));     printf '  %s✓%s %s\n' "$CG" "$C0" "$*"; }
warn() { N_WARN=$((N_WARN + 1)); printf '  %s!%s %s\n' "$CY" "$C0" "$*"; }
bad()  { N_BAD=$((N_BAD + 1));   printf '  %s✗%s %s\n' "$CR" "$C0" "$*"; }
note() { printf '    %s%s%s\n' "$CD" "$*" "$C0"; }
step() { printf '\n%s%s━━ %s ━━%s\n' "$CB" "$CC" "$*" "$C0"; }
die()  { printf '%sFehler:%s %s\n' "$CR" "$C0" "$*" >&2; exit 1; }
log() {
  printf '%s\n' "$*"
  if [[ -z ${INVOCATION_ID:-} ]]; then logger -t bunny-guard -- "$*" 2>/dev/null || true; fi
}

cleanup() { if [[ -n $TMPD && -d $TMPD ]]; then rm -rf -- "$TMPD"; fi; }
on_err() {
  local rc=$? ln=${1:-?}
  # Fehler in Unter-Shells (Befehlsersetzung) meldet die aufrufende Ebene selbst.
  if (( BASH_SUBSHELL > 0 )); then return 0; fi
  printf '%sAbbruch%s in Zeile %s (Exit %s): %s\n' "$CR" "$C0" "$ln" "$rc" "$BASH_COMMAND" >&2
  if (( RB_ARMED )); then
    printf 'Das automatische Zurücksetzen bleibt scharf und greift in spätestens %s s.\n' "$ROLLBACK_SECS" >&2
  fi
}
trap cleanup EXIT
trap 'on_err $LINENO' ERR

mk_tmpd() { if [[ -z $TMPD ]]; then TMPD=$(mktemp -d "${TMPDIR:-/tmp}/bunny-guard.XXXXXX"); fi; }
have() { command -v "$1" >/dev/null 2>&1; }
need_root() { if [[ $EUID -ne 0 ]]; then die "Bitte mit sudo bzw. als root ausführen."; fi; }
in_list() { local n=$1 x; shift; for x in "$@"; do [[ $x == "$n" ]] && return 0; done; return 1; }
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }

# --- Eingabe -------------------------------------------------------------------
TTY_FD=""
# Terminal einmal öffnen und offen halten (alle Fragen lesen von diesem Kanal).
tty_ok() {
  if [[ -n $TTY_FD ]]; then return 0; fi
  if { exec {TTY_FD}<"$TTY_IN"; } 2>/dev/null; then return 0; fi
  TTY_FD=""
  return 1
}

# ask VAR "Frage" [Standard]
ask() {
  local __v=$1 __p=$2 __d=${3-} __a=""
  if [[ -n $__d ]]; then __p+=" [$__d]"; fi
  tty_ok || die "Keine Eingabe möglich (läuft das Skript in einem Terminal?)"
  printf '  %s: ' "$__p"
  IFS= read -r __a <&"$TTY_FD" || die "Keine Eingabe mehr (Terminal geschlossen?)"
  if [[ ! -t $TTY_FD ]]; then printf '%s\n' "$__a"; fi
  printf -v "$__v" '%s' "$(trim "${__a:-$__d}")"
}

# Auswahl zerlegen: Leerzeichen oder Komma, Bereiche "2-4", "alle"  -> Array SEL
SEL=()
split_selection() { # EINGABE MAX
  local input=${1//,/ } max=${2:-0} t a b i
  local -a raw=()
  SEL=()
  read -r -a raw <<<"$input" || true
  for t in "${raw[@]}"; do
    t=${t,,}
    if [[ $t =~ ^([0-9]{1,4})-([0-9]{1,4})$ ]]; then
      a=$((10#${BASH_REMATCH[1]})); b=$((10#${BASH_REMATCH[2]}))
      if (( a > b )); then i=$a; a=$b; b=$i; fi
      for (( i = a; i <= b; i++ )); do SEL+=("$i"); done
    elif [[ $t == alle || $t == all || $t == '*' ]] && (( max > 0 )); then
      for (( i = 1; i <= max; i++ )); do SEL+=("$i"); done
    else
      SEL+=("$t")
    fi
  done
}

# ask_yn "Frage" j|n   -> 0 = ja
ask_yn() {
  local p=$1 d=${2:-n} a hint="j/N"
  if [[ $d == j ]]; then hint="J/n"; fi
  tty_ok || die "Keine Eingabe möglich (läuft das Skript in einem Terminal?)"
  while true; do
    printf '  %s [%s]: ' "$p" "$hint"
    IFS= read -r a <&"$TTY_FD" || die "Keine Eingabe mehr (Terminal geschlossen?)"
    if [[ ! -t $TTY_FD ]]; then printf '%s\n' "$a"; fi
    a=$(trim "${a,,}"); a=${a:-$d}
    case $a in
      j|ja|y|yes) return 0 ;;
      n|nein|no)  return 1 ;;
    esac
    say "  Bitte j oder n eingeben."
  done
}

# --- Validierung ---------------------------------------------------------------
is_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

is_ipv4() {
  local a=${1%/*} p o
  [[ $a =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
  if [[ $1 == */* ]]; then
    p=${1#*/}
    [[ $p =~ ^[0-9]{1,2}$ ]] && (( 10#$p <= 32 )) || return 1
  fi
  return 0
}

is_ipv6() {
  local a=${1%/*} p t
  [[ $a == *:* && $a =~ ^[0-9A-Fa-f:.]{2,45}$ ]] || return 1
  [[ $a != *:::* ]] || return 1
  t=${a//::/}
  (( ${#a} - ${#t} <= 2 )) || return 1
  if [[ $1 == */* ]]; then
    p=${1#*/}
    [[ $p =~ ^[0-9]{1,3}$ ]] && (( 10#$p <= 128 )) || return 1
  fi
  return 0
}

is_ip_net() { is_ipv4 "$1" || is_ipv6 "$1"; }
is_ip() { [[ $1 != */* ]] && is_ip_net "$1"; }

is_domain() {
  local d=$1 tld
  (( ${#d} <= 253 )) || return 1
  [[ $d =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z0-9-]{2,63})$ ]] || return 1
  tld=${BASH_REMATCH[3]}
  [[ $tld =~ ^[a-z]{2,63}$ || $tld =~ ^xn--[a-z0-9-]+$ ]]
}

is_private_ip() {
  case $1 in
    10.*|192.168.*|127.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    fc*|fd*|fe80:*|::1) return 0 ;;
  esac
  return 1
}

# words_filter validator "liste" -> eindeutige, gültige Einträge (Leerzeichen-getrennt)
words_filter() {
  local fn=$1 w
  local -a arr=() out=()
  read -r -a arr <<<"${2-}" || true
  for w in "${arr[@]}"; do
    w=${w,,}
    if [[ $fn == is_port ]] && is_port "$w"; then w=$((10#$w)); fi
    if ! "$fn" "$w"; then
      printf '  %s!%s Ungültiger Eintrag ignoriert: %s\n' "$CY" "$C0" "$w" >&2
      continue
    fi
    if ! in_list "$w" "${out[@]}"; then out+=("$w"); fi
  done
  printf '%s' "${out[*]-}"
}

only_v4() { local w; for w in "$@"; do if is_ipv4 "$w"; then printf '%s\n' "$w"; fi; done; }
only_v6() { local w; for w in "$@"; do if is_ipv6 "$w"; then printf '%s\n' "$w"; fi; done; }

# --- Sperre --------------------------------------------------------------------
lock() { exec 9>"$LOCK_FILE"; flock -w 90 9 || die "Eine andere bunny-guard-Instanz läuft gerade."; }
# Achtung: "exec 9>&- 2>/dev/null" würde stderr dauerhaft umleiten (exec ohne
# Befehl macht alle Umleitungen permanent) – dann wären Fragen und Eingaben unsichtbar.
unlock() { flock -u 9 2>/dev/null || true; exec 9>&-; }

# --- Konfiguration -------------------------------------------------------------
sanitize_config() {
  PORTS=$(words_filter is_port "$PORTS")
  if [[ -z $PORTS ]]; then PORTS="443"; fi
  ALLOW_SRC=$(words_filter is_ip_net "$ALLOW_SRC")
  EXEMPT_DST=$(words_filter is_ip "$EXEMPT_DST")
  DIRECT_DOMAINS=$(words_filter is_domain "$DIRECT_DOMAINS")
  TEST_DOMAINS=$(words_filter is_domain "$TEST_DOMAINS")
  if [[ $ALLOW_PRIVATE != 0 ]]; then ALLOW_PRIVATE=1; fi
  if [[ $NGINX_MODE != 1 ]]; then NGINX_MODE=0; fi
  if ! [[ $UPDATE_HOURS =~ ^[0-9]{1,3}$ ]] || (( 10#$UPDATE_HOURS < 1 || 10#$UPDATE_HOURS > 168 )); then
    UPDATE_HOURS=6
  fi
  UPDATE_HOURS=$((10#$UPDATE_HOURS))
}

load_config() {
  if [[ -f $CONF_FILE ]]; then
    local own perm
    read -r own perm < <(stat -c '%u %a' "$CONF_FILE")
    if [[ $own != 0 ]]; then die "$CONF_FILE gehört nicht root – abgebrochen."; fi
    if (( (8#$perm & 8#022) != 0 )); then die "$CONF_FILE ist für Gruppe/Andere beschreibbar – abgebrochen."; fi
    # shellcheck source=/dev/null
    . "$CONF_FILE"
  fi
  sanitize_config
}

save_config() {
  install -d -m 755 "$CONF_DIR"
  local t="$CONF_FILE.tmp.$$"
  {
    printf '# bunny-guard %s – Konfiguration (geschrieben %s)\n' "$VERSION" "$(date '+%F %T')"
    printf '# Nach Änderungen von Hand: sudo bunny-guard reload\n\n'
    printf '# Ports, die nur für Bunny offen sind (TCP und UDP)\n'
    printf 'PORTS=%q\n' "$PORTS"
    printf '# Private Netze (Docker, VPN, LAN) immer erlauben: 1/0\n'
    printf 'ALLOW_PRIVATE=%q\n' "$ALLOW_PRIVATE"
    printf '# Zusätzliche erlaubte Quell-IPs/Netze (IPv4/IPv6, CIDR erlaubt)\n'
    printf 'ALLOW_SRC=%q\n' "$ALLOW_SRC"
    printf '# Ziel-IPs dieses Servers, auf denen die Ports für ALLE offen sind\n'
    printf 'EXEMPT_DST=%q\n' "$EXEMPT_DST"
    printf '# Domains, die ohne Bunny direkt erreichbar sein sollen (Info + nginx-Modus)\n'
    printf 'DIRECT_DOMAINS=%q\n' "$DIRECT_DOMAINS"
    printf '# Domains über Bunny, mit denen "bunny-guard check" testet\n'
    printf 'TEST_DOMAINS=%q\n' "$TEST_DOMAINS"
    printf '# nginx sperrt Nicht-Bunny-Besucher zusätzlich pro Domain: 1/0\n'
    printf 'NGINX_MODE=%q\n' "$NGINX_MODE"
    printf '# Bunny-Liste alle N Stunden aktualisieren\n'
    printf 'UPDATE_HOURS=%q\n' "$UPDATE_HOURS"
  } >"$t"
  chmod 644 "$t"
  mv -f "$t" "$CONF_FILE"
}

# --- Bunny-Listen --------------------------------------------------------------
list_count() { if [[ -s $1 ]]; then wc -l <"$1" | tr -d ' '; else echo 0; fi; }
read_stamp() {
  local s=0
  if [[ -f $STAMP_FILE ]]; then s=$(tr -dc '0-9' <"$STAMP_FILE" || true); fi
  printf '%s' "${s:-0}"
}
fmt_age() {
  local s=$1
  if (( s > 1000000000 )); then printf 'noch nie'; return 0; fi
  if (( s < 0 )); then s=0; fi
  if (( s < 3600 )); then printf 'vor %d min' $((s / 60))
  elif (( s < 172800 )); then printf 'vor %d h %d min' $((s / 3600)) $((s % 3600 / 60))
  else printf 'vor %d Tagen' $((s / 86400)); fi
}

# download_list 4|6 ZIELDATEI
download_list() {
  local fam=$1 dest=$2 url raw clean n bad line min
  local -a urls
  mk_tmpd
  raw="$TMPD/raw$fam" clean="$TMPD/clean$fam"
  if [[ $fam == 4 ]]; then urls=("${URLS4[@]}"); min=$MIN4; else urls=("${URLS6[@]}"); min=$MIN6; fi
  for url in "${urls[@]}"; do
    rm -f "$raw"
    if ! curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 45 \
         --retry 2 --retry-delay 3 -A "$UA" -H 'Accept: text/plain, application/json;q=0.9' \
         -o "$raw" "$url" 2>"$TMPD/curl.err"; then
      continue
    fi
    tr -d '\r[]"' <"$raw" | tr ', \t' '\n\n\n' | sed '/^$/d' | tr 'A-F' 'a-f' >"$clean" || true
    n=0 bad=0
    while IFS= read -r line; do
      if [[ $fam == 4 ]]; then
        is_ipv4 "$line" || { bad=1; break; }
      else
        is_ipv6 "$line" || { bad=1; break; }
      fi
      n=$((n + 1))
    done <"$clean"
    if (( bad == 0 && n >= min )); then
      LC_ALL=C sort -u "$clean" >"$dest" || return 1
      return 0
    fi
  done
  return 1
}

# update_lists 0|1(force)  -> 0, wenn danach beide Listen vorhanden sind
update_lists() {
  local force=${1:-0} fam file new old_n new_n added removed rc=0
  mk_tmpd
  install -d -m 755 "$STATE_DIR" || return 1
  for fam in 4 6; do
    if [[ $fam == 4 ]]; then file=$LIST4; else file=$LIST6; fi
    new="$TMPD/new$fam"
    if ! download_list "$fam" "$new"; then
      if [[ -s $file ]]; then
        warn "IPv$fam-Liste konnte nicht geladen werden – bisherige Liste bleibt ($(list_count "$file") Einträge)."
      else
        bad "IPv$fam-Liste konnte nicht geladen werden."
        rc=1
      fi
      continue
    fi
    old_n=$(list_count "$file"); new_n=$(list_count "$new")
    if [[ $force != 1 ]] && (( old_n > 0 && new_n * 2 < old_n )); then
      warn "Neue IPv$fam-Liste hat nur $new_n statt $old_n Einträgen – verdächtig, alte Liste bleibt (erzwingen: bunny-guard update --force)."
      continue
    fi
    if [[ -s $file ]]; then
      added=$(LC_ALL=C comm -13 "$file" "$new" | wc -l) || added=0
      removed=$(LC_ALL=C comm -23 "$file" "$new" | wc -l) || removed=0
    else
      added=$new_n removed=0
    fi
    if (( added + removed > 0 )); then LISTS_CHANGED=1; fi
    install -m 644 "$new" "$file" || return 1
    ok "IPv$fam: $new_n Bunny-IPs (+$added / -$removed)"
  done
  if (( rc == 0 )); then date +%s >"$STAMP_FILE"; fi
  return $rc
}

# valid_lines 4|6 DATEI -> nur gültige Adressen (schützt vor beschädigtem Cache;
# nft würde unbekannte Wörter sonst als Hostnamen per DNS auflösen)
valid_lines() {
  local fam=$1 line
  [[ -f $2 ]] || return 0
  while IFS= read -r line; do
    if [[ $fam == 4 ]]; then
      if is_ipv4 "$line"; then printf '%s\n' "$line"; fi
    elif is_ipv6 "$line"; then
      printf '%s\n' "$line"
    fi
  done <"$2"
}

ip_in_bunny() {
  local f=$LIST4
  if [[ $1 == *:* ]]; then f=$LIST6; fi
  [[ -s $f ]] && grep -qxF -- "$1" "$f"
}

# --- nftables ------------------------------------------------------------------
join_nft() { paste -sd, - | sed 's/,/, /g'; }

# set_block NAME TYP INTERVALL(0|1) "zeilen"
set_block() {
  local name=$1 type=$2 interval=$3 data=$4 elems
  elems=$(printf '%s\n' "$data" | sed '/^$/d' | join_nft)
  printf '\tset %s {\n\t\ttype %s\n' "$name" "$type"
  if [[ $interval == 1 ]]; then printf '\t\tflags interval\n\t\tauto-merge\n'; fi
  if [[ -n $elems ]]; then printf '\t\telements = { %s }\n' "$elems"; fi
  printf '\t}\n'
}

build_ruleset() {
  local -a allow=() exempt=() ports=() priv=()
  local plist
  read -r -a allow <<<"$ALLOW_SRC" || true
  if [[ $ALLOW_PRIVATE == 1 ]]; then read -r -a priv <<<"$PRIVATE_NETS" || true; allow+=("${priv[@]}"); fi
  read -r -a exempt <<<"$EXEMPT_DST" || true
  read -r -a ports <<<"$PORTS" || true
  plist=$(printf '%s\n' "${ports[@]}" | join_nft)
  cat <<EOF
# Erzeugt von bunny-guard $VERSION am $(date '+%F %T') – nicht von Hand bearbeiten.
# Einstellungen: $CONF_FILE, danach: bunny-guard reload
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {
	counter c_bunny { }
	counter c_allow { }
	counter c_exempt { }
	counter c_drop { }
EOF
  set_block bunny4 ipv4_addr 1 "$(valid_lines 4 "$LIST4")"
  set_block bunny6 ipv6_addr 1 "$(valid_lines 6 "$LIST6")"
  set_block allow4 ipv4_addr 1 "$(only_v4 "${allow[@]}")"
  set_block allow6 ipv6_addr 1 "$(only_v6 "${allow[@]}")"
  set_block exempt4 ipv4_addr 0 "$(only_v4 "${exempt[@]}")"
  set_block exempt6 ipv6_addr 0 "$(only_v6 "${exempt[@]}")"
  # input:   Verbindungen an den Server selbst (nginx, Apache, Caddy ...)
  # forward: per DNAT weitergeleitete Verbindungen (Docker-Ports) – geprüft
  #          wird der ursprüngliche Zielport bzw. die ursprüngliche Ziel-IP.
  cat <<EOF
	chain input {
		type filter hook input priority -10; policy accept;
		iifname "lo" accept
		tcp dport { $plist } jump guard_in
		udp dport { $plist } jump guard_in
	}
	chain forward {
		type filter hook forward priority -10; policy accept;
		ct status dnat meta l4proto { tcp, udp } ct original proto-dst { $plist } jump guard_fwd
	}
	chain guard_in {
		ip saddr @bunny4 counter name c_bunny accept
		ip6 saddr @bunny6 counter name c_bunny accept
		ip saddr @allow4 counter name c_allow accept
		ip6 saddr @allow6 counter name c_allow accept
		ip daddr @exempt4 counter name c_exempt accept
		ip6 daddr @exempt6 counter name c_exempt accept
		counter name c_drop drop
	}
	chain guard_fwd {
		ip saddr @bunny4 counter name c_bunny accept
		ip6 saddr @bunny6 counter name c_bunny accept
		ip saddr @allow4 counter name c_allow accept
		ip6 saddr @allow6 counter name c_allow accept
		ct original ip daddr @exempt4 counter name c_exempt accept
		ct original ip6 daddr @exempt6 counter name c_exempt accept
		counter name c_drop drop
	}
}
EOF
}

table_loaded() { nft list table inet "$TABLE" >/dev/null 2>&1; }

apply_rules() {
  mk_tmpd
  if [[ ! -s $LIST4 || ! -s $LIST6 ]]; then bad "Keine Bunny-IP-Listen vorhanden."; return 1; fi
  local f="$TMPD/ruleset.nft" n4 n6
  n4=$(valid_lines 4 "$LIST4" | wc -l) || n4=0
  n6=$(valid_lines 6 "$LIST6" | wc -l) || n6=0
  if (( n4 < MIN4 || n6 < MIN6 )); then
    bad "Bunny-Liste im Cache ist beschädigt ($n4 gültige IPv4 / $n6 gültige IPv6) – bitte: bunny-guard update --force"
    return 1
  fi
  build_ruleset >"$f" || return 1
  if ! nft -c -f "$f" 2>"$TMPD/nft.err"; then
    bad "nftables lehnt den Regelsatz ab:"
    sed 's/^/      /' "$TMPD/nft.err" | head -n 20
    return 1
  fi
  if ! nft -f "$f" 2>"$TMPD/nft.err"; then
    bad "nftables-Regeln konnten nicht geladen werden:"
    sed 's/^/      /' "$TMPD/nft.err" | head -n 20
    return 1
  fi
  install -d -m 755 "$STATE_DIR" || return 1
  install -m 600 "$f" "$RULESET" || return 1
  return 0
}

counter_val() {
  local v
  v=$(nft list counter inet "$TABLE" "$1" 2>/dev/null \
      | awk '{for (i = 1; i < NF; i++) if ($i == "packets") {print $(i + 1); exit}}') || true
  printf '%s' "${v:-0}"
}

nft_probe() {
  mk_tmpd
  local f="$TMPD/probe.nft"
  cat >"$f" <<'EOF'
table inet bunny_guard_probe
delete table inet bunny_guard_probe
table inet bunny_guard_probe {
	counter c { }
	set s4 {
		type ipv4_addr
		flags interval
		auto-merge
		elements = { 192.0.2.1, 192.0.2.2, 198.51.100.0/24 }
	}
	set e6 {
		type ipv6_addr
	}
	chain probe_in {
		type filter hook input priority -10; policy accept;
		tcp dport { 65000 } jump probe_g
	}
	chain probe_fwd {
		type filter hook forward priority -10; policy accept;
		ct status dnat meta l4proto { tcp, udp } ct original proto-dst { 65000 } jump probe_g
	}
	chain probe_g {
		ip saddr @s4 counter name c accept
		ct original ip6 daddr @e6 accept
	}
}
EOF
  if ! nft -f "$f" 2>"$TMPD/probe.err"; then sed 's/^/      /' "$TMPD/probe.err" >&2; return 1; fi
  nft delete table inet bunny_guard_probe 2>/dev/null || true
  return 0
}

# --- Netzwerk-Infos ------------------------------------------------------------
gather_local_ips() {
  LOCAL_IPS=() LOCAL_IFS=()
  local ifc ip
  while read -r ifc ip; do
    [[ -n $ip ]] || continue
    LOCAL_IPS+=("${ip,,}"); LOCAL_IFS+=("$ifc")
  done < <(ip -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print $2, a[1]}' || true)
}
is_local_ip() { in_list "${1,,}" "${LOCAL_IPS[@]}"; }

ssh_ports() {
  ss -ltnp 2>/dev/null | awk 'NR > 1 && /"sshd"/ {n = split($4, a, ":"); print a[n]}' | sort -u || true
}

listeners() { # PORT PROTO(t|u)
  local out
  out=$(ss -l"$2"np "( sport = :$1 )" 2>/dev/null | awk 'NR > 1' | grep -oE '"[^"]+"' | tr -d '"' | sort -u | paste -sd, - || true)
  printf '%s' "$out"
}

# --- DNS / Domains -------------------------------------------------------------
dns_lookup() { # NAME A|AAAA -> CNAME-Ziele und Adressen
  local name=$1 type=$2
  if have dig; then
    dig +short +time=2 +tries=2 "$name" "$type" 2>/dev/null | grep -v '^;' || true
  elif have host; then
    host -W 3 -t "$type" "$name" 2>/dev/null \
      | awk '/is an alias for/ {print $NF} /has address/ {print $NF} /has IPv6 address/ {print $NF}' || true
  elif [[ $type == A ]]; then
    getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u || true
  else
    getent ahostsv6 "$name" 2>/dev/null | awk '{print $1}' | grep -v '^::ffff:' | sort -u || true
  fi
}

classify_domain() { # -> CL_STAT bunny|direct|external|none, CL_TGT, CL_LOCAL, CL_IPS
  local d=$1 r cname="" isb=0 ip
  local -a ips=() loc=()
  while IFS= read -r r; do
    r=${r,,}; r=${r%.}
    [[ -n $r ]] || continue
    if is_ipv4 "$r" || is_ipv6 "$r"; then
      if ! in_list "$r" "${ips[@]}"; then ips+=("$r"); fi
    else
      if [[ -z $cname ]]; then cname=$r; fi
      if [[ $r =~ (^|\.)(b-cdn\.net|bunnycdn\.com|bunny\.net|bunnyinfra\.net)$ ]]; then isb=1; fi
    fi
  done < <({ dns_lookup "$d" A; dns_lookup "$d" AAAA; } 2>/dev/null || true)
  for ip in "${ips[@]}"; do
    if is_local_ip "$ip"; then loc+=("$ip"); fi
    if ip_in_bunny "$ip"; then isb=1; fi
  done
  CL_LOCAL="${loc[*]-}"
  CL_IPS="${ips[*]-}"
  if (( ${#loc[@]} > 0 )); then CL_STAT=direct
  elif (( isb )); then CL_STAT=bunny
  elif (( ${#ips[@]} == 0 )); then CL_STAT=none
  else CL_STAT=external; fi
  if [[ -n $cname ]]; then
    CL_TGT="CNAME $cname"
  elif (( ${#ips[@]} > 0 )); then
    CL_TGT="${ips[0]}"
    if (( ${#ips[@]} > 1 )); then CL_TGT+=" (+$(( ${#ips[@]} - 1 )))"; fi
  else
    CL_TGT="–"
  fi
}

stat_label() {
  case $1 in
    bunny)    printf '%süber Bunny%s' "$CG" "$C0" ;;
    direct)   printf '%sDIREKT auf diesen Server%s' "$CY" "$C0" ;;
    external) printf 'anderer Server/CDN' ;;
    *)        printf '%skeine DNS-Antwort%s' "$CD" "$C0" ;;
  esac
}

raw_domains() { # Zeilen "domain<TAB>quelle"
  local c f
  if have nginx; then
    nginx -T 2>/dev/null | sed 's/#.*$//' | awk '
      { buf = buf $0 " " }
      END {
        n = split(buf, parts, ";")
        for (i = 1; i <= n; i++) {
          s = parts[i]
          if (match(s, /(^|[[:space:]{}])server_name[[:space:]]/)) {
            s = substr(s, RSTART + RLENGTH)
            m = split(s, t, /[[:space:]]+/)
            for (j = 1; j <= m; j++) if (t[j] != "") print t[j] "\tnginx"
          }
        }
      }' || true
  fi
  for c in apache2ctl apachectl httpd; do
    if have "$c"; then
      "$c" -S 2>/dev/null | awk '{
        for (i = 1; i < NF; i++) {
          if ($i == "namevhost" || $i == "alias") print $(i + 1) "\tapache"
          if (i > 1 && $i == "server" && $(i - 1) == "default") print $(i + 1) "\tapache"
        }}' || true
      break
    fi
  done
  if [[ -f /etc/caddy/Caddyfile ]]; then
    awk '{
      line = $0; sub(/#.*/, "", line)
      if (depth == 0 && line ~ /\{[[:space:]]*$/) {
        a = line; sub(/\{[[:space:]]*$/, "", a)
        n = split(a, t, /[[:space:],]+/)
        for (i = 1; i <= n; i++) if (t[i] != "" && t[i] !~ /^\(/) print t[i] "\tcaddy"
      }
      o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line); depth += o - c
    }' /etc/caddy/Caddyfile || true
  fi
  if [[ -d /etc/letsencrypt/live ]] && have openssl; then
    for f in /etc/letsencrypt/live/*/cert.pem; do
      [[ -f $f ]] || continue
      openssl x509 -in "$f" -noout -text 2>/dev/null | grep -oE 'DNS:[^,[:space:]]+' \
        | sed 's/^DNS://; s/$/\tzertifikat/' || true
    done
  fi
}

detect_domains() { # eindeutige Zeilen "domain<TAB>quelle1,quelle2", sortiert nach Hauptdomain
  local d s
  raw_domains | while IFS=$'\t' read -r d s; do
    d=${d,,}; d=${d#http://}; d=${d#https://}; d=${d%%/*}
    if [[ $d =~ ^([^:]+):[0-9]+$ ]]; then d=${BASH_REMATCH[1]}; fi
    d=${d%.}; d=${d#.}
    if is_domain "$d"; then printf '%s\t%s\n' "$d" "$s"; fi
  done | LC_ALL=C sort -u | awk -F'\t' '
      { if ($1 == p) s = s "," $2; else { if (p != "") print p "\t" s; p = $1; s = $2 } }
      END { if (p != "") print p "\t" s }' \
    | awk -F'\t' '{ n = split($1, L, "."); k = ""; for (i = n; i > 0; i--) k = k L[i] "."; print k "\t" $0 }' \
    | LC_ALL=C sort | cut -f2- || true
}

add_domain() { # NAME QUELLE
  classify_domain "$1"
  DOM_NAME+=("$1"); DOM_SRC+=("$2"); DOM_STAT+=("$CL_STAT"); DOM_TGT+=("$CL_TGT")
  DOM_LOCAL+=("$CL_LOCAL"); DOM_IPS+=("$CL_IPS")
}

dom_index() { local i; for i in "${!DOM_NAME[@]}"; do if [[ ${DOM_NAME[i]} == "$1" ]]; then printf '%s' "$i"; return 0; fi; done; return 1; }

print_domain_table() {
  local i tgt
  printf '  %s%3s  %-36s %-34s %s%s\n' "$CB" "Nr" "Domain" "DNS" "Einschätzung" "$C0"
  for i in "${!DOM_NAME[@]}"; do
    tgt=${DOM_TGT[i]}
    if (( ${#tgt} > 34 )); then tgt="${tgt:0:31}..."; fi
    printf '  %3d  %-36s %-34s %s\n' $((i + 1)) "${DOM_NAME[i]}" "$tgt" "$(stat_label "${DOM_STAT[i]}")"
  done
}

print_local_ips() {
  local i tag
  for i in "${!LOCAL_IPS[@]}"; do
    tag="öffentlich"
    if is_private_ip "${LOCAL_IPS[i]}"; then tag="privat/intern"; fi
    printf '  %3d  %-40s %-12s %s\n' $((i + 1)) "${LOCAL_IPS[i]}" "${LOCAL_IFS[i]}" "$tag"
  done
}

# --- Tests ---------------------------------------------------------------------
hdr_val() { # HEADERNAME "header"
  local k=${1,,}
  awk -v k="$k" '{ l = $0; n = index(l, ":"); if (n > 0 && tolower(substr(l, 1, n - 1)) == k) { v = substr(l, n + 1); sub(/^[[:space:]]+/, "", v) } } END { print v }' <<<"$2"
}

# probe_bunny DOMAIN -> PROBE_RES ok|warn|fail, PROBE_MSG
probe_bunny() {
  local d=$1 hdr rc code server pull pullcode cache ip=""
  local -a resolve=()
  mk_tmpd
  while IFS= read -r ip; do
    ip=${ip%.}
    if is_ipv4 "$ip"; then break; fi
    ip=""
  done < <(dns_lookup "$d" A)
  if [[ -n $ip ]]; then resolve=(--resolve "$d:443:$ip"); fi
  rc=0
  hdr=$(curl -sS -o /dev/null -D - --connect-timeout 10 --max-time 35 -A "$UA" \
        -H 'Cache-Control: no-cache' "${resolve[@]}" \
        "https://$d/?bunny-guard-check=$(date +%s)$RANDOM" 2>"$TMPD/probe.err") || rc=$?
  hdr=$(tr -d '\r' <<<"$hdr")
  code=$(awk '/^HTTP\// {c = $2} END {print c}' <<<"$hdr")
  server=$(hdr_val server "$hdr")
  pull=$(hdr_val cdn-requestpullsuccess "$hdr")
  pullcode=$(hdr_val cdn-requestpullcode "$hdr")
  cache=$(hdr_val cdn-cache "$hdr")
  if (( rc != 0 )) && [[ -z $code ]]; then
    # Die Verbindung Besucher -> Bunny-Edge hat mit der Firewall nichts zu tun.
    PROBE_RES=warn
    PROBE_MSG="Bunny-Edge nicht erreichbar oder TLS-Fehler – Hostname in der Pull-Zone eingetragen? ($(head -n 1 "$TMPD/probe.err" 2>/dev/null | cut -c1-70))"
  elif [[ ${server,,} != bunnycdn* ]]; then
    PROBE_RES=warn; PROBE_MSG="HTTP $code, aber die Antwort kam nicht von Bunny (Server: ${server:-?}) – DNS/hosts prüfen"
  elif [[ ${pull,,} == false ]]; then
    PROBE_RES=fail; PROBE_MSG="Bunny erreicht den Server NICHT (HTTP $code, Pull-Code ${pullcode:-?})"
  elif [[ $code == 502 || $code == 504 ]] && [[ ${pull,,} != true ]]; then
    PROBE_RES=fail; PROBE_MSG="Bunny meldet HTTP $code – Server vermutlich nicht erreichbar"
  elif [[ ${cache^^} == HIT* && ${pull,,} != true ]]; then
    PROBE_RES=warn; PROBE_MSG="HTTP $code aus dem Bunny-Cache – Verbindung zum Server nicht bewiesen"
  else
    PROBE_RES=ok; PROBE_MSG="über Bunny erreichbar (HTTP $code, Pull ${pullcode:-?}, Cache ${cache:-?})"
  fi
}

probe_port() { if in_list 443 $PORTS; then echo 443; else echo "${PORTS%% *}"; fi; }

# local_probe DOMAIN IP -> curl-Exitcode (52 = leere Antwort = nginx 444)
local_probe() {
  local d=$1 ip=$2 r rc=0 p
  p=$(probe_port); r=$ip
  if [[ $ip == *:* ]]; then r="[$ip]"; fi
  curl -sk -o /dev/null --connect-timeout 5 --max-time 12 -A "$UA" --resolve "$d:$p:$r" "https://$d:$p/" 2>/dev/null || rc=$?
  return $rc
}

# site_served DOMAIN IP -> 0 = Webserver liefert DOMAIN auf IP aus,
#                          1 = nicht (anderes Zertifikat/keine Verbindung), 2 = gesperrt (nginx 444)
site_served() {
  local d=$1 ip=$2 r rc=0 err p
  p=$(probe_port); r=$ip
  if [[ $ip == *:* ]]; then r="[$ip]"; fi
  err=$(curl -sS -o /dev/null --connect-timeout 5 --max-time 12 -A "$UA" --resolve "$d:$p:$r" "https://$d:$p/" 2>&1) || rc=$?
  # 52/56: Verbindung ohne Antwort geschlossen = nginx "return 444"
  # (OpenSSL 3 meldet das als "unexpected eof" -> curl 56)
  case $rc in
    0) return 0 ;;
    52|56) return 2 ;;
    51|60)
      err=${err,,}
      # Zertifikat passt nicht zur Domain -> nginx hat einen anderen server-Block gewählt
      if [[ $err == *"subject name"* || $err == *"does not match"* || $err == *"no alternative"* ]]; then return 1; fi
      rc=0; local_probe "$d" "$ip" || rc=$?
      if (( rc == 0 )); then return 0; elif (( rc == 52 || rc == 56 )); then return 2; fi
      return 1
      ;;
  esac
  return 1
}

# external_tcp_test IP PORT -> EXT_OK EXT_FAIL EXT_TOTAL, Rückgabe 2 = Dienst nicht erreichbar
external_tcp_test() {
  local ip=$1 port=$2 resp="" id="" res="" i
  EXT_OK=0 EXT_FAIL=0 EXT_TOTAL=0
  for i in 1 2 3; do
    resp=$(curl -fsS --max-time 20 -A "$UA" -H 'Accept: application/json' \
           "https://check-host.net/check-tcp?host=${ip}:${port}&max_nodes=6" 2>/dev/null) || resp=""
    id=$(sed -nE 's/.*"request_id"[[:space:]]*:[[:space:]]*"([A-Za-z0-9]+)".*/\1/p' <<<"$resp")
    if [[ -n $id ]]; then break; fi
    if [[ $resp == *limit_exceeded* ]]; then note "check-host.net: Limit erreicht, warte 15 s ..."; sleep 15; else sleep 3; fi
  done
  if [[ -z $id ]]; then return 2; fi
  for i in $(seq 1 15); do
    sleep 2
    res=$(curl -fsS --max-time 15 -A "$UA" -H 'Accept: application/json' \
          "https://check-host.net/check-result/$id" 2>/dev/null) || continue
    if [[ ${res// /} != *:null* ]]; then break; fi
  done
  EXT_OK=$(grep -o '"time"' <<<"$res" | wc -l) || EXT_OK=0
  EXT_FAIL=$(grep -o '"error"' <<<"$res" | wc -l) || EXT_FAIL=0
  EXT_TOTAL=$(grep -o '\.node\.check-host\.net"' <<<"$res" | wc -l) || EXT_TOTAL=0
  return 0
}

# --- Firewall-Abgleich (UFW / firewalld) --------------------------------------
ufw_active() {
  have ufw || return 1
  local s
  s=$(LC_ALL=C ufw status 2>/dev/null) || return 1
  [[ $s == *"Status: active"* ]]
}

ufw_to_covers() { # TO-SPALTE PORT
  local to=$1 port=$2 spec proto item a b info p
  local -a items=()
  if [[ $to == Anywhere* ]]; then return 0; fi
  if [[ $to =~ ^([0-9][0-9,:]*)(/(tcp|udp))?$ ]]; then
    spec=${BASH_REMATCH[1]}; proto=${BASH_REMATCH[3]}
    if [[ $proto == udp ]]; then return 1; fi
    IFS=, read -r -a items <<<"$spec" || true
    for item in "${items[@]}"; do
      if [[ $item == *:* ]]; then
        a=${item%%:*}; b=${item##*:}
        if [[ $a =~ ^[0-9]+$ && $b =~ ^[0-9]+$ ]] && (( port >= a && port <= b )); then return 0; fi
      elif [[ $item == "$port" ]]; then
        return 0
      fi
    done
    return 1
  fi
  info=$(LC_ALL=C ufw app info "$to" 2>/dev/null) || return 1
  while IFS= read -r p; do
    p=$(trim "$p")
    if [[ -n $p ]] && ufw_to_covers "$p" "$port"; then return 0; fi
  done < <(sed -n '/^Ports:/,$p' <<<"$info" | sed '1d')
  return 1
}

ufw_allows_any() { # PORT -> 0, wenn UFW TCP PORT von überall erlaubt
  local port=$1 st line to from
  st=$(LC_ALL=C ufw status 2>/dev/null) || return 1
  while IFS= read -r line; do
    [[ $line == *" ALLOW"* ]] || continue
    to=$(trim "${line%% ALLOW*}")
    from=${line#* ALLOW}
    from=$(trim "${from%%#*}")
    from=$(trim "${from#IN}")
    [[ $from == Anywhere* ]] || continue
    to=${to% (v6)}
    if ufw_to_covers "$to" "$port"; then return 0; fi
  done <<<"$st"
  return 1
}

ufw_labeled_rules() { # nummerierte UFW-Regeln mit Bunny-/Gcore-Kommentar
  local st
  st=$(LC_ALL=C ufw status numbered 2>/dev/null) || return 0
  grep -Ei '^\[[[:space:]]*[0-9]+\].*(bunny[[:space:]_-]?cdn|(^|[^a-z])g[[:space:]_-]?core([^a-z]|$))' <<<"$st" || true
}

firewalld_active() { have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; }
firewalld_allows() {
  local p=$1
  if firewall-cmd --quiet --query-port="$p/tcp" 2>/dev/null; then return 0; fi
  case $p in
    443) firewall-cmd --quiet --query-service=https 2>/dev/null && return 0 ;;
    80)  firewall-cmd --quiet --query-service=http 2>/dev/null && return 0 ;;
  esac
  return 1
}

record_rule() {
  install -d -m 755 "$STATE_DIR" "$RB_DIR"
  printf '%s\n' "$1" >>"$ADDED_RULES"
  printf '%s\n' "$1" >>"$RB_DIR/added-rules"
}

fw_add() { # "ufw 443/tcp" | "firewalld 443/tcp"
  local kind=${1%% *} spec=${1#* } out
  case $kind in
    ufw)
      if ! out=$(ufw allow "$spec" comment 'bunny-guard: Filter per nftables' 2>&1); then
        bad "ufw allow $spec fehlgeschlagen: $out"; return 0
      fi
      if [[ $out == *"Rule added"* ]]; then
        record_rule "ufw $spec"; ok "UFW: $spec erlaubt (die Filterung übernimmt bunny-guard)"
      else
        note "UFW: $(head -n 1 <<<"$out")"
      fi
      ;;
    firewalld)
      if firewall-cmd --quiet --add-port="$spec" && firewall-cmd --quiet --permanent --add-port="$spec"; then
        record_rule "firewalld $spec"; ok "firewalld: $spec erlaubt (die Filterung übernimmt bunny-guard)"
      else
        bad "firewalld: $spec konnte nicht freigegeben werden"
      fi
      ;;
  esac
}

fw_remove_recorded() { # DATEI
  local kind spec list
  mk_tmpd
  list="$TMPD/remove-rules"
  cp -f "$1" "$list"
  while read -r kind spec; do
    [[ -n $kind ]] || continue
    case $kind in
      ufw)
        if ufw --force delete allow "$spec" >/dev/null 2>&1; then ok "UFW-Regel entfernt: allow $spec"
        else warn "UFW-Regel allow $spec konnte nicht entfernt werden"; fi
        ;;
      firewalld)
        firewall-cmd --quiet --remove-port="$spec" >/dev/null 2>&1 || true
        firewall-cmd --quiet --permanent --remove-port="$spec" >/dev/null 2>&1 || true
        ok "firewalld: $spec entfernt"
        ;;
    esac
    if [[ -f $ADDED_RULES ]]; then
      grep -vxF -- "$kind $spec" "$ADDED_RULES" >"$ADDED_RULES.tmp" || true
      mv -f "$ADDED_RULES.tmp" "$ADDED_RULES"
    fi
  done <"$list"
}

ufw_cleanup_apply() { # Regelzeilen ...
  local stamp backup n line cur
  local -a nums=()
  local -A expect=()
  stamp=$(date +%Y%m%d-%H%M%S)
  backup="/root/ufw-cdn-backup-$stamp"
  mkdir -m 700 "$backup"
  ufw status numbered >"$backup/ufw-status-numbered.txt" 2>&1 || true
  ufw status verbose >"$backup/ufw-status-verbose.txt" 2>&1 || true
  if have iptables-save; then iptables-save >"$backup/iptables-save.v4" 2>/dev/null || true; fi
  if have ip6tables-save; then ip6tables-save >"$backup/ip6tables-save.v6" 2>/dev/null || true; fi
  if [[ -d /etc/ufw ]]; then cp -a /etc/ufw "$backup/ufw-config"; fi
  ok "Backup: $backup"
  for line in "$@"; do
    n=$(sed -nE 's/^\[[[:space:]]*([0-9]+)\].*/\1/p' <<<"$line")
    if [[ -n $n ]]; then expect[$n]=$line; fi
  done
  mapfile -t nums < <(printf '%s\n' "${!expect[@]}" | sort -nru)
  # Höchste Nummer zuerst löschen, damit die übrigen Nummern gültig bleiben.
  for n in "${nums[@]}"; do
    cur=$(LC_ALL=C ufw status numbered 2>/dev/null | grep -E "^\[[[:space:]]*$n\]" || true)
    if [[ $cur != "${expect[$n]}" ]]; then warn "Regel Nr. $n hat sich verändert – übersprungen"; continue; fi
    if ufw --force delete "$n" >/dev/null 2>&1; then ok "UFW-Regel Nr. $n entfernt"; else bad "UFW-Regel Nr. $n konnte nicht entfernt werden"; fi
  done
  note "Backup liegt unter $backup"
}

# --- nginx-Modus ---------------------------------------------------------------
nginx_present() { have nginx && [[ -d /etc/nginx ]]; }
nginx_test() { nginx -t >/dev/null 2>&1; }
nginx_reload() {
  if systemctl is-active --quiet nginx 2>/dev/null; then systemctl reload nginx 2>/dev/null || true
  else nginx -s reload 2>/dev/null || true; fi
}
nginx_dump() { nginx -T 2>/dev/null || true; }

nginx_write_snippet() {
  install -d -m 755 "$(dirname "$NGINX_SNIPPET")"
  cat >"$NGINX_SNIPPET" <<EOF
# bunny-guard: lässt nur BunnyCDN (und erlaubte Quellen) durch, alle anderen
# bekommen eine leere Antwort (444). Wird von bunny-guard verwaltet.
# Einbinden in server-Blöcke, die NUR über Bunny erreichbar sein sollen:
#     include $NGINX_SNIPPET;
if (\$bunny_guard_ok = 0) {
    return 444;
}
EOF
}

nginx_geo_content() { # QUELLVARIABLE(oder leer) OFFEN(0|1)
  local srcvar=$1 open=$2 x
  local -a allow=() priv=()
  read -r -a allow <<<"$ALLOW_SRC" || true
  if [[ $ALLOW_PRIVATE == 1 ]]; then read -r -a priv <<<"$PRIVATE_NETS" || true; allow+=("${priv[@]}"); fi
  printf '# Erzeugt von bunny-guard %s am %s – wird automatisch aktualisiert.\n' "$VERSION" "$(date '+%F %T')"
  if [[ $open == 1 ]]; then printf '# bunny-guard ist deaktiviert: alle Besucher erlaubt.\n'; fi
  printf 'geo %s$bunny_guard_ok {\n' "$srcvar"
  printf '    default %s;\n' "$open"
  printf '    127.0.0.0/8 1;\n    ::1 1;\n'
  for x in "${allow[@]}"; do printf '    %s 1;\n' "$x"; done
  { valid_lines 4 "$LIST4"; valid_lines 6 "$LIST6"; } | sed 's/^.*$/    & 1;/'
  printf '}\n'
}

# nginx_apply_geo OFFEN(0|1) -> 0 bei Erfolg (inkl. Reload)
nginx_apply_geo() {
  local open=${1:-0} had=0 srcvar
  nginx_present || return 1
  mk_tmpd
  if [[ -f $NGINX_GEO ]]; then cp -a "$NGINX_GEO" "$TMPD/geo.bak"; had=1; fi
  install -d -m 755 "$(dirname "$NGINX_GEO")" || return 1
  if [[ ! -f $NGINX_SNIPPET ]]; then nginx_write_snippet || return 1; fi
  for srcvar in '$realip_remote_addr ' ''; do
    nginx_geo_content "$srcvar" "$open" >"$NGINX_GEO.tmp" || return 1
    mv -f "$NGINX_GEO.tmp" "$NGINX_GEO"
    if nginx_test; then nginx_reload; return 0; fi
  done
  if (( had )); then cp -a "$TMPD/geo.bak" "$NGINX_GEO"; else rm -f "$NGINX_GEO"; fi
  return 1
}

nginx_config_files() {
  local f
  nginx_dump | sed -n 's/^# configuration file \(.*\):$/\1/p' | LC_ALL=C sort -u | while IFS= read -r f; do
    if [[ $f == /etc/nginx/* && -f $f && $f != "$NGINX_GEO" && $f != "$NGINX_SNIPPET" && $f != *stream* ]]; then
      printf '%s\n' "$f"
    fi
  done || true
}

# awk-Programm: fügt "include <snippet>;" in server-Blöcke ein, die auf einem
# geschützten Port lauschen und keine direkte Domain enthalten.
read -r -d '' NGINX_AWK <<'AWK' || true
function cnt(s, c,   n, i) { n = 0; for (i = 1; i <= length(s); i++) if (substr(s, i, 1) == c) n++; return n }
function clean(s) { gsub(/"[^"]*"/, "", s); gsub(/\047[^\047]*\047/, "", s); sub(/#.*/, "", s); return s }
function flush(   i, ind) {
  for (i = 1; i <= nl; i++) {
    print L[i]
    if (i == ins_after) {
      match(L[i], /^[[:space:]]*/); ind = substr(L[i], 1, RLENGTH)
      if (!sn_end) ind = ind "    "
      print ind inc
    }
  }
}
BEGIN { nd = split(direct, D, " "); for (i = 1; i <= nd; i++) isD[D[i]] = 1; depth = 0; inblk = 0; inskip = 0 }
{
  raw = $0; s = clean(raw)
  # stream-/mail-Kontexte kennen kein "if" -> dort nichts einfügen
  if (!inblk && !inskip && s ~ /^[[:space:]]*(stream|mail)[[:space:]]*\{/) { inskip = 1; sdepth = depth }
  if (!inblk && !inskip && s ~ /(^|[[:space:];{}])server[[:space:]]*\{/) {
    inblk = 1; bdepth = depth; nl = 0; listen_ok = 0; has_direct = 0; has_inc = 0; sn_end = 0; sn_open = 0; names = ""
  }
  if (inblk) {
    L[++nl] = raw
    if (depth == bdepth + 1) {
      if (s ~ /^[[:space:]]*listen[[:space:]]/ && s ~ portre) listen_ok = 1
      if (index(raw, snip) > 0) has_inc = 1
      if (sn_open || s ~ /^[[:space:]]*server_name([[:space:]]|$)/) {
        t = s; sub(/^[[:space:]]*server_name/, "", t)
        semi = index(t, ";"); if (semi > 0) t = substr(t, 1, semi - 1)
        n = split(t, T, /[[:space:]]+/)
        for (i = 1; i <= n; i++) { x = tolower(T[i]); sub(/\.$/, "", x); if (x != "") { names = names " " x; if (x in isD) has_direct = 1 } }
        if (semi > 0) { sn_open = 0; sn_end = nl } else sn_open = 1
      }
    }
  }
  depth += cnt(s, "{") - cnt(s, "}")
  if (inskip && depth <= sdepth) inskip = 0
  if (inblk && depth <= bdepth) {
    ins_after = 0
    if (names == "") names = " (ohne server_name)"
    if (listen_ok && has_inc) printf "HAS\t%s\t%s\n", FILENAME, names > "/dev/stderr"
    else if (listen_ok && has_direct) printf "SKIP\t%s\t%s\n", FILENAME, names > "/dev/stderr"
    else if (listen_ok) { ins_after = (sn_end ? sn_end : 1); printf "ADD\t%s\t%s\n", FILENAME, names > "/dev/stderr" }
    flush(); inblk = 0
  } else if (!inblk) print raw
}
END { if (inblk) { ins_after = 0; flush() } }
AWK

nginx_manual_hint() {
  note "Von Hand: in jeden server-Block (Port ${PORTS// /, }), der NUR über Bunny laufen soll, diese Zeile einfügen:"
  note "    include $NGINX_SNIPPET;"
  note "Danach: nginx -t && systemctl reload nginx – und mit 'sudo bunny-guard check' prüfen."
}

nginx_insert_includes() {
  local f i portre lg skip has bk
  local -a files=() changed=() newf=()
  mk_tmpd
  portre="(^|[[:space:]:])($(tr ' ' '|' <<<"$PORTS"))([[:space:];]|\$)"
  mapfile -t files < <(nginx_config_files)
  lg="$TMPD/nginx-ins.log"; : >"$lg"
  i=0
  for f in "${files[@]}"; do
    i=$((i + 1))
    if ! awk -v direct="$DIRECT_DOMAINS" -v inc="include $NGINX_SNIPPET;" -v snip="$NGINX_SNIPPET" \
             -v portre="$portre" "$NGINX_AWK" "$f" >"$TMPD/ngx.$i" 2>>"$lg"; then
      continue
    fi
    if ! cmp -s "$f" "$TMPD/ngx.$i"; then changed+=("$f"); newf+=("$TMPD/ngx.$i"); fi
  done
  has=$(grep -c '^HAS' "$lg" || true); skip=$(grep -c '^SKIP' "$lg" || true)
  if (( has > 0 )); then ok "$has server-Block/Blöcke binden die Sperre bereits ein"; fi
  if (( skip > 0 )); then
    warn "Diese server-Blöcke enthalten eine direkte Domain und bleiben offen:"
    grep '^SKIP' "$lg" | cut -f2- | sed 's/\t/:/; s/^/      /' || true
    note "Steht dort auch eine Bunny-Domain mit drin, trenne sie in einen eigenen server-Block."
  fi
  if (( ${#changed[@]} == 0 )); then
    if (( has == 0 )); then warn "Keine passenden server-Blöcke gefunden."; nginx_manual_hint; fi
    return 0
  fi
  say ""
  say "  In diesen server-Blöcken würde die Sperre eingefügt (alle außer den direkten Domains):"
  grep '^ADD' "$lg" | cut -f2- | sed 's/\t/:/; s/^/      /' || true
  say ""
  for i in "${!changed[@]}"; do
    diff -u "${changed[i]}" "${newf[i]}" | sed '1,2d; s/^/      /' | head -n 40 || true
  done
  say ""
  if ! ask_yn "Diese Zeilen jetzt einfügen? (Backup + nginx -t, bei Fehler automatisch zurück)" j; then
    nginx_manual_hint; return 0
  fi
  bk="$STATE_DIR/nginx-backup-$(date +%Y%m%d-%H%M%S)"
  for i in "${!changed[@]}"; do
    install -d -m 700 "$bk$(dirname "${changed[i]}")"
    cp -L --preserve=mode,ownership "${changed[i]}" "$bk${changed[i]}"
    printf '%s\n' "${changed[i]}" >>"$bk/.files"
  done
  for i in "${!changed[@]}"; do cat "${newf[i]}" >"${changed[i]}"; done
  if nginx_test; then
    nginx_reload
    printf '%s\n' "$bk" >"$RB_DIR/nginx-backup"
    ok "nginx: Sperre in ${#changed[@]} Datei(en) eingefügt und neu geladen (Backup: $bk)"
  else
    for i in "${!changed[@]}"; do cat "$bk${changed[i]}" >"${changed[i]}"; done
    bad "nginx -t ist fehlgeschlagen – Änderungen zurückgenommen:"
    nginx -t 2>&1 | sed 's/^/      /' | head -n 10 || true
    nginx_manual_hint
  fi
}

nginx_restore_backup() { # BACKUP-VERZEICHNIS
  local bk=$1 f
  [[ -f $bk/.files ]] || return 0
  while IFS= read -r f; do
    if [[ -f $bk$f ]]; then cat "$bk$f" >"$f"; fi
  done <"$bk/.files"
}

nginx_remove_includes() {
  local f
  while IFS= read -r f; do
    if grep -qF "$NGINX_SNIPPET" "$f" 2>/dev/null; then
      sed --follow-symlinks -i "\\|^[[:space:]]*include[[:space:]]\\+${NGINX_SNIPPET//./\\.};[[:space:]]*\$|d" "$f"
      ok "Sperre entfernt aus $f"
    fi
  done < <(nginx_config_files)
}

# --- Rollback ------------------------------------------------------------------
prepare_rollback() {
  rm -rf "$RB_DIR"
  install -d -m 700 "$RB_DIR"
  if [[ -f $CONF_FILE ]]; then cp -a "$CONF_FILE" "$RB_DIR/conf"; fi
  if systemctl is-active --quiet "$SVC" 2>/dev/null; then : >"$RB_DIR/was_active"; fi
  if [[ -f $NGINX_GEO ]]; then cp -a "$NGINX_GEO" "$RB_DIR/nginx-geo"; else : >"$RB_DIR/nginx-geo-new"; fi
  : >"$RB_DIR/added-rules"
}

arm_rollback() {
  have systemd-run || { warn "systemd-run fehlt – kein automatisches Zurücksetzen."; return 0; }
  systemctl stop "$RB_UNIT.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$RB_UNIT.service" "$RB_UNIT.timer" >/dev/null 2>&1 || true
  if systemd-run --quiet --unit="$RB_UNIT" --on-active="${ROLLBACK_SECS}s" --timer-property=AccuracySec=1s \
       --description="bunny-guard: automatisches Zurücksetzen" "$INSTALL_BIN" rollback --auto >/dev/null 2>&1; then
    RB_ARMED=1
  else
    warn "Automatisches Zurücksetzen konnte nicht geplant werden."
  fi
}

disarm_rollback() {
  systemctl stop "$RB_UNIT.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$RB_UNIT.service" "$RB_UNIT.timer" >/dev/null 2>&1 || true
  RB_ARMED=0
}

cmd_rollback() {
  need_root
  local auto=0
  if [[ ${1:-} == --auto ]]; then auto=1; fi
  disarm_rollback
  if [[ ! -d $RB_DIR ]]; then say "Nichts zurückzusetzen."; return 0; fi
  if (( auto )); then log "bunny-guard: keine Bestätigung erhalten – setze die letzte Einrichtung automatisch zurück."
  else log "bunny-guard: setze die letzte Einrichtung zurück."; fi
  # Zuerst die geöffneten Firewall-Regeln schließen, dann erst den Filter ändern.
  if [[ -s $RB_DIR/added-rules ]]; then fw_remove_recorded "$RB_DIR/added-rules"; fi
  local ngx=0
  if [[ -f $RB_DIR/nginx-backup ]]; then nginx_restore_backup "$(cat "$RB_DIR/nginx-backup")"; ngx=1; fi
  if [[ -f $RB_DIR/nginx-geo ]]; then
    if ! cmp -s "$RB_DIR/nginx-geo" "$NGINX_GEO"; then cp -a "$RB_DIR/nginx-geo" "$NGINX_GEO"; ngx=1; fi
  elif [[ -f $RB_DIR/nginx-geo-new && -f $NGINX_GEO ]]; then
    rm -f "$NGINX_GEO"; ngx=1
  fi
  if (( ngx )) && nginx_present; then
    if nginx_test; then nginx_reload; else warn "nginx -t schlägt nach dem Zurücksetzen fehl – bitte prüfen."; fi
  fi
  if [[ -f $RB_DIR/conf ]]; then
    install -m 644 "$RB_DIR/conf" "$CONF_FILE"
    if [[ -f $RB_DIR/was_active ]]; then
      systemctl reload-or-restart "$SVC" || true
      log "bunny-guard: vorherige Konfiguration wiederhergestellt."
    else
      systemctl disable --now "$UPD_TIMER" "$SVC" >/dev/null 2>&1 || true
      nft delete table inet "$TABLE" 2>/dev/null || true
      log "bunny-guard: Schutz wieder deaktiviert (wie vorher)."
    fi
  else
    systemctl disable --now "$UPD_TIMER" "$SVC" >/dev/null 2>&1 || true
    nft delete table inet "$TABLE" 2>/dev/null || true
    rm -f "$CONF_FILE"
    log "bunny-guard: Schutz entfernt (Zustand wie vor der Einrichtung)."
  fi
  rm -rf "$RB_DIR"
}

# --- Installation --------------------------------------------------------------
install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)
  if [[ -z $src || ! -f $src ]]; then
    die "Bitte das Skript als Datei speichern und mit 'sudo bash bunny-guard.sh' starten."
  fi
  if [[ $src != "$INSTALL_BIN" ]]; then install -m 755 "$src" "$INSTALL_BIN"; fi
}

install_units() {
  cat >"$UNIT_DIR/$SVC" <<EOF
[Unit]
Description=bunny-guard: geschützte Ports nur für BunnyCDN
Documentation=file://$INSTALL_BIN
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target
After=local-fs.target nftables.service
Conflicts=shutdown.target
PartOf=nftables.service
ReloadPropagatedFrom=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$INSTALL_BIN load
ExecReload=$INSTALL_BIN load
ExecStop=$INSTALL_BIN unload

[Install]
WantedBy=sysinit.target
EOF
  cat >"$UNIT_DIR/$UPD_SVC" <<EOF
[Unit]
Description=bunny-guard: Bunny-IP-Liste aktualisieren und Regeln prüfen
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_BIN cron
Nice=10
EOF
  cat >"$UNIT_DIR/$UPD_TIMER" <<EOF
[Unit]
Description=bunny-guard: regelmäßige Aktualisierung und Selbstheilung

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
RandomizedDelaySec=30s
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
}

ensure_deps() {
  local c pkg
  local -a missing=() pkgs=()
  for c in nft curl ip ss flock awk; do have "$c" || missing+=("$c"); done
  if (( ${#missing[@]} > 0 )); then
    for c in "${missing[@]}"; do
      case $c in
        nft) pkg=nftables ;;
        ip|ss) if have apt-get; then pkg=iproute2; else pkg=iproute; fi ;;
        flock) pkg=util-linux ;;
        awk) pkg=gawk ;;
        *) pkg=$c ;;
      esac
      if ! in_list "$pkg" "${pkgs[@]}"; then pkgs+=("$pkg"); fi
    done
    warn "Es fehlen: ${missing[*]} (Pakete: ${pkgs[*]})"
    ask_yn "Jetzt installieren?" j || die "Ohne diese Programme geht es nicht."
    pkg_install "${pkgs[@]}" || die "Installation fehlgeschlagen."
  fi
  have systemctl || die "systemd wird benötigt."
  if ! have dig && ! have host; then
    warn "'dig' fehlt – die DNS-Analyse erkennt dann keine CNAMEs auf Bunny."
    if ask_yn "dig installieren (dnsutils/bind-utils)?" j; then
      if have apt-get; then pkg_install dnsutils || warn "Installation fehlgeschlagen."
      else pkg_install bind-utils || warn "Installation fehlgeschlagen."; fi
    fi
  fi
  ok "Benötigte Programme vorhanden"
}

pkg_install() {
  if have apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif have dnf; then dnf install -y -q "$@"
  elif have yum; then yum install -y -q "$@"
  else return 1; fi
}

# --- Prüfungen -----------------------------------------------------------------
show_counters() {
  table_loaded || return 0
  note "Pakete seit dem letzten Laden: Bunny $(counter_val c_bunny) · erlaubte Quellen $(counter_val c_allow) · Ausnahme-IPs $(counter_val c_exempt) · blockiert $(counter_val c_drop)"
}

check_rules() {
  local n4 n6 age sample p loaded=0
  step "Firewall-Regeln"
  if table_loaded; then ok "nftables-Tabelle inet $TABLE ist geladen"; loaded=1
  else bad "nftables-Tabelle fehlt – Schutz ist NICHT aktiv (sudo bunny-guard enable)"; fi
  if systemctl is-enabled --quiet "$SVC" 2>/dev/null; then ok "Dienst startet beim Booten"; else bad "$SVC ist nicht aktiviert"; fi
  if systemctl is-active --quiet "$UPD_TIMER" 2>/dev/null; then ok "Auto-Update-Timer läuft (alle $UPDATE_HOURS h Liste, alle 10 min Selbstheilung)"
  else warn "Auto-Update-Timer läuft nicht"; fi
  n4=$(list_count "$LIST4"); n6=$(list_count "$LIST6")
  if (( n4 >= MIN4 && n6 >= MIN6 )); then ok "Bunny-Liste: $n4 IPv4 / $n6 IPv6"; else bad "Bunny-Liste unvollständig ($n4 IPv4 / $n6 IPv6)"; fi
  age=$(( $(date +%s) - $(read_stamp) ))
  if (( age <= UPDATE_HOURS * 7200 + 3600 )); then ok "Liste zuletzt aktualisiert $(fmt_age "$age")"
  else warn "Liste ist alt ($(fmt_age "$age")) – ist api.bunny.net erreichbar? (sudo bunny-guard update)"; fi
  if (( loaded )); then
    sample=$(head -n 1 "$LIST4" 2>/dev/null || true)
    if [[ -n $sample ]]; then
      if nft get element inet "$TABLE" bunny4 "{ $sample }" >/dev/null 2>&1; then ok "Stichprobe $sample ist im Kernel-Set"
      else warn "Stichprobe $sample im Kernel-Set nicht gefunden"; fi
    fi
    show_counters
  fi
  if ufw_active; then
    for p in $PORTS; do
      if ufw_allows_any "$p"; then ok "UFW lässt $p/tcp durch (gefiltert wird von bunny-guard)"
      else warn "UFW erlaubt $p/tcp nicht generell – Bunny kommt nur durch, wenn UFW die Bunny-IPs einzeln erlaubt"; fi
    done
  fi
  if firewalld_active; then
    for p in $PORTS; do
      if firewalld_allows "$p"; then ok "firewalld lässt $p/tcp durch"; else warn "firewalld blockt $p/tcp – auch für Bunny"; fi
    done
  fi
}

check_bunny_e2e() {
  local d i=0 base
  local -a doms=()
  read -r -a doms <<<"$TEST_DOMAINS" || true
  step "Ende-zu-Ende: Besucher → Bunny → dieser Server"
  if (( ${#doms[@]} == 0 )); then
    warn "Keine Test-Domain hinterlegt (TEST_DOMAINS in $CONF_FILE) – Bunny-Weg nicht geprüft"; return 0
  fi
  for d in "${doms[@]}"; do
    i=$((i + 1))
    if (( i > 10 )); then note "weitere Domains übersprungen"; break; fi
    probe_bunny "$d"
    base=${BASELINE[$d]-}
    case $PROBE_RES in
      ok)   ok "$d: $PROBE_MSG" ;;
      warn) warn "$d: $PROBE_MSG" ;;
      *)
        if [[ $base == fail ]]; then warn "$d: $PROBE_MSG (war schon VOR der Änderung so)"
        else bad "$d: $PROBE_MSG"; fi
        ;;
    esac
  done
}

check_exempt_l7() { # strict(1)=Fehler zählen, 0=nur Hinweise (direkt nach dem Einrichten)
  local strict=${1:-1} ip d rc i
  local -a ex=() doms=() direct=()
  read -r -a ex <<<"$EXEMPT_DST" || true
  (( ${#ex[@]} > 0 )) || return 0
  read -r -a doms <<<"$TEST_DOMAINS" || true
  read -r -a direct <<<"$DIRECT_DOMAINS" || true
  step "Offene Ziel-IPs: sind Bunny-Seiten dort direkt erreichbar?"
  for ip in "${ex[@]}"; do
    if is_private_ip "$ip" && [[ $ALLOW_PRIVATE == 1 ]]; then note "$ip ist privat und erlaubt – lokaler Test nicht aussagekräftig"; continue; fi
    if in_list "$ip" $ALLOW_SRC; then note "$ip steht in ALLOW_SRC – lokaler Test nicht aussagekräftig"; continue; fi
    i=0
    for d in "${doms[@]}"; do
      i=$((i + 1)); if (( i > 15 )); then break; fi
      rc=0; site_served "$d" "$ip" || rc=$?
      case $rc in
        2) ok "$d über $ip: gesperrt (nginx 444)" ;;
        1) ok "$d wird auf $ip nicht ausgeliefert" ;;
        *)
          if (( strict )); then bad "$d ist über $ip DIREKT erreichbar (ohne Bunny)"
          else warn "$d ist über $ip noch direkt erreichbar"; fi
          ;;
      esac
    done
    for d in "${direct[@]}"; do
      rc=0; site_served "$d" "$ip" || rc=$?
      case $rc in
        0) ok "$d (direkt) antwortet auf $ip" ;;
        2) bad "$d (direkt) wird auf $ip gesperrt – Sperre in diesem server-Block entfernen" ;;
        *) note "$d (direkt) wird auf $ip nicht ausgeliefert" ;;
      esac
    done
  done
  if [[ $NGINX_MODE == 1 ]]; then
    local dump
    dump=$(nginx_dump)
    if [[ -f $NGINX_GEO && $dump == *bunny_guard_ok* ]]; then ok "nginx: Bunny-Liste ($NGINX_GEO) ist eingebunden"
    else bad "nginx: $NGINX_GEO wird nicht geladen (conf.d im http-Block eingebunden?)"; fi
  fi
}

check_direct() {
  local d ip hit
  local -a direct=() ex=() locs=()
  read -r -a direct <<<"$DIRECT_DOMAINS" || true
  (( ${#direct[@]} > 0 )) || return 0
  read -r -a ex <<<"$EXEMPT_DST" || true
  step "Domains ohne Bunny"
  for d in "${direct[@]}"; do
    classify_domain "$d"
    read -r -a locs <<<"$CL_LOCAL" || true
    hit=""
    for ip in "${locs[@]}"; do if in_list "$ip" "${ex[@]}"; then hit=$ip; break; fi; done
    if [[ -n $hit ]]; then ok "$d zeigt auf $hit (freigegeben)"
    else warn "$d zeigt nicht auf eine freigegebene IP (DNS: $CL_TGT)"; fi
  done
}

check_external() {
  local port=${PORTS%% *} ip before after rc
  local -a pub=() ex=()
  read -r -a ex <<<"$EXEMPT_DST" || true
  step "Test von außen (check-host.net, mehrere Länder)"
  for ip in "${LOCAL_IPS[@]}"; do
    if is_ipv4 "$ip" && ! is_private_ip "$ip"; then pub+=("$ip"); fi
  done
  if (( ${#pub[@]} == 0 )); then
    ip=$(curl -4 -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    if is_ipv4 "$ip"; then pub=("$ip"); note "Öffentliche IPv4 hinter NAT: $ip"; fi
  fi
  if (( ${#pub[@]} == 0 )); then warn "Keine öffentliche IPv4 gefunden – externer Test übersprungen"; return 0; fi
  before=$(counter_val c_drop)
  for ip in "${pub[@]}"; do
    note "teste $ip:$port ..."
    rc=0; external_tcp_test "$ip" "$port" || rc=$?
    if (( rc != 0 )); then warn "check-host.net nicht erreichbar – Test von außen nicht möglich"; break; fi
    if in_list "$ip" "${ex[@]}"; then
      if (( EXT_OK > 0 )); then ok "$ip:$port ist von außen erreichbar – gewollt (Ausnahme-IP)"
      else warn "$ip:$port ist von außen nicht erreichbar, obwohl als Ausnahme freigegeben"; fi
    else
      if (( EXT_OK == 0 && EXT_FAIL > 0 )); then ok "$ip:$port ist von außen GESPERRT ($EXT_FAIL von $EXT_TOTAL Messpunkten)"
      elif (( EXT_OK > 0 )); then bad "$ip:$port ist von außen ERREICHBAR ($EXT_OK von $EXT_TOTAL Messpunkten)"
      else warn "$ip:$port: keine Messergebnisse erhalten"; fi
    fi
  done
  after=$(counter_val c_drop)
  if table_loaded; then note "Blockierte Pakete während des Tests: +$(( after - before ))"; fi
}

print_manual_tests() {
  local ip port=${PORTS%% *}
  local -a pub=()
  for ip in "${LOCAL_IPS[@]}"; do if ! is_private_ip "$ip"; then pub+=("$ip"); fi; done
  (( ${#pub[@]} > 0 )) || return 0
  say ""
  say "  ${CB}Selbst testen von deinem PC (PowerShell)${C0} – nicht freigegebene IPs müssen fehlschlagen:"
  for ip in "${pub[@]}"; do
    if in_list "$ip" $EXEMPT_DST; then continue; fi
    if [[ $ip == *:* ]]; then
      say "    Test-NetConnection -ComputerName $ip -Port $port     # erwartet: TcpTestSucceeded False"
    else
      say "    Test-NetConnection $ip -Port $port     # erwartet: TcpTestSucceeded False"
    fi
  done
  note "Hast du deine eigene IP freigegeben, klappt die Verbindung von dort natürlich."
}

summary_line() {
  say ""
  if (( N_BAD > 0 )); then say "  ${CR}${CB}Ergebnis: $N_BAD Fehler${C0}, $N_WARN Hinweise, $N_OK in Ordnung"
  elif (( N_WARN > 0 )); then say "  ${CY}${CB}Ergebnis: keine Fehler${C0}, $N_WARN Hinweise, $N_OK in Ordnung"
  else say "  ${CG}${CB}Ergebnis: alles in Ordnung${C0} ($N_OK Prüfungen)"; fi
}

# --- Befehle -------------------------------------------------------------------
cmd_load() {
  need_root; lock; load_config
  if apply_rules; then
    log "bunny-guard: Regeln geladen ($(list_count "$LIST4") IPv4 / $(list_count "$LIST6") IPv6, Ports: $PORTS)"
    return 0
  fi
  if [[ -s $RULESET ]] && nft -f "$RULESET" 2>/dev/null; then
    log "bunny-guard: WARNUNG – zuletzt gespeicherter Regelsatz geladen."
    return 0
  fi
  log "bunny-guard: FEHLER – Regeln nicht geladen, Port(s) $PORTS sind NICHT geschützt!"
  exit 1
}

cmd_unload() {
  need_root; lock
  nft delete table inet "$TABLE" 2>/dev/null || true
  log "bunny-guard: Regeln entfernt."
}

cmd_cron() {
  need_root
  systemctl is-active --quiet "$SVC" 2>/dev/null || exit 0
  lock; load_config
  if ! table_loaded; then
    log "bunny-guard: nftables-Tabelle fehlte (z.B. 'nft flush ruleset') – wird neu geladen."
    if ! apply_rules; then
      if [[ -s $RULESET ]]; then nft -f "$RULESET" || true; fi
    fi
  fi
  local now last
  now=$(date +%s); last=$(read_stamp)
  if (( now - last >= UPDATE_HOURS * 3600 )); then
    LISTS_CHANGED=0
    if update_lists 0 && (( LISTS_CHANGED )); then
      if apply_rules; then log "bunny-guard: Bunny-Liste aktualisiert und Regeln neu geladen."; fi
      if [[ $NGINX_MODE == 1 ]]; then
        if nginx_apply_geo 0; then log "bunny-guard: nginx-Liste aktualisiert."
        else log "bunny-guard: WARNUNG – nginx-Liste konnte nicht aktualisiert werden (nginx -t)."; fi
      fi
    fi
  fi
}

cmd_update() {
  need_root
  local force=0
  if [[ ${1:-} == --force ]]; then force=1; fi
  load_config
  step "Bunny-IP-Listen aktualisieren"
  lock
  LISTS_CHANGED=0
  update_lists "$force" || die "Bunny-Listen konnten nicht geladen werden."
  if systemctl is-active --quiet "$SVC" 2>/dev/null; then
    if apply_rules; then ok "Regeln neu geladen"; else bad "Regeln konnten nicht neu geladen werden"; fi
  else
    note "Schutz ist nicht aktiv – nur die Listen wurden aktualisiert."
  fi
  if [[ $NGINX_MODE == 1 ]]; then
    if nginx_apply_geo 0; then ok "nginx-Liste aktualisiert"; else bad "nginx-Liste konnte nicht aktualisiert werden (nginx -t)"; fi
  fi
  unlock
}

cmd_reload() {
  need_root; need_conf; load_config
  if systemctl is-active --quiet "$SVC" 2>/dev/null; then
    if systemctl reload "$SVC"; then ok "Regeln neu geladen (Ports: $PORTS)"
    else bad "Neu laden fehlgeschlagen – siehe: journalctl -u $SVC"; fi
  else
    warn "Schutz ist nicht aktiv – mit 'sudo bunny-guard enable' einschalten."
  fi
  if [[ $NGINX_MODE == 1 ]]; then
    if nginx_apply_geo 0; then ok "nginx-Liste neu geschrieben"; else bad "nginx-Liste fehlerhaft (nginx -t)"; fi
  fi
}

need_conf() { if [[ ! -f $CONF_FILE ]]; then die "bunny-guard ist noch nicht eingerichtet – starte den Assistenten: sudo bash bunny-guard.sh"; fi; }

cmd_status() {
  need_root; need_conf; load_config
  local age svc tim next
  say "${CB}bunny-guard $VERSION${C0}"
  if table_loaded; then ok "Schutz AKTIV"; else bad "Schutz NICHT aktiv"; fi
  svc=$(systemctl is-enabled "$SVC" 2>/dev/null || true)
  tim=$(systemctl is-active "$UPD_TIMER" 2>/dev/null || true)
  next=$(systemctl show -p NextElapseUSecRealtime --value "$UPD_TIMER" 2>/dev/null || true)
  age=$(( $(date +%s) - $(read_stamp) ))
  printf '  %-22s %s\n' "Dienst beim Booten:" "${svc:-?}"
  printf '  %-22s %s\n' "Auto-Update:" "${tim:-?} (alle $UPDATE_HOURS h, nächster Lauf: ${next:-?})"
  printf '  %-22s %s IPv4 / %s IPv6, aktualisiert %s\n' "Bunny-IPs:" "$(list_count "$LIST4")" "$(list_count "$LIST6")" "$(fmt_age "$age")"
  printf '  %-22s %s (TCP + UDP)\n' "Geschützte Ports:" "$PORTS"
  printf '  %-22s %s\n' "Erlaubte Quellen:" "$( [[ $ALLOW_PRIVATE == 1 ]] && printf 'private Netze ' )${ALLOW_SRC:-}"
  printf '  %-22s %s\n' "Offene Ziel-IPs:" "${EXEMPT_DST:-–}"
  printf '  %-22s %s\n' "Domains ohne Bunny:" "${DIRECT_DOMAINS:-–}"
  printf '  %-22s %s\n' "nginx-Modus:" "$( [[ $NGINX_MODE == 1 ]] && echo an || echo aus )"
  printf '  %-22s %s\n' "Test-Domains:" "${TEST_DOMAINS:-–}"
  show_counters
  if systemctl is-active --quiet "$RB_UNIT.timer" 2>/dev/null; then warn "Automatisches Zurücksetzen ist geplant (Einrichtung nicht bestätigt)"; fi
}

cmd_check() {
  need_root
  local ext=ask
  case ${1:-} in
    --extern) ext=1 ;;
    --intern|--no-extern) ext=0 ;;
    "") ;;
    *) die "Unbekannte Option: $1" ;;
  esac
  need_conf; load_config; mk_tmpd; gather_local_ips
  N_OK=0 N_WARN=0 N_BAD=0
  check_rules
  check_bunny_e2e
  check_exempt_l7 1
  check_direct
  if [[ $ext == 1 ]] || { [[ $ext == ask ]] && tty_ok && ask_yn "Zusätzlich von außen testen? (über check-host.net – dabei wird die Server-IP dorthin übermittelt)" n; }; then
    check_external
  fi
  print_manual_tests
  summary_line
  if (( N_BAD > 0 )); then exit 1; fi
}

cmd_disable() {
  need_root; load_config
  if [[ ${1:-} != --yes ]]; then
    tty_ok || die "Bitte mit --yes bestätigen."
    ask_yn "Schutz abschalten? Port(s) $PORTS sind dann wieder für alle offen (soweit die übrige Firewall es zulässt)." n || exit 0
  fi
  disarm_rollback
  systemctl disable --now "$UPD_TIMER" "$SVC" >/dev/null 2>&1 || true
  nft delete table inet "$TABLE" 2>/dev/null || true
  if [[ $NGINX_MODE == 1 && -f $NGINX_GEO ]]; then
    if nginx_apply_geo 1; then ok "nginx-Sperre gelockert (alle Besucher erlaubt)"; fi
  fi
  ok "Schutz deaktiviert. Konfiguration bleibt – 'sudo bunny-guard enable' schaltet ihn wieder ein."
}

cmd_enable() {
  need_root
  [[ -f $CONF_FILE ]] || die "Noch nicht eingerichtet – starte den Assistenten: sudo bunny-guard"
  load_config
  systemctl enable --quiet "$SVC" "$UPD_TIMER"
  systemctl reload-or-restart "$SVC"
  systemctl start "$UPD_TIMER"
  if [[ $NGINX_MODE == 1 ]]; then
    if nginx_apply_geo 0; then ok "nginx-Sperre aktiv"; else bad "nginx-Liste fehlerhaft (nginx -t)"; fi
  fi
  if table_loaded; then ok "Schutz aktiv – prüfen mit: sudo bunny-guard check"; else bad "Regeln wurden nicht geladen (journalctl -u $SVC)"; fi
}

cmd_cleanup_ufw() {
  need_root
  have ufw || die "UFW ist nicht installiert."
  ufw_active || { say "UFW ist nicht aktiv. Keine Änderungen."; exit 0; }
  local p ans
  local -a matches=()
  mapfile -t matches < <(ufw_labeled_rules)
  if (( ${#matches[@]} == 0 )); then
    say "Keine UFW-Regeln mit BunnyCDN-/Gcore-Kommentar gefunden."
    note "Unbeschriftete IP-Regeln werden absichtlich NICHT automatisch entfernt."
    exit 0
  fi
  say "Diese UFW-Regeln wurden anhand ihres Kommentars gefunden:"
  printf '  %s\n' "${matches[@]}"
  if [[ ${1:-} != --apply ]]; then
    say ""; say "Nur Vorschau. Zum Entfernen: sudo bunny-guard cleanup-ufw --apply"; exit 0
  fi
  load_config
  if ! table_loaded; then warn "bunny-guard ist nicht aktiv – nach dem Entfernen filtert niemand mehr nach Bunny-IPs."; fi
  for p in $PORTS; do
    if ! ufw_allows_any "$p"; then warn "UFW erlaubt $p/tcp nicht generell – nach dem Entfernen kommt Bunny evtl. nicht mehr durch."; fi
  done
  tty_ok || die "Für --apply wird ein Terminal benötigt."
  IFS= read -r -p "  Zum Fortfahren exakt ENTFERNEN eingeben: " ans <&"$TTY_FD" || ans=""
  if [[ $ans != ENTFERNEN ]]; then say "Abgebrochen. Keine Änderung."; exit 0; fi
  ufw_cleanup_apply "${matches[@]}"
  note "Direkt über iptables/nftables angelegte Regeln wurden NICHT gelöscht."
}

cmd_uninstall() {
  need_root
  local yes=0
  if [[ ${1:-} == --yes ]]; then yes=1; fi
  load_config
  if (( ! yes )); then
    tty_ok || die "Bitte mit --yes bestätigen."
    ask_yn "bunny-guard komplett entfernen? Port(s) $PORTS sind danach wieder für alle offen (soweit die übrige Firewall es zulässt)." n || exit 0
  fi
  disarm_rollback
  systemctl disable --now "$UPD_TIMER" "$SVC" >/dev/null 2>&1 || true
  nft delete table inet "$TABLE" 2>/dev/null || true
  ok "Firewall-Regeln entfernt"
  if [[ -s $ADDED_RULES ]]; then
    say "  Von bunny-guard angelegte Firewall-Freigaben:"
    sed 's/^/      /' "$ADDED_RULES"
    if (( yes )); then
      note "Bleiben bestehen (mit --yes wird nichts geschlossen, damit Bunny weiter durchkommt)."
    elif ask_yn "Diese Freigaben ebenfalls entfernen? (Nein = Port bleibt in UFW/firewalld offen)" n; then
      fw_remove_recorded "$ADDED_RULES"
    fi
  fi
  if nginx_present && [[ -f $NGINX_SNIPPET || -f $NGINX_GEO ]]; then
    nginx_remove_includes
    rm -f "$NGINX_SNIPPET" "$NGINX_GEO"
    if nginx_test; then nginx_reload; ok "nginx-Dateien entfernt und nginx neu geladen"
    else bad "nginx -t schlägt fehl – bitte die nginx-Konfiguration prüfen"; fi
  fi
  rm -f "$UNIT_DIR/$SVC" "$UNIT_DIR/$UPD_SVC" "$UNIT_DIR/$UPD_TIMER"
  systemctl daemon-reload || true
  rm -rf "$STATE_DIR" "$CONF_DIR"
  rm -f "$INSTALL_BIN" "$LOCK_FILE"
  ok "bunny-guard wurde entfernt."
}

usage() {
  cat <<EOF
bunny-guard $VERSION – Ports nur für BunnyCDN freigeben

  sudo bunny-guard                  Assistent (einrichten oder ändern)
  sudo bunny-guard status           Zustand, Listen, Zähler
  sudo bunny-guard check            alle Tests (--extern: zusätzlich von außen)
  sudo bunny-guard update [--force] Bunny-Liste sofort aktualisieren
  sudo bunny-guard reload           Konfiguration neu laden (nach Handänderung)
  sudo bunny-guard disable [--yes]  Schutz abschalten (Konfiguration bleibt)
  sudo bunny-guard enable           Schutz wieder einschalten
  sudo bunny-guard rollback         letzte Einrichtung zurücknehmen
  sudo bunny-guard cleanup-ufw [--apply]
                                    alte UFW-Regeln mit Bunny-/Gcore-Kommentar entfernen
  sudo bunny-guard uninstall [--yes] alles entfernen

Dateien: $CONF_FILE, $STATE_DIR
Logs:    journalctl -u $SVC -u $UPD_SVC
EOF
}

# --- Assistent -----------------------------------------------------------------
banner() {
  say ""
  say "${CB}bunny-guard $VERSION${C0} – Ports nur noch für BunnyCDN"
  say "${CD}Der Assistent fragt Schritt für Schritt nach. Vor Schritt 8 wird nichts an der Firewall geändert.${C0}"
}

wizard_ports() {
  local input ok_ports p srvport
  local -a list=() sshl=()
  mapfile -t sshl < <(ssh_ports)
  srvport=""
  if [[ -n ${SSH_CONNECTION:-} ]]; then srvport=${SSH_CONNECTION##* }; fi
  while true; do
    ask input "Welche Ports sollen nur für Bunny offen sein? (mehrere mit Leerzeichen oder Komma, z.B. 443,8443)" "$PORTS"
    read -r -a list <<<"${input//,/ }" || true
    ok_ports=1
    for p in "${list[@]}"; do
      if ! is_port "$p"; then warn "Ungültiger Port: $p"; ok_ports=0; continue; fi
      if in_list "$((10#$p))" "${sshl[@]}" || [[ $((10#$p)) == "$srvport" ]]; then
        bad "Auf Port $p läuft SSH – das würde dich aussperren."; ok_ports=0
      fi
    done
    (( ${#list[@]} > 0 )) || ok_ports=0
    (( ok_ports )) || continue
    PORTS=$(words_filter is_port "${list[*]}")
    if in_list 80 $PORTS; then
      warn "Port 80 gesperrt: Let's-Encrypt-Prüfungen (HTTP-01) von außen schlagen dann fehl."
      note "Nur sinnvoll, wenn deine Zertifikate per DNS-Challenge oder über Bunny kommen."
      ask_yn "Port 80 trotzdem schützen?" n || continue
    fi
    break
  done
  for p in $PORTS; do
    local lt lu
    lt=$(listeners "$p" t); lu=$(listeners "$p" u)
    if [[ -n $lt ]]; then ok "Port $p/tcp: ${lt}"; else warn "Auf Port $p/tcp lauscht gerade nichts"; fi
    if [[ -n $lu ]]; then note "Port $p/udp (HTTP/3): ${lu} – wird mit geschützt"; fi
  done
}

wizard_domains() {
  local d s i input tok n okflag
  local -a toks=() sel=() unsel=()
  DOM_NAME=() DOM_SRC=() DOM_STAT=() DOM_TGT=() DOM_LOCAL=() DOM_IPS=()
  note "Suche Domains in nginx, Apache, Caddy und Let's-Encrypt-Zertifikaten ..."
  local -a found=() names=()
  mapfile -t found < <(detect_domains)
  for s in "${found[@]}"; do names+=("${s%%$'\t'*}"); done
  # Bereits konfigurierte Domains immer mit anzeigen
  for d in $DIRECT_DOMAINS $TEST_DOMAINS; do
    if ! in_list "$d" "${names[@]}"; then found+=("$d"$'\t'"konfiguriert"); names+=("$d"); fi
  done
  i=0
  for s in "${found[@]}"; do
    i=$((i + 1))
    if [[ -t 1 ]]; then printf '\r    %sprüfe DNS %d/%d ...%s' "$CD" "$i" "${#found[@]}" "$C0"; fi
    add_domain "${s%%$'\t'*}" "${s#*$'\t'}"
  done
  if (( ${#found[@]} > 0 )) && [[ -t 1 ]]; then printf '\r%60s\r' ""; fi
  if (( ${#DOM_NAME[@]} == 0 )); then
    warn "Keine Domains in der Webserver-Konfiguration gefunden (Docker-Proxy?) – du kannst sie unten eintippen."
  else
    print_domain_table
  fi
  say ""
  say "  ${CB}Welche Domains sollen OHNE Bunny direkt erreichbar sein?${C0}"
  note "Mehrere möglich: Nummern oder Domains mit Leerzeichen oder Komma (z.B. 2 3 oder 2,3),"
  note "Bereiche (2-4) oder 'alle'. Nicht gelistete Domains einfach eintippen. '-' = keine."
  while true; do
    ask input "Domains ohne Bunny" "${DIRECT_DOMAINS:--}"
    if [[ $input == - ]]; then input=""; fi
    split_selection "$input" "${#DOM_NAME[@]}"
    toks=("${SEL[@]}")
    sel=(); okflag=1
    for tok in "${toks[@]}"; do
      if [[ $tok =~ ^[0-9]+$ ]]; then
        n=$((10#$tok))
        if (( n >= 1 && n <= ${#DOM_NAME[@]} )); then
          if ! in_list "${DOM_NAME[n - 1]}" "${sel[@]}"; then sel+=("${DOM_NAME[n - 1]}"); fi
        else warn "Nummer $tok gibt es nicht."; okflag=0; fi
      elif is_domain "$tok"; then
        if ! dom_index "$tok" >/dev/null; then
          add_domain "$tok" "manuell"
          i=$(dom_index "$tok")
          note "$tok → ${DOM_TGT[i]} ($(stat_label "${DOM_STAT[i]}"))"
        fi
        if ! in_list "$tok" "${sel[@]}"; then sel+=("$tok"); fi
      else
        warn "Ungültige Eingabe: $tok"; okflag=0
      fi
    done
    (( okflag )) || continue
    unsel=()
    for i in "${!DOM_NAME[@]}"; do
      if [[ ${DOM_STAT[i]} == direct ]] && ! in_list "${DOM_NAME[i]}" "${sel[@]}"; then unsel+=("${DOM_NAME[i]}"); fi
    done
    if (( ${#unsel[@]} > 0 )); then
      warn "Diese Domains zeigen per DNS DIREKT auf den Server und wären danach NICHT mehr erreichbar:"
      printf '      %s\n' "${unsel[@]}"
      ask_yn "Trotzdem so übernehmen?" n || continue
    fi
    break
  done
  SEL_DIRECT=("${sel[@]}")
}

wizard_exemptions() {
  local d i ip input n rc choice reach tok
  local -a cand=() bunny_doms=() locs=() reach_list=()
  local -A ip_doms=()
  EXEMPT_DST="" DIRECT_DOMAINS="" NGINX_MODE=0
  bunny_doms=()
  for i in "${!DOM_NAME[@]}"; do
    if [[ ${DOM_STAT[i]} == bunny ]] && ! in_list "${DOM_NAME[i]}" "${SEL_DIRECT[@]}"; then bunny_doms+=("${DOM_NAME[i]}"); fi
  done
  (( ${#SEL_DIRECT[@]} > 0 )) || return 0
  step "5b Freigaben für Domains ohne Bunny"
  for d in "${SEL_DIRECT[@]}"; do
    i=$(dom_index "$d")
    read -r -a locs <<<"${DOM_LOCAL[i]}" || true
    if (( ${#locs[@]} == 0 )); then
      if [[ ${DOM_STAT[i]} == bunny ]]; then
        warn "$d läuft laut DNS gerade über Bunny. Direkt erreichbar wird sie erst, wenn ihr DNS-Eintrag direkt auf den Server zeigt."
      else
        warn "$d zeigt auf keine IP dieses Servers (DNS: ${DOM_TGT[i]})."
      fi
      print_local_ips
      ask input "Auf welcher Server-IP soll $d direkt laufen? (Nummer, mehrere z.B. '1 2' für IPv4+IPv6; Enter = überspringen)" ""
      split_selection "$input" "${#LOCAL_IPS[@]}"
      locs=()
      for tok in "${SEL[@]}"; do
        if [[ $tok =~ ^[0-9]+$ ]] && (( 10#$tok >= 1 && 10#$tok <= ${#LOCAL_IPS[@]} )); then
          if ! in_list "${LOCAL_IPS[10#$tok - 1]}" "${locs[@]}"; then locs+=("${LOCAL_IPS[10#$tok - 1]}"); fi
        else
          warn "Nummer $tok gibt es nicht – ignoriert."
        fi
      done
      if (( ${#locs[@]} == 0 )); then note "$d übersprungen."; continue; fi
    fi
    for ip in "${locs[@]}"; do
      if [[ -z ${ip_doms[$ip]-} ]]; then cand+=("$ip"); fi
      ip_doms[$ip]="${ip_doms[$ip]-} $d"
    done
  done
  for ip in "${cand[@]}"; do
    say ""
    say "  ${CB}$ip${C0} (direkt:${ip_doms[$ip]})"
    reach_list=()
    n=0
    for d in "${bunny_doms[@]}"; do
      n=$((n + 1)); if (( n > 15 )); then break; fi
      rc=0; site_served "$d" "$ip" || rc=$?
      # 2 = von der nginx-Sperre blockiert: die Seite liegt trotzdem auf dieser IP
      if (( rc == 0 || rc == 2 )); then reach_list+=("$d"); fi
    done
    if (( ${#bunny_doms[@]} == 0 )); then
      note "Keine Bunny-Domain zum Gegentesten bekannt."
      if ask_yn "Laufen auf $ip auch Seiten, die NUR über Bunny erreichbar sein sollen?" j; then reach="ja"; else reach="nein"; fi
    elif (( ${#reach_list[@]} > 0 )); then
      reach="ja"
      warn "Der Webserver liefert auf $ip auch Bunny-Seiten aus: ${reach_list[*]:0:4}$( (( ${#reach_list[@]} > 4 )) && printf ' …')"
    else
      reach="nein"
      ok "Auf $ip antworten keine Bunny-Seiten – die IP kann sauber freigegeben werden."
    fi
    if [[ $reach == nein ]]; then
      EXEMPT_DST+=" $ip"; DIRECT_DOMAINS+="${ip_doms[$ip]}"; continue
    fi
    say "    Die Firewall sieht nur IP und Port, keine Domain. Öffnet man $ip für alle,"
    say "    sind auch die Bunny-Seiten auf dieser IP direkt erreichbar. Möglichkeiten:"
    if nginx_present; then
      say "      1) nginx-Modus: IP öffnen, nginx sperrt alle Nicht-Bunny-Besucher für die übrigen Domains (empfohlen)"
    else
      say "      1) (nginx-Modus – nicht verfügbar, nginx ist nicht installiert)"
    fi
    say "      2) IP trotzdem komplett öffnen – Bunny-Schutz auf $ip praktisch aus"
    say "      3) überspringen – die direkte Domain bleibt gesperrt (besser: zweite IP für direkte Dienste)"
    while true; do
      if nginx_present; then ask choice "Auswahl" "1"; else ask choice "Auswahl" "3"; fi
      case $choice in
        1) if nginx_present; then EXEMPT_DST+=" $ip"; DIRECT_DOMAINS+="${ip_doms[$ip]}"; NGINX_MODE=1; break; fi
           warn "nginx ist nicht installiert." ;;
        2) EXEMPT_DST+=" $ip"; DIRECT_DOMAINS+="${ip_doms[$ip]}"; warn "$ip wird komplett geöffnet."; break ;;
        3) note "$ip bleibt geschützt,${ip_doms[$ip]} ist dann nicht direkt erreichbar."; break ;;
        *) say "  Bitte 1, 2 oder 3 eingeben." ;;
      esac
    done
  done
  EXEMPT_DST=$(words_filter is_ip "$EXEMPT_DST")
  DIRECT_DOMAINS=$(words_filter is_domain "$DIRECT_DOMAINS")
}

wizard_test_domains() {
  local i input
  local -a t=()
  for i in "${!DOM_NAME[@]}"; do
    if [[ ${DOM_STAT[i]} == bunny ]] && ! in_list "${DOM_NAME[i]}" $DIRECT_DOMAINS; then t+=("${DOM_NAME[i]}"); fi
  done
  if (( ${#t[@]} == 0 )); then
    say ""
    note "Für den Funktionstest wird eine Domain gebraucht, die über Bunny auf diesen Server zeigt."
    ask input "Test-Domain (Enter = ohne Ende-zu-Ende-Test)" "${TEST_DOMAINS%% *}"
    TEST_DOMAINS=$(words_filter is_domain "$input")
  else
    TEST_DOMAINS="${t[*]}"
    ok "Funktionstest über: ${t[*]:0:5}$( (( ${#t[@]} > 5 )) && printf ' (+%d)' $(( ${#t[@]} - 5 )))"
  fi
}

wizard_sources() {
  local d input cip
  if [[ $ALLOW_PRIVATE == 1 ]]; then d=j; else d=n; fi
  note "Private Netze: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fc00::/7"
  note "(Docker-Container, VPN wie WireGuard/Tailscale, LAN). Aus dem Internet kommt von dort nichts."
  if ask_yn "Private/interne Netze immer erlauben?" "$d"; then ALLOW_PRIVATE=1; else ALLOW_PRIVATE=0; fi
  cip=""
  if [[ -n ${SSH_CONNECTION:-} ]]; then cip=${SSH_CONNECTION%% *}; cip=${cip#::ffff:}; fi
  if [[ -n $cip ]] && ! is_private_ip "$cip" && ! in_list "$cip" $ALLOW_SRC; then
    note "Deine aktuelle SSH-Verbindung kommt von $cip."
    if ask_yn "Diese IP ebenfalls direkt erlauben (z.B. zum Testen)?" n; then ALLOW_SRC+=" $cip"; fi
  fi
  local w good
  local -a words=()
  while true; do
    ask input "Weitere Quell-IPs/Netze, die immer direkt dürfen (mehrere mit Leerzeichen oder Komma; '-' = keine)" "${ALLOW_SRC:--}"
    if [[ $input == - ]]; then input=""; fi
    input=${input//,/ }
    read -r -a words <<<"$input" || true
    good=1
    for w in "${words[@]}"; do if ! is_ip_net "${w,,}"; then warn "Ungültig: $w"; good=0; fi; done
    if (( good )); then break; fi
  done
  ALLOW_SRC=$(words_filter is_ip_net "$input")
}

FW_PLAN=()
wizard_firewall() {
  local p
  FW_PLAN=()
  if ufw_active; then
    for p in $PORTS; do
      if ufw_allows_any "$p"; then ok "UFW lässt $p/tcp schon durch"; continue; fi
      warn "UFW lässt $p/tcp bisher nicht generell zu (nur einzelne IPs oder gar nicht)."
      note "bunny-guard filtert selbst – UFW muss den Port dafür durchlassen."
      if ask_yn "'ufw allow $p/tcp' hinzufügen? (erst NACHDEM der Bunny-Filter aktiv ist)" j; then FW_PLAN+=("ufw $p/tcp")
      else warn "Dann entscheidet weiter UFW – Bunny kommt nur durch, wenn die Bunny-IPs dort einzeln erlaubt sind."; fi
    done
  fi
  if firewalld_active; then
    for p in $PORTS; do
      if firewalld_allows "$p"; then ok "firewalld lässt $p/tcp schon durch"; continue; fi
      warn "firewalld blockt $p/tcp."
      if ask_yn "Port $p/tcp in firewalld freigeben? (erst NACHDEM der Bunny-Filter aktiv ist)" j; then FW_PLAN+=("firewalld $p/tcp"); fi
    done
  fi
  if ! ufw_active && ! firewalld_active; then
    local pol=""
    if have iptables; then pol=$(iptables -S INPUT 2>/dev/null | head -n 1 || true); fi
    if [[ $pol == *DROP* ]]; then
      warn "iptables INPUT-Policy ist DROP – stelle sicher, dass Port(s) $PORTS dort erlaubt sind."
    else
      note "Keine weitere Firewall aktiv – bunny-guard ist allein zuständig."
    fi
  fi
}

wizard_summary() {
  local allowtxt
  allowtxt="Bunny ($(list_count "$LIST4") IPv4 / $(list_count "$LIST6") IPv6)"
  if [[ $ALLOW_PRIVATE == 1 ]]; then allowtxt+=", private Netze"; fi
  if [[ -n $ALLOW_SRC ]]; then allowtxt+=", $ALLOW_SRC"; fi
  printf '  %-22s %s (TCP + UDP)\n' "Geschützte Ports:" "$PORTS"
  printf '  %-22s %s\n' "Erlaubt:" "$allowtxt"
  printf '  %-22s %s\n' "Offene Ziel-IPs:" "${EXEMPT_DST:-–}"
  printf '  %-22s %s\n' "Domains ohne Bunny:" "${DIRECT_DOMAINS:-–}"
  printf '  %-22s %s\n' "nginx-Modus:" "$( [[ $NGINX_MODE == 1 ]] && echo 'an (Sperre pro server-Block)' || echo aus )"
  printf '  %-22s %s\n' "Firewall-Abgleich:" "$( (( ${#FW_PLAN[@]} )) && printf '%s; ' "${FW_PLAN[@]}" || echo 'nichts nötig' )"
  printf '  %-22s %s\n' "Auto-Update:" "alle $UPDATE_HOURS h, Selbstheilung alle 10 min"
  printf '  %-22s %s\n' "Funktionstest:" "${TEST_DOMAINS:-–}"
  printf '  %-22s %s\n' "Sicherheitsnetz:" "ohne deine Bestätigung nach $((ROLLBACK_SECS / 60)) min automatisch zurück"
}

cmd_setup() {
  need_root
  tty_ok || die "Der Assistent braucht ein Terminal (für Skripte: status, check, update ...)."
  mk_tmpd
  banner
  load_config
  local -a SEL_DIRECT=()
  local d item ans t

  step "1/8 Voraussetzungen"
  ensure_deps
  if ! nft_probe; then die "Der Kernel unterstützt die benötigten nftables-Funktionen nicht (z.B. OpenVZ/LXC-Container)."; fi
  ok "nftables funktioniert ($(nft --version 2>/dev/null | head -n 1))"
  if ufw_active; then note "UFW ist aktiv – bleibt unverändert, bunny-guard filtert davor."; fi
  if firewalld_active; then note "firewalld ist aktiv – bleibt unverändert, bunny-guard filtert davor."; fi
  if systemctl is-active --quiet docker 2>/dev/null; then note "Docker läuft – veröffentlichte Container-Ports werden mit geschützt."; fi
  if systemctl is-enabled --quiet nftables 2>/dev/null; then note "nftables.service ist aktiv – bunny-guard lädt sich nach jedem Neustart davon automatisch neu."; fi

  step "2/8 Bunny-IP-Listen laden"
  lock
  LISTS_CHANGED=0
  update_lists 0 || die "Ohne Bunny-IP-Listen geht es nicht (Internet/api.bunny.net erreichbar?)."
  unlock

  step "3/8 Server"
  gather_local_ips
  if (( ${#LOCAL_IPS[@]} == 0 )); then warn "Keine globalen IP-Adressen gefunden."; else print_local_ips; fi

  step "4/8 Ports"
  wizard_ports

  step "5/8 Domains"
  wizard_domains
  wizard_exemptions
  wizard_test_domains

  step "6/8 Weitere Ausnahmen"
  wizard_sources

  step "7/8 Firewall-Abgleich und Zusammenfassung"
  wizard_firewall
  say ""
  wizard_summary
  say ""
  if ! ask_yn "Jetzt aktivieren?" n; then say "  Abgebrochen – an der Firewall wurde nichts geändert."; exit 0; fi

  step "8/8 Aktivieren und testen"
  BASELINE=()
  if [[ -n $TEST_DOMAINS ]]; then
    note "Vorher-Test über Bunny ..."
    for d in $TEST_DOMAINS; do probe_bunny "$d"; BASELINE[$d]=$PROBE_RES; done
  fi
  N_OK=0 N_WARN=0 N_BAD=0
  prepare_rollback
  install_self
  save_config
  install_units
  systemctl enable --quiet "$SVC" "$UPD_TIMER"
  if ! systemctl reload-or-restart "$SVC"; then
    bad "Der Dienst konnte die Regeln nicht laden:"
    journalctl -u "$SVC" -n 15 --no-pager 2>/dev/null | sed 's/^/      /' || true
    cmd_rollback
    die "Einrichtung zurückgenommen."
  fi
  systemctl start "$UPD_TIMER" || true
  arm_rollback
  ok "Bunny-Filter ist aktiv"
  for item in "${FW_PLAN[@]}"; do fw_add "$item"; done
  if [[ $NGINX_MODE == 1 ]]; then
    if ! nginx_test; then
      bad "nginx -t meldet schon vorher Fehler – nginx-Modus wird nicht eingerichtet."
    elif nginx_apply_geo 0; then
      ok "nginx: Bunny-Liste geschrieben ($NGINX_GEO)"
      nginx_insert_includes
    else
      bad "nginx-Liste konnte nicht eingebunden werden (nginx -t)."
    fi
  elif [[ -f $NGINX_GEO ]] && nginx_present; then
    # nginx-Modus abgeschaltet: Sperre unschädlich machen, damit eine veraltete
    # Liste später keine neuen Bunny-IPs aussperrt.
    if nginx_apply_geo 1; then note "nginx-Modus aus – vorhandene nginx-Sperre auf 'alle erlaubt' gestellt."; fi
  fi

  check_rules
  check_bunny_e2e
  check_exempt_l7 0
  check_direct
  if ask_yn "Zusätzlich von außen testen? (über check-host.net – dabei wird die Server-IP dorthin übermittelt)" j; then
    check_external
  fi
  summary_line

  # Sicherheitsnetz neu starten, damit für die Antwort die volle Zeit bleibt.
  arm_rollback
  say ""
  if (( N_BAD > 0 )); then
    say "  ${CR}Es gab Fehler.${C0} Empfehlung: zurücksetzen (n) und die Meldungen oben prüfen."
  fi
  t=$((ROLLBACK_SECS - 10))
  printf '  Konfiguration behalten? [j/N] (ohne Antwort in %d s automatisch zurück): ' "$t"
  ans=""
  if ! IFS= read -r -t "$t" ans <&"$TTY_FD"; then ans="timeout"; say ""; fi
  if [[ ! -t $TTY_FD && $ans != timeout ]]; then say "$ans"; fi
  ans=${ans,,}
  if [[ $ans != j && $ans != ja && $ans != y && $ans != yes ]]; then
    if [[ $ans == timeout ]]; then warn "Keine Antwort."; fi
    cmd_rollback
    say "  Zurückgesetzt. Neu starten mit: sudo bunny-guard"
    exit 0
  fi
  disarm_rollback
  rm -rf "$RB_DIR"
  ok "Konfiguration übernommen"

  if ufw_active; then
    local -a labeled=()
    mapfile -t labeled < <(ufw_labeled_rules)
    if (( ${#labeled[@]} > 0 )); then
      step "Alte UFW-Regeln"
      say "  Diese UFW-Regeln tragen einen BunnyCDN-/Gcore-Kommentar und werden durch bunny-guard ersetzt:"
      printf '      %s\n' "${labeled[@]}"
      local allp=1 p
      for p in $PORTS; do if ! ufw_allows_any "$p"; then allp=0; fi; done
      if (( ! allp )); then
        warn "UFW erlaubt Port(s) $PORTS nicht generell – ohne diese Regeln käme Bunny nicht mehr durch. Sie bleiben."
      elif ask_yn "Diese Regeln jetzt entfernen? (mit Backup unter /root)" n; then
        ufw_cleanup_apply "${labeled[@]}"
      else
        note "Später möglich mit: sudo bunny-guard cleanup-ufw --apply"
      fi
    fi
  fi

  step "Fertig"
  say "  Der Schutz ist aktiv und startet automatisch beim Booten."
  say ""
  say "    sudo bunny-guard status       Zustand und Zähler"
  say "    sudo bunny-guard check        alle Tests erneut (--extern: auch von außen)"
  say "    sudo bunny-guard              Assistent erneut (z.B. Domains ändern)"
  say "    sudo bunny-guard disable      abschalten (Konfiguration bleibt)"
  say "    sudo bunny-guard uninstall    alles entfernen"
  print_manual_tests
}

main() {
  local cmd=${1:-setup}
  if (( $# > 0 )); then shift; fi
  case $cmd in
    setup|install)   cmd_setup "$@" ;;
    status)          cmd_status ;;
    check|test)      cmd_check "$@" ;;
    update)          cmd_update "$@" ;;
    reload)          cmd_reload ;;
    load)            cmd_load ;;
    unload)          cmd_unload ;;
    cron)            cmd_cron ;;
    rollback)        cmd_rollback "$@" ;;
    disable|stop)    cmd_disable "$@" ;;
    enable|start)    cmd_enable ;;
    cleanup-ufw)     cmd_cleanup_ufw "$@" ;;
    uninstall)       cmd_uninstall "$@" ;;
    -h|--help|help)  usage ;;
    -V|--version|version) say "bunny-guard $VERSION" ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
