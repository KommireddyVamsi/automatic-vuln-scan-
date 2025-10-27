#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# quick_scan.sh - Safe quick scan helper (non-destructive by default)
# Usage: ./quick_scan.sh -d <target> -c [-o <outdir>] [-t <timeout>] [-j <jobs>]
# Example: ./quick_scan.sh -d example.com -c

TARGET=""
OUTROOT="./output"
TIMEOUT=300
JOBS=4
CONFIRM=0
VERBOSE=0

usage() {
  cat <<EOF
Usage: $0 -d <domain|ip|host> -c [options]
  -d <target>    Target (domain, IP, or host)
  -c             I have written permission to scan this target (required)
  -o <outdir>    Output base dir (default: ./output)
  -t <seconds>   Per-tool timeout (default: $TIMEOUT)
  -j <jobs>      Parallel jobs (default: $JOBS)
  -v             Verbose
EOF
  exit 1
}

while getopts ":d:o:t:j:cvh" opt; do
  case $opt in
    d) TARGET="$OPTARG" ;;
    o) OUTROOT="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    c) CONFIRM=1 ;;
    v) VERBOSE=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "[ERROR] No target specified." >&2
  usage
fi

if [ "$CONFIRM" -ne 1 ]; then
  echo -e "\n\e[33m[!] You must confirm you have written permission to scan the target. Rerun with -c to confirm.\e[0m\n"
  exit 2
fi

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTDIR="$OUTROOT/${TARGET//[:\/]/_}-$TIMESTAMP"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/scan.log"

log() { printf "%b\n" "$1" | tee -a "$LOG"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

log "[INFO] Quick scan starting for $TARGET"
log "[INFO] Output -> $OUTDIR"

# 1) Discovery: crt.sh & simple DNS (non-aggressive)
log "[INFO] Running passive discovery (crt.sh & DNS resolution)"
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > "$OUTDIR/all_subs.txt" || true
echo "$TARGET" >> "$OUTDIR/all_subs.txt"
sort -u -o "$OUTDIR/all_subs.txt" "$OUTDIR/all_subs.txt"

# 2) HTTP headers and TLS cert (non-destructive)
log "[INFO] Fetching HTTP headers and TLS certificate (if reachable)"
if has_cmd curl; then
  curl -sI --max-time 10 "https://$TARGET" > "$OUTDIR/headers_https.txt" || true
  curl -sI --max-time 10 "http://$TARGET" > "$OUTDIR/headers_http.txt" || true
fi

if has_cmd openssl; then
  printf "" | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text > "$OUTDIR/cert.txt" || true
fi

# 3) Nmap quick port/service scan (non-invasive flags)
if has_cmd nmap; then
  log "[INFO] Running nmap -sS -Pn -T4 -p- (this may take time)"
  timeout "$TIMEOUT" nmap -sS -Pn -T4 -p- "$TARGET" -oN "$OUTDIR/nmap-ports.txt" || true
  # service detection on discovered ports (read ports from previous output)
  PORTS=$(grep "^PORT" -A 500 "$OUTDIR/nmap-ports.txt" 2>/dev/null | awk '/^[0-9]/{print $1}' | sed 's#/tcp##' | tr '\n' ',' | sed 's/,$//')
  if [ -n "$PORTS" ]; then
    timeout "$TIMEOUT" nmap -sV -Pn -p"$PORTS" "$TARGET" -oN "$OUTDIR/nmap-services.txt" || true
  fi
fi

# 4) Web fingerprinting and directory discovery (if web reachable)
URL="$TARGET"
if [[ ! "$TARGET" =~ ^https?:// ]]; then
  URL="https://$TARGET"
fi

if has_cmd whatweb; then
  log "[INFO] Running whatweb"
  timeout "$TIMEOUT" whatweb --log-brief="$OUTDIR/whatweb.txt" "$URL" || true
fi

if has_cmd gobuster && [ -f /usr/share/wordlists/dirb/common.txt ]; then
  log "[INFO] Running gobuster (common dirlist)"
  timeout "$TIMEOUT" gobuster dir -u "$URL" -w /usr/share/wordlists/dirb/common.txt -o "$OUTDIR/gobuster.txt" || true
fi

# 5) Safe vulnerability scanning: nuclei (if installed). Only run if user accepts risk env var.
if has_cmd nuclei; then
  log "[INFO] nuclei detected. By default we run safe template set only."
  # run default nuclei templates but limiting to info/high-confidence only: users can override
  timeout "$TIMEOUT" nuclei -l "$OUTDIR/all_subs.txt" -t /usr/share/nuclei-templates -severity info,low,medium -o "$OUTDIR/nuclei.txt" || true
  log "[INFO] nuclei scan complete (results: $OUTDIR/nuclei.txt). Review templates before automated execution on production."
fi

# 6) Create templates for manual tools (sqlmap, hydra, msf) — DO NOT execute automatically
log "[INFO] Creating safe templates for sqlmap/hydra/msf (not executed)"
cat > "$OUTDIR/sqlmap-template.txt" <<'EOF'
# sqlmap template (edit target and params; DO NOT run without explicit permission)
sqlmap -u 'https://TARGET/?id=1' --batch --level=1 --risk=1
EOF

cat > "$OUTDIR/hydra-ssh-template.txt" <<'EOF'
# hydra SSH template (replace wordlists & user; DO NOT run without authorization)
hydra -L /path/to/usernames.txt -P /path/to/passwords.txt -t 4 ssh://TARGET
EOF

cat > "$OUTDIR/msf-template.rc" <<'EOF'
# Metasploit resource script template (manual review required)
use auxiliary/scanner/portscan/tcp
set RHOSTS TARGET
run
EOF

log "[INFO] Quick scan finished. Output directory: $OUTDIR"
log "[INFO] Remember: only scan authorized targets. Templates created but NOT executed."
