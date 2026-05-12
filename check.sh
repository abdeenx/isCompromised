#!/usr/bin/env bash
# =============================================================================
# TanStack NPM Supply Chain Compromise — IOC Detection Script
# Based on the official TanStack postmortem
# Run as root on your VPS to check for signs of compromise
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

FINDINGS=0
WARNINGS=0

banner() {
  echo ""
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo -e "${BOLD}${CYAN}  TanStack Supply Chain Compromise — IOC Scanner${RESET}"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo -e "  Running as: $(whoami)  |  Host: $(hostname)  |  $(date)"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo ""
}

section() {
  echo ""
  echo -e "${BOLD}${CYAN}── $1 ${RESET}"
}

ok() {
  echo -e "  ${GREEN}[OK]${RESET}  $1"
}

warn() {
  echo -e "  ${YELLOW}[WARN]${RESET} $1"
  ((WARNINGS++)) || true
}

hit() {
  echo -e "  ${RED}[HIT]${RESET}  $1"
  ((FINDINGS++)) || true
}

info() {
  echo -e "  ${CYAN}[INFO]${RESET} $1"
}

# =============================================================================
# 1. Check for malicious optionalDependency in installed node_modules
# =============================================================================
check_package_manifests() {
  section "1/8  Scanning package.json manifests for malicious optionalDependency"

  local pattern='@tanstack/setup.*github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c'
  local found=0

  # Search common locations
  while IFS= read -r -d '' f; do
    if grep -qP '@tanstack/setup' "$f" 2>/dev/null; then
      if grep -qP '79ac49eedf774dd4b0cfa308722bc463cfe5885c' "$f" 2>/dev/null; then
        hit "Malicious optionalDependency found in: $f"
        found=1
      else
        warn "Found @tanstack/setup reference (manual review needed): $f"
      fi
    fi
  done < <(find / -name "package.json" \
    -not -path "*/proc/*" \
    -not -path "*/sys/*" \
    -not -path "*/dev/*" \
    -print0 2>/dev/null)

  [[ $found -eq 0 ]] && ok "No malicious @tanstack/setup optionalDependency found"
}

# =============================================================================
# 2. Check for the 2.3 MB router_init.js payload file
# =============================================================================
check_router_init() {
  section "2/8  Searching for router_init.js payload (~2.3 MB)"

  local found=0
  while IFS= read -r -d '' f; do
    local size
    size=$(stat -c%s "$f" 2>/dev/null || echo 0)
    # Flag if between 2MB and 3MB (covers the ~2.3 MB stated size)
    if [[ $size -ge 2000000 && $size -le 3000000 ]]; then
      hit "Suspicious router_init.js found (size: ${size} bytes): $f"
      found=1
    else
      warn "router_init.js found but unexpected size (${size} bytes — review): $f"
      found=1
    fi
  done < <(find / -name "router_init.js" \
    -not -path "*/proc/*" \
    -not -path "*/sys/*" \
    -not -path "*/dev/*" \
    -print0 2>/dev/null)

  [[ $found -eq 0 ]] && ok "No router_init.js found"
}

# =============================================================================
# 3. Check pnpm store for the malicious cache key
# =============================================================================
check_pnpm_cache() {
  section "3/8  Checking pnpm store for malicious cache key"

  local cache_key="6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11"
  local found=0

  # Common pnpm store locations
  for dir in ~/.pnpm-store /root/.pnpm-store /home/*/.pnpm-store \
              ~/.local/share/pnpm/store /root/.local/share/pnpm/store; do
    if [[ -d "$dir" ]]; then
      if grep -rq "$cache_key" "$dir" 2>/dev/null; then
        hit "Malicious pnpm cache key found in: $dir"
        found=1
      fi
    fi
  done

  # Also search for the key in GitHub Actions cache dirs
  for dir in /root/.cache /home/*/.cache /tmp; do
    if [[ -d "$dir" ]]; then
      if grep -rlq "$cache_key" "$dir" 2>/dev/null; then
        hit "Malicious cache key string found in: $dir"
        found=1
      fi
    fi
  done

  [[ $found -eq 0 ]] && ok "Malicious pnpm cache key not found"
}

# =============================================================================
# 4. Check DNS / network history for exfiltration domains
# =============================================================================
check_exfil_domains() {
  section "4/8  Checking for connections to exfiltration domains"

  local domains=(
    "filev2.getsession.org"
    "seed1.getsession.org"
    "seed2.getsession.org"
    "seed3.getsession.org"
    "litter.catbox.moe"
  )

  # Check active connections
  for domain in "${domains[@]}"; do
    local ip
    ip=$(dig +short "$domain" 2>/dev/null | head -1 || true)

    if ss -tnp 2>/dev/null | grep -q "$ip" && [[ -n "$ip" ]]; then
      hit "ACTIVE CONNECTION to exfil domain: $domain ($ip)"
    fi

    # Check /etc/hosts for any redirect attempts
    if grep -q "$domain" /etc/hosts 2>/dev/null; then
      warn "/etc/hosts entry for exfil domain (could be a block): $domain"
    fi
  done

  # Check systemd journal for domain references (last 7 days)
  if command -v journalctl &>/dev/null; then
    for domain in "${domains[@]}"; do
      if journalctl --since "7 days ago" 2>/dev/null | grep -q "$domain"; then
        hit "Exfil domain seen in system journal (last 7 days): $domain"
      fi
    done
  fi

  # Check common log files
  for log in /var/log/syslog /var/log/messages /var/log/auth.log; do
    if [[ -f "$log" ]]; then
      for domain in "${domains[@]}"; do
        if grep -q "$domain" "$log" 2>/dev/null; then
          hit "Exfil domain found in $log: $domain"
        fi
      done
    fi
  done

  ok "Active connection scan to exfil domains complete"
}

# =============================================================================
# 5. Check for payload URLs in scripts / history
# =============================================================================
check_payload_urls() {
  section "5/8  Scanning for 2nd-stage payload URLs"

  local urls=(
    "litter.catbox.moe/h8nc9u.js"
    "litter.catbox.moe/7rrc6l.mjs"
  )

  local search_paths=(
    /root /home /tmp /var /opt /srv /etc
    /usr/local/bin /usr/local/lib
  )

  # Resolve the real path of this script so we can exclude it from searches
  local this_script
  this_script=$(realpath "${BASH_SOURCE[0]}" 2>/dev/null || readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "")

  for url in "${urls[@]}"; do
    local found=0
    for path in "${search_paths[@]}"; do
      if [[ -d "$path" ]]; then
        while IFS= read -r match; do
          # Skip hits that point back to this script itself
          [[ -n "$this_script" && "$match" == "$this_script" ]] && continue
          hit "Payload URL '$url' found in: $match"
          found=1
        done < <(grep -rl "$url" "$path" 2>/dev/null)
      fi
    done
    # Check shell histories
    for hist in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do
      if [[ -f "$hist" ]] && grep -q "$url" "$hist" 2>/dev/null; then
        hit "Payload URL '$url' found in shell history: $hist"
        found=1
      fi
    done
    [[ $found -eq 0 ]] && ok "Payload URL not found: $url"
  done
}

# =============================================================================
# 6. Check for processes making suspicious outbound connections
# =============================================================================
check_suspicious_processes() {
  section "6/8  Inspecting active outbound connections from Node.js processes"

  local exfil_ips=()
  for domain in filev2.getsession.org seed1.getsession.org seed2.getsession.org seed3.getsession.org litter.catbox.moe; do
    local ip
    ip=$(dig +short "$domain" 2>/dev/null | head -1 || true)
    [[ -n "$ip" ]] && exfil_ips+=("$ip")
  done

  if command -v ss &>/dev/null; then
    local node_conns
    node_conns=$(ss -tnp 2>/dev/null | grep -E 'node|npm' || true)
    if [[ -n "$node_conns" ]]; then
      info "Active Node.js/npm connections:"
      echo "$node_conns" | while read -r line; do
        info "  $line"
        for ip in "${exfil_ips[@]}"; do
          if echo "$line" | grep -q "$ip"; then
            hit "Node.js process connected to known exfil IP: $ip"
          fi
        done
      done
    else
      ok "No active Node.js outbound connections detected"
    fi
  fi

  # Check for suspicious node processes with env vars that might carry stolen tokens
  if command -v ps &>/dev/null; then
    local suspicious
    suspicious=$(ps aux 2>/dev/null | grep -E '\bnode\b' | grep -v grep || true)
    if [[ -n "$suspicious" ]]; then
      info "Running Node.js processes (review manually):"
      echo "$suspicious" | while read -r line; do
        info "  $line"
      done
    fi
  fi
}

# =============================================================================
# 7. Check environment for stolen secrets that may have been exfiltrated
# =============================================================================
check_env_secrets() {
  section "7/8  Checking if sensitive env vars are exposed in process environments"

  local sensitive_vars=(
    "NPM_TOKEN" "NODE_AUTH_TOKEN" "NPM_AUTH_TOKEN"
    "GITHUB_TOKEN" "GH_TOKEN" "GITHUB_PAT"
    "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY"
    "CI_TOKEN" "PUBLISH_TOKEN"
  )

  local exposed=0
  for var in "${sensitive_vars[@]}"; do
    # Check if any running process has this var in its environment
    while IFS= read -r -d '' envfile; do
      if grep -qz "$var" "$envfile" 2>/dev/null; then
        local pid
        pid=$(basename "$(dirname "$envfile")")
        local cmdline
        cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "unknown")
        warn "Sensitive var '$var' found in process $pid env: $cmdline"
        exposed=1
      fi
    done < <(find /proc -maxdepth 2 -name environ -print0 2>/dev/null)
  done

  # Check .npmrc files for tokens
  while IFS= read -r -d '' f; do
    if grep -qiE '(authToken|_auth|token)' "$f" 2>/dev/null; then
      warn ".npmrc with auth token found: $f — verify it has not been leaked"
    fi
  done < <(find / -name ".npmrc" \
    -not -path "*/proc/*" -not -path "*/sys/*" \
    -print0 2>/dev/null)

  [[ $exposed -eq 0 ]] && ok "No sensitive CI/auth vars detected in running process environments"
}

# =============================================================================
# 8. Check installed @tanstack package versions
# =============================================================================
check_tanstack_versions() {
  section "8/8  Auditing installed @tanstack package versions"

  local found_any=0

  while IFS= read -r -d '' pkg; do
    local dir
    dir=$(dirname "$pkg")
    local name version
    name=$(node -e "try{const p=require('$pkg');console.log(p.name||'')}catch(e){}" 2>/dev/null || \
           grep -oP '"name"\s*:\s*"\K[^"]+' "$pkg" 2>/dev/null | head -1 || echo "unknown")
    version=$(grep -oP '"version"\s*:\s*"\K[^"]+' "$pkg" 2>/dev/null | head -1 || echo "unknown")

    # Check for @tanstack/* packages
    if echo "$name" | grep -q '@tanstack/'; then
      found_any=1
      # Check if the package contains router_init.js (shouldn't be there)
      if [[ -f "$dir/router_init.js" ]]; then
        hit "@tanstack package '$name@$version' contains router_init.js: $dir"
      fi
      # Check if it has the malicious optionalDependency
      if grep -q '79ac49eedf774dd4b0cfa308722bc463cfe5885c' "$pkg" 2>/dev/null; then
        hit "@tanstack package '$name@$version' has malicious commit hash in manifest: $pkg"
      fi
      info "Found: $name@$version  ($dir)"
    fi
  done < <(find /usr /opt /root /home /srv \
    -name "package.json" \
    -path "*/node_modules/@tanstack/*/package.json" \
    -not -path "*/proc/*" -not -path "*/sys/*" \
    -print0 2>/dev/null)

  [[ $found_any -eq 0 ]] && ok "No @tanstack packages installed on this system"
}

# =============================================================================
# Summary
# =============================================================================
summary() {
  echo ""
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo -e "${BOLD}  SCAN COMPLETE — SUMMARY${RESET}"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"

  if [[ $FINDINGS -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}COMPROMISE INDICATORS FOUND: $FINDINGS hit(s)${RESET}"
    echo ""
    echo -e "  ${RED}Recommended immediate actions:${RESET}"
    echo -e "  1. Rotate ALL npm tokens, GitHub PATs, and CI secrets immediately"
    echo -e "  2. Revoke and re-issue any cloud credentials (AWS, GCP, etc.)"
    echo -e "  3. Check npm audit log for unauthorized publishes of your packages"
    echo -e "  4. Remove node_modules and reinstall from a clean lockfile"
    echo -e "  5. Block outbound traffic to: filev2.getsession.org, *.getsession.org"
    echo -e "  6. Report to npm security: https://www.npmjs.com/support"
    echo -e "  7. Consider taking this VPS offline and forensically imaging it"
  elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}No confirmed hits, but $WARNINGS warning(s) need manual review${RESET}"
    echo -e "  Review the [WARN] lines above carefully."
  else
    echo -e "  ${GREEN}${BOLD}No IOCs detected. System appears clean.${RESET}"
    echo -e "  Continue monitoring. Stay updated on the TanStack postmortem."
  fi

  echo ""
  echo -e "  Reference: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"
  echo -e "${BOLD}${CYAN}============================================================${RESET}"
  echo ""
}

# =============================================================================
# Entry point
# =============================================================================
main() {
  banner

  if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[WARN] Not running as root — some checks may be incomplete.${RESET}"
    echo -e "       Re-run with: sudo bash $0"
    echo ""
  fi

  # Require dig for DNS checks
  if ! command -v dig &>/dev/null; then
    info "Installing 'dig' (dnsutils)..."
    apt-get install -y dnsutils &>/dev/null || yum install -y bind-utils &>/dev/null || true
  fi

  check_package_manifests
  check_router_init
  check_pnpm_cache
  check_exfil_domains
  check_payload_urls
  check_suspicious_processes
  check_env_secrets
  check_tanstack_versions

  summary
}

main "$@"
