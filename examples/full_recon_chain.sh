#!/bin/bash
# Complete automated recon chain: Rankle -> httpx -> Nuclei -> Nmap

DOMAIN=$1
WORKSPACE="recon_$(date +%Y%m%d_%H%M%S)_$DOMAIN"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

mkdir -p $WORKSPACE
echo "[*] Workspace: $WORKSPACE"

echo "[1/5] Rankle reconnaissance"
docker run --rm -v "$(pwd)/$WORKSPACE:/output" rankle "$DOMAIN" --output both
JSON="$WORKSPACE/${DOMAIN//./_}_rankle.json"

echo "[2/5] Extract and deduplicate subdomains"
jq -r '.subdomains[]' $JSON | grep -vE '(@|\*)' | sort -u > $WORKSPACE/subdomains.txt
echo "    Found: $(wc -l < $WORKSPACE/subdomains.txt) subdomains"

echo "[3/5] Live host detection with httpx"
cat $WORKSPACE/subdomains.txt | \
  httpx -silent -title -status-code -tech-detect -o $WORKSPACE/live_hosts.txt
echo "    Live: $(wc -l < $WORKSPACE/live_hosts.txt) hosts"

echo "[4/5] Nuclei vulnerability scan"
nuclei -l $WORKSPACE/live_hosts.txt \
  -severity medium,high,critical \
  -o $WORKSPACE/nuclei_vulns.txt
echo "    Found: $(wc -l < $WORKSPACE/nuclei_vulns.txt) potential issues"

echo "[5/5] Nmap port scan on IPs"
jq -r '.dns.A[]' $JSON | \
  nmap -iL - -sV -p 80,443,8080,8443,22,21,25,3306,5432 \
  -oA $WORKSPACE/nmap_scan

cat > $WORKSPACE/REPORT.txt << REPORT
Reconnaissance Report - $DOMAIN
Generated: $(date)
================================

Statistics:
  Total Subdomains: $(wc -l < $WORKSPACE/subdomains.txt)
  Live Hosts: $(wc -l < $WORKSPACE/live_hosts.txt)
  Vulnerabilities: $(wc -l < $WORKSPACE/nuclei_vulns.txt)
  IPs Scanned: $(jq '.dns.A | length' $JSON)

Files:
  - Rankle JSON: ${DOMAIN//./_}_rankle.json
  - Rankle Text: ${DOMAIN//./_}_rankle_report.txt
  - Subdomains: subdomains.txt
  - Live Hosts: live_hosts.txt
  - Vulnerabilities: nuclei_vulns.txt
  - Port Scan: nmap_scan.xml

Top Findings:
$(head -20 $WORKSPACE/nuclei_vulns.txt)
REPORT

echo ""
echo "Complete! Results in: $WORKSPACE/"
echo "Summary: $WORKSPACE/REPORT.txt"
