#!/bin/bash
# Rankle to Nuclei pipeline

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

OUTPUT_DIR="./recon_output"
mkdir -p $OUTPUT_DIR

echo "[+] Running Rankle scan on $DOMAIN"
docker run --rm -v $OUTPUT_DIR:/output rankle $DOMAIN --json

JSON_FILE="$OUTPUT_DIR/${DOMAIN//./_}_rankle.json"

echo "[+] Extracting subdomains"
jq -r '.subdomains[]' $JSON_FILE | \
  grep -vE '(@|\*)' | \
  sort -u > $OUTPUT_DIR/subdomains.txt

SUBDOMAIN_COUNT=$(wc -l < $OUTPUT_DIR/subdomains.txt)
echo "[+] Found $SUBDOMAIN_COUNT valid subdomains"

echo "[+] Checking live hosts with httpx"
cat $OUTPUT_DIR/subdomains.txt | \
  httpx -silent -title -tech-detect -o $OUTPUT_DIR/live_hosts.txt

LIVE_COUNT=$(wc -l < $OUTPUT_DIR/live_hosts.txt)
echo "[+] Found $LIVE_COUNT live hosts"

echo "[+] Running Nuclei scan"
nuclei -l $OUTPUT_DIR/live_hosts.txt \
  -t nuclei-templates/cves/ \
  -t nuclei-templates/vulnerabilities/ \
  -severity high,critical \
  -o $OUTPUT_DIR/nuclei_findings.txt

echo "[+] Scan complete!"
echo "    Results: $OUTPUT_DIR/nuclei_findings.txt"
