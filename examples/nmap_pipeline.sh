#!/bin/bash
# Rankle to Nmap pipeline

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

echo "[+] Extracting IP addresses"
jq -r '.dns.A[]' $JSON_FILE > $OUTPUT_DIR/ips.txt

IP_COUNT=$(wc -l < $OUTPUT_DIR/ips.txt)
echo "[+] Found $IP_COUNT IPv4 addresses"

echo "[+] Running Nmap service scan"
nmap -iL $OUTPUT_DIR/ips.txt \
  -sV \
  -p 80,443,8080,8443,22,21,3306,5432 \
  --script=banner,http-title,ssl-cert \
  -oA $OUTPUT_DIR/nmap_services

echo "[+] Running full port scan on first IP"
FIRST_IP=$(head -1 $OUTPUT_DIR/ips.txt)
nmap $FIRST_IP -p- -T4 -oA $OUTPUT_DIR/nmap_full_$FIRST_IP

echo "[+] Scan complete!"
echo "    Service scan: $OUTPUT_DIR/nmap_services.xml"
echo "    Full scan: $OUTPUT_DIR/nmap_full_$FIRST_IP.xml"
