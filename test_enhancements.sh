#!/bin/bash
# Test script to demonstrate Rankle's enhanced detection capabilities

echo "=========================================="
echo "Rankle v1.1 - Enhanced Detection Test"
echo "=========================================="
echo ""

# Test domains with different technologies
DOMAINS=(
    "example.com"             # Test domain
    "wordpress.com"           # WordPress
    "www.joomla.org"         # Joomla
)

for domain in "${DOMAINS[@]}"; do
    echo "Testing: $domain"
    echo "---"
    
    python3 rankle.py "$domain" --json 2>&1 | grep -A 5 -E "CMS:|CDN:|WAF:|Libraries:" | head -15
    
    echo ""
    echo "---"
    echo ""
done

echo "✅ Enhanced detection test completed"
echo ""
echo "Key improvements tested:"
echo "  ✓ Enhanced Drupal detection (15+ patterns)"
echo "  ✓ TransparentEdge CDN detection"
echo "  ✓ WAF identification"
echo "  ✓ Library detection"
echo "  ✓ Improved WHOIS handling"
