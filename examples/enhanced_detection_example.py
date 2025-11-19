#!/usr/bin/env python3
"""
Example: Enhanced Technology Detection

Demonstrates the new confidence-based technology detection system
"""

import os
import sys

# Add parent directory to path  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rankle import Rankle  # noqa: E402


def main():
    """Run enhanced detection examples"""

    print("=" * 80)
    print("🔬 Enhanced Technology Detection Examples")
    print("=" * 80)

    # Example 1: Detect technologies with confidence scoring
    print("\n📝 Example 1: Basic Enhanced Detection")
    print("-" * 80)

    target = "wordpress.org"
    print(f"\nTarget: {target}")

    try:
        rankle = Rankle(target)

        # Get HTTP response
        import requests

        response = requests.get(f"https://{target}", timeout=15)

        # Run enhanced detection
        results = rankle.detect_technologies_enhanced(response)

        if results:
            print(f"\n✅ Found {results['total_count']} technologies\n")

            # Display by category
            categorized = results.get("categorized", {})
            for category, techs in categorized.items():
                print(f"📦 {category}:")
                for tech in techs:
                    confidence_pct = int(tech["confidence"] * 100)
                    version_str = f" v{tech['version']}" if tech["version"] else ""

                    # Confidence indicator
                    if confidence_pct >= 80:
                        indicator = "🟢"
                    elif confidence_pct >= 50:
                        indicator = "🟡"
                    else:
                        indicator = "🟠"

                    print(
                        f"  {indicator} {tech['name']}{version_str} ({confidence_pct}%)"
                    )
                print()

        else:
            print("⚠️  No technologies detected")

    except Exception as e:
        print(f"❌ Error: {e}")

    # Example 2: Compare with legacy detection
    print("\n" + "=" * 80)
    print("📝 Example 2: Enhanced vs Legacy Detection Comparison")
    print("-" * 80)

    target2 = "github.com"
    print(f"\nTarget: {target2}")

    try:
        rankle2 = Rankle(target2)
        response2 = requests.get(f"https://{target2}", timeout=15)

        # Enhanced detection
        print("\n🔬 Enhanced Detection Results:")
        enhanced = rankle2.detect_technologies_enhanced(response2)
        if enhanced:
            print(f"   Technologies found: {enhanced['total_count']}")

        # Legacy detection
        print("\n🔧 Legacy Detection Results:")
        legacy = rankle2.detect_technologies(response2)
        if legacy:
            print(f"   CMS: {legacy.get('cms', 'Unknown')}")
            print(f"   Frameworks: {len(legacy.get('frameworks', []))}")
            print(f"   Libraries: {len(legacy.get('libraries', []))}")

    except Exception as e:
        print(f"❌ Error: {e}")

    # Example 3: Accessing detailed detection data
    print("\n" + "=" * 80)
    print("📝 Example 3: Detailed Detection Data")
    print("-" * 80)

    target3 = "reactjs.org"
    print(f"\nTarget: {target3}")

    try:
        rankle3 = Rankle(target3)
        response3 = requests.get(f"https://{target3}", timeout=15)

        results3 = rankle3.detect_technologies_enhanced(response3)

        if results3 and results3["detected"]:
            print("\n📊 Detailed Detection Information:\n")

            for tech_name, tech_data in list(results3["detected"].items())[:3]:
                print(f"Technology: {tech_name}")
                print(f"  Category: {tech_data['category']}")
                print(f"  Confidence: {tech_data['confidence']:.2f}")
                if tech_data.get("version"):
                    print(f"  Version: {tech_data['version']}")
                print("  Indicators found:")
                for indicator in tech_data.get("indicators", []):
                    print(f"    - {indicator}")
                print()

    except Exception as e:
        print(f"❌ Error: {e}")

    print("=" * 80)
    print("✅ Examples completed")
    print("=" * 80)


if __name__ == "__main__":
    main()
