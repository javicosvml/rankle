#!/usr/bin/env python3
"""
Rankle - Web Infrastructure Reconnaissance Tool
Main entry point

Named after Rankle, Master of Pranks from Magic: The Gathering

A comprehensive web infrastructure analyzer:
- DNS enumeration and configuration
- Subdomain discovery via Certificate Transparency
- Technology stack detection (CMS, frameworks, libraries)
- TLS/SSL certificate analysis
- HTTP security headers audit
- CDN and WAF detection
- Geolocation and hosting provider information
- WHOIS lookup

100% Open Source - No API keys required
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config.settings import OUTPUT_DIR
    from rankle.core.scanner import RankleScanner
    from rankle.utils.helpers import save_json_file
    from rankle.utils.validators import (
        extract_domain,
        sanitize_filename,
        validate_domain,
    )
except ImportError as e:
    print(f"\n❌ Import Error: {e}")
    print("\nPlease ensure all dependencies are installed:")
    print("  pip install -r requirements.txt")
    sys.exit(1)


def print_banner():
    """Print Rankle banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗  █████╗ ███╗   ██╗██╗  ██╗██╗     ███████╗                     ║
║   ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██║     ██╔════╝                     ║
║   ██████╔╝███████║██╔██╗ ██║█████╔╝ ██║     █████╗                       ║
║   ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██║     ██╔══╝                       ║
║   ██║  ██║██║  ██║██║ ╚████║██║  ██╗███████╗███████╗                     ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝                     ║
║                                                                           ║
║              Web Infrastructure Reconnaissance Tool                       ║
║          Named after Rankle, Master of Pranks (MTG)                      ║
║                                                                           ║
║                      100% Open Source - No API Keys                      ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Rankle - Web Infrastructure Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py https://example.com --output json
  python main.py example.com --no-save

For more information, visit: https://github.com/javicosvml/rankle
        """,
    )

    parser.add_argument(
        "domain",
        help="Domain or URL to analyze (e.g., example.com or https://example.com)",
    )

    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "text", "both"],
        default="both",
        help="Output format (default: both)",
    )

    parser.add_argument(
        "--no-save", action="store_true", help="Don't save output to files"
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR,
        help=f"Output directory (default: {OUTPUT_DIR})",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    parser.add_argument("--version", action="version", version="Rankle v2.0.0")

    return parser.parse_args()


def main():
    """Main entry point"""
    print_banner()

    args = parse_arguments()

    # Extract and validate domain
    domain = extract_domain(args.domain)

    if not validate_domain(domain):
        print(f"❌ Invalid input: Invalid domain format: {args.domain}")
        sys.exit(1)

    # Print scan info
    print("=" * 80)
    print("🃏 RANKLE - Web Infrastructure Reconnaissance")
    print("=" * 80)
    print(f"🎯 Target: {domain}")
    print(f"⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    try:
        # Initialize scanner
        scanner = RankleScanner(domain, verbose=args.verbose)

        # Run comprehensive scan
        results = scanner.run_full_scan()

        # Save results if requested
        if not args.no_save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"rankle_{sanitize_filename(domain)}_{timestamp}"

            if args.output in ["json", "both"]:
                json_path = args.output_dir / f"{base_filename}.json"
                if save_json_file(results, json_path):
                    print(f"\n✅ Results saved to: {json_path}")

            if args.output in ["text", "both"]:
                text_path = args.output_dir / f"{base_filename}.txt"
                scanner.save_text_report(text_path)
                print(f"✅ Text report saved to: {text_path}")

        print("\n" + "=" * 80)
        print("✅ Scan completed successfully!")
        print("=" * 80)

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error during scan: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
