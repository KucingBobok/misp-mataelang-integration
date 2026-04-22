#!/usr/bin/env python3
"""
Generate a cryptographically secure API key for inter-service authentication.

Usage:
    python scripts/generate_api_key.py
    python scripts/generate_api_key.py --count 3

The generated key(s) should be added to .env as:
    SERVICE_API_KEY=<key>           # for a single key
    SERVICE_API_KEYS=key1,key2      # for multiple keys (comma-separated)
"""

import secrets
import argparse


def generate_key(length: int = 32) -> str:
    """Generate a URL-safe base64 token."""
    return secrets.token_urlsafe(length)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate API key(s) for Mata Elang integration service")
    parser.add_argument("--count", type=int, default=1, help="Number of keys to generate (default: 1)")
    parser.add_argument("--length", type=int, default=32, help="Key length in bytes (default: 32 → 43 chars)")
    args = parser.parse_args()

    print(f"\nGenerated {args.count} API key(s):\n")
    keys = [generate_key(args.length) for _ in range(args.count)]
    for i, key in enumerate(keys, 1):
        print(f"  Key {i}: {key}")

    print()
    if args.count == 1:
        print(f"Add to .env:")
        print(f"  SERVICE_API_KEY={keys[0]}")
    else:
        print(f"Add to .env:")
        print(f"  SERVICE_API_KEYS={','.join(keys)}")

    print()
    print("Send to clients as HTTP header:")
    print(f"  X-API-Key: {keys[0]}")
    print()
