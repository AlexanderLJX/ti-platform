#!/usr/bin/env python3
"""Extract TOTP secrets from Google Authenticator migration QR codes.

This script decodes Google Authenticator export QR codes that use the
otpauth-migration:// format and extracts the base32 TOTP secrets.

Usage:
    python extract_google_auth_qr.py <qr_image_file>
    python extract_google_auth_qr.py <otpauth_migration_url>
"""

import sys
import base64
import urllib.parse
from typing import List, Dict


def decode_otpauth_migration(data: str) -> List[Dict]:
    """Decode Google Authenticator migration data.

    Args:
        data: Base64 encoded migration data from otpauth-migration:// URL

    Returns:
        List of account dictionaries with name, secret, issuer
    """
    # Simple protobuf parser for Google Authenticator format
    # Format: Field 1 repeated: name, secret, issuer, type, algorithm, digits

    try:
        decoded = base64.b64decode(data, validate=True)
    except Exception as e:
        print(f"Error: Invalid base64 data: {e}")
        return []

    accounts = []
    i = 0

    while i < len(decoded):
        # Check for field tag (0x0A = field 1, wire type 2 = length-delimited)
        if decoded[i] == 0x0A:
            i += 1
            # Get length of this account block
            account_length = decoded[i]
            i += 1

            account_data = decoded[i:i+account_length]
            account = parse_account(account_data)
            if account:
                accounts.append(account)

            i += account_length
        else:
            i += 1

    return accounts


def parse_account(data: bytes) -> Dict:
    """Parse a single account from protobuf data.

    Args:
        data: Account data bytes

    Returns:
        Dictionary with account info
    """
    account = {}
    i = 0

    while i < len(data):
        if i >= len(data):
            break

        tag = data[i]
        field = tag >> 3
        wire_type = tag & 0x07
        i += 1

        if wire_type == 2:  # Length-delimited (string)
            if i >= len(data):
                break
            length = data[i]
            i += 1
            if i + length > len(data):
                break
            value = data[i:i+length]
            i += length

            if field == 1:  # Secret (bytes)
                # Convert bytes to base32
                account['secret'] = base64.b32encode(value).decode('utf-8')
            elif field == 2:  # Name (string)
                account['name'] = value.decode('utf-8', errors='ignore')
            elif field == 3:  # Issuer (string)
                account['issuer'] = value.decode('utf-8', errors='ignore')
        elif wire_type == 0:  # Varint
            # Skip varint fields (type, algorithm, digits, counter)
            while i < len(data) and data[i] & 0x80:
                i += 1
            i += 1
        else:
            i += 1

    return account


def extract_from_url(url: str) -> List[Dict]:
    """Extract accounts from otpauth-migration URL.

    Args:
        url: Full otpauth-migration:// URL

    Returns:
        List of account dictionaries
    """
    if not url.startswith('otpauth-migration://'):
        print("Error: Not a valid otpauth-migration URL")
        return []

    # Parse URL
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if 'data' not in params:
        print("Error: No 'data' parameter found in URL")
        return []

    data = params['data'][0]
    return decode_otpauth_migration(data)


def extract_from_qr_image(image_path: str) -> List[Dict]:
    """Extract accounts from QR code image.

    Args:
        image_path: Path to QR code image file

    Returns:
        List of account dictionaries
    """
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
    except ImportError:
        print("Error: Required libraries not installed")
        print("Install with: pip install pillow pyzbar")
        return []

    try:
        img = Image.open(image_path)
        decoded_qr = decode(img)

        if not decoded_qr:
            print("Error: No QR code found in image")
            return []

        url = decoded_qr[0].data.decode('utf-8')
        return extract_from_url(url)

    except Exception as e:
        print(f"Error reading QR code: {e}")
        return []


def print_accounts(accounts: List[Dict]):
    """Print extracted accounts in a readable format.

    Args:
        accounts: List of account dictionaries
    """
    if not accounts:
        print("\nNo accounts found!")
        return

    print(f"\n{'='*70}")
    print(f"Found {len(accounts)} account(s):")
    print(f"{'='*70}\n")

    for idx, account in enumerate(accounts, 1):
        issuer = account.get('issuer', 'Unknown')
        name = account.get('name', 'Unknown')
        secret = account.get('secret', 'NOT FOUND')

        print(f"Account {idx}:")
        print(f"  Issuer:  {issuer}")
        print(f"  Name:    {name}")
        print(f"  Secret:  {secret}")
        print()

        # Generate .env format
        env_name = issuer.upper().replace(' ', '_').replace('-', '_')
        print(f"  Add to .env file:")
        print(f"  {env_name}_TOTP_SECRET={secret}")
        print()

    print(f"{'='*70}\n")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python extract_google_auth_qr.py <qr_image_file>")
        print("  python extract_google_auth_qr.py <otpauth_migration_url>")
        print()
        print("Example:")
        print("  python extract_google_auth_qr.py google_auth_export.png")
        print("  python extract_google_auth_qr.py 'otpauth-migration://offline?data=...'")
        sys.exit(1)

    input_data = sys.argv[1]

    # Determine if it's a URL or file
    if input_data.startswith('otpauth-migration://'):
        print("Processing otpauth-migration URL...")
        accounts = extract_from_url(input_data)
    else:
        print(f"Processing QR code image: {input_data}")
        accounts = extract_from_qr_image(input_data)

    print_accounts(accounts)


if __name__ == '__main__':
    main()