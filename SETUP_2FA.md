# Automatic Google Authenticator 2FA Setup Guide

## Overview
The platform now automatically handles Google Authenticator 2FA for both Mandiant and CrowdStrike platforms. No manual token entry required!

## How It Works
The system uses TOTP (Time-based One-Time Password) secrets to generate 6-digit codes automatically, just like your Google Authenticator app.

## Setup Instructions

### Step 1: Get Your TOTP Secret

When setting up 2FA on Mandiant or CrowdStrike:

1. Navigate to the 2FA setup page in your account settings
2. When presented with a QR code, look for options like:
   - "Can't scan QR code?"
   - "Manual entry"
   - "Enter key manually"
   - "View secret key"
3. Click that option to reveal the **base32 secret key**
4. Copy the secret (typically 16-32 characters, like: `JBSWY3DPEHPK3PXP`)

**Important**: If you've already set up 2FA, you'll need to:
- Remove the existing 2FA from your account
- Set it up again to get the secret key
- Add the same secret to both this platform AND your Google Authenticator app

### Step 2: Add Secret to .env File

1. Copy `.env.example` to `.env` if you haven't already:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file and add your TOTP secrets:

   ```bash
   # Mandiant Credentials
   MANDIANT_EMAIL=your_email@example.com
   MANDIANT_PASSWORD=your_secure_password
   MANDIANT_TOTP_SECRET=JBSWY3DPEHPK3PXP  # Your actual secret here

   # CrowdStrike Credentials
   CROWDSTRIKE_EMAIL=your_email@example.com
   CROWDSTRIKE_PASSWORD=your_secure_password
   CROWDSTRIKE_TOTP_SECRET=KBSWY3DPEHPK3PXQ  # Your actual secret here
   ```

3. Save the file

### Step 3: Test It

Run a scrape command:
```bash
ti-platform scrape --source mandiant
```

The platform will:
1. Navigate to login page
2. Enter email and password
3. **Automatically generate and enter the 2FA code**
4. Complete authentication
5. Start scraping

## What Happens During Authentication

```
[INFO] Starting authentication for mandiant
[INFO] Email entered: your_email@example.com
[INFO] Password entered
[INFO] Login form submitted
[INFO] 2FA required - generating TOTP token
[INFO] Generated TOTP token: 123456
[INFO] Entering 2FA token in single field
[INFO] 2FA token entered
[INFO] 2FA form submitted
[INFO] Validating 2FA token...
[INFO] 2FA validation completed
[INFO] Authentication successful
```

## Security Best Practices

1. **Never commit `.env` to version control**
   - Already protected by `.gitignore`

2. **Secure your TOTP secrets**
   - Treat them like passwords
   - They provide the same access as a physical 2FA device

3. **Use strong passwords**
   - 2FA is your second layer of security

4. **Backup your secrets**
   - Store them securely (password manager)
   - If lost, you'll need to reset 2FA

## Troubleshooting

### "Automatic 2FA failed"
- **Check secret format**: Should be base32 (A-Z, 2-7)
- **Verify time sync**: TOTP depends on accurate system time
- **Check spaces**: Remove any spaces from the secret
- **Verify source**: Make sure you're using the correct secret for each platform

### "Still on 2FA page, validation may have failed"
- **Time sync issue**: Run `w32tm /resync` (Windows) or `ntpdate` (Linux)
- **Wrong secret**: Double-check you copied the correct secret
- **Account locked**: Too many failed attempts may temporarily lock your account

### Falls back to manual 2FA
If the system doesn't find a TOTP secret, it will prompt you:
```
[INFO] No TOTP secret found, falling back to manual 2FA
Enter your 2FA token:
```

This means:
- TOTP_SECRET is not set in `.env`
- Or the environment variable name is incorrect

## Manual 2FA Fallback

If you prefer manual 2FA or can't get the secret:
- Simply don't set the `TOTP_SECRET` variables
- The system will prompt you to enter codes manually
- You can use your Google Authenticator app normally

## Code Changes Made

**Fixed bug in `src/utils/auth_handler.py`**:
- Line 244 & 346: Fixed incorrect `By` attribute conversion
- Changed `by.upper()` to `by.upper().replace(' ', '_')`
- This ensures proper handling of element locators like `CSS_SELECTOR`

## How TOTP Works

1. Your secret key + current time = unique 6-digit code
2. Code changes every 30 seconds
3. Both server and client use the same algorithm
4. Codes stay in sync as long as time is accurate

The `pyotp` library handles all this automatically:
```python
totp = pyotp.TOTP(totp_secret)
token = totp.now()  # Generates current 6-digit code
```

## Platform-Specific Notes

### Mandiant
- Single text field for 6-digit code
- Standard TOTP implementation
- 30-second token validity

### CrowdStrike
- May use separate input fields (one per digit)
- System automatically detects and fills appropriately
- Also supports single field format

Both platforms use standard TOTP, so any Google Authenticator-compatible secret will work.