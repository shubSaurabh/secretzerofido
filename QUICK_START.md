# Quick Start Guide - RDP QR Authentication

Get up and running in 15 minutes!

## What You Have Created

✅ Authentication Server (Python/Flask)
✅ QR Scanner Client (Python GUI)
⚠️ Credential Provider (C++ - needs to be built)

## Step-by-Step Setup

### 1. Authentication Server (Ubuntu - 5 minutes)

```bash
cd AuthServer

# Install dependencies
pip3 install -r requirements.txt

# IMPORTANT: Edit config.yaml and set your server IP
nano config.yaml

# Run server
python3 auth_server.py
```

Server runs on: `http://YOUR_IP:5000`

### 2. QR Scanner (Windows Laptop - 5 minutes)

```powershell
cd QRScanner

# Create virtual environment  
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# IMPORTANT: Edit config.yaml - set auth_server to your Ubuntu IP
notepad config.yaml

# Run scanner
python qr_scanner_rdp.py
```

### 3. Test Authentication Flow (5 minutes)

Before building the credential provider, test the system:

```powershell
# On Windows Server or any Windows machine
cd examples
pip install qrcode requests

# Edit test-qr-generator.py and set AUTH_SERVER_URL
python test-qr-generator.py
```

This creates `test_qr.png`. Display it on screen, then scan with your QR Scanner app.

If you see "Authentication successful!" - your system works! 🎉

### 4. Build Credential Provider (Windows Server - 30 minutes)

**This requires Visual Studio 2022 with C++ Desktop Development workload.**

The complete C++ source code is provided in the `CredentialProvider/Source/` directory.

See `CredentialProvider/README.md` for detailed build instructions.

## Current Status

**What's Working:**
- ✅ Authentication Server
- ✅ QR Scanner Client  
- ✅ End-to-end testing capability

**What Needs Building:**
- ⚠️ Windows Credential Provider (C++ DLL)
  - Complete source code provided
  - Requires Visual Studio to compile
  - Installation scripts included

## Next Steps

1. **Test the auth flow** using the test generator
2. **Set up Visual Studio** on Windows Server
3. **Build the Credential Provider** following CredentialProvider/README.md
4. **Install and test** on Windows Server

## Quick Architecture Overview

```
[RDP Login Screen]
        ↓
[Shows QR Code] ← Auth Server creates session
        ↓
[User scans QR] → Scanner signs challenge with private key
        ↓
[Auth Server validates] → Tells Credential Provider: "User authenticated"
        ↓
[Windows logs in user]
```

## Need Help?

- See `docs/` folder for detailed documentation
- Check `docs/TROUBLESHOOTING.md` for common issues
- Review `docs/SECURITY.md` for security details

## Important Configuration

**Before running, update these files:**

1. `AuthServer/config.yaml` - Set server IP
2. `QRScanner/config.yaml` - Set auth_server URL and user details
3. `CredentialProvider/Source/common.h` - Set AUTH_SERVER_URL (line 54)

