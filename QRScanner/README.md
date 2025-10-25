# QR Scanner Client

Python application for scanning QR codes and authenticating to RDP sessions.

## Installation

### Windows

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux/Mac

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Edit `config.yaml` to set your authentication server URL and user details.

## Running

```bash
python qr_scanner_rdp.py
```

## Features

- Screen region scanning for QR codes
- Automatic RDP connection
- RSA key generation and management
- User registration with auth server

