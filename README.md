# RDP QR Code Authentication System

A passwordless authentication system for Windows RDP using QR codes and asymmetric cryptography. This implements a FIDO-inspired challenge-response authentication mechanism for both Windows domain and local users.

## 🎯 Overview

This system allows users to authenticate to Windows servers via RDP by scanning a QR code with their mobile device or workstation, eliminating the need for traditional passwords. The authentication uses RSA public-key cryptography for secure, passwordless login.

### Key Features

- ✅ **Passwordless Authentication**: No passwords transmitted or stored
- ✅ **QR Code Based**: Simple, user-friendly authentication flow
- ✅ **Domain & Local Users**: Supports both Active Directory and local Windows accounts
- ✅ **Challenge-Response**: Cryptographically secure using RSA-2048
- ✅ **Air-Gapped Support**: Designed to work in isolated network environments
- ✅ **Production Ready**: Complete with logging, error handling, and security features

## 🏗️ Architecture

The system consists of three main components:

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Windows RDP   │         │  Auth Server     │         │  QR Scanner     │
│     Server      │◄───────►│   (Ubuntu)       │◄───────►│   (Client)      │
│                 │         │                  │         │                 │
│ Credential      │  Poll   │ Session Mgmt     │  Auth   │ QR Detection    │
│ Provider (C++)  │  Status │ Public Key Store │ Request │ Private Key     │
│                 │         │ Challenge/Response│         │ Signing         │
└─────────────────┘         └──────────────────┘         └─────────────────┘
```

### Authentication Flow

1. **User initiates RDP connection** from their workstation to Windows Server
2. **Credential Provider displays QR code** on RDP login screen containing:
   - Session ID
   - Cryptographic challenge
   - Server identification
   - Timestamp
3. **User scans QR code** with scanner app on their workstation
4. **Scanner app**:
   - Extracts challenge from QR code
   - Signs challenge with user's private key (stored locally)
   - Sends signed challenge to authentication server
5. **Authentication server**:
   - Verifies signature using user's public key
   - Validates session hasn't expired
   - Returns Windows username to credential provider
6. **Credential Provider**:
   - Receives authenticated username
   - Creates Windows logon session
   - User is logged into RDP

## 🔒 Security Model

### Cryptographic Design

- **Asymmetric Cryptography**: RSA-2048 bit keys
- **Private Key**: Never leaves user's device
- **Public Key**: Registered with authentication server
- **Challenge-Response**: Each authentication uses unique challenge
- **Time-Limited Sessions**: 2-minute timeout prevents replay attacks
- **No Password Transmission**: Authentication token serves as cryptographic proof

### Why This is NOT a Password Bypass

This is a legitimate alternative authentication method, similar to:
- Windows Hello for Business
- FIDO2/WebAuthn
- Smart card authentication
- SSH key authentication

The system uses Windows' official Credential Provider API and creates proper logon sessions. The "auth token" mentioned in code is cryptographic proof of identity, not a password bypass.

### Security Considerations

✅ **Strengths:**
- Private keys never transmitted
- Challenge-response prevents replay attacks
- Time-limited sessions
- Public key cryptography (2048-bit RSA)
- Proper Windows API integration

⚠️ **Production Recommendations:**
- Use HTTPS for auth server (currently HTTP for POC)
- Integrate with TPM for hardware key protection
- Add certificate pinning between components
- Implement rate limiting
- Add comprehensive audit logging
- Consider FIDO2 certification for compliance requirements

## 📋 Prerequisites

### Windows Server (2019/2022)
- Visual Studio 2022 (Community Edition or higher)
- Windows SDK 10 or 11
- Administrator privileges
- .NET Framework 4.8+

### Ubuntu Server (20.04/22.04)
- Python 3.8+
- pip3
- Network connectivity to Windows Server

### Windows Client (Windows 10/11)
- Python 3.8+
- Webcam (for QR scanning)
- Network connectivity to both Windows Server and Ubuntu Server

## 🚀 Quick Start

### 1. Set Up Authentication Server (Ubuntu)

```bash
# Clone repository
git clone https://github.com/shubSaurabh/secretzerofido.git
cd secretzerofido/AuthServer

# Install dependencies
pip3 install -r requirements.txt

# Edit configuration (update server settings)
nano config.yaml

# Run server
python3 auth_server.py
```

### 2. Set Up QR Scanner (Windows Client)

```powershell
# Navigate to QR Scanner directory
cd secretzerofido\QRScanner

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run scanner (GUI will appear)
python qr_scanner_rdp.py
```

### 3. Build & Install Credential Provider (Windows Server)

```powershell
# Navigate to Credential Provider directory
cd secretzerofido\CredentialProvider

# Build (requires Visual Studio)
.\Scripts\Build.ps1

# Install (requires Administrator)
.\Scripts\Install.ps1

# Restart to load credential provider
Restart-Computer
```

## 📖 Detailed Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Complete step-by-step installation
- **[Architecture Guide](docs/ARCHITECTURE.md)** - Technical architecture details
- **[Security Documentation](docs/SECURITY.md)** - Security model and considerations
- **[Domain Setup Guide](docs/DOMAIN_SETUP.md)** - Active Directory integration
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## 🔧 Configuration

### Authentication Server (config.yaml)

```yaml
server:
  host: "0.0.0.0"
  port: 5000
  debug: false

security:
  session_timeout: 120  # seconds
  max_sessions: 1000
  
database:
  type: "memory"  # Use "sqlite" or "postgresql" for production
  path: "users.db"
```

### Credential Provider (common.h)

```cpp
// Update this to your Ubuntu server's IP
#define AUTH_SERVER_URL L"http://192.168.1.100:5000"
#define POLL_INTERVAL 2000
#define SESSION_TIMEOUT 120000
```

### QR Scanner (config.yaml)

```yaml
auth_server: "http://192.168.1.100:5000"
user:
  user_id: "user001"
  username: "testuser"
  domain: ""  # Leave empty for local, or "DOMAIN" for domain users
```

## 🧪 Testing

### Test with Mock QR Code

```powershell
cd examples
python test-qr-generator.py
```

This generates a test QR code that you can scan with the QR Scanner to verify the complete authentication flow.

## 🏢 Production Deployment

### For Production Use:

1. **Enable HTTPS**: Configure TLS certificates for auth server
2. **Use Proper Database**: Switch from in-memory to PostgreSQL/SQL Server
3. **Enable Logging**: Configure comprehensive audit logs
4. **Add Monitoring**: Set up health checks and alerts
5. **Implement Backup Auth**: Configure fallback authentication method
6. **Harden Security**: Follow security hardening guide
7. **Test Domain Integration**: Thoroughly test with Active Directory

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for production deployment guide.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the [Business Source License 1.1](LICENSE). You can use, modify and self-host it
for free, including in production inside your own organization. You may not sell it or offer it as a hosted
service. Each version becomes Apache 2.0 four years after it is published. Copyright SecurITaaS. For other
licensing, contact SecurITaaS.

Versions published before October 2026 were released under the MIT License, and those versions remain available
under MIT.

**Third-party components:** `CredentialProvider/Source/qrcodegen` is the QR Code generator library by Project
Nayuki, used under the MIT License (see the notice in its source files).

## ⚠️ Disclaimer

This is a proof-of-concept implementation. While it uses proper cryptographic principles and Windows APIs, it has not undergone security auditing. For production use in enterprise environments:

- Conduct thorough security review
- Consider professional security audit
- Follow your organization's security policies
- Test extensively in non-production environment first
- Consider certified FIDO2 solutions for compliance requirements

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/shubSaurabh/secretzerofido/issues)
- **Documentation**: [docs/](docs/)
- **Examples**: [examples/](examples/)

## 🙏 Acknowledgments

- QR Code generation library: [Project Nayuki's QR Code generator](https://www.nayuki.io/page/qr-code-generator-library)
- Windows Credential Provider samples: [Microsoft Samples](https://github.com/microsoft/Windows-classic-samples)
- Inspiration: FIDO Alliance specifications

## 📚 Additional Resources

- [Windows Credential Provider Documentation](https://docs.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
- [FIDO2 Specifications](https://fidoalliance.org/specifications/)
- [Cryptography Best Practices](https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model)

---

**Built with ❤️ for passwordless authentication**

