# Windows RDP QR Authentication with Ephemeral Certificates - POC

This package contains everything you need to implement certificate-based Windows authentication using QR codes and ephemeral certificates (no TPM/Smart Card required).

---

## 📦 What's Included

### 1. **auth_server_cert.py** - Authentication Server
Enhanced auth server with certificate generation capabilities:
- ✅ Generates ephemeral certificates (5-minute validity)
- ✅ Includes Microsoft SID extension for strong mapping (CVE-2022-26931)
- ✅ Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2)
- ✅ UPN in Subject Alternative Name
- ✅ Built-in CRL service for certificate revocation
- ✅ Uses pyOpenSSL for certificate generation
- ✅ Test user hardcoded: ross.green@secretzero.com with SID: S-1-5-21-2065755198-886904826-1734203342-1104

### 2. **requirements.txt** - Python Dependencies
```
Flask==3.0.0
flask-cors==4.0.0
pyOpenSSL==24.0.0
PyYAML==6.0.1
cryptography==41.0.7
```

### 3. **config.yaml** - Server Configuration
Configurable settings for:
- Server host/port
- Session timeout
- Certificate validity period
- CA certificate paths

### 4. **test_auth_server.py** - Comprehensive Test Suite
Validates:
- ✅ Certificate structure and Windows compatibility
- ✅ SID extension presence and correctness
- ✅ Smart Card Logon EKU
- ✅ UPN in Subject Alternative Name
- ✅ Private key accessibility
- ✅ PFX format validity
- ✅ CRL service

### 5. **WINDOWS_SERVER_SETUP.md** - Windows Configuration Guide
Complete step-by-step instructions for:
- Installing CA certificate to Trusted Root and NTAuth stores
- Configuring PKINIT for certificate authentication
- Setting up RDP for QR code authentication
- Troubleshooting common issues
- Includes PowerShell automation script

### 6. **CREDENTIAL_PROVIDER_CHANGES.md** - CP Integration Guide
Detailed implementation guide for modifying your Credential Provider:
- Certificate import functions using Windows Crypto API
- Certificate authentication workflow
- GetSerialization updates for KERB_CERTIFICATE_LOGON
- Complete code examples in C++
- Testing and debugging tips

### 7. **QUICK_START.md** - Complete Setup Guide
End-to-end setup guide covering:
- Auth server installation (5 minutes)
- Windows Server configuration (15 minutes)
- Credential Provider updates (30 minutes)
- Testing procedures (10 minutes)
- Success checklist
- Troubleshooting guide

---

## 🚀 Quick Start

### 1. Start Auth Server (5 min)

```bash
# Install dependencies
pip install -r requirements.txt

# Start server
python auth_server_cert.py
```

### 2. Test Certificate Generation (2 min)

```bash
python test_auth_server.py
```

Expected output:
```
🎉 ALL TESTS PASSED! Server is ready for Windows integration.
COMPATIBILITY SCORE: 5.0/5.0
✓ CERTIFICATE FULLY COMPATIBLE WITH WINDOWS
```

### 3. Configure Windows Server (15 min)

On Windows Server, run PowerShell as Administrator:

```powershell
# Download CA certificate
Invoke-WebRequest -Uri "http://YOUR_AUTH_SERVER_IP:5000/api/ca/certificate/der" -OutFile "C:\Temp\ca_cert.cer"

# Install to Trusted Root
Import-Certificate -FilePath "C:\Temp\ca_cert.cer" -CertStoreLocation "Cert:\LocalMachine\Root"

# Add to NTAuth store (CRITICAL)
certutil -dspublish -f "C:\Temp\ca_cert.cer" NTAuthCA

# Restart services
Restart-Service -Name "KDC" -Force
Restart-Service -Name "TermService" -Force

# Update Group Policy
gpupdate /force
```

### 4. Update Credential Provider (30 min)

Follow instructions in **CREDENTIAL_PROVIDER_CHANGES.md** to:
1. Add certificate import function
2. Update authentication polling to fetch certificates
3. Modify GetSerialization for KERB_CERTIFICATE_LOGON
4. Build and deploy

---

## 🎯 Key Features

### Certificate Properties (Windows-Compatible)
- ✅ **Ephemeral:** 5-minute validity period
- ✅ **Strong Mapping:** SID extension (OID 1.3.6.1.4.1.311.25.2)
- ✅ **Smart Card Logon:** EKU 1.3.6.1.4.1.311.20.2.2
- ✅ **User Identification:** UPN in Subject Alternative Name
- ✅ **No TPM Required:** Uses Software KSP
- ✅ **Revocable:** CRL service included

### Security Features
- Cryptographically secure random session IDs
- Certificate auto-expiration after 5 minutes
- Certificate revocation on session expiry
- Built-in CRL distribution
- Session timeout protection
- Memory leak prevention

### Production-Ready Components
- Health check endpoint
- Comprehensive logging
- Background cleanup threads
- RESTful API design
- Error handling

---

## 🔧 Architecture

```
┌─────────────┐
│  QR Code    │
│  Displayed  │
│  on Login   │
└──────┬──────┘
       │
       v
┌─────────────────┐
│  User Scans     │
│  with Mobile    │
└──────┬──────────┘
       │
       v
┌──────────────────────┐
│  Auth Server         │
│  - Validates user    │
│  - Generates cert    │
│  - Adds SID ext      │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│  Credential Provider │
│  - Fetches cert      │
│  - Imports to store  │
│  - Calls LSA         │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│  Windows / DC        │
│  - Validates cert    │
│  - Checks NTAuth     │
│  - Verifies SID      │
│  - Issues TGT        │
└──────┬───────────────┘
       │
       v
┌──────────────────────┐
│  User Logged In      │
└──────────────────────┘
```

---

## 📋 Prerequisites

### Development Machine:
- Python 3.8+
- pip
- Network access to Windows Server

### Windows Server:
- Windows Server 2019/2022
- Active Directory Domain Services
- Domain Controller role
- Your existing Credential Provider DLL

### Test User:
- UPN: ross.green@secretzero.com
- SID: S-1-5-21-2065755198-886904826-1734203342-1104
- ⚠️ **Important:** Update SID in auth_server_cert.py if using different user

---

## 🧪 Testing

### Test Auth Server:
```bash
python test_auth_server.py
```

### Test Certificate Generation:
```bash
curl http://localhost:5000/api/ca/certificate
```

### Test Session Flow:
```python
import requests

# Create session
resp = requests.post("http://localhost:5000/api/session/create", 
                     json={"server_id": "TEST"})
session_id = resp.json()['session_id']

# Authenticate
requests.post("http://localhost:5000/api/authenticate",
             json={"session_id": session_id, "user_id": "testuser001"})

# Get certificate
status = requests.get(f"http://localhost:5000/api/session/status/{session_id}")
print(status.json())
```

---

## 🔍 Troubleshooting

### Common Issues:

**1. "Certificate not trusted"**
- Solution: Verify CA in NTAuth store
- Command: `certutil -viewstore -enterprise NTAuth`

**2. "SID mismatch"**
- Solution: Update auth_server_cert.py with actual user SID
- Command: `Get-ADUser -Identity "ross.green" | Select-Object SID`

**3. "Session expired"**
- Solution: Certificates expire after 5 minutes. Generate new session.

**4. "Authentication failed"**
- Solution: Check DC event logs for specific error
- Command: `Get-WinEvent -LogName "System" -FilterHashtable @{ProviderName="Microsoft-Windows-Kerberos-Key-Distribution-Center"}`

---

## 📚 Documentation

1. **QUICK_START.md** - Start here for complete setup
2. **WINDOWS_SERVER_SETUP.md** - Windows configuration details
3. **CREDENTIAL_PROVIDER_CHANGES.md** - CP implementation guide
4. **auth_server_cert.py** - Server code with inline documentation
5. **test_auth_server.py** - Testing code with validation logic

---

## 🔐 Security Notes

### For POC:
- ✅ NLA disabled for easy testing
- ✅ CRL checking may be disabled
- ✅ HTTP (not HTTPS) for auth server
- ✅ Hardcoded test user

### For Production (implement these):
1. **Re-enable NLA** after testing
2. **Use HTTPS** for auth server
3. **Store CA key in HSM** or secure key vault
4. **Enable CRL checking** and configure CDP
5. **Integrate with real AD** (remove hardcoded users)
6. **Implement proper audit logging**
7. **Add monitoring and alerting**
8. **Use database** instead of in-memory storage
9. **Implement rate limiting**
10. **Add biometric authentication** to mobile app

---

## 🎓 Learning Resources

### Microsoft Documentation:
- [Smart Card Logon with Third-Party CAs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/enabling-smart-card-logon-third-party-certification-authorities)
- [Certificate Requirements for Smart Card Logon](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [KB5014754: Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)

### Technical Details:
- **PKINIT:** RFC 4556 - Public Key Cryptography for Initial Authentication in Kerberos
- **SID Extension:** OID 1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT)
- **Smart Card Logon EKU:** OID 1.3.6.1.4.1.311.20.2.2

---

## 📊 Success Criteria

Your POC is successful when:
- ✅ test_auth_server.py passes all tests (5/5 score)
- ✅ CA certificate installed in Windows NTAuth store
- ✅ User can scan QR code on login screen
- ✅ Certificate is generated and retrieved by CP
- ✅ Windows logs user in without password
- ✅ Event ID 4768 appears in Security logs (certificate auth)
- ✅ Certificate expires after 5 minutes
- ✅ Subsequent scans generate new certificates

---

## 🆘 Support

If you encounter issues:

1. **Run test script first:** `python test_auth_server.py`
2. **Check Windows Event Logs:** Security, System, CAPI2
3. **Review QUICK_START.md** checklist
4. **Check auth server console** for errors
5. **Verify user SID matches** between AD and auth server

---

## 🎉 What You'll Achieve

After completing this POC:

✅ Passwordless Windows authentication
✅ QR code-based login
✅ Ephemeral certificates (5-minute validity)
✅ No TPM/Smart Card required
✅ Strong certificate mapping (SID extension)
✅ CRL-based revocation
✅ Production-ready foundation

**Total Setup Time: ~1 hour**

---

## 📜 License

This is a POC implementation. Ensure proper security hardening before production use.

---

## 🚀 Next Steps

1. **Complete POC:** Follow QUICK_START.md
2. **Test thoroughly:** Use test_auth_server.py
3. **Build mobile app:** Implement QR scanner with biometric auth
4. **Add production features:** See Security Notes above
5. **Scale:** Deploy behind load balancer, add monitoring

---

**Good luck with your implementation! 🎯**

For questions or issues, refer to the detailed documentation in each file.