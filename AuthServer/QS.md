# Quick Start Guide - Windows RDP QR Authentication with Ephemeral Certificates

This guide will help you set up the complete POC system for Windows authentication using QR codes and ephemeral certificates.

---

## 🎯 What We're Building

A passwordless Windows authentication system where:
1. User scans QR code on login screen
2. Auth server generates ephemeral certificate (5-minute validity)
3. Certificate includes user's SID for strong mapping
4. Windows validates certificate and logs user in
5. Certificate expires automatically

**Test User:** ross.green@secretzero.com (hardcoded in auth server)

---

## 📋 Prerequisites

### On Your Development Machine (where auth server runs):
- Python 3.8+
- pip
- OpenSSL

### On Your Windows Server:
- Windows Server 2019/2022
- Active Directory Domain Services
- Domain Controller role
- Your existing Credential Provider DLL
- Administrative privileges

---

## 🚀 Part 1: Auth Server Setup (5 minutes)

### Step 1: Install Dependencies

```bash
# On your development machine
cd /path/to/project

# Install Python packages
pip install -r requirements.txt
```

**requirements.txt contents:**
```
Flask==3.0.0
flask-cors==4.0.0
pyOpenSSL==24.0.0
PyYAML==6.0.1
cryptography==41.0.7
```

### Step 2: Start Auth Server

```bash
# Start the auth server
python auth_server_cert.py
```

**Expected output:**
```
============================================================
RDP QR Authentication Server with Certificate Generation
============================================================
Starting server...
Host: 0.0.0.0
Port: 5000
Session timeout: 120 seconds
Certificate validity: 5 minutes
CA Certificate: ./ca/ca_cert.pem
============================================================

IMPORTANT: Install CA certificate on Windows:
  Download: http://localhost:5000/api/ca/certificate/der
  Add to NTAuth store using certutil
============================================================
```

The server will automatically:
- ✅ Create CA certificate and key (./ca/ directory)
- ✅ Register test user: ross.green@secretzero.com
- ✅ Start listening on port 5000

### Step 3: Test Auth Server

Run the test script to validate everything works:

```bash
python test_auth_server.py
```

**Expected output:**
```
╔══════════════════════════════════════════════════════════╗
║          AUTH SERVER CERTIFICATE TEST SUITE              ║
╚══════════════════════════════════════════════════════════╝

============================================================
TEST 1: Health Check
============================================================
✓ Server Status: ok
  Registered Users: 1
  Active Sessions: 0
  CA Subject: SecretZero QR Authentication CA

============================================================
TEST 5: Certificate Retrieval & Validation
============================================================
✓ Certificate Retrieved

📜 Certificate Details:
  Subject CN: ross.green@secretzero.com
  Issuer CN: SecretZero QR Authentication CA
  Serial Number: 1730012345678
  Valid From: 2025-10-26 10:00:00
  Valid Until: 2025-10-26 10:05:00
  Validity Period: 5.0 minutes

🔐 Certificate Extensions:
  ✓ Extended Key Usage: TLS Web Client Authentication, 1.3.6.1.4.1.311.20.2.2
    ✓ Smart Card Logon EKU present
  ✓ Subject Alternative Name: othername:<unsupported>
    ✓ UPN present
  ✓ SID Extension present
    Decoded SID: S-1-5-21-2065755198-886904826-1734203342-1104
    ✓ SID matches expected value

📊 Windows Compatibility Check:
  ✓ Smart Card Logon EKU
  ✓ UPN in Subject Alternative Name
  ✓ SID Extension for Strong Mapping
  ✓ Private key valid (2048 bits)
  ✓ PFX/PKCS12 valid

============================================================
COMPATIBILITY SCORE: 5.0/5.0
✓ CERTIFICATE FULLY COMPATIBLE WITH WINDOWS
============================================================

🎉 ALL TESTS PASSED! Server is ready for Windows integration.
```

---

## 🖥️ Part 2: Windows Server Setup (15 minutes)

### Step 1: Download CA Certificate

On your Windows Server, open PowerShell as Administrator:

```powershell
# Create temp directory
New-Item -Path "C:\Temp" -ItemType Directory -Force

# Download CA certificate (replace YOUR_AUTH_SERVER_IP with actual IP)
Invoke-WebRequest -Uri "http://YOUR_AUTH_SERVER_IP:5000/api/ca/certificate/der" -OutFile "C:\Temp\ca_cert.cer"
```

**Verify download:**
```powershell
Test-Path "C:\Temp\ca_cert.cer"  # Should return True
```

### Step 2: Run Configuration Script

**Option A: Automated (Recommended)**

Download the configuration script from the WINDOWS_SERVER_SETUP.md file and run:

```powershell
# Run configuration script
.\Configure-ThirdPartyCA.ps1 -AuthServerIP "192.168.1.100" -AuthServerPort 5000
```

**Option B: Manual Steps**

```powershell
# 1. Install CA to Trusted Root
Import-Certificate -FilePath "C:\Temp\ca_cert.cer" -CertStoreLocation "Cert:\LocalMachine\Root"

# 2. Add CA to NTAuth store (CRITICAL)
certutil -dspublish -f "C:\Temp\ca_cert.cer" NTAuthCA

# 3. Enable PKINIT
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "UsePkinit" -Value 1 -Type DWord

# 4. Disable NLA for testing
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0

# 5. Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0

# 6. Configure firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# 7. Restart services
Restart-Service -Name "KDC" -Force
Restart-Service -Name "TermService" -Force

# 8. Update Group Policy
gpupdate /force
```

### Step 3: Verify Configuration

```powershell
# Verify CA in NTAuth store
certutil -viewstore -enterprise NTAuth

# Verify CA in Trusted Root
Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object {$_.Subject -like "*SecretZero*"}

# Check PKINIT
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "UsePkinit"
```

### Step 4: Verify Test User

```powershell
# Check if user exists
Get-ADUser -Identity "ross.green" -Properties UserPrincipalName, SID

# Expected output:
# UserPrincipalName : ross.green@secretzero.com
# SID               : S-1-5-21-2065755198-886904826-1734203342-1104

# If user doesn't exist, create it:
New-ADUser -Name "Ross Green" `
           -GivenName "Ross" `
           -Surname "Green" `
           -SamAccountName "ross.green" `
           -UserPrincipalName "ross.green@secretzero.com" `
           -AccountPassword (ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force) `
           -Enabled $true `
           -PasswordNeverExpires $true

# Add to Remote Desktop Users
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "ross.green"
```

**⚠️ CRITICAL:** If the SID doesn't match `S-1-5-21-2065755198-886904826-1734203342-1104`, you have two options:
1. Update auth_server_cert.py line with the actual SID
2. Use a different user whose SID matches

---

## 🔧 Part 3: Credential Provider Updates (30 minutes)

### Step 1: Update Your CP Project

Add the code from CREDENTIAL_PROVIDER_CHANGES.md to your existing Credential Provider project.

**Key files to modify:**
- `QRCodeCredential.h` - Add certificate-related members
- `QRCodeCredential.cpp` - Add certificate import/auth functions
- `GetSerialization()` - Change to use KERB_CERTIFICATE_LOGON

### Step 2: Update Project Settings

**In Visual Studio:**

1. **Additional Include Directories:**
   ```
   $(WindowsSdkDir)Include\$(WindowsSDKVersion)shared
   $(WindowsSdkDir)Include\$(WindowsSDKVersion)um
   ```

2. **Additional Dependencies:**
   ```
   crypt32.lib
   cryptui.lib
   secur32.lib
   ncrypt.lib
   ```

### Step 3: Update Authentication Polling

Change your existing polling function to fetch certificates instead of just checking status:

```cpp
// Old code (password-based):
if (status == "authenticated") {
    m_password = response["password"];
    // ... trigger logon
}

// New code (certificate-based):
if (jsonResp["status"] == "authenticated") {
    std::string pfxBase64 = jsonResp["pfx"];
    std::string username = jsonResp["username"];
    
    // Import certificate
    PCCERT_CONTEXT pCert = NULL;
    HRESULT hr = ImportCertificateFromPFX(pfxBase64, usernameW, &pCert);
    
    if (SUCCEEDED(hr)) {
        m_pCertContext = pCert;
        m_authenticationComplete = true;
    }
}
```

### Step 4: Build and Deploy

```cmd
:: Build in Release mode
msbuild QRCodeCredentialProvider.sln /p:Configuration=Release /p:Platform=x64

:: Copy to System32
copy x64\Release\QRCodeCredentialProvider.dll C:\Windows\System32\

:: Register
regsvr32 /s C:\Windows\System32\QRCodeCredentialProvider.dll

:: Restart LogonUI
taskkill /f /im LogonUI.exe
```

---

## 🧪 Part 4: Testing the Complete Flow (10 minutes)

### Step 1: Ensure Auth Server is Running

```bash
# On your dev machine
python auth_server_cert.py
```

### Step 2: Lock Windows or RDP In

**Option A: Lock Screen (Win+L)**
- Press Win+L to lock
- QR code should appear on lock screen

**Option B: RDP Connection**
- RDP to your server
- Should go straight to login screen (no password prompt due to disabled NLA)

### Step 3: Simulate QR Code Scan

For testing, you can manually trigger authentication without a mobile app:

```bash
# On your dev machine, run this Python script:

python << EOF
import requests
import json

# Create session
resp = requests.post("http://localhost:5000/api/session/create", 
                     json={"server_id": "TEST-SERVER"})
session = resp.json()
print(f"Session ID: {session['session_id']}")

# Simulate mobile app authentication
auth_resp = requests.post("http://localhost:5000/api/authenticate",
                         json={
                             "session_id": session['session_id'],
                             "user_id": "testuser001"
                         })
print(f"Auth Result: {auth_resp.json()}")

# Check status (this is what your CP polls)
status_resp = requests.get(f"http://localhost:5000/api/session/status/{session['session_id']}")
status = status_resp.json()
print(f"Status: {status['status']}")
print(f"Certificate Serial: {status.get('certificate', 'N/A')[:100]}...")

EOF
```

### Step 4: Monitor Logs

**On Windows Server - Event Viewer:**

1. **Security Logs:**
   ```powershell
   Get-WinEvent -LogName "Security" -MaxEvents 20 | Where-Object {$_.Id -in @(4768, 4769, 4776)} | Format-Table TimeCreated, Id, Message -AutoSize
   ```

2. **KDC Logs (Domain Controller):**
   ```powershell
   Get-WinEvent -LogName "System" -FilterHashtable @{ProviderName="Microsoft-Windows-Kerberos-Key-Distribution-Center"} -MaxEvents 20 | Format-Table TimeCreated, Id, Message -AutoSize
   ```

3. **CAPI2 Logs (Certificate Validation):**
   ```powershell
   # Enable first
   wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true
   
   # Then view
   Get-WinEvent -LogName "Microsoft-Windows-CAPI2/Operational" -MaxEvents 20
   ```

**Look for:**
- ✅ Event 4768: Kerberos TGT requested (certificate authentication)
- ✅ Event 39: Certificate accepted for strong mapping
- ❌ Event 40: Certificate rejected (investigate why)

**On Auth Server:**
Watch the console output for:
```
Created session: <session_id> for server: TEST-SERVER
User testuser001 (ross.green@secretzero.com) authenticated for session <session_id>
Issued certificate serial: 1730012345678
Session <session_id> completed and removed
```

---

## 🔍 Troubleshooting

### Issue: "Session not found"

**Symptom:** CP polls for session but gets 404

**Solution:**
- Check auth server is running
- Verify session_id is correct
- Check network connectivity

```bash
# Test from Windows Server
curl http://AUTH_SERVER_IP:5000/health
```

### Issue: "Certificate import failed"

**Symptom:** ImportCertificateFromPFX returns error

**Solution:**
- Check PFX base64 decoding
- Verify certificate store permissions
- Check user context (must run as user, not SYSTEM)

```powershell
# Check certificate stores
certmgr.msc
```

### Issue: "The system cannot log you on due to certificate error"

**Symptom:** Windows rejects certificate

**Possible Causes:**

**1. CA not in NTAuth store**
```powershell
# Verify
certutil -viewstore -enterprise NTAuth

# Re-add if missing
certutil -dspublish -f "C:\Temp\ca_cert.cer" NTAuthCA
gpupdate /force
```

**2. SID mismatch**
```powershell
# Get actual SID
Get-ADUser -Identity "ross.green" | Select-Object SID

# Update auth server with correct SID
```

**3. Certificate expired**
- Check system clock synchronization
- Certificate validity is only 5 minutes - ensure prompt authentication

**4. Strong mapping not configured**
- Verify certificate contains SID extension (run test_auth_server.py)
- Check DC is fully patched (May 2022+ updates)

### Issue: "Failed to acquire private key"

**Symptom:** CryptAcquireCertificatePrivateKey fails

**Solution:**
- Ensure PFX import used CRYPT_EXPORTABLE flag
- Check certificate store location (CURRENT_USER vs LOCAL_MACHINE)
- Verify private key is included in PFX

```cpp
// Debug: Check if private key exists
DWORD dwKeySpec = 0;
BOOL bCallerFree = FALSE;
HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;

if (!CryptAcquireCertificatePrivateKey(
    pCertContext,
    CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
    NULL,
    &hKey,
    &dwKeySpec,
    &bCallerFree))
{
    DWORD error = GetLastError();
    // Log error code
}
```

---

## 📊 Success Checklist

Before testing, verify all these:

### Auth Server:
- [ ] Server running on port 5000
- [ ] CA certificate generated in ./ca/ directory
- [ ] Test user registered (testuser001)
- [ ] test_auth_server.py passes all tests
- [ ] Health endpoint returns status: ok

### Windows Server:
- [ ] CA certificate in Trusted Root store
- [ ] CA certificate in NTAuth store
- [ ] Group Policy updated (gpupdate /force)
- [ ] PKINIT enabled on KDC
- [ ] RDP NLA disabled (for testing)
- [ ] RDP firewall rules enabled
- [ ] Services restarted (KDC, TermService)

### Active Directory:
- [ ] User ross.green exists
- [ ] User UPN: ross.green@secretzero.com
- [ ] User SID matches: S-1-5-21-2065755198-886904826-1734203342-1104
- [ ] User in Remote Desktop Users group
- [ ] User account enabled

### Credential Provider:
- [ ] Certificate import function added
- [ ] Certificate authentication function added
- [ ] GetSerialization updated for KERB_CERTIFICATE_LOGON
- [ ] Polling function fetches certificates
- [ ] DLL built in Release mode
- [ ] DLL registered in System32
- [ ] CP appears in credential tiles

---

## 🎯 Next Steps After POC

Once the POC is working:

1. **Security Hardening:**
   - Re-enable NLA
   - Implement proper CRL checking
   - Use HTTPS for auth server
   - Store CA key in HSM
   - Implement audit logging

2. **Production Features:**
   - Build mobile QR scanner app
   - Integrate with real AD (not hardcoded users)
   - Implement user enrollment flow
   - Add biometric authentication to mobile app
   - Implement certificate revocation workflow

3. **Scale Considerations:**
   - Deploy auth server behind load balancer
   - Use database instead of in-memory storage
   - Implement proper session management
   - Add monitoring and alerting
   - Performance testing

---

## 📚 Reference Documentation

- **Auth Server:** See auth_server_cert.py comments
- **Windows Setup:** See WINDOWS_SERVER_SETUP.md
- **CP Changes:** See CREDENTIAL_PROVIDER_CHANGES.md
- **Testing:** See test_auth_server.py

### Key Microsoft Documentation:
- [Smart Card Logon with Third-Party CAs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/enabling-smart-card-logon-third-party-certification-authorities)
- [Certificate Requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [KB5014754: Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)

---

## ✨ Summary

You now have:
- ✅ Auth server that generates Windows-compatible ephemeral certificates
- ✅ Certificates with SID extension for strong mapping
- ✅ Certificate validity of 5 minutes (ephemeral)
- ✅ CRL service for revocation
- ✅ Windows Server configured to trust your CA
- ✅ Credential Provider code to use certificates
- ✅ Complete testing framework

**Total setup time: ~1 hour**

Good luck with your POC! 🚀

---

## 🆘 Support

If you encounter issues:

1. **Check logs first:**
   - Auth server console output
   - Windows Event Viewer (Security, System, CAPI2)
   - Credential Provider debug output (DebugView)

2. **Run test script:**
   ```bash
   python test_auth_server.py
   ```

3. **Verify configuration:**
   ```powershell
   certutil -viewstore -enterprise NTAuth
   Get-ADUser -Identity "ross.green"
   ```

4. **Review checklist above**

Most issues are due to:
- CA not in NTAuth store
- SID mismatch
- User doesn't exist in AD
- Certificate expired (5-minute window)
- Network connectivity issues