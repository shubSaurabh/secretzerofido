# Windows Server Configuration for Third-Party CA Authentication

This guide configures Windows Server to accept certificates from your custom CA for user authentication.

## Prerequisites

- Windows Server 2019/2022 with Active Directory Domain Services
- Domain Controller role installed
- Administrative privileges
- CA certificate from auth server (download from http://YOUR_AUTH_SERVER:5000/api/ca/certificate/der)

---

## Part 1: Install and Trust the CA Certificate

### Step 1: Download CA Certificate

```powershell
# Download CA certificate from auth server
Invoke-WebRequest -Uri "http://YOUR_AUTH_SERVER_IP:5000/api/ca/certificate/der" -OutFile "C:\Temp\ca_cert.cer"
```

### Step 2: Install CA Certificate to Trusted Root Store

```powershell
# Import CA certificate to Trusted Root Certification Authorities
Import-Certificate -FilePath "C:\Temp\ca_cert.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
```

**Verify Installation:**
```powershell
# List certificates in Root store
Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object {$_.Subject -like "*SecretZero*"}
```

### Step 3: Add CA to NTAuth Store (CRITICAL)

The NTAuth store contains CAs that Windows trusts for authentication. This is MANDATORY.

**Option A: Using certutil (Recommended)**

```cmd
certutil -dspublish -f "C:\Temp\ca_cert.cer" NTAuthCA
```

**Option B: Using Enterprise PKI snap-in**

1. Open MMC (mmc.exe)
2. File → Add/Remove Snap-in → Certificates → Computer Account → Local Computer
3. Expand "Certificates (Local Computer)" → "Trusted Root Certification Authorities"
4. Right-click "Certificates" → All Tasks → Import
5. Browse to ca_cert.cer and import

Then publish to NTAuth:
```cmd
certutil -viewstore -enterprise NTAuth
```
Click "Add" and select the CA certificate.

**Verify NTAuth Store:**
```powershell
# List certificates in NTAuth store (run on Domain Controller)
certutil -viewstore -enterprise NTAuth

# Or via PowerShell
Get-ChildItem -Path "Cert:\LocalMachine\AuthRoot" | Where-Object {$_.Subject -like "*SecretZero*"}
```

### Step 4: Force Group Policy Update (on all machines)

```powershell
gpupdate /force
```

Wait 5 minutes for replication across domain controllers.

---

## Part 2: Configure Domain Controller for PKINIT

PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) enables certificate-based authentication.

### Step 1: Install Domain Controller Certificate

The DC needs a certificate to support PKINIT.

**Option A: Using Certificate Autoenrollment (if you have internal CA)**

Already done if you have an Enterprise CA.

**Option B: Manual Certificate Request**

You'll need to either:
1. Get a DC certificate from your auth server (requires modifying auth server)
2. Use a different CA for DC certificates only
3. Self-sign DC certificates (not recommended for production)

For POC, you can use your auth server to generate DC certificates.

**Check if DC has certificate:**
```powershell
# Check for DC certificate with Server Authentication EKU
Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.EnhancedKeyUsageList.FriendlyName -contains "Server Authentication"}
```

### Step 2: Enable PKINIT on Domain Controller

PKINIT is enabled by default on Windows Server 2008 and later, but verify:

**Check PKINIT Status:**
```powershell
# Check if PKINIT is enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "UsePkinit"
```

If not present or set to 0:
```powershell
# Enable PKINIT
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "UsePkinit" -Value 1 -Type DWord

# Restart KDC service
Restart-Service -Name "KDC" -Force
```

### Step 3: Configure Certificate Mapping

Windows needs to map certificates to user accounts. For POC with hardcoded users:

**Option 1: Strong Mapping via SID Extension (RECOMMENDED - Already implemented in auth server)**

The auth server includes the SID extension (OID 1.3.6.1.4.1.311.25.2) in certificates. This is the strongest and required mapping method since May 2022 security updates.

No additional configuration needed if:
- Certificate contains SID extension ✓ (auth server does this)
- Domain is fully patched ✓
- User exists in AD ✓

**Option 2: Subject/Issuer Mapping (Fallback)**

If you need to configure explicit mapping:

```powershell
# Set user certificate mapping (on DC)
Set-ADUser -Identity "ross.green" -Replace @{
    altSecurityIdentities="X509:<I>CN=SecretZero QR Authentication CA,OU=QR Auth CA,O=SecretZero,L=City,ST=State,C=US<S>CN=ross.green@secretzero.com,O=SecretZero,C=US"
}
```

### Step 4: Configure CRL Distribution Point (CDP)

Windows checks certificate revocation. Configure CDP in registry:

```powershell
# Add CRL URL to certificate validation
$crlUrl = "http://YOUR_AUTH_SERVER_IP:5000/api/crl"

# This requires modifying the CA certificate or configuring via Group Policy
# For POC, you can disable CRL checking (NOT recommended for production)
```

**Disable CRL checking for POC (temporary):**
```powershell
# Disable CRL checking for testing only
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local" -Name "ChainCacheResyncFiletime" -Value 0 -Type DWord

# Restart services
Restart-Service -Name "KDC" -Force
```

---

## Part 3: Configure RDP Server

### Step 1: Disable Network Level Authentication (for testing)

```powershell
# Disable NLA to bypass RDP credential prompt
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0

# Allow RDP connections
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0

# Restart Terminal Services
Restart-Service -Name "TermService" -Force
```

### Step 2: Enable Certificate-Based RDP Authentication

```powershell
# Allow certificate-based RDP authentication
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'fAllowSecurityNegotiation' -Value 1

# Configure RDP to support TLS
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2
```

### Step 3: Configure Windows Firewall

```powershell
# Enable RDP firewall rule
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

---

## Part 4: User Account Configuration

For your test user ross.green@secretzero.com with SID S-1-5-21-2065755198-886904826-1734203342-1104:

### Step 1: Create User Account (if not exists)

```powershell
# Create user account
New-ADUser -Name "Ross Green" `
           -GivenName "Ross" `
           -Surname "Green" `
           -SamAccountName "ross.green" `
           -UserPrincipalName "ross.green@secretzero.com" `
           -AccountPassword (ConvertTo-SecureString "TempPassword123!" -AsPlainText -Force) `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -CannotChangePassword $false
```

**IMPORTANT: Verify the SID matches:**
```powershell
# Get user SID
Get-ADUser -Identity "ross.green" | Select-Object Name, SID, UserPrincipalName

# Expected: S-1-5-21-2065755198-886904826-1734203342-1104
```

If SID doesn't match, you need to either:
1. Update the SID in auth server to match the actual user SID
2. Use the existing user account

### Step 2: Configure User for Certificate Logon

```powershell
# Allow interactive logon
Add-ADGroupMember -Identity "Remote Desktop Users" -Members "ross.green"

# Grant "Allow log on locally" right
# This is usually already set for domain users
```

---

## Part 5: Verify Configuration

### Step 1: Test CA Trust Chain

```powershell
# Test certificate chain validation
$cert = Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object {$_.Subject -like "*SecretZero*"}
Test-Certificate -Cert $cert -Policy SSL
```

### Step 2: Test PKINIT

```powershell
# Check KDC logs for PKINIT events
Get-WinEvent -LogName "System" -FilterHashtable @{ProviderName="Microsoft-Windows-Kerberos-Key-Distribution-Center"} -MaxEvents 50 | Format-Table TimeCreated, Id, Message -AutoSize
```

Look for Event IDs:
- **Event 39**: Certificate accepted for strong mapping
- **Event 40**: Certificate rejected (investigate why)
- **Event 41**: Certificate mapping succeeded

### Step 3: Test Certificate Authentication

Once your Credential Provider fetches a certificate, test Windows logon:

```powershell
# Monitor authentication attempts
Get-WinEvent -LogName "Security" -FilterHashtable @{ID=4768,4769,4776} -MaxEvents 20 | Format-Table TimeCreated, Id, Message -AutoSize
```

Look for:
- **Event 4768**: Kerberos TGT requested (should show certificate authentication)
- **Event 4769**: Kerberos service ticket requested
- **Event 4776**: Credential validation

---

## Part 6: Group Policy Settings (Optional for Enhanced Security)

### Configure Smart Card Logon Policy

```powershell
# These settings can be configured via Group Policy
# Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options

# 1. Interactive logon: Require smart card
#    - Set to: Disabled (for hybrid authentication)

# 2. Interactive logon: Smart card removal behavior
#    - Set to: Lock workstation

# 3. Smart card logon is required
#    - Set per user if needed
```

---

## Part 7: Troubleshooting

### Common Issues

**Issue 1: "The specified user does not have a valid profile"**
```powershell
# Create user profile
New-Item -Path "C:\Users\ross.green" -ItemType Directory -Force
```

**Issue 2: "The system cannot log you on due to the following error: The smart card certificate used for authentication was not trusted"**
```powershell
# Verify CA in NTAuth store
certutil -viewstore -enterprise NTAuth

# Re-publish if missing
certutil -dspublish -f "C:\Temp\ca_cert.cer" NTAuthCA

# Force policy update
gpupdate /force
```

**Issue 3: "A required certificate is not within its validity period"**
- Check system clock synchronization
- Verify certificate validity period (should be 5 minutes from issuance)

**Issue 4: Certificate chain validation fails**
```powershell
# Check CRL accessibility
certutil -URL "http://YOUR_AUTH_SERVER_IP:5000/api/crl"

# Temporarily disable CRL checking
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllVerifyRevocation\DEFAULT" -Name "DefaultUrlRetrievalTimeoutMilliseconds" -Value 0
```

### Enable Debug Logging

**Enable CAPI2 Logging:**
```powershell
wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true
```

**Enable KDC Debug Logging:**
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v KdcDebugLevel /t REG_DWORD /d 0xFFFFFFFF /f
net stop kdc && net start kdc
```

**View Logs:**
```powershell
# CAPI2 logs (certificate validation)
Get-WinEvent -LogName "Microsoft-Windows-CAPI2/Operational" -MaxEvents 100

# KDC logs (authentication)
Get-WinEvent -LogName "System" -FilterHashtable @{ProviderName="Microsoft-Windows-Kerberos-Key-Distribution-Center"} -MaxEvents 100
```

---

## Part 8: Security Hardening (Post-POC)

Once POC is working, implement these security measures:

1. **Enable NLA** (re-enable after testing)
2. **Enforce CRL checking**
3. **Use HTTPS for CRL distribution**
4. **Implement proper key storage** (HSM or secure key vault)
5. **Enable audit logging** for all certificate operations
6. **Configure certificate templates** properly
7. **Implement proper session management**
8. **Use production-grade CA** infrastructure

---

## Quick Configuration Script

Here's a complete PowerShell script to automate the configuration:

```powershell
# ================================================
# Windows Server Third-Party CA Configuration
# ================================================

param(
    [string]$AuthServerIP = "192.168.1.100",
    [int]$AuthServerPort = 5000,
    [string]$CACertPath = "C:\Temp\ca_cert.cer"
)

Write-Host "=" * 60
Write-Host "Configuring Windows for Third-Party CA Authentication"
Write-Host "=" * 60

# Create temp directory
New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null

# Download CA certificate
Write-Host "[1/8] Downloading CA certificate..."
try {
    Invoke-WebRequest -Uri "http://${AuthServerIP}:${AuthServerPort}/api/ca/certificate/der" -OutFile $CACertPath
    Write-Host "  ✓ CA certificate downloaded"
} catch {
    Write-Host "  ✗ Failed to download CA certificate: $_"
    exit 1
}

# Install CA to Trusted Root
Write-Host "[2/8] Installing CA certificate to Trusted Root..."
try {
    Import-Certificate -FilePath $CACertPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Write-Host "  ✓ CA certificate installed to Trusted Root"
} catch {
    Write-Host "  ✗ Failed to install CA certificate: $_"
}

# Add CA to NTAuth store
Write-Host "[3/8] Adding CA to NTAuth store..."
try {
    $result = certutil -dspublish -f $CACertPath NTAuthCA 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ✓ CA added to NTAuth store"
    } else {
        Write-Host "  ✗ Failed to add CA to NTAuth store: $result"
    }
} catch {
    Write-Host "  ✗ Failed: $_"
}

# Enable PKINIT
Write-Host "[4/8] Enabling PKINIT..."
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "UsePkinit" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "  ✓ PKINIT enabled"
} catch {
    Write-Host "  ⚠ PKINIT registry key not found (might already be enabled by default)"
}

# Configure RDP
Write-Host "[5/8] Configuring RDP..."
try {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2
    Write-Host "  ✓ RDP configured"
} catch {
    Write-Host "  ✗ Failed to configure RDP: $_"
}

# Enable RDP firewall rules
Write-Host "[6/8] Configuring firewall..."
try {
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
    Write-Host "  ✓ Firewall rules enabled"
} catch {
    Write-Host "  ✗ Failed to enable firewall rules: $_"
}

# Restart services
Write-Host "[7/8] Restarting services..."
try {
    Restart-Service -Name "KDC" -Force -ErrorAction Stop
    Write-Host "  ✓ KDC service restarted"
    Restart-Service -Name "TermService" -Force -ErrorAction Stop
    Write-Host "  ✓ Terminal Services restarted"
} catch {
    Write-Host "  ✗ Failed to restart services: $_"
}

# Force Group Policy update
Write-Host "[8/8] Updating Group Policy..."
gpupdate /force | Out-Null
Write-Host "  ✓ Group Policy updated"

Write-Host ""
Write-Host "=" * 60
Write-Host "Configuration Complete!"
Write-Host "=" * 60
Write-Host ""
Write-Host "Next Steps:"
Write-Host "1. Wait 5 minutes for AD replication"
Write-Host "2. Verify test user: ross.green@secretzero.com"
Write-Host "3. Update Credential Provider with certificate logic"
Write-Host "4. Test authentication"
Write-Host ""
Write-Host "Verification Commands:"
Write-Host "  certutil -viewstore -enterprise NTAuth"
Write-Host "  Get-ADUser -Identity 'ross.green'"
Write-Host ""
```

Save this as `Configure-ThirdPartyCA.ps1` and run:
```powershell
.\Configure-ThirdPartyCA.ps1 -AuthServerIP "YOUR_IP" -AuthServerPort 5000
```

---

## Summary Checklist

- [ ] CA certificate downloaded from auth server
- [ ] CA installed to Trusted Root Certification Authorities
- [ ] CA added to NTAuth enterprise store
- [ ] Group Policy updated on all machines
- [ ] PKINIT enabled on Domain Controller
- [ ] DC has valid certificate with Server Authentication EKU
- [ ] RDP configured (NLA disabled for testing)
- [ ] Firewall rules enabled
- [ ] Test user account exists with correct SID
- [ ] User added to Remote Desktop Users group
- [ ] Services restarted (KDC, TermService)
- [ ] Wait 5 minutes for replication
- [ ] Test certificate generation from auth server
- [ ] Test authentication flow

---

## References

- [Microsoft: Smart Card Logon with Third-Party CAs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/enabling-smart-card-logon-third-party-certification-authorities)
- [Microsoft: PKINIT Certificate Mapping](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
- [KB5014754: CVE-2022-26931 - Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)