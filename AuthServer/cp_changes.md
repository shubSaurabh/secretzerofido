# Credential Provider Modifications for Certificate-Based Authentication

This document outlines the changes needed in your Windows Credential Provider to fetch ephemeral certificates from the auth server and use them for Windows logon.

---

## Overview

**Flow:**
1. User scans QR code with mobile app
2. Mobile app authenticates with auth server
3. Auth server generates ephemeral certificate (5 min validity)
4. Credential Provider polls auth server
5. Credential Provider receives certificate + private key
6. Credential Provider installs certificate to user's store
7. Windows uses certificate for PKINIT authentication
8. User logged in
9. Certificate expires after 5 minutes

---

## Part 1: Add Certificate Handling to Credential Provider

### 1.1 Add Required Headers

Add these includes to your Credential Provider C++ project:

```cpp
// Existing includes
#include <credentialprovider.h>
#include <ntsecapi.h>

// Add certificate handling
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <schannel.h>
#include <security.h>

// Link libraries
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "cryptui.lib")
#pragma comment(lib, "secur32.lib")
```

### 1.2 Create Certificate Import Function

Add this function to import PFX certificate into user's certificate store:

```cpp
HRESULT ImportCertificateFromPFX(
    const std::string& pfxBase64,
    const std::wstring& username,
    PCCERT_CONTEXT* ppCertContext
)
{
    HRESULT hr = S_OK;
    HCERTSTORE hTempStore = NULL;
    HCERTSTORE hUserStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    CRYPT_DATA_BLOB pfxBlob = { 0 };
    
    // Decode base64 PFX data
    DWORD dwBinarySize = 0;
    if (!CryptStringToBinaryA(
        pfxBase64.c_str(),
        pfxBase64.length(),
        CRYPT_STRING_BASE64,
        NULL,
        &dwBinarySize,
        NULL,
        NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    std::vector<BYTE> binaryData(dwBinarySize);
    if (!CryptStringToBinaryA(
        pfxBase64.c_str(),
        pfxBase64.length(),
        CRYPT_STRING_BASE64,
        binaryData.data(),
        &dwBinarySize,
        NULL,
        NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Prepare PFX blob
    pfxBlob.cbData = dwBinarySize;
    pfxBlob.pbData = binaryData.data();
    
    // Import PFX to temporary store (no password for ephemeral cert)
    hTempStore = PFXImportCertStore(
        &pfxBlob,
        L"",  // Empty password
        CRYPT_EXPORTABLE | CRYPT_USER_KEYSET
    );
    
    if (!hTempStore) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Get the certificate from temp store
    pCertContext = CertFindCertificateInStore(
        hTempStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_ANY,
        NULL,
        NULL
    );
    
    if (!pCertContext) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Open user's personal certificate store
    // Use CERT_SYSTEM_STORE_CURRENT_USER for user store
    hUserStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
        L"MY"
    );
    
    if (!hUserStore) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Add certificate to user's store
    if (!CertAddCertificateContextToStore(
        hUserStore,
        pCertContext,
        CERT_STORE_ADD_REPLACE_EXISTING,
        ppCertContext
    ))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Log success
    OutputDebugString(L"Certificate imported to user store successfully\n");
    
cleanup:
    if (hTempStore) CertCloseStore(hTempStore, 0);
    if (hUserStore) CertCloseStore(hUserStore, 0);
    if (pCertContext && !*ppCertContext) CertFreeCertificateContext(pCertContext);
    
    return hr;
}
```

### 1.3 Create Certificate Authentication Function

Add this function to authenticate using the certificate:

```cpp
HRESULT AuthenticateWithCertificate(
    PCCERT_CONTEXT pCertContext,
    const std::wstring& username,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus
)
{
    HRESULT hr = S_OK;
    
    // For certificate-based authentication, we use KerbLogonSubmitType
    // with KERB_CERTIFICATE_LOGON
    
    KERB_CERTIFICATE_LOGON kerbCertLogon = { 0 };
    kerbCertLogon.MessageType = KerbCertificateLogon;
    
    // Set certificate data
    kerbCertLogon.CertificateLength = pCertContext->cbCertEncoded;
    kerbCertLogon.Certificate = pCertContext->pbCertEncoded;
    
    // Note: The actual logon is handled by LsaLogonUser in GetSerialization
    // This function validates the certificate is ready for use
    
    // Verify certificate has private key
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
        hr = HRESULT_FROM_WIN32(GetLastError());
        OutputDebugString(L"Failed to acquire private key\n");
        return hr;
    }
    
    // Clean up key handle if necessary
    if (bCallerFree) {
        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) {
            NCryptFreeObject(hKey);
        } else {
            CryptReleaseContext(hKey, 0);
        }
    }
    
    OutputDebugString(L"Certificate validated with private key\n");
    return S_OK;
}
```

### 1.4 Modify Your Polling Function

Update your existing polling function that checks auth server status:

```cpp
HRESULT CQRCodeCredential::CheckAuthenticationStatus()
{
    HRESULT hr = S_OK;
    std::string response;
    
    // Your existing code to poll auth server
    // GET /api/session/status/<session_id>
    
    // Parse JSON response
    // If status == "authenticated":
    
    try {
        // Parse JSON response (use your JSON library)
        // Example with nlohmann/json:
        auto jsonResp = json::parse(response);
        
        if (jsonResp["status"] == "authenticated") {
            // Extract certificate data
            std::string username = jsonResp["username"];
            std::string pfxBase64 = jsonResp["pfx"];
            std::string certPem = jsonResp["certificate"];
            std::string keyPem = jsonResp["private_key"];
            
            // Convert username to wide string
            std::wstring usernameW = StringToWString(username);
            
            // Import certificate
            PCCERT_CONTEXT pCertContext = NULL;
            hr = ImportCertificateFromPFX(pfxBase64, usernameW, &pCertContext);
            
            if (SUCCEEDED(hr)) {
                OutputDebugString(L"Certificate imported successfully\n");
                
                // Store certificate context for GetSerialization
                m_pCertContext = pCertContext;
                m_username = usernameW;
                
                // Validate certificate for authentication
                hr = AuthenticateWithCertificate(pCertContext, usernameW, m_cpus);
                
                if (SUCCEEDED(hr)) {
                    // Signal successful authentication
                    m_authenticationComplete = true;
                    
                    // Notify credential provider events
                    if (m_pCredProvCredentialEvents) {
                        m_pCredProvCredentialEvents->SetFieldState(
                            this,
                            SFI_LARGE_TEXT,
                            CPFS_DISPLAY_IN_SELECTED_TILE
                        );
                        
                        m_pCredProvCredentialEvents->SetFieldString(
                            this,
                            SFI_LARGE_TEXT,
                            L"Authentication Successful"
                        );
                    }
                    
                    // Trigger credential submission
                    if (m_pCredProvCredentialEvents) {
                        m_pCredProvCredentialEvents->OnCreatingWindow(&m_hwndOwner);
                    }
                } else {
                    OutputDebugString(L"Certificate validation failed\n");
                }
            } else {
                OutputDebugString(L"Certificate import failed\n");
            }
        }
        else if (jsonResp["status"] == "expired") {
            // Session expired
            m_authenticationComplete = false;
            m_authenticationFailed = true;
        }
        // else status == "pending", keep polling
        
    } catch (const std::exception& e) {
        hr = E_FAIL;
        OutputDebugString(L"JSON parsing error\n");
    }
    
    return hr;
}
```

---

## Part 2: Modify GetSerialization for Certificate Logon

### 2.1 Update GetSerialization Method

This is the critical method that Windows calls to get authentication credentials:

```cpp
HRESULT CQRCodeCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
    HRESULT hr = E_UNEXPECTED;
    
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    
    // Check if authentication is complete
    if (!m_authenticationComplete || !m_pCertContext) {
        return E_FAIL;
    }
    
    // For certificate-based authentication, we need to use KERB_CERTIFICATE_LOGON
    
    KERB_CERTIFICATE_UNLOCK_LOGON kerbCertLogon = { 0 };
    kerbCertLogon.Logon.MessageType = KerbCertificateLogon;
    
    // Set username (UPN format)
    hr = StringCbLength(m_username.c_str(), STRSAFE_MAX_CCH * sizeof(wchar_t), &kerbCertLogon.Logon.UserNameLength);
    if (SUCCEEDED(hr)) {
        kerbCertLogon.Logon.UserName = (PWSTR)CoTaskMemAlloc(kerbCertLogon.Logon.UserNameLength);
        if (kerbCertLogon.Logon.UserName) {
            hr = StringCbCopy(kerbCertLogon.Logon.UserName, kerbCertLogon.Logon.UserNameLength, m_username.c_str());
        } else {
            hr = E_OUTOFMEMORY;
        }
    }
    
    if (SUCCEEDED(hr)) {
        // Set certificate data
        kerbCertLogon.Logon.CertificateLength = m_pCertContext->cbCertEncoded;
        kerbCertLogon.Logon.Certificate = (PUCHAR)CoTaskMemAlloc(kerbCertLogon.Logon.CertificateLength);
        
        if (kerbCertLogon.Logon.Certificate) {
            CopyMemory(
                kerbCertLogon.Logon.Certificate,
                m_pCertContext->pbCertEncoded,
                kerbCertLogon.Logon.CertificateLength
            );
        } else {
            hr = E_OUTOFMEMORY;
        }
    }
    
    if (SUCCEEDED(hr)) {
        // Get private key info
        DWORD dwKeySpec = 0;
        BOOL bCallerFree = FALSE;
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
        
        if (CryptAcquireCertificatePrivateKey(
            m_pCertContext,
            CRYPT_ACQUIRE_CACHE_FLAG,
            NULL,
            &hKey,
            &dwKeySpec,
            &bCallerFree))
        {
            // Set key spec
            kerbCertLogon.Logon.Flags = KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES;
            
            // For smart card/certificate logon
            pcpcs->ulAuthenticationPackage = LsaLookupAuthenticationPackage(L"Kerberos");
            pcpcs->clsidCredentialProvider = CLSID_QRCodeCredentialProvider;
            
            // Allocate credential buffer
            DWORD cbLogon = sizeof(kerbCertLogon);
            pcpcs->rgbSerialization = (BYTE*)CoTaskMemAlloc(cbLogon);
            
            if (pcpcs->rgbSerialization) {
                CopyMemory(pcpcs->rgbSerialization, &kerbCertLogon, cbLogon);
                pcpcs->cbSerialization = cbLogon;
                
                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                hr = S_OK;
            } else {
                hr = E_OUTOFMEMORY;
            }
            
            // Clean up key handle
            if (bCallerFree) {
                if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) {
                    NCryptFreeObject(hKey);
                } else {
                    CryptReleaseContext(hKey, 0);
                }
            }
        } else {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    
    // Set status
    if (SUCCEEDED(hr)) {
        *ppszOptionalStatusText = nullptr;
        *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
    } else {
        SHStrDup(L"Certificate authentication failed", ppszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
    }
    
    return hr;
}
```

### 2.2 Alternative: Use KERB_CERTIFICATE_UNLOCK_LOGON for Unlock Scenario

If you're implementing both login and unlock scenarios:

```cpp
// For unlock scenario (cpus == CPUS_UNLOCK_WORKSTATION)
if (m_cpus == CPUS_UNLOCK_WORKSTATION) {
    KERB_CERTIFICATE_UNLOCK_LOGON unlockLogon = { 0 };
    unlockLogon.Logon.MessageType = KerbCertificateUnlockLogon;
    
    // Get current session LogonId
    unlockLogon.LogonId = GetCurrentLogonId();
    
    // Set certificate data (same as above)
    // ...
}
```

---

## Part 3: Class Member Additions

Add these members to your credential class:

```cpp
class CQRCodeCredential : public ICredentialProviderCredential2
{
private:
    // Existing members...
    
    // Add certificate-related members
    PCCERT_CONTEXT m_pCertContext;  // Certificate context
    std::wstring m_username;         // Username from auth server
    bool m_authenticationComplete;   // Authentication status
    bool m_authenticationFailed;     // Authentication failed status
    
    // Add helper methods
    HRESULT ImportCertificateFromPFX(
        const std::string& pfxBase64,
        const std::wstring& username,
        PCCERT_CONTEXT* ppCertContext
    );
    
    HRESULT AuthenticateWithCertificate(
        PCCERT_CONTEXT pCertContext,
        const std::wstring& username,
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus
    );
};
```

### Constructor Updates

```cpp
CQRCodeCredential::CQRCodeCredential() :
    m_cRef(1),
    m_pCertContext(nullptr),
    m_authenticationComplete(false),
    m_authenticationFailed(false)
{
    // Existing initialization...
}
```

### Destructor Updates

```cpp
CQRCodeCredential::~CQRCodeCredential()
{
    // Clean up certificate context
    if (m_pCertContext) {
        CertFreeCertificateContext(m_pCertContext);
        m_pCertContext = nullptr;
    }
    
    // Existing cleanup...
}
```

---

## Part 4: HTTP Request Changes

Update your HTTP request function to handle the new response format:

```cpp
std::string CQRCodeCredential::HttpGet(const std::string& url)
{
    std::string response;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    
    // Your existing WinHTTP code...
    
    // Parse URL to extract host, port, path
    // Make GET request to /api/session/status/<session_id>
    
    // Read response
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    std::vector<char> buffer;
    
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            break;
        }
        
        if (dwSize == 0) {
            break;
        }
        
        buffer.resize(dwSize + 1);
        ZeroMemory(buffer.data(), dwSize + 1);
        
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
            break;
        }
        
        response.append(buffer.data(), dwDownloaded);
        
    } while (dwSize > 0);
    
    // Cleanup
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return response;
}
```

---

## Part 5: Testing and Debugging

### 5.1 Add Debug Logging

```cpp
void LogCertificateInfo(PCCERT_CONTEXT pCertContext)
{
    if (!pCertContext) return;
    
    // Get subject name
    wchar_t szSubject[256] = { 0 };
    CertGetNameString(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        szSubject,
        256
    );
    
    std::wstring msg = L"Certificate Subject: ";
    msg += szSubject;
    msg += L"\n";
    OutputDebugString(msg.c_str());
    
    // Get serial number
    DWORD dwSerial = pCertContext->pCertInfo->SerialNumber.cbData;
    std::wstring serialMsg = L"Certificate Serial: ";
    for (DWORD i = 0; i < dwSerial; i++) {
        wchar_t hex[4];
        swprintf_s(hex, L"%02X", pCertContext->pCertInfo->SerialNumber.pbData[i]);
        serialMsg += hex;
    }
    serialMsg += L"\n";
    OutputDebugString(serialMsg.c_str());
    
    // Get validity period
    SYSTEMTIME notBefore, notAfter;
    FileTimeToSystemTime(&pCertContext->pCertInfo->NotBefore, &notBefore);
    FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &notAfter);
    
    wchar_t validity[256];
    swprintf_s(validity, L"Valid From: %04d-%02d-%02d %02d:%02d:%02d\n",
        notBefore.wYear, notBefore.wMonth, notBefore.wDay,
        notBefore.wHour, notBefore.wMinute, notBefore.wSecond);
    OutputDebugString(validity);
    
    swprintf_s(validity, L"Valid To: %04d-%02d-%02d %02d:%02d:%02d\n",
        notAfter.wYear, notAfter.wMonth, notAfter.wDay,
        notAfter.wHour, notAfter.wMinute, notAfter.wSecond);
    OutputDebugString(validity);
}
```

### 5.2 View Debug Output

Use DebugView to see OutputDebugString messages:
- Download Sysinternals DebugView
- Run as Administrator
- Enable "Capture Global Win32" option

### 5.3 Test Certificate Import Manually

Create a test function:

```cpp
void TestCertificateImport()
{
    // Get certificate from auth server
    std::string response = HttpGet("http://auth-server:5000/api/session/status/test");
    
    // Parse JSON and extract PFX
    // ...
    
    PCCERT_CONTEXT pCert = NULL;
    HRESULT hr = ImportCertificateFromPFX(pfxBase64, L"ross.green@secretzero.com", &pCert);
    
    if (SUCCEEDED(hr)) {
        LogCertificateInfo(pCert);
        
        // Test authentication
        hr = AuthenticateWithCertificate(pCert, L"ross.green@secretzero.com", CPUS_LOGON);
        
        if (SUCCEEDED(hr)) {
            OutputDebugString(L"✓ Certificate authentication test passed\n");
        } else {
            OutputDebugString(L"✗ Certificate authentication test failed\n");
        }
        
        CertFreeCertificateContext(pCert);
    } else {
        OutputDebugString(L"✗ Certificate import test failed\n");
    }
}
```

---

## Part 6: Build Configuration

### 6.1 Update Project Settings

In Visual Studio:

**C/C++ → General → Additional Include Directories:**
```
$(WindowsSdkDir)Include\$(WindowsSDKVersion)shared
$(WindowsSdkDir)Include\$(WindowsSDKVersion)um
```

**Linker → Input → Additional Dependencies:**
```
crypt32.lib
cryptui.lib
secur32.lib
ncrypt.lib
credui.lib
winhttp.lib
```

### 6.2 Update Manifest

Ensure your manifest requests appropriate permissions:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    type="win32"
    name="QRCodeCredentialProvider"
    version="1.0.0.0"
    processorArchitecture="amd64"/>
  
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
```

---

## Part 7: Installation and Registration

After building the updated DLL:

```cmd
:: Copy DLL
copy QRCodeCredentialProvider.dll C:\Windows\System32\

:: Register COM
regsvr32 /s C:\Windows\System32\QRCodeCredentialProvider.dll

:: Register Credential Provider
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{YOUR-GUID}" /ve /t REG_SZ /d "QR Code Credential Provider" /f

:: Restart LogonUI
taskkill /f /im LogonUI.exe
```

---

## Summary Flow Diagram

```
┌─────────────────┐
│  User Scans QR  │
└────────┬────────┘
         │
         v
┌──────────────────────┐
│  Mobile App Auth     │──────► Auth Server validates
└──────────┬───────────┘
           │
           v
┌────────────────────────────┐
│  Auth Server Generates     │
│  Ephemeral Certificate     │
│  - 5 min validity          │
│  - SID extension           │
│  - Smart Card Logon EKU    │
│  - UPN in SAN              │
└────────────┬───────────────┘
             │
             v
┌─────────────────────────────┐
│  CP Polls Auth Server       │
│  GET /api/session/status    │
└──────────┬──────────────────┘
           │
           v  (status: authenticated)
┌──────────────────────────────┐
│  CP Receives:                │
│  - Certificate (PEM)         │
│  - Private Key (PEM)         │
│  - PFX (Base64)              │
└──────────┬───────────────────┘
           │
           v
┌──────────────────────────────┐
│  CP Imports PFX to           │
│  Current User\My Store       │
└──────────┬───────────────────┘
           │
           v
┌──────────────────────────────┐
│  CP Validates Certificate    │
│  - Check private key access  │
│  - Verify validity period    │
└──────────┬───────────────────┘
           │
           v
┌──────────────────────────────┐
│  CP Calls GetSerialization   │
│  - Build KERB_CERTIFICATE_   │
│    LOGON structure           │
│  - Include cert + username   │
└──────────┬───────────────────┘
           │
           v
┌──────────────────────────────┐
│  Windows LogonUI             │
│  - Sends to LSA              │
│  - LSA → Kerberos KDC        │
└──────────┬───────────────────┘
           │
           v
┌──────────────────────────────┐
│  DC/KDC Validates Cert       │
│  - Check CA in NTAuth        │
│  - Verify SID extension      │
│  - Match UPN to AD user      │
│  - Issue Kerberos TGT        │
└──────────┬───────────────────┘
           │
           v
┌──────────────────────────────┐
│  User Logged In Successfully │
└──────────────────────────────┘
           │
           v (after 5 minutes)
┌──────────────────────────────┐
│  Certificate Expires         │
│  - Cannot be reused          │
│  - Revoked on server         │
└──────────────────────────────┘
```

---

## Troubleshooting

### Issue: "Failed to acquire private key"

**Cause:** Private key not accessible or not imported correctly

**Solution:**
- Ensure PFX import includes private key
- Use CRYPT_EXPORTABLE flag
- Check certificate store permissions

### Issue: "Certificate authentication failed"

**Cause:** Certificate not valid for authentication

**Solution:**
- Verify Smart Card Logon EKU present
- Check UPN in Subject Alternative Name
- Ensure SID extension is correct
- Verify CA in NTAuth store

### Issue: "The system cannot log you on"

**Cause:** Certificate validation failed at DC

**Solution:**
- Check DC event logs (Event ID 39, 40, 41)
- Verify user exists in AD with correct SID
- Ensure CA certificate in NTAuth store
- Check certificate validity period

### Issue: Certificate not found in user store

**Cause:** Import failed or wrong store location

**Solution:**
- Verify PFX decode successful
- Check store location (CERT_SYSTEM_STORE_CURRENT_USER)
- Run certmgr.msc to view user certificates
- Try importing with CERT_STORE_CREATE_NEW_FLAG

---

## Next Steps

1. ✅ Implement certificate import function
2. ✅ Update polling function to handle certificates
3. ✅ Modify GetSerialization for certificate logon
4. ✅ Add debug logging
5. ✅ Build and test DLL
6. ✅ Install on test machine
7. ✅ Test full authentication flow
8. ✅ Monitor event logs
9. ✅ Iterate based on errors

---

Good luck with your POC! 🚀