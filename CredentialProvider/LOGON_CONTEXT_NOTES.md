# Logon Context - Registry and DPAPI Notes

## Overview

This document addresses concerns about registry access and DPAPI encryption/decryption during the logon screen, specifically for first user session over RDP.

## 1. Registry Access During Logon

### Question: Can Credential Provider access registry during logon (first user session over RDP)?

**Answer: YES** - Credential Providers can access `HKLM` (HKEY_LOCAL_MACHINE) during logon.

### Why This Works:

1. **Credential Provider Execution Context**: 
   - Credential Providers run in the **SYSTEM** security context
   - They are loaded by `winlogon.exe` or `LogonUI.exe` which run as SYSTEM
   - SYSTEM has full read access to `HKLM`

2. **Registry Access Permissions**:
   - `HKLM\SOFTWARE` is readable by SYSTEM and all users
   - No user profile or user session is required to read from `HKLM`
   - This works even before any user logs on

3. **First User Session Over RDP**:
   - When connecting via RDP for the first time, the logon screen appears
   - The Credential Provider loads in SYSTEM context
   - Registry reads from `HKLM` work immediately, no user session needed

### Implementation Details:

Our code reads from:
```
HKLM\SOFTWARE\SecurITaas\CredentialProvider\AuthServer
HKLM\SOFTWARE\SecurITaas\CredentialProvider\AuthPort
HKLM\SOFTWARE\SecurITaas\CredentialProvider\EncryptedUsername
HKLM\SOFTWARE\CredentialProvider\EncryptedPassword
```

All of these are in `HKLM`, which is accessible during logon.

## 2. DPAPI Encryption/Decryption During Logon

### Question: Will DPAPI encryption/decryption work during logon when there's no valid user session?

**Answer: YES** - When using `CRYPTPROTECT_LOCAL_MACHINE` flag.

### Why This Works:

1. **CRYPTPROTECT_LOCAL_MACHINE Flag**:
   - This flag uses **machine-specific** encryption keys
   - These keys are stored in the machine's registry, not in user profiles
   - No user session or user profile is required

2. **Machine Keys Location**:
   - Machine keys are stored in `HKLM\SOFTWARE\Microsoft\Cryptography\Protect`
   - These keys are accessible to SYSTEM account
   - They exist regardless of whether any user is logged on

3. **Encryption/Decryption Process**:
   - **Encryption (Installer)**: Uses machine keys to encrypt credentials
   - **Decryption (Credential Provider)**: Uses same machine keys to decrypt
   - Both operations work in SYSTEM context during logon

### Important Notes:

1. **Machine-Specific**: 
   - Data encrypted with `LOCAL_MACHINE` can only be decrypted on the **same machine**
   - If the machine is reimaged or the domain changes, decryption will fail
   - This is by design for security

2. **No User Profile Required**:
   - Unlike `CRYPTPROTECT_LOCAL_MACHINE` (without flag), which requires user profile
   - `CRYPTPROTECT_LOCAL_MACHINE` works without any logged-in user
   - Perfect for logon screen scenarios

3. **Windows 2016 Server Compatibility**:
   - DPAPI with `LOCAL_MACHINE` flag has been available since Windows 2000
   - Fully supported on Windows 2016 Server and later
   - No compatibility issues

### Error Handling:

If DPAPI decryption fails during logon, it could indicate:
1. Data was encrypted on a different machine
2. Machine registry was corrupted or reset
3. Credential Provider is not running as SYSTEM (shouldn't happen)

Our code includes error logging to help diagnose these issues.

## 3. Testing Recommendations

### To Verify Registry Access:
1. Check that installer successfully writes to `HKLM\SOFTWARE\SecurITaas\CredentialProvider`
2. Verify Credential Provider can read these values during logon
3. Check logs for any registry access errors

### To Verify DPAPI:
1. Encrypt credentials during installation (installer does this)
2. Attempt to decrypt during logon (Credential Provider does this)
3. If decryption fails, check:
   - Are you testing on the same machine where encryption occurred?
   - Is the Credential Provider running as SYSTEM? (Check Task Manager)
   - Are machine keys intact? (Check `HKLM\SOFTWARE\Microsoft\Cryptography\Protect`)

## 4. Alternative Approaches (If Needed)

If DPAPI with `LOCAL_MACHINE` doesn't work for some reason, alternatives include:

1. **Base64 Encoding (Not Recommended)**: 
   - Simple but not secure
   - Credentials would be visible in registry

2. **Custom Encryption with Machine-Specific Key**:
   - Derive key from machine GUID or other machine-specific data
   - More complex but gives full control

3. **Windows Credential Manager**:
   - Use `CredWrite` with `CRED_PERSIST_LOCAL_MACHINE`
   - Still uses DPAPI internally but with different API

For our use case, `CRYPTPROTECT_LOCAL_MACHINE` is the recommended and standard approach.

## Conclusion

Both registry access and DPAPI decryption **will work** during logon for first user session over RDP because:
- Credential Providers run as SYSTEM
- `HKLM` is accessible to SYSTEM
- `CRYPTPROTECT_LOCAL_MACHINE` uses machine keys, not user keys
- No user session or profile is required

The implementation is correct and follows Windows best practices for Credential Providers.

