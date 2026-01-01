# SecurITaas Credential Provider Installer

## Overview

The installer is a standalone executable that configures and installs the SecurITaas Credential Provider. It replaces the PowerShell installation script with a native Windows executable.

## Building the Installer

The installer source code is located in `Source/Installer.cpp`. To build it:

1. Create a new Visual Studio project (Console Application) or add it to the existing solution
2. Set the project type to "Console Application" (not DLL)
3. Add `Source/Installer.cpp` to the project
4. Link against: `shlwapi.lib` and `crypt32.lib` (already included via pragma comments)
5. Build in Release mode

Alternatively, you can compile it manually:
```cmd
cl /EHsc /O2 Source/Installer.cpp /link shlwapi.lib crypt32.lib /OUT:SecurITaasInstaller.exe
```

## Usage

```cmd
SecurITaasInstaller.exe <server_ip> <port>
```

Example:
```cmd
SecurITaasInstaller.exe 172.31.46.149 5000
```

## What the Installer Does

1. **Validates Administrator Privileges**: Ensures the installer is run as Administrator
2. **Stores Server Configuration**: Writes auth server IP and port to registry:
   - `HKLM\SOFTWARE\SecurITaas\CredentialProvider\AuthServer`
   - `HKLM\SOFTWARE\SecurITaas\CredentialProvider\AuthPort`
3. **Encrypts and Stores Credentials**: 
   - Encrypts the registration username and password using Windows DPAPI (Data Protection API)
   - Stores encrypted credentials in registry:
     - `HKLM\SOFTWARE\SecurITaas\CredentialProvider\EncryptedUsername`
     - `HKLM\SOFTWARE\SecurITaas\CredentialProvider\EncryptedPassword`
4. **Copies DLL**: Copies `RDPQRProvider.dll` from the installer directory to `C:\Windows\System32\`
5. **Registers Provider**: Registers the credential provider DLL using `regsvr32.exe`

## Credentials

The installer uses hardcoded credentials (as specified):
- Username: `soagent|d6500253-d644-441e-8b72-27c98bd381b4`
- Password: `9a05ff3547cc9c0c6b6c4d2ed040f732bcd32608cad2607842b69e3338026381`

These are encrypted using Windows DPAPI with `CRYPTPROTECT_LOCAL_MACHINE` flag, which allows decryption by any user on the machine (required for logon screen).

## Requirements

- Windows 2016 Server or later
- Administrator privileges
- `RDPQRProvider.dll` must be in the same directory as the installer

## Notes

- The installer must be run as Administrator
- A system restart is required after installation for the credential provider to appear on the logon screen
- The encrypted credentials are machine-specific and cannot be decrypted on a different machine

