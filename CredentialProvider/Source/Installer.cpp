//
// Installer.cpp
// Installation executable for SecurITaas Credential Provider
// Takes auth server IP and port as command line parameters
//

#include <windows.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

// Registry paths
#define REGISTRY_CONFIG_PATH L"SOFTWARE\\SecurITaas\\CredentialProvider"
#define REGISTRY_SERVER_KEY L"AuthServer"
#define REGISTRY_PORT_KEY L"AuthPort"
#define REGISTRY_USERNAME_KEY L"EncryptedUsername"
#define REGISTRY_PASSWORD_KEY L"EncryptedPassword"

// Credential Provider registration path
#define REGISTRY_CP_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers"

// Credential Provider GUID
// This GUID matches the one defined in Source/common.h: CLSID_RDPQRProvider
// {8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}
#define CREDENTIAL_PROVIDER_GUID L"{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"
#define CREDENTIAL_PROVIDER_NAME L"Logon using Securitaas"

// Hardcoded credentials (as specified)
#define REGISTRATION_USERNAME L"soagent|d6500253-d644-441e-8b72-27c98bd381b4"
#define REGISTRATION_PASSWORD L"9a05ff3547cc9c0c6b6c4d2ed040f732bcd32608cad2607842b69e3338026381"

// Encrypt data using Windows DPAPI
HRESULT EncryptCredential(const std::wstring& plaintext, std::vector<BYTE>& encrypted)
{
    if (plaintext.empty())
    {
        return E_INVALIDARG;
    }
    
    // Convert to UTF-8
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, plaintext.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Size <= 0)
    {
        return E_FAIL;
    }
    
    std::vector<char> utf8Data(utf8Size);
    WideCharToMultiByte(CP_UTF8, 0, plaintext.c_str(), -1, utf8Data.data(), utf8Size, nullptr, nullptr);
    
    DATA_BLOB dataIn, dataOut;
    dataIn.pbData = (BYTE*)utf8Data.data();
    dataIn.cbData = utf8Size - 1; // Exclude null terminator
    
    // Encrypt using LocalMachine scope (works during logon)
    // CRYPTPROTECT_LOCAL_MACHINE allows decryption by any user on the machine
    BOOL result = CryptProtectData(&dataIn, L"SecurITaas Credential Provider", nullptr, nullptr, nullptr,
                                   CRYPTPROTECT_LOCAL_MACHINE, &dataOut);
    
    if (!result)
    {
        DWORD error = GetLastError();
        std::wcerr << L"CryptProtectData failed, error: " << error << std::endl;
        return HRESULT_FROM_WIN32(error);
    }
    
    encrypted.assign(dataOut.pbData, dataOut.pbData + dataOut.cbData);
    LocalFree(dataOut.pbData);
    
    return S_OK;
}

// Write string value to registry
HRESULT WriteRegistryString(HKEY hKey, LPCWSTR valueName, LPCWSTR data)
{
    LONG result = RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)data, 
                                  (DWORD)((wcslen(data) + 1) * sizeof(WCHAR)));
    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"Failed to write registry value " << valueName << L", error: " << result << std::endl;
        return HRESULT_FROM_WIN32(result);
    }
    return S_OK;
}

// Write binary value to registry
HRESULT WriteRegistryBinary(HKEY hKey, LPCWSTR valueName, const std::vector<BYTE>& data)
{
    LONG result = RegSetValueExW(hKey, valueName, 0, REG_BINARY, data.data(), (DWORD)data.size());
    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"Failed to write registry value " << valueName << L", error: " << result << std::endl;
        return HRESULT_FROM_WIN32(result);
    }
    return S_OK;
}

// Copy DLL to System32
HRESULT CopyDllToSystem32()
{
    WCHAR currentPath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, currentPath, MAX_PATH))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Get directory of installer
    PathRemoveFileSpecW(currentPath);
    std::wstring dllPath = currentPath;
    dllPath += L"\\RDPQRProvider.dll";
    
    // Check if DLL exists
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcerr << L"DLL not found at: " << dllPath << std::endl;
        return E_FAIL;
    }
    
    // Copy to System32
    std::wstring destPath = L"C:\\Windows\\System32\\RDPQRProvider.dll";
    
    if (!CopyFileW(dllPath.c_str(), destPath.c_str(), FALSE))
    {
        DWORD error = GetLastError();
        std::wcerr << L"Failed to copy DLL, error: " << error << std::endl;
        return HRESULT_FROM_WIN32(error);
    }
    
    std::wcout << L"DLL copied to System32" << std::endl;
    return S_OK;
}

// Register DLL using regsvr32
HRESULT RegisterDll()
{
    std::wstring dllPath = L"C:\\Windows\\System32\\RDPQRProvider.dll";
    std::wstring regsvr32 = L"C:\\Windows\\System32\\regsvr32.exe";
    
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas"; // Run as administrator
    sei.lpFile = regsvr32.c_str();
    sei.lpParameters = (L"/s \"" + dllPath + L"\"").c_str();
    sei.nShow = SW_HIDE;
    
    if (!ShellExecuteExW(&sei))
    {
        DWORD error = GetLastError();
        std::wcerr << L"Failed to execute regsvr32, error: " << error << std::endl;
        return HRESULT_FROM_WIN32(error);
    }
    
    // Wait for registration to complete
    if (sei.hProcess)
    {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        
        if (exitCode != 0)
        {
            std::wcerr << L"regsvr32 failed with exit code: " << exitCode << std::endl;
            return E_FAIL;
        }
    }
    
    std::wcout << L"DLL registered successfully" << std::endl;
    return S_OK;
}

// Register Credential Provider in Windows registry
// This is REQUIRED for Windows to recognize and load the Credential Provider
HRESULT RegisterCredentialProvider()
{
    // Create the Credential Provider registry key
    // Path: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{GUID}
    std::wstring cpKeyPath = std::wstring(REGISTRY_CP_PATH) + L"\\" + CREDENTIAL_PROVIDER_GUID;
    
    HKEY hKey = nullptr;
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, cpKeyPath.c_str(), 0, nullptr,
                                  REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    
    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"Failed to create Credential Provider registry key, error: " << result << std::endl;
        return HRESULT_FROM_WIN32(result);
    }
    
    // Set the display name (optional but recommended)
    result = RegSetValueExW(hKey, nullptr, 0, REG_SZ, 
                            (const BYTE*)CREDENTIAL_PROVIDER_NAME, 
                            (DWORD)((wcslen(CREDENTIAL_PROVIDER_NAME) + 1) * sizeof(WCHAR)));
    
    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"Warning: Failed to set display name, error: " << result << std::endl;
        // Non-fatal, continue
    }
    
    RegCloseKey(hKey);
    
    std::wcout << L"Credential Provider registered in registry: " << cpKeyPath << std::endl;
    return S_OK;
}

// Check if DLL exists in System32
bool DllExists()
{
    std::wstring dllPath = L"C:\\Windows\\System32\\RDPQRProvider.dll";
    return GetFileAttributesW(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// Check if registry configuration exists
bool RegistryConfigExists()
{
    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REGISTRY_CONFIG_PATH, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Read existing registry value
HRESULT ReadRegistryString(HKEY hKey, LPCWSTR valueName, std::wstring& value)
{
    WCHAR buffer[256] = {0};
    DWORD bufferSize = sizeof(buffer);
    DWORD type = REG_SZ;
    
    LONG result = RegQueryValueExW(hKey, valueName, nullptr, &type, (LPBYTE)buffer, &bufferSize);
    if (result == ERROR_SUCCESS)
    {
        value = buffer;
        return S_OK;
    }
    return HRESULT_FROM_WIN32(result);
}

// Check if registry values need updating
bool RegistryNeedsUpdate(HKEY hKey, LPCWSTR serverIp, LPCWSTR port)
{
    std::wstring existingServer, existingPort;
    
    if (SUCCEEDED(ReadRegistryString(hKey, REGISTRY_SERVER_KEY, existingServer)) &&
        SUCCEEDED(ReadRegistryString(hKey, REGISTRY_PORT_KEY, existingPort)))
    {
        return (existingServer != serverIp || existingPort != port);
    }
    return true; // If we can't read, assume update needed
}

// Unregister DLL using regsvr32
HRESULT UnregisterDll()
{
    std::wstring dllPath = L"C:\\Windows\\System32\\RDPQRProvider.dll";
    std::wstring regsvr32 = L"C:\\Windows\\System32\\regsvr32.exe";
    
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = regsvr32.c_str();
    sei.lpParameters = (L"/s /u \"" + dllPath + L"\"").c_str();
    sei.nShow = SW_HIDE;
    
    if (!ShellExecuteExW(&sei))
    {
        DWORD error = GetLastError();
        std::wcerr << L"Failed to execute regsvr32 /u, error: " << error << std::endl;
        return HRESULT_FROM_WIN32(error);
    }
    
    if (sei.hProcess)
    {
        WaitForSingleObject(sei.hProcess, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeProcess(sei.hProcess, &exitCode);
        CloseHandle(sei.hProcess);
        
        if (exitCode != 0)
        {
            std::wcerr << L"regsvr32 /u failed with exit code: " << exitCode << std::endl;
            return E_FAIL;
        }
    }
    
    return S_OK;
}

// Delete DLL from System32
HRESULT DeleteDllFromSystem32()
{
    std::wstring dllPath = L"C:\\Windows\\System32\\RDPQRProvider.dll";
    
    // Try to delete the file
    if (!DeleteFileW(dllPath.c_str()))
    {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND)
        {
            // File doesn't exist, that's OK
            return S_OK;
        }
        std::wcerr << L"Failed to delete DLL, error: " << error << std::endl;
        return HRESULT_FROM_WIN32(error);
    }
    
    return S_OK;
}

// Unregister Credential Provider from Windows registry
HRESULT UnregisterCredentialProvider()
{
    // Remove Credential Provider registry entry
    std::wstring cpKeyPath = std::wstring(REGISTRY_CP_PATH) + L"\\" + CREDENTIAL_PROVIDER_GUID;
    
    LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, cpKeyPath.c_str());
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND)
    {
        std::wcerr << L"Warning: Failed to delete Credential Provider registry key, error: " << result << std::endl;
        // Non-fatal, continue
    }
    
    // Also remove CLSID entry from HKEY_CLASSES_ROOT
    std::wstring clsidPath = std::wstring(L"CLSID\\") + CREDENTIAL_PROVIDER_GUID;
    result = RegDeleteTreeW(HKEY_CLASSES_ROOT, clsidPath.c_str());
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND)
    {
        std::wcerr << L"Warning: Failed to delete CLSID registry key, error: " << result << std::endl;
        // Non-fatal, continue
    }
    
    return S_OK;
}

// Delete configuration registry entries
HRESULT DeleteRegistryConfig()
{
    LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, REGISTRY_CONFIG_PATH);
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND)
    {
        std::wcerr << L"Failed to delete registry configuration, error: " << result << std::endl;
        return HRESULT_FROM_WIN32(result);
    }
    
    return S_OK;
}

// Perform uninstallation
HRESULT PerformUninstall()
{
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"SecurITaas Credential Provider Uninstaller" << std::endl;
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"" << std::endl;
    
    HRESULT hr = S_OK;
    bool hasErrors = false;
    
    // Unregister DLL (COM)
    if (DllExists())
    {
        std::wcout << L"Unregistering DLL (COM)..." << std::endl;
        hr = UnregisterDll();
        if (FAILED(hr))
        {
            std::wcerr << L"Warning: Failed to unregister DLL" << std::endl;
            hasErrors = true;
        }
        else
        {
            std::wcout << L"DLL unregistered" << std::endl;
        }
    }
    
    // Unregister Credential Provider
    std::wcout << L"Removing Credential Provider from Windows registry..." << std::endl;
    hr = UnregisterCredentialProvider();
    if (FAILED(hr))
    {
        std::wcerr << L"Warning: Failed to remove Credential Provider registry entry" << std::endl;
        hasErrors = true;
    }
    else
    {
        std::wcout << L"Credential Provider registry entry removed" << std::endl;
    }
    
    // Delete DLL
    std::wcout << L"Deleting DLL from System32..." << std::endl;
    hr = DeleteDllFromSystem32();
    if (FAILED(hr))
    {
        std::wcerr << L"Warning: Failed to delete DLL" << std::endl;
        hasErrors = true;
    }
    else
    {
        std::wcout << L"DLL deleted" << std::endl;
    }
    
    // Delete configuration registry
    std::wcout << L"Removing configuration from registry..." << std::endl;
    hr = DeleteRegistryConfig();
    if (FAILED(hr))
    {
        std::wcerr << L"Warning: Failed to remove configuration registry entries" << std::endl;
        hasErrors = true;
    }
    else
    {
        std::wcout << L"Configuration registry entries removed" << std::endl;
    }
    
    std::wcout << L"" << std::endl;
    if (hasErrors)
    {
        std::wcout << L"Uninstallation completed with warnings. Some items may not have been removed." << std::endl;
        return S_FALSE;
    }
    else
    {
        std::wcout << L"========================================" << std::endl;
        std::wcout << L"Uninstallation Complete!" << std::endl;
        std::wcout << L"========================================" << std::endl;
        std::wcout << L"" << std::endl;
        std::wcout << L"IMPORTANT: You must restart your computer for changes to take effect!" << std::endl;
        std::wcout << L"" << std::endl;
        return S_OK;
    }
}

// Print usage
void PrintUsage(LPCWSTR programName)
{
    std::wcout << L"Usage:" << std::endl;
    std::wcout << L"  Install: " << programName << L" install <server_ip> <port>" << std::endl;
    std::wcout << L"  Uninstall: " << programName << L" uninstall" << std::endl;
    std::wcout << L"" << std::endl;
    std::wcout << L"Examples:" << std::endl;
    std::wcout << L"  " << programName << L" install 172.31.46.149 5000" << std::endl;
    std::wcout << L"  " << programName << L" uninstall" << std::endl;
    std::wcout << L"" << std::endl;
    std::wcout << L"Installation will:" << std::endl;
    std::wcout << L"  1. Store auth server configuration in registry" << std::endl;
    std::wcout << L"  2. Encrypt and store credentials in registry" << std::endl;
    std::wcout << L"  3. Copy/Replace RDPQRProvider.dll to System32" << std::endl;
    std::wcout << L"  4. Register the DLL (COM)" << std::endl;
    std::wcout << L"  5. Register the Credential Provider in Windows registry" << std::endl;
    std::wcout << L"" << std::endl;
    std::wcout << L"Note: This installer must be run as Administrator" << std::endl;
}

int wmain(int argc, wchar_t* argv[])
{
    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup = nullptr;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
    {
        CheckTokenMembership(nullptr, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }
    
    if (!isAdmin)
    {
        std::wcerr << L"ERROR: This installer must be run as Administrator!" << std::endl;
        std::wcerr << L"Right-click and select 'Run as Administrator'" << std::endl;
        return 1;
    }
    
    // Check arguments
    if (argc < 2)
    {
        PrintUsage(argv[0]);
        return 1;
    }
    
    // Handle uninstall
    std::wstring command = argv[1];
    if (command == L"uninstall" || command == L"/u" || command == L"-u")
    {
        HRESULT hr = PerformUninstall();
        return FAILED(hr) ? 1 : 0;
    }
    
    // Handle install
    if (command != L"install" && argc != 3)
    {
        // Backward compatibility: if first arg is not "install" and we have 3 args, treat as old format
        if (argc != 3)
        {
            PrintUsage(argv[0]);
            return 1;
        }
        // Old format: installer.exe <server_ip> <port>
        command = L"install";
    }
    else if (command == L"install" && argc != 4)
    {
        PrintUsage(argv[0]);
        return 1;
    }
    
    // Get server IP and port
    std::wstring serverIp, port;
    if (command == L"install")
    {
        serverIp = argv[2];
        port = argv[3];
    }
    else
    {
        // Old format compatibility
        serverIp = argv[1];
        port = argv[2];
    }
    
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"SecurITaas Credential Provider Installer" << std::endl;
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"Server: " << serverIp << L":" << port << std::endl;
    std::wcout << L"" << std::endl;
    
    // Check for existing installation
    bool dllExists = DllExists();
    bool registryExists = RegistryConfigExists();
    
    if (dllExists || registryExists)
    {
        std::wcout << L"Existing installation detected." << std::endl;
        if (dllExists)
        {
            std::wcout << L"  - DLL found in System32" << std::endl;
        }
        if (registryExists)
        {
            std::wcout << L"  - Registry configuration found" << std::endl;
        }
        std::wcout << L"Updating installation..." << std::endl;
        std::wcout << L"" << std::endl;
    }
    
    HRESULT hr = S_OK;
    
    // Declare variables before any goto statements
    HKEY hKey = nullptr;
    std::vector<BYTE> encryptedUsername, encryptedPassword;
    
    // Create/open registry key
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, REGISTRY_CONFIG_PATH, 0, nullptr,
                                  REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, nullptr, &hKey, nullptr);
    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"Failed to create/open registry key, error: " << result << std::endl;
        return 1;
    }
    
    // Check if registry values need updating
    bool needsUpdate = true;
    if (registryExists)
    {
        needsUpdate = RegistryNeedsUpdate(hKey, serverIp.c_str(), port.c_str());
        if (!needsUpdate)
        {
            std::wcout << L"Registry configuration is up to date." << std::endl;
        }
        else
        {
            std::wcout << L"Registry configuration needs updating." << std::endl;
        }
    }
    
    // Write server configuration
    if (needsUpdate)
    {
        std::wcout << L"Writing server configuration..." << std::endl;
        hr = WriteRegistryString(hKey, REGISTRY_SERVER_KEY, serverIp.c_str());
        if (FAILED(hr)) goto cleanup;
        
        hr = WriteRegistryString(hKey, REGISTRY_PORT_KEY, port.c_str());
        if (FAILED(hr)) goto cleanup;
    }
    
    // Encrypt and store credentials (always update credentials to ensure they're current)
    std::wcout << L"Encrypting credentials..." << std::endl;
    
    hr = EncryptCredential(REGISTRATION_USERNAME, encryptedUsername);
    if (FAILED(hr)) goto cleanup;
    
    hr = EncryptCredential(REGISTRATION_PASSWORD, encryptedPassword);
    if (FAILED(hr)) goto cleanup;
    
    hr = WriteRegistryBinary(hKey, REGISTRY_USERNAME_KEY, encryptedUsername);
    if (FAILED(hr)) goto cleanup;
    
    hr = WriteRegistryBinary(hKey, REGISTRY_PASSWORD_KEY, encryptedPassword);
    if (FAILED(hr)) goto cleanup;
    
    RegCloseKey(hKey);
    hKey = nullptr;
    
    std::wcout << L"Configuration stored in registry" << std::endl;
    std::wcout << L"" << std::endl;
    
    // Copy DLL (will replace if exists)
    if (dllExists)
    {
        std::wcout << L"Replacing DLL in System32..." << std::endl;
    }
    else
    {
        std::wcout << L"Copying DLL to System32..." << std::endl;
    }
    hr = CopyDllToSystem32();
    if (FAILED(hr)) goto cleanup;
    
    // Register DLL (COM registration) - will update if already registered
    std::wcout << L"Registering DLL (COM)..." << std::endl;
    hr = RegisterDll();
    if (FAILED(hr)) goto cleanup;
    
    // Register Credential Provider in Windows registry (REQUIRED)
    std::wcout << L"Registering Credential Provider in Windows registry..." << std::endl;
    hr = RegisterCredentialProvider();
    if (FAILED(hr)) goto cleanup;
    
    std::wcout << L"" << std::endl;
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"Installation Complete!" << std::endl;
    std::wcout << L"========================================" << std::endl;
    std::wcout << L"" << std::endl;
    std::wcout << L"IMPORTANT: You must restart your computer for changes to take effect!" << std::endl;
    std::wcout << L"" << std::endl;
    
    return 0;
    
cleanup:
    if (hKey) RegCloseKey(hKey);
    std::wcerr << L"Installation failed with error: 0x" << std::hex << hr << std::endl;
    return 1;
}

