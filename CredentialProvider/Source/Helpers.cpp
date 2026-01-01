//
// Helpers.cpp
// Implementation of helper functions for authentication and system utilities
//

#include "common.h"
#include <sddl.h>
#include <dsgetdc.h>
#include <ntstatus.h>
#include <lmcons.h>
#include <Wtsapi32.h>
#include <wincrypt.h>
#pragma comment(lib, "Wtsapi32.lib")
#ifndef NEGOSSP_NAME_A
#define NEGOSSP_NAME_A "Negotiate"
#endif
#ifndef LsaInitString
#define LsaInitString(d, s) { \
    (d)->Buffer = (PCHAR)(s); \
    (d)->Length = (s) ? (USHORT)strlen(s) : 0; \
    (d)->MaximumLength = (d)->Length; \
}
#endif
#pragma comment(lib, "netapi32.lib")
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
//
// Retrieve the Negotiate authentication package ID
// The Negotiate package automatically chooses Kerberos or NTLM
// based on whether the machine is domain-joined
//
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage)
{
    if (!pulAuthPackage)
    {
        return E_INVALIDARG;
    }

    *pulAuthPackage = 0;

    HRESULT hr;
    HANDLE hLsa = NULL;

    // Connect to LSA
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (!NT_SUCCESS(status))
    {
        LogDebugMessage(L"LsaConnectUntrusted failed: 0x%08X", status);
        return HRESULT_FROM_NT(status);
    }

    // ✅ CRITICAL FIX - Use "Kerberos" for KERB_CERTIFICATE_LOGON
    LSA_STRING packageName;
    packageName.Buffer = (PCHAR)"Kerberos";  // NOT "Negotiate"
    packageName.Length = (USHORT)strlen(packageName.Buffer);
    packageName.MaximumLength = packageName.Length + 1;

    status = LsaLookupAuthenticationPackage(hLsa, &packageName, pulAuthPackage);

    LsaDeregisterLogonProcess(hLsa);

    if (!NT_SUCCESS(status))
    {
        LogDebugMessage(L"LsaLookupAuthenticationPackage(Kerberos) failed: 0x%08X", status);
        return HRESULT_FROM_NT(status);
    }

    if (*pulAuthPackage == 0)
    {
        LogDebugMessage(L"❌ Kerberos package returned ID 0 - invalid!");
        return E_FAIL;
    }

    LogDebugMessage(L"✅ Retrieved Kerberos auth package ID: %lu", *pulAuthPackage);

    return S_OK;
}

HRESULT GetActiveSessionLogonLuid(LUID* pLuid)
{
    if (!pLuid) return E_POINTER;

    DWORD sid = WTSGetActiveConsoleSessionId();
    if (sid == 0xFFFFFFFF) return HRESULT_FROM_WIN32(ERROR_NO_LOGON_SESSION);

    HANDLE hUser = NULL;
    if (WTSQueryUserToken(sid, &hUser)) {
        TOKEN_STATISTICS ts{}; DWORD cb = 0;
        BOOL ok = GetTokenInformation(hUser, TokenStatistics, &ts, sizeof(ts), &cb);
        CloseHandle(hUser);
        if (!ok) return HRESULT_FROM_WIN32(GetLastError());
        *pLuid = ts.AuthenticationId;
        return S_OK;
    }

    // Fallback: try current process token (only if not SYSTEM)
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok))
        return HRESULT_FROM_WIN32(GetLastError());

    TOKEN_STATISTICS ts{}; DWORD cb = 0;
    BOOL ok = GetTokenInformation(hTok, TokenStatistics, &ts, sizeof(ts), &cb);
    CloseHandle(hTok);
    if (!ok) return HRESULT_FROM_WIN32(GetLastError());

    // Reject SYSTEM (0x3E7) – it will cause 0xC000006D for UNLOCK
    if (ts.AuthenticationId.HighPart == 0 && ts.AuthenticationId.LowPart == 0x3E7)
        return HRESULT_FROM_WIN32(ERROR_NO_LOGON_SESSION);

    *pLuid = ts.AuthenticationId;
    return S_OK;
}

HRESULT GetCurrentLogonLuid(LUID* pLuid) {
    if (!pLuid) return E_POINTER;
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    TOKEN_STATISTICS ts = {};
    DWORD cb = 0;
    BOOL ok = GetTokenInformation(hTok, TokenStatistics, &ts, sizeof(ts), &cb);
    CloseHandle(hTok);
    if (!ok) return HRESULT_FROM_WIN32(GetLastError());
    *pLuid = ts.AuthenticationId;   // This is the LogonId LUID the UNLOCK path needs
    return S_OK;
}
HRESULT RetrieveKerberosAuthPackage(ULONG* pulAuthPackage)
{
    if (!pulAuthPackage) return E_POINTER;
    HANDLE hLsa = NULL;
    ULONG packageId = 0;
    LSA_STRING pkg;
    pkg.Buffer = const_cast<PSTR>("Kerberos"); // MICROSOFT_KERBEROS_NAME_A
    pkg.Length = (USHORT)strlen(pkg.Buffer);
    pkg.MaximumLength = pkg.Length;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status) return HRESULT_FROM_NT(status);

    status = LsaLookupAuthenticationPackage(hLsa, &pkg, &packageId);
    LsaDeregisterLogonProcess(hLsa);

    if (status) return HRESULT_FROM_NT(status);
    *pulAuthPackage = packageId;
    return S_OK;
}

//
// Initialize Kerberos Interactive Unlock Logon structure
// This is used for domain authentication with Kerberos
//
HRESULT KerbInteractiveUnlockLogonInit(
    __in PWSTR pwzDomain,
    __in PWSTR pwzUsername,
    __in PWSTR pwzPassword,
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __out KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
    HRESULT hr = S_OK;

    ZeroMemory(pkiul, sizeof(KERB_INTERACTIVE_UNLOCK_LOGON));

    KERB_LOGON_SUBMIT_TYPE submitType;
    if (cpus == CPUS_UNLOCK_WORKSTATION)
    {
        submitType = KerbWorkstationUnlockLogon;
        pkiul->Logon.MessageType = submitType;
    }
    else
    {
        submitType = KerbInteractiveLogon;
        pkiul->Logon.MessageType = submitType;
    }

    if (pwzDomain)
    {
        size_t domainLen = wcslen(pwzDomain);
        pkiul->Logon.LogonDomainName.Length = (USHORT)(domainLen * sizeof(WCHAR));
        pkiul->Logon.LogonDomainName.MaximumLength = (USHORT)((domainLen + 1) * sizeof(WCHAR));
        pkiul->Logon.LogonDomainName.Buffer = (PWSTR)CoTaskMemAlloc(pkiul->Logon.LogonDomainName.MaximumLength);
        
        if (!pkiul->Logon.LogonDomainName.Buffer)
        {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }
        
        hr = StringCchCopyW(pkiul->Logon.LogonDomainName.Buffer, domainLen + 1, pwzDomain);
        if (FAILED(hr))
        {
            goto cleanup;
        }
    }

    size_t userLen = wcslen(pwzUsername);
    pkiul->Logon.UserName.Length = (USHORT)(userLen * sizeof(WCHAR));
    pkiul->Logon.UserName.MaximumLength = (USHORT)((userLen + 1) * sizeof(WCHAR));
    pkiul->Logon.UserName.Buffer = (PWSTR)CoTaskMemAlloc(pkiul->Logon.UserName.MaximumLength);
    
    if (!pkiul->Logon.UserName.Buffer)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    
    hr = StringCchCopyW(pkiul->Logon.UserName.Buffer, userLen + 1, pwzUsername);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    if (pwzPassword)
    {
        size_t passLen = wcslen(pwzPassword);
        pkiul->Logon.Password.Length = (USHORT)(passLen * sizeof(WCHAR));
        pkiul->Logon.Password.MaximumLength = (USHORT)((passLen + 1) * sizeof(WCHAR));
        pkiul->Logon.Password.Buffer = (PWSTR)CoTaskMemAlloc(pkiul->Logon.Password.MaximumLength);
        
        if (!pkiul->Logon.Password.Buffer)
        {
            hr = E_OUTOFMEMORY;
            goto cleanup;
        }
        
        hr = StringCchCopyW(pkiul->Logon.Password.Buffer, passLen + 1, pwzPassword);
        if (FAILED(hr))
        {
            goto cleanup;
        }
    }

cleanup:
    if (FAILED(hr))
    {
        if (pkiul->Logon.LogonDomainName.Buffer)
        {
            CoTaskMemFree(pkiul->Logon.LogonDomainName.Buffer);
            pkiul->Logon.LogonDomainName.Buffer = nullptr;
        }
        if (pkiul->Logon.UserName.Buffer)
        {
            CoTaskMemFree(pkiul->Logon.UserName.Buffer);
            pkiul->Logon.UserName.Buffer = nullptr;
        }
        if (pkiul->Logon.Password.Buffer)
        {
            CoTaskMemFree(pkiul->Logon.Password.Buffer);
            pkiul->Logon.Password.Buffer = nullptr;
        }
    }

    return hr;
}

//
// Pack Kerberos Interactive Unlock Logon structure into a serialized buffer
//
void KerbInteractiveUnlockLogonPack(
    __in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    __deref_out_bcount(*pcb) BYTE** ppbBuffer,
    __out DWORD* pcb)
{
    DWORD cb = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    
    if (rkiulIn.Logon.LogonDomainName.Length > 0)
    {
        cb += rkiulIn.Logon.LogonDomainName.MaximumLength;
    }
    
    if (rkiulIn.Logon.UserName.Length > 0)
    {
        cb += rkiulIn.Logon.UserName.MaximumLength;
    }
    
    if (rkiulIn.Logon.Password.Length > 0)
    {
        cb += rkiulIn.Logon.Password.MaximumLength;
    }

    BYTE* pbBuffer = (BYTE*)CoTaskMemAlloc(cb);
    if (!pbBuffer)
    {
        *ppbBuffer = nullptr;
        *pcb = 0;
        return;
    }

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)pbBuffer;
    CopyMemory(pkiul, &rkiulIn, sizeof(KERB_INTERACTIVE_UNLOCK_LOGON));

    BYTE* pbStringData = pbBuffer + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);

    if (rkiulIn.Logon.LogonDomainName.Length > 0)
    {
        CopyMemory(pbStringData, rkiulIn.Logon.LogonDomainName.Buffer, rkiulIn.Logon.LogonDomainName.MaximumLength);
        pkiul->Logon.LogonDomainName.Buffer = (PWSTR)(pbStringData - pbBuffer);
        pbStringData += rkiulIn.Logon.LogonDomainName.MaximumLength;
    }

    if (rkiulIn.Logon.UserName.Length > 0)
    {
        CopyMemory(pbStringData, rkiulIn.Logon.UserName.Buffer, rkiulIn.Logon.UserName.MaximumLength);
        pkiul->Logon.UserName.Buffer = (PWSTR)(pbStringData - pbBuffer);
        pbStringData += rkiulIn.Logon.UserName.MaximumLength;
    }

    if (rkiulIn.Logon.Password.Length > 0)
    {
        CopyMemory(pbStringData, rkiulIn.Logon.Password.Buffer, rkiulIn.Logon.Password.MaximumLength);
        pkiul->Logon.Password.Buffer = (PWSTR)(pbStringData - pbBuffer);
        pbStringData += rkiulIn.Logon.Password.MaximumLength;
    }

    *ppbBuffer = pbBuffer;
    *pcb = cb;
}

BOOL IsDomainJoined()
{
    BOOL bDomainJoined = FALSE;
    LPWSTR pDomainName = nullptr;
    NETSETUP_JOIN_STATUS joinStatus;

    NET_API_STATUS status = NetGetJoinInformation(
        nullptr,
        &pDomainName,
        &joinStatus
    );

    if (status == NERR_Success)
    {
        bDomainJoined = (joinStatus == NetSetupDomainName);
        
        if (pDomainName)
        {
            NetApiBufferFree(pDomainName);
        }
    }

    return bDomainJoined;
}

HRESULT GetMachineDomain(std::wstring& domain)
{
    LPWSTR pDomainName = nullptr;
    NETSETUP_JOIN_STATUS joinStatus;

    NET_API_STATUS status = NetGetJoinInformation(
        nullptr,
        &pDomainName,
        &joinStatus
    );

    if (status == NERR_Success && joinStatus == NetSetupDomainName)
    {
        domain = pDomainName;
        NetApiBufferFree(pDomainName);
        return S_OK;
    }

    domain.clear();
    if (pDomainName)
    {
        NetApiBufferFree(pDomainName);
    }
    
    return E_FAIL;
}

HRESULT ParseUserName(
    __in LPCWSTR fullUsername,
    __out std::wstring& domain,
    __out std::wstring& username,
    __out bool& isDomainUser)
{
    if (!fullUsername || wcslen(fullUsername) == 0)
    {
        return E_INVALIDARG;
    }

    std::wstring input = fullUsername;
    
    size_t backslashPos = input.find(L'\\');
    if (backslashPos != std::wstring::npos)
    {
        domain = input.substr(0, backslashPos);
        username = input.substr(backslashPos + 1);
        
        if (domain == L".")
        {
            isDomainUser = false;
            domain = L".";
        }
        else
        {
            isDomainUser = true;
        }
        
        return S_OK;
    }
    
    size_t atPos = input.find(L'@');
    if (atPos != std::wstring::npos)
    {
        username = input.substr(0, atPos);
        domain = input.substr(atPos + 1);
        isDomainUser = true;
        return S_OK;
    }
    
    username = input;
    domain = L".";
    isDomainUser = false;
    
    return S_OK;
}

std::wstring Utf8ToWide(const std::string& utf8)
{
    if (utf8.empty())
    {
        return std::wstring();
    }

    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    if (sizeNeeded <= 0)
    {
        return std::wstring();
    }

    std::wstring result(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), &result[0], sizeNeeded);
    
    return result;
}

std::string WideToUtf8(const std::wstring& wide)
{
    if (wide.empty())
    {
        return std::string();
    }

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0)
    {
        return std::string();
    }

    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), &result[0], sizeNeeded, nullptr, nullptr);
    
    return result;
}

void LogDebugMessage(LPCWSTR format, ...)
{
    if (!format) return;

    // Prepare message
    WCHAR message[1024];
    va_list args;
    va_start(args, format);
    StringCchVPrintfW(message, ARRAYSIZE(message), format, args);
    va_end(args);

    // Get timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);

    WCHAR timestamp[100];
    StringCchPrintfW(timestamp, ARRAYSIZE(timestamp),
        L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // Write to persistent log file
    WCHAR logPath[] = L"C:\\ProgramData\\RDPQRProvider.log";

    HANDLE hFile = CreateFileW(
        logPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile != INVALID_HANDLE_VALUE)
    {
        // Add session marker on first log
        static bool sessionMarkerWritten = false;
        if (!sessionMarkerWritten)
        {
            char separator[512];
            sprintf_s(separator, sizeof(separator),
                "\r\n========================================\r\n"
                "NEW BOOT SESSION - %04d-%02d-%02d %02d:%02d:%02d\r\n"
                "========================================\r\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);

            DWORD bytesWritten;
            WriteFile(hFile, separator, (DWORD)strlen(separator), &bytesWritten, nullptr);
            sessionMarkerWritten = true;
        }

        WCHAR fullMessage[2048];
        StringCchPrintfW(fullMessage, ARRAYSIZE(fullMessage),
            L"%s%s\r\n", timestamp, message);

        char utf8Message[4096];
        WideCharToMultiByte(CP_UTF8, 0, fullMessage, -1,
            utf8Message, sizeof(utf8Message), nullptr, nullptr);

        DWORD bytesWritten;
        WriteFile(hFile, utf8Message, (DWORD)strlen(utf8Message),
            &bytesWritten, nullptr);

        CloseHandle(hFile);
    }
}

// Obfuscate sensitive strings for logging
std::wstring ObfuscateString(const std::wstring& value, size_t visibleChars)
{
    if (value.empty())
    {
        return L"<empty>";
    }
    
    if (value.length() <= visibleChars)
    {
        // If string is shorter than visible chars, show first char only
        if (value.length() == 1)
        {
            return L"*";
        }
        return value.substr(0, 1) + std::wstring(value.length() - 1, L'*');
    }
    
    // Show first few chars, mask the rest
    return value.substr(0, visibleChars) + std::wstring(L"***") + L"[" + std::to_wstring(value.length() - visibleChars) + L" chars]";
}

// Read authentication server configuration from registry
// NOTE: Credential Providers run in SYSTEM context during logon, so HKLM access works fine.
// This is safe for first user session over RDP as the CP loads before user logon.
HRESULT ReadAuthServerConfig(std::wstring& serverUrl)
{
    HKEY hKey = nullptr;
    HRESULT hr = S_OK;
    
    // Open registry key
    // Credential Providers run as SYSTEM, so HKLM access is always available
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, RDPQR_REGISTRY_CONFIG_PATH, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS)
    {
        LogDebugMessage(L"Failed to open registry key: %s, error: %d", RDPQR_REGISTRY_CONFIG_PATH, result);
        return HRESULT_FROM_WIN32(result);
    }
    
    // Read server IP
    WCHAR server[256] = {0};
    DWORD serverSize = sizeof(server);
    DWORD type = REG_SZ;
    result = RegQueryValueExW(hKey, RDPQR_REGISTRY_SERVER_KEY, nullptr, &type, (LPBYTE)server, &serverSize);
    if (result != ERROR_SUCCESS)
    {
        LogDebugMessage(L"Failed to read server from registry, error: %d", result);
        RegCloseKey(hKey);
        return HRESULT_FROM_WIN32(result);
    }
    
    // Read port
    WCHAR port[32] = {0};
    DWORD portSize = sizeof(port);
    result = RegQueryValueExW(hKey, RDPQR_REGISTRY_PORT_KEY, nullptr, &type, (LPBYTE)port, &portSize);
    if (result != ERROR_SUCCESS)
    {
        LogDebugMessage(L"Failed to read port from registry, error: %d", result);
        RegCloseKey(hKey);
        return HRESULT_FROM_WIN32(result);
    }
    
    RegCloseKey(hKey);
    
    // Build URL: https://server:port
    serverUrl = L"https://";
    serverUrl += server;
    serverUrl += L":";
    serverUrl += port;
    
    LogDebugMessage(L"Read auth server config: %s", serverUrl.c_str());
    return S_OK;
}

// Decrypt credential using Windows DPAPI (Data Protection API)
// NOTE: CRYPTPROTECT_LOCAL_MACHINE works during logon because:
// 1. It uses machine-specific encryption (not user-specific)
// 2. Credential Providers run as SYSTEM, which has access to machine keys
// 3. No user profile is required - encryption is tied to the machine, not a user account
// This is safe for first user session over RDP as it doesn't depend on user context.
HRESULT DecryptCredential(const std::vector<BYTE>& encryptedData, std::wstring& decrypted)
{
    if (encryptedData.empty())
    {
        return E_INVALIDARG;
    }
    
    DATA_BLOB dataIn, dataOut;
    dataIn.pbData = const_cast<BYTE*>(encryptedData.data());
    dataIn.cbData = (DWORD)encryptedData.size();
    dataOut.pbData = nullptr;
    dataOut.cbData = 0;
    
    // Decrypt using LocalMachine scope (works during logon)
    // CRYPTPROTECT_LOCAL_MACHINE uses machine-specific keys managed by LSA (SYSTEM)
    // The Credential Provider runs as SYSTEM and can decrypt this during logon
    // This works because it uses machine keys (stored in HKLM), not user profile keys
    BOOL result = CryptUnprotectData(&dataIn, nullptr, nullptr, nullptr, nullptr,
                                     CRYPTPROTECT_LOCAL_MACHINE, &dataOut);
    
    if (!result)
    {
        DWORD error = GetLastError();
        LogDebugMessage(L"CryptUnprotectData failed, error: %d", error);
        LogDebugMessage(L"NOTE: DPAPI with LOCAL_MACHINE should work during logon. If this fails, check:");
        LogDebugMessage(L"  1. Data was encrypted on the same machine");
        LogDebugMessage(L"  2. Machine has not been reimaged or domain changed");
        LogDebugMessage(L"  3. Credential Provider is running as SYSTEM");
        return HRESULT_FROM_WIN32(error);
    }
    
    // Convert to wide string
    int wideSize = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)dataOut.pbData, dataOut.cbData, nullptr, 0);
    if (wideSize <= 0)
    {
        LocalFree(dataOut.pbData);
        return E_FAIL;
    }
    
    decrypted.resize(wideSize);
    MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)dataOut.pbData, dataOut.cbData, &decrypted[0], wideSize);
    
    LocalFree(dataOut.pbData);
    return S_OK;
}

// Read and decrypt credential from registry
HRESULT ReadEncryptedCredential(LPCWSTR keyName, std::wstring& decrypted)
{
    HKEY hKey = nullptr;
    HRESULT hr = S_OK;
    
    // Open registry key
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, RDPQR_REGISTRY_CONFIG_PATH, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS)
    {
        LogDebugMessage(L"Failed to open registry key: %s, error: %d", RDPQR_REGISTRY_CONFIG_PATH, result);
        return HRESULT_FROM_WIN32(result);
    }
    
    // Query value size
    DWORD dataSize = 0;
    DWORD type = REG_BINARY;
    result = RegQueryValueExW(hKey, keyName, nullptr, &type, nullptr, &dataSize);
    if (result != ERROR_SUCCESS || dataSize == 0)
    {
        LogDebugMessage(L"Failed to query credential size, error: %d", result);
        RegCloseKey(hKey);
        return HRESULT_FROM_WIN32(result);
    }
    
    // Read encrypted data
    std::vector<BYTE> encryptedData(dataSize);
    result = RegQueryValueExW(hKey, keyName, nullptr, &type, encryptedData.data(), &dataSize);
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS)
    {
        LogDebugMessage(L"Failed to read credential, error: %d", result);
        return HRESULT_FROM_WIN32(result);
    }
    
    // Decrypt
    hr = DecryptCredential(encryptedData, decrypted);
    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to decrypt credential, hr: 0x%08X", hr);
        return hr;
    }
    
    return S_OK;
}

