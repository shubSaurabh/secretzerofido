//
// Helpers.cpp
// Implementation of helper functions for authentication and system utilities
//

#include "common.h"
#include <sddl.h>
#include <dsgetdc.h>
#include <lmcons.h>
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

//
// Retrieve the Negotiate authentication package ID
// The Negotiate package automatically chooses Kerberos or NTLM
// based on whether the machine is domain-joined
//
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage)
{
    HRESULT hr;
    HANDLE hLsa = nullptr;

    // Establish connection to LSA (Local Security Authority)
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        return HRESULT_FROM_NT(status);
    }

    // Lookup the Negotiate authentication package
    ULONG ulAuthPackage;
    LSA_STRING lsaAuthPackageName;
    LsaInitString(&lsaAuthPackageName, NEGOSSP_NAME_A);

    status = LsaLookupAuthenticationPackage(hLsa, &lsaAuthPackageName, &ulAuthPackage);
    hr = HRESULT_FROM_NT(status);

    if (SUCCEEDED(hr))
    {
        *pulAuthPackage = ulAuthPackage;
    }

    LsaDeregisterLogonProcess(hLsa);
    return hr;
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

