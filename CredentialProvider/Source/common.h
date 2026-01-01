//
// common.h
// Common definitions, structures, and constants used throughout the credential provider
//
#pragma once
// Toggle: 1 = CP imports PFX at runtime (current behavior)
//         0 = CP uses an existing cert already in LocalMachine\MY
#define RDPQR_IMPORT_PFX_AT_RUNTIME 0

// Windows Headers
#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>

// Credential Provider Headers
#include <credentialprovider.h>
#include <ntsecapi.h>
#include <lm.h>

// Additional Windows APIs
#include <wincred.h>
#include <winhttp.h>
#include <ntstatus.h>
#include <gdiplus.h>

// Security headers
#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>
#include <shlwapi.h>

// ATL/STL
#include <atlbase.h>
#include <atlstr.h>
#include <string>
#include <memory>
#include <vector>

// Crypto
#include <ncrypt.h>
#pragma comment(lib, "ncrypt.lib")
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#ifndef ERROR_NO_LOGON_SESSION
#define ERROR_NO_LOGON_SESSION 1312L  // WinError.h: "A specified logon session does not exist."
#endif
// WinHTTP / misc
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "Shlwapi.lib")

//
// GUID for our credential provider
// {8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}
//
DEFINE_GUID(CLSID_RDPQRProvider,
    0x8b5c9f21, 0x3a4d, 0x4e2f, 0x9c, 0x1b, 0x7a, 0x8e, 0x6d, 0x5f, 0x4c, 0x3b);

// =====================
// Configuration
// =====================
// Auth server URL is now read from registry (set by installer)
// Registry path: HKLM\SOFTWARE\SecurITaas\CredentialProvider
#define RDPQR_REGISTRY_CONFIG_PATH L"SOFTWARE\\SecurITaas\\CredentialProvider"
#define RDPQR_REGISTRY_SERVER_KEY L"AuthServer"
#define RDPQR_REGISTRY_PORT_KEY L"AuthPort"
#define RDPQR_REGISTRY_USERNAME_KEY L"EncryptedUsername"
#define RDPQR_REGISTRY_PASSWORD_KEY L"EncryptedPassword"

// Polling behavior
#define POLL_INTERVAL     2000      // ms
#define SESSION_TIMEOUT   120000    // ms
#define MAX_POLL_ATTEMPTS 60

// Alignment macros
#define ALIGN_LPVOID sizeof(LPVOID)
#define ROUND_UP_COUNT(Count,Pow2) \
    ( ((Count)+(Pow2)-1) & (~(((LONG)(Pow2))-1)) )

// =====================
// UI Field IDs
// =====================
enum RDPQR_FIELD_ID
{
    RDPQR_FI_LABEL = 0,        // "Securitaas QR Code Login" text
    RDPQR_FI_QR_IMAGE = 1,     // The QR code bitmap
    RDPQR_FI_STATUS_TEXT = 2,  // Status message
    RDPQR_FI_NUM_FIELDS
};

// Field state pair
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE              cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE  cpfis;
};

// =====================
// Status strings (PFX flow)
// =====================
#define RDPQR_PROVIDER_NAME   L"Logon using Securitaas"
#define RDPQR_TILE_NAME       L"Scan QR Code to Login"

#define RDPQR_STATUS_INITIALIZING  L"Creating your passwordless experience, please wait.."
#define RDPQR_STATUS_WAITING       L"Scan the QR code with your secret-0 agent"
#define RDPQR_STATUS_AUTHENTICATED L"Authenticated. Importing certificate�"
#define RDPQR_STATUS_SUCCESS       L"Certificate imported. Signing you in�"
#define RDPQR_STATUS_ERROR         L"An error occurred. Please try again, or contact your secret-0 administrator."
#define RDPQR_STATUS_TIMEOUT       L"Authentication timeout. Please try again."
#define RDPQR_STATUS_ERROR_CONNECTION L"Failed to connect to authentication server. Please check your network connection."
#define RDPQR_STATUS_ERROR_TOKEN    L"Failed to obtain authentication token. Please contact your administrator."
#define RDPQR_STATUS_ERROR_SESSION  L"Failed to create authentication session. Please try again."
#define RDPQR_STATUS_ERROR_CERT     L"Failed to retrieve certificate. Please try again."
#define RDPQR_STATUS_ERROR_PIN      L"Could not authenticate with SecurITaas server. Invalid key received."

// =====================
// KERB_SMARTCARD_CSP_INFO (not in public headers)
// =====================
typedef struct _KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;  // Must be 1 (KerbCertificateLogon)
    union {
        PVOID   ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    WCHAR bBuffer[1];   // variable length
} KERB_SMARTCARD_CSP_INFO, * PKERB_SMARTCARD_CSP_INFO;

// =====================
// Session data
// =====================
struct SessionData
{
    std::wstring sessionId;
    std::wstring challenge;
    std::wstring serverId;
    std::wstring qrData;
    DWORD        createdTime = 0;

    bool         authenticated = false;
    std::wstring username;       // may be DOMAIN\user or user@domain
    std::wstring authToken;
    std::wstring domain;
    std::wstring userPrincipal;
    bool         isDomainUser = false;

    // Certificate payload from server
    std::string  pkcs12Base64;

    // Imported cert/store (for cleanup & key discovery)
    PCCERT_CONTEXT pCertContext = nullptr;
    HCERTSTORE     hCertStore = NULL;

    // Key material for KERB_CERTIFICATE_LOGON
    std::wstring containerName;   // key container (CSP or CNG unique name)
    std::wstring providerName;    // CSP/KSP provider name
    DWORD        keySpec = 0;     // AT_* or CERT_NCRYPT_KEY_SPEC
    
    // VSC PIN from authentication response
    std::wstring vscPin;
};

// =====================
// Forward Declarations
// =====================
class CProvider;
class CCredential;
class CCommandWindow;
class AuthClient;

// Helpers provided elsewhere
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);
HRESULT RetrieveKerberosAuthPackage(ULONG* pulAuthPackage);
HRESULT GetCurrentLogonLuid(LUID* pLuid);
// common.h
HRESULT GetActiveSessionLogonLuid(LUID* pLuid);


HRESULT KerbInteractiveUnlockLogonInit(
    __in PWSTR pwzDomain,
    __in PWSTR pwzUsername,
    __in PWSTR pwzPassword,
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __out KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
);

void KerbInteractiveUnlockLogonPack(
    __in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    __deref_out_bcount(*pcb) BYTE** ppbBuffer,
    __out DWORD* pcb
);

BOOL IsDomainJoined();
HRESULT GetMachineDomain(std::wstring& domain);
HRESULT ParseUserName(
    __in LPCWSTR fullUsername,
    __out std::wstring& domain,
    __out std::wstring& username,
    __out bool& isDomainUser
);

std::wstring Utf8ToWide(const std::string& utf8);
std::string  WideToUtf8(const std::wstring& wide);

// Configuration helpers
HRESULT ReadAuthServerConfig(std::wstring& serverUrl);
HRESULT DecryptCredential(const std::vector<BYTE>& encryptedData, std::wstring& decrypted);
HRESULT ReadEncryptedCredential(LPCWSTR keyName, std::wstring& decrypted);

// Logging
void LogDebugMessage(LPCWSTR format, ...);

// Obfuscate sensitive strings for logging (shows first 4 chars, masks the rest)
std::wstring ObfuscateString(const std::wstring& value, size_t visibleChars = 4);

// =====================
// Registry keys
// =====================
#define RDPQR_REGISTRY_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"
#define CLSID_REGISTRY_PATH L"CLSID\\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"
