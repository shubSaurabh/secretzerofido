//
// common.h
// Common definitions, structures, and constants used throughout the credential provider
//

#pragma once

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

#pragma comment(lib, "credui.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "Shlwapi.lib")
//
// GUID for our credential provider
// This uniquely identifies our provider in the Windows registry
// Generated using guidgen.exe
// {8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}
//
DEFINE_GUID(CLSID_RDPQRProvider,
    0x8b5c9f21, 0x3a4d, 0x4e2f, 0x9c, 0x1b, 0x7a, 0x8e, 0x6d, 0x5f, 0x4c, 0x3b);
//EXTERN_C const GUID CLSID_RDPQRProvider;
//
// 
// // Status text messages
#define RDPQR_STATUS_INITIALIZING       L"Initializing..."
#define RDPQR_STATUS_GENERATING_QR      L"Generating QR code..."
#define RDPQR_STATUS_SCAN_QR            L"SECURITAAS - Scan this QR code with your secret-0 agent"
#define RDPQR_STATUS_WAITING_AUTH       L"Waiting for authentication..."
#define RDPQR_STATUS_AUTHENTICATED      L"Authentication successful with secret-0!"
#define RDPQR_STATUS_ERROR              L"Authentication failed. Please try again."
#define RDPQR_STATUS_TIMEOUT            L"Authentication timed out."
#define RDPQR_STATUS_CONNECTION_ERROR   L"Cannot connect to authentication server."
// Configuration Constants
// IMPORTANT: Change AUTH_SERVER_URL to your Ubuntu server's IP address
//
#define AUTH_SERVER_URL L"http://192.168.126.133:5000"  // *** CHANGE THIS ***
#define POLL_INTERVAL 2000          // Poll authentication server every 2 seconds
#define SESSION_TIMEOUT 120000      // Session expires after 2 minutes (120 seconds)
#define MAX_POLL_ATTEMPTS 60        // Maximum number of poll attempts (2 min / 2 sec)

//
// Field IDs for the credential tile UI
// These represent the visual elements shown to the user
//
enum RDPQR_FIELD_ID
{
    RDPQR_FI_LABEL = 0,          // "QR Code Login" text
    RDPQR_FI_QR_IMAGE = 1,       // The actual QR code bitmap
    RDPQR_FI_STATUS_TEXT = 2, // Status message below QR
    RDPQR_FI_NUM_FIELDS          // Total count (will be 3)
};

//
// Field State Pair
// Defines the state and interactivity of each field
//
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;              // Field state (hidden/displayed)
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis; // Interactive state (readonly/editable)
};

//
// Session Data Structure
// Contains all information about an authentication session
//
struct SessionData
{
    std::wstring sessionId;        // Unique session identifier from auth server
    std::wstring challenge;        // Challenge string to be signed by client
    std::wstring serverId;         // Identifier of this RDP server
    std::wstring qrData;           // JSON data encoded in QR code
    DWORD createdTime;             // Tick count when session was created
    bool authenticated;            // Whether user has been authenticated
    std::wstring username;         // Authenticated username (DOMAIN\\user or .\\user)
    std::wstring authToken;        // Authentication token from server
    std::wstring domain;           // User's domain (or "." for local)
    std::wstring userPrincipal;    // User principal name for domain users
    bool isDomainUser;             // True if domain account, false if local
};

//
// Forward Declarations
//
class CProvider;
class CCredential;
class CCommandWindow;
class AuthClient;

//
// Helper Functions (implemented in Helpers.cpp)
//

// Retrieve the Negotiate authentication package
// This is used for both domain and local authentication
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);

// Initialize Kerberos Interactive Unlock Logon structure
// Used for domain authentication
HRESULT KerbInteractiveUnlockLogonInit(
    __in PWSTR pwzDomain,
    __in PWSTR pwzUsername,
    __in PWSTR pwzPassword,
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __out KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
);

// Pack Kerberos logon data into serialized buffer
// Required format for passing credentials to LSA
void KerbInteractiveUnlockLogonPack(
    __in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    __deref_out_bcount(*pcb) BYTE** ppbBuffer,
    __out DWORD* pcb
);

// Check if this machine is joined to a domain
// Returns true if domain-joined, false if workgroup
BOOL IsDomainJoined();

// Get the name of the domain this machine is joined to
// Returns empty string if not domain-joined
HRESULT GetMachineDomain(std::wstring& domain);

// Parse a username string to extract domain and username components
// Handles formats: DOMAIN\user, user@domain.com, .\user, user
HRESULT ParseUserName(
    __in LPCWSTR fullUsername,
    __out std::wstring& domain,
    __out std::wstring& username,
    __out bool& isDomainUser
);

// Convert UTF-8 string to wide string (UTF-16)
std::wstring Utf8ToWide(const std::string& utf8);

// Convert wide string (UTF-16) to UTF-8 string
std::string WideToUtf8(const std::wstring& wide);

// Log debug message to file (for troubleshooting)
// Logs are written to C:\Windows\Temp\RDPQRProvider.log
void LogDebugMessage(LPCWSTR format, ...);

//
// Registry Keys for Credential Provider Registration
//
#define RDPQR_REGISTRY_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"
#define CLSID_REGISTRY_PATH L"CLSID\\{8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}"

//
// String Constants for UI
//
#define RDPQR_PROVIDER_NAME L"SECURITAAS - QR Code Authentication"
#define RDPQR_TILE_NAME L"Scan QR Code to Login"
#define RDPQR_STATUS_INITIALIZING L"Initializing authentication..."
#define RDPQR_STATUS_WAITING L"Scan the QR code with your secret-0 agent"
#define RDPQR_STATUS_AUTHENTICATING L"Authenticating..."
#define RDPQR_STATUS_SUCCESS L"Authentication successful with secret-0! Press enter to log in."
#define RDPQR_STATUS_FAILED L"Authentication failed. Please try again, or contact your secret-0 administrator."
#define RDPQR_STATUS_TIMEOUT L"Authentication timeout. Please try again."
#define RDPQR_STATUS_ERROR L"An error occurred. Please try again, or contact your secret-0 administrator."

