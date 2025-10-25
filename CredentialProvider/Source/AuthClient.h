//
// AuthClient.h
// HTTP client for authentication server communication and QR code generation
//

#pragma once

#include "common.h"
#include <winhttp.h>
#include <string>

class AuthClient
{
public:
    // Constructor - Initialize with auth server URL
    AuthClient(LPCWSTR serverUrl);
    
    // Destructor - Clean up resources
    ~AuthClient();

    // Create a new authentication session on the server
    // Returns session data including challenge and QR data
    HRESULT CreateSession(SessionData& sessionData);
    
    // Check session status (poll for authentication)
    // Returns S_OK if authenticated, S_FALSE if still pending, E_FAIL if expired
    HRESULT CheckSessionStatus(LPCWSTR sessionId, SessionData& sessionData);
    
    // Generate QR code bitmap from session data
    // Creates an actual QR code image that can be displayed
    HRESULT GenerateQRCodeBitmap(LPCWSTR qrData, HBITMAP* phBitmap);

private:
    std::wstring m_serverUrl;           // Authentication server URL
    ULONG_PTR m_gdiplusToken;          // GDI+ token for graphics operations
    
    // Make HTTP request (GET or POST)
    HRESULT HttpRequest(LPCWSTR method, LPCWSTR path, LPCWSTR jsonData, std::wstring& response);
    
    // Parse JSON string value (simple parser for our use case)
    HRESULT ParseJsonString(const std::wstring& json, LPCWSTR key, std::wstring& value);
};
