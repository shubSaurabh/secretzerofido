//
// AuthClient.cpp  
// Complete implementation of HTTP client and QR code generation
//

#include "AuthClient.h"
#include "common.h"
#include <sstream>
#include <iomanip>
#include <cctype>
#include <vector>

// Include QR code generation library
#include "qrcodegen/qrcodegen.hpp"

using namespace qrcodegen;

// URL encode a string for form data
std::string UrlEncode(const std::string& value)
{
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex;

    for (char c : value)
    {
        // Keep alphanumeric and other unreserved characters as-is
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded << c;
        }
        else if (c == ' ')
        {
            encoded << '+';
        }
        else
        {
            // Encode special characters
            encoded << '%' << std::setw(2) << (int)(unsigned char)c;
        }
    }

    return encoded.str();
}

AuthClient::AuthClient(LPCWSTR serverUrl) : m_serverUrl(serverUrl)
{
    // Initialize GDI+ for bitmap operations
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&m_gdiplusToken, &gdiplusStartupInput, nullptr);
    
    LogDebugMessage(L"AuthClient initialized with server: %s", serverUrl);
}

AuthClient::~AuthClient()
{
    Gdiplus::GdiplusShutdown(m_gdiplusToken);
}

HRESULT AuthClient::GetAuthToken(std::wstring& token)
{
    HRESULT hr = S_OK;
    std::wstring response;
    
    LogDebugMessage(L"Getting authentication token...");
    
    // Read encrypted credentials from registry
    // NOTE: This works during logon because:
    // - Credential Providers run as SYSTEM (has HKLM access)
    // - DPAPI with LOCAL_MACHINE uses machine keys (no user profile needed)
    std::wstring username, password;
    hr = ReadEncryptedCredential(RDPQR_REGISTRY_USERNAME_KEY, username);
    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to read username from registry: hr=0x%08X", hr);
        LogDebugMessage(L"This may indicate registry access issue or DPAPI decryption failure");
        return hr;
    }
    
    hr = ReadEncryptedCredential(RDPQR_REGISTRY_PASSWORD_KEY, password);
    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to read password from registry: hr=0x%08X", hr);
        LogDebugMessage(L"This may indicate registry access issue or DPAPI decryption failure");
        return hr;
    }
    
    // Build form data payload (username and password)
    // Convert to UTF-8 first, then URL encode
    std::string usernameUtf8 = WideToUtf8(username);
    std::string passwordUtf8 = WideToUtf8(password);
    
    // URL encode the values
    std::string usernameEncoded = UrlEncode(usernameUtf8);
    std::string passwordEncoded = UrlEncode(passwordUtf8);
    
    // Build form data string
    std::string formData = "username=" + usernameEncoded + "&password=" + passwordEncoded;
    
    LogDebugMessage(L"Form data length: %d", (int)formData.length());
    
    // POST /auth/token
    hr = HttpRequest(L"POST", L"/auth/token", nullptr, response, formData.c_str(), L"Content-Type: application/x-www-form-urlencoded");
    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to get token: hr=0x%08X", hr);
        return hr;
    }
    
    // Parse access_token from response
    hr = ParseJsonString(response, L"access_token", token);
    if (FAILED(hr) || token.empty())
    {
        LogDebugMessage(L"Failed to parse access_token from response");
        // Don't log full response as it may contain sensitive data
        LogDebugMessage(L"Response length: %d", (int)response.length());
        return E_FAIL;
    }
    
    m_authToken = token;
    LogDebugMessage(L"Token obtained successfully, length: %d", (int)token.length());
    LogDebugMessage(L"Token: %s", ObfuscateString(token, 8).c_str());
    return S_OK;
}

HRESULT AuthClient::CreateSession(SessionData& sessionData, LPCWSTR token)
{
    HRESULT hr = S_OK;
    std::wstring response;
    std::wstring authToken;

    LogDebugMessage(L"Creating new authentication session...");

    // Get token if not provided
    if (token != nullptr)
    {
        authToken = token;
        // Store it for future use
        m_authToken = authToken;
        LogDebugMessage(L"CreateSession: Using provided token");
    }
    else if (!m_authToken.empty())
    {
        authToken = m_authToken;
        LogDebugMessage(L"CreateSession: Using cached token");
    }
    else
    {
        // Get token using credentials
        hr = GetAuthToken(authToken);
        if (FAILED(hr))
        {
            LogDebugMessage(L"Failed to get auth token: hr=0x%08X", hr);
            return hr;
        }
        // m_authToken is already set in GetAuthToken
        LogDebugMessage(L"CreateSession: Obtained new token");
    }

    // Get computer name for server_id
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = ARRAYSIZE(computerName);
    GetComputerNameW(computerName, &size);

    // Build JSON payload
    std::wstring jsonPayload = L"{\"server_id\":\"";
    jsonPayload += computerName;
    jsonPayload += L"\"}";

    // POST /api/session/create with Authorization header
    std::wstring authHeader = L"Authorization: Bearer ";
    authHeader += authToken;
    
    hr = HttpRequest(L"POST", L"/api/session/create", jsonPayload.c_str(), response, nullptr, nullptr, authHeader.c_str());
    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to create session: hr=0x%08X", hr);
        return hr;
    }

    LogDebugMessage(L"RAW SERVER RESPONSE: %s", response.c_str());

    // Parse fields
    hr = ParseJsonString(response, L"session_id", sessionData.sessionId);
    if (FAILED(hr) || sessionData.sessionId.empty()) return E_FAIL;

    // Try to get qr_data; if missing, fall back to session_id
    if (FAILED(ParseJsonString(response, L"qr_data", sessionData.qrData)) || sessionData.qrData.empty())
        sessionData.qrData = sessionData.sessionId;

    // Optionally extract challenge/server_id from the qr_data JSON string
    std::wstring challenge, serverId;
    ParseJsonString(sessionData.qrData, L"challenge", challenge);
    ParseJsonString(sessionData.qrData, L"server_id", serverId);

    sessionData.challenge = challenge;
    sessionData.serverId = serverId;
    sessionData.createdTime = GetTickCount();
    sessionData.authenticated = false;

    LogDebugMessage(L"Session created: %s", sessionData.sessionId.c_str());
    return S_OK;
}


HRESULT AuthClient::CheckSessionStatus(LPCWSTR sessionId, SessionData& sessionData)
{
    std::wstring response;

    // Correct endpoint: GET /api/session/<id>
    std::wstring path = L"/api/session/";
    path += sessionId;

    // Use token if available
    std::wstring authHeader;
    if (!m_authToken.empty())
    {
        authHeader = L"Authorization: Bearer ";
        authHeader += m_authToken;
        LogDebugMessage(L"CheckSessionStatus: Using cached token, length: %d", (int)m_authToken.length());
        LogDebugMessage(L"CheckSessionStatus: Token: %s", ObfuscateString(m_authToken, 8).c_str());
    }
    else
    {
        // Token not available, try to get it
        std::wstring token;
        HRESULT hr = GetAuthToken(token);
        if (SUCCEEDED(hr) && !token.empty())
        {
            m_authToken = token;
            authHeader = L"Authorization: Bearer ";
            authHeader += m_authToken;
            LogDebugMessage(L"CheckSessionStatus: Obtained new token");
        }
        else
        {
            LogDebugMessage(L"CheckSessionStatus: WARNING - No token available for session check");
        }
    }

    HRESULT hr = HttpRequest(L"GET", path.c_str(), nullptr, response, nullptr, nullptr, 
                             authHeader.empty() ? nullptr : authHeader.c_str());
    if (FAILED(hr)) return hr;

    // Parse status only; username/auth_token aren't guaranteed in this response
    std::wstring status;
    hr = ParseJsonString(response, L"status", status);
    if (FAILED(hr)) return hr;

    if (status == L"authenticated")
    {
        sessionData.authenticated = true;
        
        // Parse all fields from authenticated response
        ParseJsonString(response, L"username", sessionData.username);
        ParseJsonString(response, L"auth_token", sessionData.authToken);
        ParseJsonString(response, L"vsc_pin", sessionData.vscPin);
        
        // Extract domain from username if present
        if (!sessionData.username.empty())
        {
            size_t backslashPos = sessionData.username.find(L'\\');
            if (backslashPos != std::wstring::npos)
            {
                sessionData.domain = sessionData.username.substr(0, backslashPos);
            }
        }
        
        LogDebugMessage(L"Session %s is authenticated", sessionId);
        return S_OK;
    }
    else if (status == L"expired")
    {
        LogDebugMessage(L"Session %s is expired", sessionId);
        return E_FAIL;
    }

    // Still pending
    return S_FALSE;
}


HRESULT AuthClient::GenerateQRCodeBitmap(LPCWSTR qrData, HBITMAP* phBitmap)
{
    if (!qrData || !phBitmap) return E_INVALIDARG;
    
    LogDebugMessage(L"Generating QR code...");
    
    try
    {
        // Convert wide string to UTF-8
        std::string utf8Data = WideToUtf8(qrData);
        
        // Generate QR code
        QrCode qr = QrCode::encodeText(utf8Data.c_str(), QrCode::Ecc::HIGH);
        
        // Calculate bitmap size
        int qrSize = qr.getSize();
        const int moduleSize = 10;  // Each QR module is 10x10 pixels
        const int borderSize = 4;   // 4 module border
        const int totalModules = qrSize + (borderSize * 2);
        const int bitmapSize = totalModules * moduleSize;
        
        // Create GDI+ bitmap
        Gdiplus::Bitmap* pBitmap = new Gdiplus::Bitmap(bitmapSize, bitmapSize, PixelFormat24bppRGB);
        if (!pBitmap) return E_OUTOFMEMORY;
        
        Gdiplus::Graphics* pGraphics = Gdiplus::Graphics::FromImage(pBitmap);
        if (!pGraphics)
        {
            delete pBitmap;
            return E_FAIL;
        }
        
        // Fill background with white
        Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255));
        pGraphics->FillRectangle(&whiteBrush, 0, 0, bitmapSize, bitmapSize);
        
        // Optimized: Pre-calculate all black module rectangles
        // This reduces function call overhead and allows better batching
        std::vector<Gdiplus::Rect> blackRects;
        // Reserve space - typically about 25-30% of modules are black
        blackRects.reserve((qrSize * qrSize * 3) / 10);
        
        for (int y = 0; y < qrSize; y++)
        {
            for (int x = 0; x < qrSize; x++)
            {
                if (qr.getModule(x, y))
                {
                    int pixelX = (x + borderSize) * moduleSize;
                    int pixelY = (y + borderSize) * moduleSize;
                    blackRects.push_back(Gdiplus::Rect(pixelX, pixelY, moduleSize, moduleSize));
                }
            }
        }
        
        // Draw all black modules in batch - more efficient than individual calls
        Gdiplus::SolidBrush blackBrush(Gdiplus::Color(0, 0, 0));
        for (const auto& rect : blackRects)
        {
            pGraphics->FillRectangle(&blackBrush, rect);
        }
        
        // Convert to HBITMAP
        Gdiplus::Color backgroundColor(255, 255, 255);
        HBITMAP hBitmap;
        Gdiplus::Status status = pBitmap->GetHBITMAP(backgroundColor, &hBitmap);
        
        delete pGraphics;
        delete pBitmap;
        
        if (status != Gdiplus::Ok)
        {
            LogDebugMessage(L"Failed to convert bitmap: status=%d", status);
            return E_FAIL;
        }
        
        *phBitmap = hBitmap;
        LogDebugMessage(L"QR code generated successfully (%dx%d pixels, %d modules)", 
                       bitmapSize, bitmapSize, (int)blackRects.size());
        
        return S_OK;
    }
    catch (const std::exception& e)
    {
        LogDebugMessage(L"Exception generating QR code: %S", e.what());
        return E_FAIL;
    }
    catch (...)
    {
        LogDebugMessage(L"Unknown exception generating QR code");
        return E_FAIL;
    }
}

HRESULT AuthClient::HttpRequest(LPCWSTR method, LPCWSTR path, LPCWSTR jsonData, std::wstring& response, LPCSTR postData, LPCWSTR contentType, LPCWSTR additionalHeaders)
{
    HRESULT hr = S_OK;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    std::string responseData;
    // Parse server URL to extract host and port
    std::wstring host;
    std::wstring headers;  // Declare early to avoid goto cleanup issues
    INTERNET_PORT port = 5000;
    
    std::wstring url = m_serverUrl;
    bool useHttps = false;
    
    // Check if URL uses HTTPS
    if (url.find(L"https://") == 0)
    {
        useHttps = true;
    }
    else if (url.find(L"http://") == 0)
    {
        // Replace http:// with https://
        url = L"https://" + url.substr(7);
        useHttps = true;
    }
    else
    {
        // No protocol specified, default to https://
        url = L"https://" + url;
        useHttps = true;
    }
    
    size_t hostStart = url.find(L"://");
    if (hostStart != std::wstring::npos)
    {
        hostStart += 3;
        size_t portStart = url.find(L":", hostStart);
        if (portStart != std::wstring::npos)
        {
            host = url.substr(hostStart, portStart - hostStart);
            size_t pathStart = url.find(L"/", portStart);
            std::wstring portStr;
            if (pathStart != std::wstring::npos)
                portStr = url.substr(portStart + 1, pathStart - portStart - 1);
            else
                portStr = url.substr(portStart + 1);
            port = (INTERNET_PORT)_wtoi(portStr.c_str());
        }
        else
        {
            size_t pathStart = url.find(L"/", hostStart);
            if (pathStart != std::wstring::npos)
                host = url.substr(hostStart, pathStart - hostStart);
            else
                host = url.substr(hostStart);
            // Default HTTPS port if not specified
            if (useHttps && port == 5000)
                port = INTERNET_DEFAULT_HTTPS_PORT;
        }
    }
    
    // Open WinHTTP session
    hSession = WinHttpOpen(L"RDP QR Auth/1.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Set timeouts (5 sec connect, 5 sec send, 5 sec receive, 10 sec total)
    WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 10000);
    
    // Connect to server
    hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Open request - use HTTPS flag if needed
    DWORD dwFlags = 0;
    if (useHttps)
    {
        dwFlags = WINHTTP_FLAG_SECURE;
    }
    
    hRequest = WinHttpOpenRequest(hConnect, method, path, nullptr,
                                   WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
    if (!hRequest)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Disable certificate verification for HTTPS
    if (useHttps)
    {
        DWORD dwOption = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwOption, sizeof(dwOption));
    }
    
    // Build and add headers using WinHttpAddRequestHeaders (more reliable)
    if (jsonData != nullptr)
    {
        // Add Content-Type header for JSON
        std::wstring contentTypeHeader = L"Content-Type: application/json";
        WinHttpAddRequestHeaders(hRequest, contentTypeHeader.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    else if (contentType != nullptr)
    {
        // Add Content-Type header from parameter
        WinHttpAddRequestHeaders(hRequest, contentType, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }
    
    if (additionalHeaders != nullptr)
    {
        // Add additional headers (like Authorization: Bearer token)
        // Obfuscate header value if it contains Authorization
        std::wstring headerStr = additionalHeaders;
        if (headerStr.find(L"Authorization:") == 0)
        {
            // Extract token part and obfuscate it
            size_t bearerPos = headerStr.find(L"Bearer ");
            if (bearerPos != std::wstring::npos)
            {
                std::wstring tokenPart = headerStr.substr(bearerPos + 7);
                std::wstring obfuscated = L"Authorization: Bearer " + ObfuscateString(tokenPart, 8);
                LogDebugMessage(L"Adding additional header: %s", obfuscated.c_str());
            }
            else
            {
                LogDebugMessage(L"Adding additional header (Authorization - obfuscated)");
            }
        }
        else
        {
            LogDebugMessage(L"Adding additional header");
        }
        
        BOOL headerResult = WinHttpAddRequestHeaders(hRequest, additionalHeaders, (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
        if (!headerResult)
        {
            DWORD error = GetLastError();
            LogDebugMessage(L"Warning: WinHttpAddRequestHeaders failed, error: %d", error);
        }
        else
        {
            LogDebugMessage(L"Additional header added successfully");
        }
    }
    
    // Send request
    BOOL bResults = FALSE;
    if (jsonData != nullptr)
    {
        // POST request with JSON body
        std::string utf8Data = WideToUtf8(jsonData);
        DWORD dataLength = (DWORD)utf8Data.size();
        
        LogDebugMessage(L"Sending POST request with JSON, data length: %d", dataLength);
        
        bResults = WinHttpSendRequest(hRequest, 
                                       WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                       (LPVOID)utf8Data.c_str(),
                                       dataLength, dataLength, 0);
    }
    else if (postData != nullptr)
    {
        // POST request with form data
        DWORD dataLength = (DWORD)strlen(postData);
        
        LogDebugMessage(L"Sending POST request with form data, data length: %d", dataLength);
        // Don't log form data content as it contains sensitive credentials
        
        bResults = WinHttpSendRequest(hRequest,
                                       WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                       (LPVOID)postData,
                                       dataLength, dataLength, 0);
    }
    else
    {
        // GET request
        LogDebugMessage(L"Sending GET request");
        
        bResults = WinHttpSendRequest(hRequest,
                                       WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }
    
    if (!bResults)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        LogDebugMessage(L"WinHttpSendRequest failed: hr=0x%08X", hr);
        goto cleanup;
    }
    
    // Receive response
    bResults = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResults)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        LogDebugMessage(L"WinHttpReceiveResponse failed: hr=0x%08X", hr);
        goto cleanup;
    }
    
    // Read response data
  
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    
    do
    {
        // Check available data
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            break;
        }
        
        if (dwSize == 0) break;
        
        // Allocate buffer
        char* pszOutBuffer = new char[dwSize + 1];
        if (!pszOutBuffer)
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        
        ZeroMemory(pszOutBuffer, dwSize + 1);
        
        // Read data
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            delete[] pszOutBuffer;
            break;
        }
        
        responseData.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;
        
    } while (dwSize > 0);
    
    // Convert response to wide string
    if (SUCCEEDED(hr) && !responseData.empty())
    {
        response = Utf8ToWide(responseData);
    }
    
cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    
    return hr;
}

HRESULT AuthClient::ParseJsonString(const std::wstring& json, LPCWSTR key, std::wstring& value)
{
    // Simple JSON parser - finds "key":"value" patterns
    std::wstring searchKey = L"\"";
    searchKey += key;
    searchKey += L"\":\"";

    size_t pos = json.find(searchKey);
    if (pos == std::wstring::npos)
    {
        // Try non-string value format: "key":value
        searchKey = L"\"";
        searchKey += key;
        searchKey += L"\":";

        pos = json.find(searchKey);
        if (pos == std::wstring::npos) return E_FAIL;

        pos += searchKey.length();
        size_t endPos = json.find_first_of(L",}", pos);
        if (endPos == std::wstring::npos) return E_FAIL;

        value = json.substr(pos, endPos - pos);

        // Trim whitespace
        value.erase(0, value.find_first_not_of(L" \t\n\r"));
        value.erase(value.find_last_not_of(L" \t\n\r") + 1);

        return S_OK;
    }

    // String value found - handle escaped quotes properly
    pos += searchKey.length();

    // *** FIX: Find the closing quote while handling escapes ***
    std::wstring extractedValue;
    bool escaped = false;

    for (size_t i = pos; i < json.length(); i++)
    {
        wchar_t c = json[i];

        if (escaped)
        {
            // Previous char was backslash, so this char is escaped
            // Add it to our value (without the backslash)
            extractedValue += c;
            escaped = false;
        }
        else if (c == L'\\')
        {
            // This is an escape character
            escaped = true;
            // Don't add the backslash to the final value
        }
        else if (c == L'"')
        {
            // Unescaped quote means end of string value
            break;
        }
        else
        {
            // Regular character
            extractedValue += c;
        }
    }

    value = extractedValue;
    return S_OK;
}
