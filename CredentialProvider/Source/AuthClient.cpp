//
// AuthClient.cpp  
// Complete implementation of HTTP client and QR code generation
//

#include "AuthClient.h"
#include "common.h"
#include <sstream>

// Include QR code generation library
#include "qrcodegen/qrcodegen.hpp"

using namespace qrcodegen;

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

HRESULT AuthClient::CreateSession(SessionData& sessionData)
{
    HRESULT hr = S_OK;
    std::wstring response;
    
    LogDebugMessage(L"Creating new authentication session...");
    
    // Get computer name for server_id
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = ARRAYSIZE(computerName);
    GetComputerNameW(computerName, &size);
    
    // Build JSON payload
    std::wstring jsonPayload = L"{\"server_id\":\"";
    jsonPayload += computerName;
    jsonPayload += L"\"}";
    
    // Make HTTP POST request to create session
    hr = HttpRequest(L"POST", L"/api/session/create", jsonPayload.c_str(), response);
    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to create session: hr=0x%08X", hr);
        return hr;
    }
    
    // Parse response JSON
    hr = ParseJsonString(response, L"session_id", sessionData.sessionId);
    if (FAILED(hr)) return hr;
    
    hr = ParseJsonString(response, L"qr_data", sessionData.qrData);
    if (FAILED(hr)) return hr;
    
    // Extract challenge and server_id from qr_data
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
    
    // Build request path
    std::wstring path = L"/api/session/status/";
    path += sessionId;
    
    // Make HTTP GET request
    HRESULT hr = HttpRequest(L"GET", path.c_str(), nullptr, response);
    if (FAILED(hr)) return hr;
    
    // Parse status
    std::wstring status;
    hr = ParseJsonString(response, L"status", status);
    if (FAILED(hr)) return hr;
    
    if (status == L"authenticated")
    {
        sessionData.authenticated = true;
        ParseJsonString(response, L"username", sessionData.username);
        ParseJsonString(response, L"auth_token", sessionData.authToken);
        
        // Parse username into domain and user components
        std::wstring domain, username;
        bool isDomainUser;
        ParseUserName(sessionData.username.c_str(), domain, username, isDomainUser);
        
        sessionData.domain = domain;
        sessionData.isDomainUser = isDomainUser;
        
        LogDebugMessage(L"Authenticated: %s", sessionData.username.c_str());
        return S_OK;
    }
    else if (status == L"expired")
    {
        LogDebugMessage(L"Session expired");
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
        const int moduleSize = 10;  // Each QR module is 8x8 pixels
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
        
        // Draw QR code modules
        Gdiplus::SolidBrush blackBrush(Gdiplus::Color(0, 0, 0));
        
        for (int y = 0; y < qrSize; y++)
        {
            for (int x = 0; x < qrSize; x++)
            {
                if (qr.getModule(x, y))
                {
                    int pixelX = (x + borderSize) * moduleSize;
                    int pixelY = (y + borderSize) * moduleSize;
                    pGraphics->FillRectangle(&blackBrush, pixelX, pixelY, moduleSize, moduleSize);
                }
            }
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
        LogDebugMessage(L"QR code generated successfully (%dx%d pixels)", bitmapSize, bitmapSize);
        
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

HRESULT AuthClient::HttpRequest(LPCWSTR method, LPCWSTR path, LPCWSTR jsonData, std::wstring& response)
{
    HRESULT hr = S_OK;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    std::string responseData;
    // Parse server URL to extract host and port
    std::wstring host;
    INTERNET_PORT port = 5000;
    
    std::wstring url = m_serverUrl;
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
    
    // Open request
    hRequest = WinHttpOpenRequest(hConnect, method, path, nullptr,
                                   WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto cleanup;
    }
    
    // Send request
    BOOL bResults = FALSE;
    if (jsonData != nullptr)
    {
        // POST request with JSON body
        LPCWSTR headers = L"Content-Type: application/json\r\n";
        std::string utf8Data = WideToUtf8(jsonData);
        DWORD dataLength = (DWORD)utf8Data.size();
        
        bResults = WinHttpSendRequest(hRequest, headers, (DWORD)-1,
                                       (LPVOID)utf8Data.c_str(),
                                       dataLength, dataLength, 0);
    }
    else
    {
        // GET request
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
