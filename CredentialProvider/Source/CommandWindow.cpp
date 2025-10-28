//
// CommandWindow.cpp
// Implementation of background polling window
//

#include "CommandWindow.h"
#include "Credential.h"
#include "AuthClient.h"
extern HINSTANCE g_hInst;
#define WM_CHECK_AUTH (WM_USER + 1)
#define TIMER_ID 1

CCommandWindow::CCommandWindow() :
    m_hwnd(nullptr),
    m_pCredential(nullptr),
    m_pAuthClient(nullptr),
    m_pSessionData(nullptr),
    m_timerId(0),
    m_pollCount(0)
{
}

CCommandWindow::~CCommandWindow()
{
    if (m_hwnd)
    {
        if (m_timerId)
        {
            KillTimer(m_hwnd, m_timerId);
        }
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
    
    if (m_pAuthClient)
    {
        delete m_pAuthClient;
        m_pAuthClient = nullptr;
    }
}

HRESULT CCommandWindow::Initialize(CCredential* pCredential)
{
    if (!pCredential)
    {
        return E_INVALIDARG;
    }
    
    m_pCredential = pCredential;
    
    // Create hidden window for message processing
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = L"RDPQRCommandWindow";
    
    RegisterClassW(&wc);
    
    m_hwnd = CreateWindowExW(
        0,
        L"RDPQRCommandWindow",
        L"",
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,
        nullptr,
        g_hInst,
        this
    );
    
    if (!m_hwnd)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Initialize auth client for polling
    m_pAuthClient = new(std::nothrow) AuthClient(AUTH_SERVER_URL);
    if (!m_pAuthClient)
    {
        return E_OUTOFMEMORY;
    }
    
    // Start polling timer
    m_timerId = SetTimer(m_hwnd, TIMER_ID, POLL_INTERVAL, nullptr);
    if (!m_timerId)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    LogDebugMessage(L"CommandWindow initialized - polling every %d ms", POLL_INTERVAL);
    
    return S_OK;
}

LRESULT CALLBACK CCommandWindow::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    CCommandWindow* pThis = nullptr;
    
    if (uMsg == WM_CREATE)
    {
        CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        pThis = reinterpret_cast<CCommandWindow*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
    }
    else
    {
        pThis = reinterpret_cast<CCommandWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (pThis)
    {
        switch (uMsg)
        {
        case WM_TIMER:
            if (wParam == TIMER_ID)
            {
                pThis->OnTimer();
                return 0;
            }
            break;
            
        case WM_CHECK_AUTH:
            pThis->CheckAuthenticationStatus();
            return 0;
        }
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void CCommandWindow::OnTimer()
{
    PostMessage(m_hwnd, WM_CHECK_AUTH, 0, 0);
}



void CCommandWindow::CheckAuthenticationStatus()
{
    if (!m_pCredential || !m_pAuthClient)
    {
        return;
    }

    m_pollCount++;

    // Check for timeout
    if (m_pollCount > MAX_POLL_ATTEMPTS)
    {
        LogDebugMessage(L"Authentication timeout - stopping poll");
        if (m_timerId)
        {
            KillTimer(m_hwnd, m_timerId);
            m_timerId = 0;
        }
        return;
    }

    LogDebugMessage(L"Polling authentication status (attempt %d/%d)", m_pollCount, MAX_POLL_ATTEMPTS);

    // *** ADD THIS: Get session data from credential ***
    SessionData& sessionData = m_pCredential->GetSessionData();

    if (sessionData.sessionId.empty())
    {
        LogDebugMessage(L"  No session ID available yet");
        return;
    }

    // Build status URL: /api/session/status/{session_id}
    std::wstring statusUrl = L"/api/session/status/";
    statusUrl += sessionData.sessionId;

    // Make HTTP GET request
    std::wstring response;
    HRESULT hr = m_pAuthClient->HttpRequest(L"GET", statusUrl.c_str(), nullptr, response);

    if (FAILED(hr))
    {
        LogDebugMessage(L"  Failed to check status: hr=0x%08X", hr);
        return;
    }

    LogDebugMessage(L"  Status response: %s", response.c_str());

    // Parse status from JSON
    std::wstring status;
    hr = m_pAuthClient->ParseJsonString(response, L"status", status);

    if (FAILED(hr))
    {
        LogDebugMessage(L"  Failed to parse status");
        return;
    }

    LogDebugMessage(L"  Status: %s", status.c_str());

    // Check if authenticated
    if (status == L"authenticated")
    {
        LogDebugMessage(L"  ✅ Session authenticated!");

        // Extract username and auth token
        std::wstring username, authToken;

        hr = m_pAuthClient->ParseJsonString(response, L"username", username);
        if (SUCCEEDED(hr))
        {
            sessionData.username = username;
            LogDebugMessage(L"  Username: %s", username.c_str());

            // Extract domain from username if present
            size_t backslashPos = username.find(L'\\');
            if (backslashPos != std::wstring::npos)
            {
                sessionData.domain = username.substr(0, backslashPos);
                LogDebugMessage(L"  Domain: %s", sessionData.domain.c_str());
            }
        }

        hr = m_pAuthClient->ParseJsonString(response, L"auth_token", authToken);
        if (SUCCEEDED(hr))
        {
            sessionData.authToken = authToken;
            LogDebugMessage(L"  Auth token received");
        }

        // Stop polling
        if (m_timerId)
        {
            KillTimer(m_hwnd, m_timerId);
            m_timerId = 0;
        }

        // Notify credential that authentication is complete
        m_pCredential->OnAuthenticationComplete();

        LogDebugMessage(L"  ✅ Authentication complete - notified credential");
    }
    else if (status == L"expired")
    {
        LogDebugMessage(L"  ⏱️ Session expired");

        // Stop polling
        if (m_timerId)
        {
            KillTimer(m_hwnd, m_timerId);
            m_timerId = 0;
        }
    }
    // else status is "pending" - keep polling
}

