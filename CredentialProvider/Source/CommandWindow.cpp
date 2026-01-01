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
    
    // Initialize auth client for polling - read config from registry
    std::wstring serverUrl;
    HRESULT hr = ReadAuthServerConfig(serverUrl);
    if (FAILED(hr))
    {
        return hr;
    }
    
    m_pAuthClient = new(std::nothrow) AuthClient(serverUrl.c_str());
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

    // Use CheckSessionStatus which handles token automatically
    HRESULT hr = m_pAuthClient->CheckSessionStatus(sessionData.sessionId.c_str(), sessionData);

    if (FAILED(hr))
    {
        if (hr == S_FALSE)
        {
            // Still pending, continue polling
            return;
        }
        LogDebugMessage(L"  Failed to check status: hr=0x%08X", hr);
        return;
    }

    // Check if authenticated (hr == S_OK means authenticated)
    if (sessionData.authenticated)
    {
        LogDebugMessage(L"  ✅ Session authenticated!");
        
        if (!sessionData.username.empty())
        {
            LogDebugMessage(L"  Username: %s", ObfuscateString(sessionData.username, 6).c_str());
        }
        
        if (!sessionData.domain.empty())
        {
            LogDebugMessage(L"  Domain: %s", sessionData.domain.c_str());
        }
        
        if (!sessionData.authToken.empty())
        {
            LogDebugMessage(L"  Auth token received, length: %d", (int)sessionData.authToken.length());
            LogDebugMessage(L"  Auth token: %s", ObfuscateString(sessionData.authToken, 8).c_str());
        }
        
        if (!sessionData.vscPin.empty())
        {
            LogDebugMessage(L"  VSC PIN received (length: %d)", (int)sessionData.vscPin.length());
        }
        else
        {
            LogDebugMessage(L"  ERROR: vsc_pin not found in response - authentication will fail");
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
    else if (hr == E_FAIL)
    {
        // Session expired or failed
        LogDebugMessage(L"  ⏱️ Session expired or failed");

        // Stop polling
        if (m_timerId)
        {
            KillTimer(m_hwnd, m_timerId);
            m_timerId = 0;
        }
    }
    // else status is "pending" - keep polling
}