//
// CommandWindow.h
// Hidden window for timer-based polling of authentication server
//

#pragma once

#include "common.h"

class CCredential;

class CCommandWindow
{
public:
    CCommandWindow();
    ~CCommandWindow();
    
    HRESULT Initialize(CCredential* pCredential);
    
private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void OnTimer();
    void CheckAuthenticationStatus();
    
private:
    HWND m_hwnd;
    CCredential* m_pCredential;
    AuthClient* m_pAuthClient;
    SessionData* m_pSessionData;
    UINT_PTR m_timerId;
    DWORD m_pollCount;
};
