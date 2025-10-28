//
// Credential.cpp
// Complete implementation of the credential tile
// This handles QR code display, polling, and authentication
//

#include "Credential.h"
#include "Provider.h"
#include "AuthClient.h"
#include "CommandWindow.h"

// Forward declaration - tells compiler this function exists
HRESULT FieldDescriptorCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd); 

CCredential::CCredential() :
    m_cRef(1),
    m_pProvider(nullptr),
    m_cpus(CPUS_INVALID),
    m_pCredProvCredentialEvents(nullptr),
    m_pAuthClient(nullptr),
    m_hQRCodeBitmap(nullptr),
    m_pCommandWindow(nullptr),
    m_bAuthenticationComplete(false),
    m_bPollingActive(false)
{
    extern void DllAddRef();

    ZeroMemory(&m_sessionData, sizeof(m_sessionData));
    ZeroMemory(m_rgFieldDescriptors, sizeof(m_rgFieldDescriptors));
    ZeroMemory(m_rgFieldStatePairs, sizeof(m_rgFieldStatePairs));
    ZeroMemory(m_rgFieldStrings, sizeof(m_rgFieldStrings));

    m_statusText = RDPQR_STATUS_INITIALIZING;

    LogDebugMessage(L"========================================");
    LogDebugMessage(L"CCredential::Constructor - Credential tile CREATED");
    LogDebugMessage(L"TickCount: %lu", GetTickCount());
    LogDebugMessage(L"========================================");
}


CCredential::~CCredential()
{
    StopPolling();
    for (int i = 0; i < ARRAYSIZE(m_rgFieldStrings); i++)
    {
        CoTaskMemFree(m_rgFieldStrings[i]);
        m_rgFieldStrings[i] = nullptr;
    }
    if (m_pAuthClient != nullptr)
    {
        delete m_pAuthClient;
        m_pAuthClient = nullptr;
    }
    
    if (m_hQRCodeBitmap != nullptr)
    {
        DeleteObject(m_hQRCodeBitmap);
        m_hQRCodeBitmap = nullptr;
    }
    
    if (m_pCredProvCredentialEvents != nullptr)
    {
        m_pCredProvCredentialEvents->Release();
        m_pCredProvCredentialEvents = nullptr;
    }
    
    for (DWORD i = 0; i < ARRAYSIZE(m_rgFieldDescriptors); i++)
    {
        CoTaskMemFree(m_rgFieldDescriptors[i].pszLabel);
    }
    
    extern void DllRelease();
    
    LogDebugMessage(L"CCredential::Destructor");
}

HRESULT CCredential::QueryInterface(__in REFIID riid, __deref_out void** ppv)
{
    LogDebugMessage(L"CCredential::QueryInterface - Called");

    HRESULT hr;

    if (ppv != nullptr)
    {
        if (IID_IUnknown == riid ||
            IID_ICredentialProviderCredential == riid)
        {
            *ppv = static_cast<ICredentialProviderCredential*>(this);
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();
            hr = S_OK;
            LogDebugMessage(L"  ✓ Returned ICredentialProviderCredential");
        }
        else if (IID_ICredentialProviderCredential2 == riid)  // Add this!
        {
            *ppv = static_cast<ICredentialProviderCredential2*>(this);
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();
            hr = S_OK;
            LogDebugMessage(L"  ✓ Returned ICredentialProviderCredential2");
        }
        else
        {
            *ppv = nullptr;
            hr = E_NOINTERFACE;

            WCHAR szGuid[40];
            StringFromGUID2(riid, szGuid, ARRAYSIZE(szGuid));
            LogDebugMessage(L"  ✗ E_NOINTERFACE for GUID: %s", szGuid);
        }
    }
    else
    {
        hr = E_INVALIDARG;
        LogDebugMessage(L"CCredential::QueryInterface - E_INVALIDARG (null ppv)");
    }

    return hr;
}

HRESULT CCredential::Initialize(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    const FIELD_STATE_PAIR* rgfsp,
    CProvider* pProvider)
{
    HRESULT hr = S_OK;

    m_cpus = cpus;
    m_pProvider = pProvider;

    LogDebugMessage(L"Field descriptors:");

    // Copy field descriptors from Provider
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(m_rgFieldDescriptors); i++)
    {
        m_rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &m_rgFieldDescriptors[i]);

        if (SUCCEEDED(hr))
        {
            LogDebugMessage(L"  Field %d: Type=%d, State=%d, Label='%s'",
                i,
                m_rgFieldDescriptors[i].cpft,
                m_rgFieldStatePairs[i].cpfs,
                m_rgFieldDescriptors[i].pszLabel);
        }
    }

    if (SUCCEEDED(hr))
    {
        m_pAuthClient = new(std::nothrow) AuthClient(AUTH_SERVER_URL);
        if (m_pAuthClient == nullptr)
        {
            hr = E_OUTOFMEMORY;
        }
        else
        {
            LogDebugMessage(L"AuthClient initialized with server: %s", AUTH_SERVER_URL);
        }
    }

    // Initialize field strings
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"QR Code Login", &m_rgFieldStrings[RDPQR_FI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &m_rgFieldStrings[RDPQR_FI_QR_IMAGE]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(m_statusText.c_str(), &m_rgFieldStrings[RDPQR_FI_STATUS_TEXT]);
    }
 
    if (SUCCEEDED(hr))
    {
        LogDebugMessage(L"CCredential::Initialize - SUCCESS");
        LogDebugMessage(L"Auth Server URL: %s", AUTH_SERVER_URL);
    }
    else
    {
        LogDebugMessage(L"CCredential::Initialize - FAILED: hr=0x%08X", hr);
    }

    return hr;
}

HRESULT CCredential::Advise(__in ICredentialProviderCredentialEvents* pcpce)
{
    if (m_pCredProvCredentialEvents != nullptr)
    {
        m_pCredProvCredentialEvents->Release();
    }

    m_pCredProvCredentialEvents = pcpce;
    m_pCredProvCredentialEvents->AddRef();

    return S_OK;
}

HRESULT CCredential::UnAdvise()
{
    if (m_pCredProvCredentialEvents != nullptr)
    {
        m_pCredProvCredentialEvents->Release();
        m_pCredProvCredentialEvents = nullptr;
    }
    
    return S_OK;
}

HRESULT CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
    LogDebugMessage(L"========================================");
    LogDebugMessage(L"CCredential::SetSelected - Tile SELECTED by user");
    LogDebugMessage(L"========================================");

    // Check if already authenticated - trigger auto-login
    if (m_bAuthenticationComplete && !m_sessionData.username.empty())
    {
        *pbAutoLogon = TRUE;
        LogDebugMessage(L"  ✓ Auto-login enabled - user already authenticated");
        LogDebugMessage(L"  Username: %s", m_sessionData.username.c_str());
        LogDebugMessage(L"CCredential::SetSelected - Complete (AutoLogon=TRUE)");
        LogDebugMessage(L"========================================");
        return S_OK;
    }

    // Not authenticated yet - start auth process
    *pbAutoLogon = FALSE;
    LogDebugMessage(L"Creating authentication session...");

    HRESULT hr = CreateAuthSession();

    if (SUCCEEDED(hr))
    {
        LogDebugMessage(L"  ✓ Auth session created successfully");
        LogDebugMessage(L"  Session ID: %s", m_sessionData.sessionId.c_str());
        LogDebugMessage(L"Starting polling...");

        hr = StartPolling();

        if (SUCCEEDED(hr))
        {
            LogDebugMessage(L"  ✓ Polling started successfully");
        }
        else
        {
            LogDebugMessage(L"  ✗ Failed to start polling: hr=0x%08X", hr);
        }
    }
    else
    {
        LogDebugMessage(L"  ✗ Failed to create auth session: hr=0x%08X", hr);
        LogDebugMessage(L"  Error details:");
        LogDebugMessage(L"    - Check auth server is running");
        LogDebugMessage(L"    - Check network connectivity");
        LogDebugMessage(L"    - Check AUTH_SERVER_URL in common.h");

        m_statusText = RDPQR_STATUS_ERROR;
        CoTaskMemFree(m_rgFieldStrings[RDPQR_FI_STATUS_TEXT]);
        SHStrDupW(m_statusText.c_str(), &m_rgFieldStrings[RDPQR_FI_STATUS_TEXT]);
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_rgFieldStrings[RDPQR_FI_STATUS_TEXT]);
        }
    }

    LogDebugMessage(L"CCredential::SetSelected - Complete (hr=0x%08X)", hr);
    LogDebugMessage(L"========================================");

    return S_OK;
}

HRESULT CCredential::SetDeselected()
{
    LogDebugMessage(L"CCredential::SetDeselected - Tile DESELECTED");
    LogDebugMessage(L"Stopping authentication...");

    StopPolling();

    if (m_hQRCodeBitmap != nullptr)
    {
        DeleteObject(m_hQRCodeBitmap);
        m_hQRCodeBitmap = nullptr;
        LogDebugMessage(L"  QR code bitmap deleted");
    }

    m_bAuthenticationComplete = false;
    m_statusText = RDPQR_STATUS_INITIALIZING;

    LogDebugMessage(L"CCredential::SetDeselected - Complete");

    return S_OK;
}

HRESULT CCredential::GetFieldState(
    DWORD dwFieldID,
    __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    LogDebugMessage(L"CCredential::GetFieldState - Field %d requested", dwFieldID);
    HRESULT hr;
    
    if ((dwFieldID < ARRAYSIZE(m_rgFieldDescriptors)) && pcpfs && pcpfis)
    {
        *pcpfs = m_rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = m_rgFieldStatePairs[dwFieldID].cpfis;
        LogDebugMessage(L"  Field %d: State=%d, Interactive=%d", dwFieldID, *pcpfs, *pcpfis);
        hr = S_OK;
    }
    else
    {
        LogDebugMessage(L"  ✗ Invalid field ID or null pointers");
        hr = E_INVALIDARG;
    }
    
    return hr;
}

HRESULT CCredential::GetStringValue(DWORD dwFieldID, __deref_out PWSTR* ppwsz)
{
    LogDebugMessage(L"CCredential::GetStringValue - Field %d requested", dwFieldID);

    HRESULT hr;

    // Validate field ID
    if (dwFieldID < RDPQR_FI_NUM_FIELDS && ppwsz)
    {
        // Return pre-allocated string
        hr = SHStrDupW(m_rgFieldStrings[dwFieldID], ppwsz);

        if (SUCCEEDED(hr))
        {
            LogDebugMessage(L"  ✓ Field %d: Returning '%s'", dwFieldID, m_rgFieldStrings[dwFieldID]);
        }
        else
        {
            LogDebugMessage(L"  ✗ Failed to duplicate string: hr=0x%08X", hr);
        }
    }
    else
    {
        *ppwsz = nullptr;
        hr = E_INVALIDARG;
        LogDebugMessage(L"  ✗ Invalid field ID: %d", dwFieldID);
    }

    return hr;
}

HRESULT CCredential::GetBitmapValue(DWORD dwFieldID, __out HBITMAP* phbmp)
{
    LogDebugMessage(L"CCredential::GetBitmapValue - Field %d requested", dwFieldID);

    HRESULT hr;

    if (dwFieldID == RDPQR_FI_QR_IMAGE)
    {
        *phbmp = m_hQRCodeBitmap;  // Can be NULL, that's OK
        hr = S_OK;  // Always return S_OK, even if bitmap is NULL

        if (m_hQRCodeBitmap != nullptr)
        {
            LogDebugMessage(L"  ✓ Returning QR bitmap (handle=0x%p)", m_hQRCodeBitmap);
        }
        else
        {
            LogDebugMessage(L"  ⚠️ QR bitmap not ready yet, returning NULL");
        }
    }
    else
    {
        *phbmp = nullptr;
        hr = E_INVALIDARG;
        LogDebugMessage(L"  ✗ Invalid field ID for bitmap: %d", dwFieldID);
    }

    return hr;
}

HRESULT CCredential::GetCheckboxValue(DWORD dwFieldID, __out BOOL* pbChecked, __deref_out LPWSTR* ppwszLabel)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);
    return E_NOTIMPL;
}

HRESULT CCredential::GetSubmitButtonValue(DWORD dwFieldID, __out DWORD* pdwAdjacentTo)
{
    // No submit button - authentication happens automatically
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pdwAdjacentTo);

    return E_NOTIMPL;
}

HRESULT CCredential::GetComboBoxValueCount(DWORD dwFieldID, __out DWORD* pcItems, __out DWORD* pdwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, __deref_out LPWSTR* ppwszItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

HRESULT CCredential::SetStringValue(DWORD dwFieldID, __in LPCWSTR pwz)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pwz);
    return E_NOTIMPL;
}

HRESULT CCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);
    return E_NOTIMPL;
}

HRESULT CCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CCredential::CommandLinkClicked(DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}

HRESULT CCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    __deref_out_opt LPWSTR* ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    
    HRESULT hr = E_FAIL;
    
    if (!m_bAuthenticationComplete || m_sessionData.username.empty())
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }
    
    LogDebugMessage(L"CCredential::GetSerialization - Authenticated as: %s", m_sessionData.username.c_str());
    
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));
    
    // Use auth token as "password" - this proves cryptographic authentication
    std::wstring authToken = m_sessionData.authToken;
    if (authToken.empty())
    {
        authToken = L"QR_AUTH_TOKEN_" + m_sessionData.sessionId;
    }
    
    std::wstring domain = m_sessionData.domain;
    std::wstring username;
    
    // Extract username from full username
    size_t backslashPos = m_sessionData.username.find(L'\\');
    if (backslashPos != std::wstring::npos)
    {
        username = m_sessionData.username.substr(backslashPos + 1);
    }
    else
    {
        username = m_sessionData.username;
    }
    
    hr = KerbInteractiveUnlockLogonInit(
        domain.empty() ? nullptr : const_cast<PWSTR>(domain.c_str()),
        const_cast<PWSTR>(username.c_str()),
        const_cast<PWSTR>(authToken.c_str()),
        m_cpus,
        &kiul
    );
    
    if (SUCCEEDED(hr))
    {
        hr = RetrieveNegotiateAuthPackage(&pcpcs->ulAuthenticationPackage);
        
        if (SUCCEEDED(hr))
        {
            BYTE* pbSerialization;
            DWORD cbSerialization;
            
            KerbInteractiveUnlockLogonPack(kiul, &pbSerialization, &cbSerialization);
            
            if (pbSerialization && cbSerialization)
            {
                pcpcs->rgbSerialization = pbSerialization;
                pcpcs->cbSerialization = cbSerialization;
                
                /*HRESULT hrCred = SHStrDupW(username.c_str(), &pcpcs->pwszUsername);
                if (SUCCEEDED(hrCred))
                {
                    pcpcs->clsidCredentialProvider = CLSID_RDPQRProvider;
                    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    hr = S_OK;
                }
                else
                {
                    CoTaskMemFree(pbSerialization);
                    hr = hrCred;
                }*/
                pcpcs->clsidCredentialProvider = CLSID_RDPQRProvider;
                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                hr = S_OK;
            }
            else
            {
                hr = E_FAIL;
            }
        }
        
        // Clean up KIUL structure
        if (kiul.Logon.LogonDomainName.Buffer)
            CoTaskMemFree(kiul.Logon.LogonDomainName.Buffer);
        if (kiul.Logon.UserName.Buffer)
            CoTaskMemFree(kiul.Logon.UserName.Buffer);
        if (kiul.Logon.Password.Buffer)
            CoTaskMemFree(kiul.Logon.Password.Buffer);
    }
    
    LogDebugMessage(L"CCredential::GetSerialization - Result: hr=0x%08X", hr);
    
    return hr;
}

HRESULT CCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    __deref_out_opt LPWSTR* ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    UNREFERENCED_PARAMETER(ntsSubstatus);
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
    
    LogDebugMessage(L"CCredential::ReportResult - ntsStatus=0x%08X", ntsStatus);
    
    return S_OK;
}

HRESULT CCredential::CreateAuthSession()
{
    if (m_pAuthClient == nullptr)
    {
        return E_FAIL;
    }

    LogDebugMessage(L"Creating authentication session...");

    HRESULT hr = m_pAuthClient->CreateSession(m_sessionData);

    if (SUCCEEDED(hr))
    {
        LogDebugMessage(L"Session created: %s", m_sessionData.sessionId.c_str());

        // Generate QR code
        hr = m_pAuthClient->GenerateQRCodeBitmap(m_sessionData.qrData.c_str(), &m_hQRCodeBitmap);

        if (SUCCEEDED(hr))
        {
            LogDebugMessage(L"QR code bitmap generated");

            m_statusText = RDPQR_STATUS_WAITING;

            if (m_pCredProvCredentialEvents)
            {
                // Just update fields - no Begin/End needed for Events (not Events2)
                m_pCredProvCredentialEvents->SetFieldBitmap(this, RDPQR_FI_QR_IMAGE, m_hQRCodeBitmap);
                m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());

                LogDebugMessage(L"  UI updated");
            }
        }
        else
        {
            LogDebugMessage(L"Failed to generate QR code: hr=0x%08X", hr);
        }
    }
    else
    {
        LogDebugMessage(L"Failed to create session: hr=0x%08X", hr);
    }

    return hr;
}

HRESULT CCredential::StartPolling()
{
    if (m_pCommandWindow != nullptr || m_bPollingActive)
    {
        return S_OK; // Already polling
    }
    
    LogDebugMessage(L"Starting authentication polling...");
    
    m_pCommandWindow = new(std::nothrow) CCommandWindow();
    if (m_pCommandWindow == nullptr)
    {
        return E_OUTOFMEMORY;
    }
    
    HRESULT hr = m_pCommandWindow->Initialize(this);
    if (SUCCEEDED(hr))
    {
        m_bPollingActive = true;
    }
    else
    {
        delete m_pCommandWindow;
        m_pCommandWindow = nullptr;
    }
    
    return hr;
}

void CCredential::StopPolling()
{
    if (m_pCommandWindow != nullptr)
    {
        LogDebugMessage(L"Stopping authentication polling...");
        
        delete m_pCommandWindow;
        m_pCommandWindow = nullptr;
        m_bPollingActive = false;
    }
}

void CCredential::OnAuthenticationComplete()
{
    LogDebugMessage(L"CCredential::OnAuthenticationComplete - User authenticated!");
    m_bAuthenticationComplete = true;
    m_statusText = RDPQR_STATUS_SUCCESS;
    if (m_pCredProvCredentialEvents)
    {
        // Update status text
        m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
    }
    StopPolling();

    // Trigger auto-login via provider
    if (m_pProvider)
    {
        m_pProvider->TriggerCredentialsChanged();
        LogDebugMessage(L"  ✓ Triggered auto-login via CredentialsChanged");
    }
}

HRESULT FieldDescriptorCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd)
{
    HRESULT hr;
    
    pcpfd->dwFieldID = rcpfd.dwFieldID;
    pcpfd->cpft = rcpfd.cpft;
    pcpfd->guidFieldType = rcpfd.guidFieldType;
    
    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
    }
    else
    {
        pcpfd->pszLabel = nullptr;
        hr = S_OK;
    }
    
    return hr;
}
HRESULT CCredential::GetUserSid(__deref_out LPWSTR* ppszSid)
{
    LogDebugMessage(L"CCredential::GetUserSid - Called");

    // Return NULL - we're not associated with a specific user
    // This makes us a "credential provider tile" not a "user tile"
    *ppszSid = nullptr;

    LogDebugMessage(L"  Returning NULL (not user-specific)");

    return S_OK;
}
