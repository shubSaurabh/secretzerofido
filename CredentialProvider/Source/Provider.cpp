//
// Provider.cpp
// Implementation of the credential provider
//

#include "Provider.h"
#include "Credential.h"
#include "ClassFactory.h"

HRESULT FieldDescriptorCoAllocCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
// Field descriptors for our credential tile
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { RDPQR_FI_LABEL, CPFT_LARGE_TEXT, L"SECURITAAS - QR Code Login" },
    { RDPQR_FI_QR_IMAGE, CPFT_TILE_IMAGE, L"QR Code" },
    { RDPQR_FI_STATUS_TEXT, CPFT_SMALL_TEXT, L"Scan QR code with your secret-0 agent" }
  
};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE }
};

CProvider::CProvider() :
    m_cRef(1),
    m_pCredential(nullptr),
    m_cpus(CPUS_INVALID),
    m_pCredProviderEvents(nullptr),
    m_upAdviseContext(0)
{
    extern void DllAddRef();

    LogDebugMessage(L"========================================");
    LogDebugMessage(L"CProvider::Constructor - Provider CREATED");
    LogDebugMessage(L"Process: Winlogon/LogonUI");
    LogDebugMessage(L"TickCount: %lu", GetTickCount());
    LogDebugMessage(L"========================================");
}
CProvider::~CProvider()
{
    LogDebugMessage(L"CProvider::Destructor - Provider being destroyed");

    if (m_pCredential != nullptr)
    {
        m_pCredential->Release();
        m_pCredential = nullptr;
    }

    if (m_pCredProviderEvents != nullptr)
    {
        m_pCredProviderEvents->Release();
        m_pCredProviderEvents = nullptr;
    }

    extern void DllRelease();
    LogDebugMessage(L"CProvider::Destructor - Complete");
}

HRESULT CProvider::QueryInterface(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;
    
    if (ppv != nullptr)
    {
        if (IID_IUnknown == riid ||
            IID_ICredentialProvider == riid)
        {
            *ppv = static_cast<ICredentialProvider*>(this);
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();
            hr = S_OK;
        }
        else
        {
            *ppv = nullptr;
            hr = E_NOINTERFACE;
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    
    return hr;
}

HRESULT CProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags)
{
    UNREFERENCED_PARAMETER(dwFlags);
    HRESULT hr;
    LogDebugMessage(L"========================================");
    LogDebugMessage(L"CProvider::SetUsageScenario CALLED");
    LogDebugMessage(L"Scenario: %d", cpus);
    LogDebugMessage(L"  (1=CPUS_LOGON, 2=CPUS_UNLOCK_WORKSTATION)");
    LogDebugMessage(L"  (3=CPUS_CHANGE_PASSWORD, 4=CPUS_CREDUI)");
    LogDebugMessage(L"Flags: 0x%08X", dwFlags);
    LogDebugMessage(L"TickCount: %lu", GetTickCount());
    m_cpus = cpus;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        if (m_pCredential == nullptr)
        {
            m_pCredential = new(std::nothrow) CCredential();
            if (m_pCredential != nullptr)
            {
                hr = m_pCredential->Initialize(cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, this);
                if (FAILED(hr))
                {
                    m_pCredential->Release();
                    m_pCredential = nullptr;
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
        else
        {
            hr = S_OK;
        }
        
        LogDebugMessage(L"CProvider::SetUsageScenario - LOGON/UNLOCK, hr=0x%08X", hr);
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        //hr = E_NOTIMPL;
        hr = S_OK;
        LogDebugMessage(L"CProvider::SetUsageScenario - Not implemented for this scenario");
        break;

    default:
        hr = E_INVALIDARG;
        LogDebugMessage(L"CProvider::SetUsageScenario - Invalid scenario");
        break;
    }

    return hr;
}

HRESULT CProvider::SetSerialization(
    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    UNREFERENCED_PARAMETER(pcpcs);
    return E_NOTIMPL;
}

HRESULT CProvider::Advise(
    __in ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext)
{
    if (m_pCredProviderEvents != nullptr)
    {
        m_pCredProviderEvents->Release();
    }
    
    m_pCredProviderEvents = pcpe;
    m_pCredProviderEvents->AddRef();
    m_upAdviseContext = upAdviseContext;
    
    LogDebugMessage(L"CProvider::Advise - Event interface registered");
    
    return S_OK;
}

HRESULT CProvider::UnAdvise()
{
    if (m_pCredProviderEvents != nullptr)
    {
        m_pCredProviderEvents->Release();
        m_pCredProviderEvents = nullptr;
    }
    
    m_upAdviseContext = 0;
    
    LogDebugMessage(L"CProvider::UnAdvise - Event interface unregistered");
    
    return S_OK;
}

HRESULT CProvider::GetFieldDescriptorCount(__out DWORD* pdwCount)
{
    *pdwCount = ARRAYSIZE(s_rgCredProvFieldDescriptors);
    return S_OK;
}

HRESULT CProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr;

    if ((dwIndex < ARRAYSIZE(s_rgCredProvFieldDescriptors)) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);

        if (SUCCEEDED(hr))
        {
            LogDebugMessage(L"CProvider::GetFieldDescriptorAt - Field %d: Type=%d, Label='%s'",
                dwIndex,
                s_rgCredProvFieldDescriptors[dwIndex].cpft,
                s_rgCredProvFieldDescriptors[dwIndex].pszLabel);
        }
    }
    else
    {
        hr = E_INVALIDARG;
        LogDebugMessage(L"CProvider::GetFieldDescriptorAt - Invalid index: %d", dwIndex);
    }

    return hr;
}

HRESULT CProvider::GetCredentialCount(
    __out DWORD* pdwCount,
    __out DWORD* pdwDefault,
    __out BOOL* pbAutoLogonWithDefault)
{
    LogDebugMessage(L"========================================");
    LogDebugMessage(L"CProvider::GetCredentialCount CALLED");
    LogDebugMessage(L"m_pCredential is: %s", (m_pCredential != nullptr) ? L"NOT NULL" : L"NULL");

    if (m_pCredential != nullptr)
    {
        *pdwCount = 1;
        *pdwDefault = 0;  // Make our tile the default (index 0)
        *pbAutoLogonWithDefault = FALSE;

        LogDebugMessage(L"Returning: Count=1, Default=0, AutoLogon=FALSE");
    }
    else
    {
        *pdwCount = 0;
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE;

        LogDebugMessage(L"⚠️ WARNING: No credential to enumerate!");
        LogDebugMessage(L"This means the tile won't be shown!");
    }

    LogDebugMessage(L"========================================");

    return S_OK;
}

HRESULT CProvider::GetCredentialAt(
    DWORD dwIndex,
    __deref_out ICredentialProviderCredential** ppcpc)
{
    LogDebugMessage(L"CProvider::GetCredentialAt - Index=%d requested", dwIndex);

    HRESULT hr;

    if ((dwIndex == 0) && (m_pCredential != nullptr))
    {
        hr = m_pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));

        if (SUCCEEDED(hr))
        {
            LogDebugMessage(L"  ✓ Returning credential tile at index 0");
        }
        else
        {
            LogDebugMessage(L"  ✗ QueryInterface failed: hr=0x%08X", hr);
        }
    }
    else
    {
        hr = E_INVALIDARG;
        LogDebugMessage(L"  ✗ Invalid: dwIndex=%d, m_pCredential=%s",
            dwIndex, (m_pCredential != nullptr) ? L"EXISTS" : L"NULL");
    }

    return hr;
}

HRESULT CProvider_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;
    CProvider* pProvider = new(std::nothrow) CProvider();
    
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}

HRESULT FieldDescriptorCoAllocCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = 
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    
    if (pcpfd)
    {
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
        
        if (SUCCEEDED(hr))
        {
            *ppcpfd = pcpfd;
        }
        else
        {
            CoTaskMemFree(pcpfd);
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}
void CProvider::TriggerCredentialsChanged()
{
    if (m_pCredProviderEvents != nullptr)
    {
        LogDebugMessage(L"CProvider::TriggerCredentialsChanged - Calling CredentialsChanged");
        HRESULT hr = m_pCredProviderEvents->CredentialsChanged(m_upAdviseContext);
        LogDebugMessage(L"  Result: hr=0x%08X", hr);
    }
    else
    {
        LogDebugMessage(L"CProvider::TriggerCredentialsChanged - No event interface available!");
    }
}