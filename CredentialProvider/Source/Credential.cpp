//
// Credential.cpp
// Complete implementation of the credential tile
// This handles QR code display, polling, and authentication
//

#include "Credential.h"
#include "Provider.h"
#include "AuthClient.h"
#include "CommandWindow.h"
#include <algorithm>
#include <aclapi.h>
#include <sddl.h>
#include <ncrypt.h>
#pragma comment(lib, "ncrypt.lib")
// Forward declaration - tells compiler this function exists
HRESULT FieldDescriptorCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd);

// VSC PIN is now read from authentication response

static bool CertHasUpnEqualTo(PCCERT_CONTEXT pCert, const std::wstring& upnWanted)
{
    PCERT_EXTENSION pSan = CertFindExtension(
        szOID_SUBJECT_ALT_NAME2,
        pCert->pCertInfo->cExtension,
        pCert->pCertInfo->rgExtension);
    if (!pSan) return false;

    DWORD cbSan = 0;
    if (!CryptDecodeObjectEx(
        X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2,
        pSan->Value.pbData, pSan->Value.cbData,
        CRYPT_DECODE_ALLOC_FLAG, nullptr, &cbSan, &cbSan))
        return false;

    CERT_ALT_NAME_INFO* pAlt = (CERT_ALT_NAME_INFO*)LocalAlloc(LPTR, cbSan);
    if (!pAlt) return false;

    bool match = false;

    if (CryptDecodeObjectEx(
        X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2,
        pSan->Value.pbData, pSan->Value.cbData,
        0, nullptr, pAlt, &cbSan))
    {
        for (DWORD i = 0; i < pAlt->cAltEntry && !match; ++i)
        {
            if (pAlt->rgAltEntry[i].dwAltNameChoice != CERT_ALT_NAME_OTHER_NAME)
                continue;

            PCERT_OTHER_NAME on = pAlt->rgAltEntry[i].pOtherName;
            if (!on || strcmp(on->pszObjId, szOID_NT_PRINCIPAL_NAME) != 0)
                continue;

            CERT_NAME_VALUE* pUPN = nullptr;
            DWORD cbUPN = 0;
            if (CryptDecodeObjectEx(
                X509_ASN_ENCODING, X509_UNICODE_ANY_STRING,
                on->Value.pbData, on->Value.cbData,
                CRYPT_DECODE_ALLOC_FLAG, nullptr,
                &pUPN, &cbUPN))
            {
                std::wstring certUPN((WCHAR*)pUPN->Value.pbData);
                LocalFree(pUPN);

                if (_wcsicmp(certUPN.c_str(), upnWanted.c_str()) == 0)
                    match = true;
            }
        }
    }

    LocalFree(pAlt);
    return match;
}

// Enumerate smart card keys from the Smart Card KSP and find one whose
// certificate has UPN == upnWanted. This is the “VSC over RDP” path.
static HRESULT FindSmartCardKeyByUPN(
    const std::wstring& upnWanted,
    std::wstring& outContainer,
    std::wstring& outProvider,
    DWORD& outKeySpec,
    PCCERT_CONTEXT* ppCertCtx)
{
    *ppCertCtx = nullptr;
    outContainer.clear();
    outProvider.clear();
    outKeySpec = 0;

    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS ss = NCryptOpenStorageProvider(
        &hProv,
        L"Microsoft Smart Card Key Storage Provider",
        0);
    if (ss != ERROR_SUCCESS)
    {
        LogDebugMessage(L"NCryptOpenStorageProvider(Smart Card) failed: 0x%08X", ss);
        return HRESULT_FROM_WIN32(ss);
    }

    NCryptKeyName* pKeyName = nullptr;   // <== FIXED TYPE
    PVOID          pEnumState = nullptr;
    HRESULT        hrMatch = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    while ((ss = NCryptEnumKeys(
        hProv,
        nullptr,          // all containers
        &pKeyName,
        &pEnumState,
        0)) == ERROR_SUCCESS)
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        ss = NCryptOpenKey(
            hProv,
            &hKey,
            pKeyName->pszName,
            pKeyName->dwLegacyKeySpec,
            0);
        if (ss != ERROR_SUCCESS)
        {
            LogDebugMessage(L"NCryptOpenKey('%s') failed: 0x%08X",
                pKeyName->pszName, ss);
            NCryptFreeBuffer(pKeyName);
            pKeyName = nullptr;
            continue;
        }

        // Extract certificate bytes from the key
        DWORD cbCert = 0;
        ss = NCryptGetProperty(
            hKey,
            NCRYPT_CERTIFICATE_PROPERTY,
            nullptr, 0, &cbCert, 0);

        if (ss == ERROR_SUCCESS && cbCert > 0)
        {
            std::vector<BYTE> certBuf(cbCert);
            ss = NCryptGetProperty(
                hKey,
                NCRYPT_CERTIFICATE_PROPERTY,
                certBuf.data(), cbCert, &cbCert, 0);

            if (ss == ERROR_SUCCESS)
            {
                PCCERT_CONTEXT pCtx = CertCreateCertificateContext(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    certBuf.data(), cbCert);

                if (pCtx)
                {
                    if (CertHasUpnEqualTo(pCtx, upnWanted))
                    {
                        LogDebugMessage(L"✅ Found smartcard key for UPN '%s'", upnWanted.c_str());

                        outContainer = pKeyName->pszName;
                        outProvider = L"Microsoft Smart Card Key Storage Provider";
                        outKeySpec = CERT_NCRYPT_KEY_SPEC;

                        *ppCertCtx = pCtx;
                        hrMatch = S_OK;

                        NCryptFreeObject(hKey);
                        NCryptFreeBuffer(pKeyName);
                        pKeyName = nullptr;
                        break;
                    }

                    CertFreeCertificateContext(pCtx);
                }
            }
        }

        NCryptFreeObject(hKey);
        NCryptFreeBuffer(pKeyName);
        pKeyName = nullptr;
    }

    if (pKeyName)
        NCryptFreeBuffer(pKeyName);
    if (pEnumState)
        NCryptFreeBuffer(pEnumState);
    if (hProv)
        NCryptFreeObject(hProv);

    if (FAILED(hrMatch))
        LogDebugMessage(L"FindSmartCardKeyByUPN: no smart card key found for UPN '%s'", upnWanted.c_str());

    return hrMatch;
}


// Find a cert in LocalMachine\MY that has a private key and UPN == upn.
// Returns a duplicated cert context and an open store handle you should keep
// (so the cert remains valid); caller must CertCloseStore(hStore, 0) in cleanup.
static HRESULT FindExistingCertInMachineMyByUPN(
    const std::wstring& upnWanted,
    _Outptr_ PCCERT_CONTEXT* ppCtx,
    _Out_    HCERTSTORE* phStore)
{
    *ppCtx = nullptr;
    *phStore = nullptr;

    HCERTSTORE hMy = CertOpenStore(
        CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY)nullptr,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");
    if (!hMy) return HRESULT_FROM_WIN32(GetLastError());

    // scan the store
    PCCERT_CONTEXT it = nullptr;
    while ((it = CertEnumCertificatesInStore(hMy, it)))
    {
        // must have a private key
        DWORD cb = 0;
        if (!(CertGetCertificateContextProperty(it, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cb) ||
            CertGetCertificateContextProperty(it, CERT_KEY_CONTEXT_PROP_ID, nullptr, &cb)))
        {
            continue;
        }

        // look for UPN in SAN
        PCERT_EXTENSION pSan = CertFindExtension(
            szOID_SUBJECT_ALT_NAME2,
            it->pCertInfo->cExtension,
            it->pCertInfo->rgExtension);
        if (!pSan) continue;

        DWORD cbSan = 0;
        if (!CryptDecodeObjectEx(
            X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2,
            pSan->Value.pbData, pSan->Value.cbData,
            CRYPT_DECODE_ALLOC_FLAG, nullptr, &cbSan, &cbSan))
            continue;

        CERT_ALT_NAME_INFO* pAlt = (CERT_ALT_NAME_INFO*)LocalAlloc(LPTR, cbSan);
        if (!pAlt) continue;

        BOOL match = FALSE;
        if (CryptDecodeObjectEx(
            X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2,
            pSan->Value.pbData, pSan->Value.cbData,
            0, nullptr, pAlt, &cbSan))
        {
            for (DWORD i = 0; i < pAlt->cAltEntry && !match; ++i)
            {
                if (pAlt->rgAltEntry[i].dwAltNameChoice != CERT_ALT_NAME_OTHER_NAME)
                    continue;

                PCERT_OTHER_NAME on = pAlt->rgAltEntry[i].pOtherName;
                if (!on || strcmp(on->pszObjId, szOID_NT_PRINCIPAL_NAME) != 0)
                    continue;

                DWORD cbUPN = 0;
                CERT_NAME_VALUE* pUPN = nullptr;
                if (CryptDecodeObjectEx(
                    X509_ASN_ENCODING, X509_UNICODE_ANY_STRING,
                    on->Value.pbData, on->Value.cbData,
                    CRYPT_DECODE_ALLOC_FLAG, nullptr, &pUPN, &cbUPN))
                {
                    std::wstring certUPN((WCHAR*)pUPN->Value.pbData);
                    LocalFree(pUPN);

                    if (_wcsicmp(certUPN.c_str(), upnWanted.c_str()) == 0)
                        match = TRUE;
                }
            }
        }
        LocalFree(pAlt);

        if (match)
        {
            *phStore = hMy; // keep store open while you hold the context
            *ppCtx = CertDuplicateCertificateContext(it);
            return S_OK;
        }
    }

    CertCloseStore(hMy, 0);
    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

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

IFACEMETHODIMP CCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    UNREFERENCED_PARAMETER(ntsSubstatus);
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

    LogDebugMessage(L"CCredential::ReportResult - ntsStatus=0x%08X", ntsStatus);
    return S_OK;
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
    CleanupCertificate();
   
    extern void DllRelease();

    LogDebugMessage(L"CCredential::Destructor");
}






IFACEMETHODIMP CCredential::QueryInterface(__in REFIID riid, __deref_out void** ppv)
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

IFACEMETHODIMP CCredential::Initialize(
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
        // Read server configuration from registry
        std::wstring serverUrl;
        hr = ReadAuthServerConfig(serverUrl);
        if (FAILED(hr))
        {
            LogDebugMessage(L"Failed to read auth server config from registry: hr=0x%08X", hr);
            m_statusText = RDPQR_STATUS_ERROR_CONNECTION;
            return hr;
        }
        
        m_pAuthClient = new(std::nothrow) AuthClient(serverUrl.c_str());
        if (m_pAuthClient == nullptr)
        {
            hr = E_OUTOFMEMORY;
        }
        else
        {
            LogDebugMessage(L"AuthClient initialized with server: %s", serverUrl.c_str());
        }
    }

    // Initialize field strings
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Securitaas QR Code Login", &m_rgFieldStrings[RDPQR_FI_LABEL]);
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
    }
    else
    {
        LogDebugMessage(L"CCredential::Initialize - FAILED: hr=0x%08X", hr);
    }

    return hr;
}

IFACEMETHODIMP CCredential::Advise(__in ICredentialProviderCredentialEvents* pcpce)
{
    if (m_pCredProvCredentialEvents != nullptr)
    {
        m_pCredProvCredentialEvents->Release();
    }

    m_pCredProvCredentialEvents = pcpce;
    m_pCredProvCredentialEvents->AddRef();

    return S_OK;
}

IFACEMETHODIMP CCredential::UnAdvise()
{
    if (m_pCredProvCredentialEvents != nullptr)
    {
        m_pCredProvCredentialEvents->Release();
        m_pCredProvCredentialEvents = nullptr;
    }

    return S_OK;
}

IFACEMETHODIMP CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
    LogDebugMessage(L"========================================");
    LogDebugMessage(L"CCredential::SetSelected - Tile SELECTED by user");
    LogDebugMessage(L"========================================");

    // Check if already authenticated - trigger auto-login
    if (m_bAuthenticationComplete && !m_sessionData.username.empty())
    {
        *pbAutoLogon = TRUE;
        LogDebugMessage(L"  ✓ Auto-login enabled - user already authenticated");
        LogDebugMessage(L"  Username: %s", ObfuscateString(m_sessionData.username, 6).c_str());
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
        LogDebugMessage(L"    - Check registry configuration");

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

IFACEMETHODIMP CCredential::SetDeselected()
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

IFACEMETHODIMP CCredential::GetFieldState(
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

IFACEMETHODIMP CCredential::GetStringValue(DWORD dwFieldID, __deref_out PWSTR* ppwsz)
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

IFACEMETHODIMP CCredential::GetBitmapValue(DWORD dwFieldID, __out HBITMAP* phbmp)
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

IFACEMETHODIMP CCredential::GetCheckboxValue(DWORD dwFieldID, __out BOOL* pbChecked, __deref_out LPWSTR* ppwszLabel)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredential::GetSubmitButtonValue(DWORD dwFieldID, __out DWORD* pdwAdjacentTo)
{
    // No submit button - authentication happens automatically
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pdwAdjacentTo);

    return E_NOTIMPL;
}

IFACEMETHODIMP CCredential::GetComboBoxValueCount(DWORD dwFieldID, __out DWORD* pcItems, __out DWORD* pdwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, __deref_out LPWSTR* ppwszItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredential::SetStringValue(DWORD dwFieldID, __in LPCWSTR pwz)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pwz);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

IFACEMETHODIMP CCredential::CommandLinkClicked(DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}

/*HRESULT CCredential::GetSerialization(
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

    LogDebugMessage(L"CCredential::GetSerialization - Authenticated as: %s", ObfuscateString(m_sessionData.username, 6).c_str());

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
                }
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
}*/

IFACEMETHODIMP CCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    __deref_out_opt LPWSTR* ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    LogDebugMessage(L"=== GetSerialization Called ===");

    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (!m_bAuthenticationComplete)
    {
        LogDebugMessage(L"Not authenticated yet");
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return E_FAIL;
    }

    // Build the KERB_CERTIFICATE_LOGON blob (uses m_sessionData.containerName/providerName/keySpec)
    BYTE* pb = nullptr; DWORD cb = 0;
    HRESULT hr = BuildKerbCertificateLogon(&pb, &cb);
    if (FAILED(hr) || !pb || !cb)
    {
        LogDebugMessage(L"BuildKerbCertificateLogon failed: hr=0x%08X", hr);
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return FAILED(hr) ? hr : E_FAIL;
    }

    ZeroMemory(pcpcs, sizeof(*pcpcs));
    pcpcs->rgbSerialization = pb;
    pcpcs->cbSerialization = cb;

    // Use Negotiate — it will route to Kerberos for KERB_CERTIFICATE_LOGON
    //hr = RetrieveNegotiateAuthPackage(&pcpcs->ulAuthenticationPackage);
    hr = RetrieveKerberosAuthPackage(&pcpcs->ulAuthenticationPackage);

    if (FAILED(hr))
    {
        LogDebugMessage(L"RetrieveNegotiateAuthPackage failed: hr=0x%08X", hr);
        CoTaskMemFree(pb);
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return hr;
    }

    pcpcs->clsidCredentialProvider = CLSID_RDPQRProvider;
    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

    LogDebugMessage(L"✅ Returning certificate credential (size=%lu) via Negotiate", cb);
    return S_OK;
}


HRESULT CCredential::CreateAuthSession()
{
    if (m_pAuthClient == nullptr)
    {
        m_statusText = RDPQR_STATUS_ERROR;
        return E_FAIL;
    }

    LogDebugMessage(L"Creating authentication session...");
    
    // Update UI immediately with loading state - user sees feedback right away
    m_statusText = RDPQR_STATUS_INITIALIZING;
    if (m_pCredProvCredentialEvents)
    {
        m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        LogDebugMessage(L"  UI updated with initializing status");
    }

    // CreateSession will automatically get token if needed
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

                LogDebugMessage(L"  UI updated with QR code");
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
        if (hr == HRESULT_FROM_WIN32(ERROR_WINHTTP_CANNOT_CONNECT) || 
            hr == HRESULT_FROM_WIN32(ERROR_WINHTTP_TIMEOUT))
        {
            m_statusText = RDPQR_STATUS_ERROR_CONNECTION;
        }
        else if (hr == E_ACCESSDENIED || hr == HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE))
        {
            m_statusText = RDPQR_STATUS_ERROR_TOKEN;
        }
        else
        {
            m_statusText = RDPQR_STATUS_ERROR_SESSION;
        }
        
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        }
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

    StopPolling();

    // Validate PIN before proceeding
    if (m_sessionData.vscPin.empty())
    {
        LogDebugMessage(L"ERROR: vsc_pin is empty or not received from server");
        m_statusText = RDPQR_STATUS_ERROR_PIN;
        m_bAuthenticationComplete = false;
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        }
        return;
    }

    // Validate PIN is exactly 8 digits
    if (m_sessionData.vscPin.length() != 8)
    {
        LogDebugMessage(L"ERROR: vsc_pin length is %d, expected 8 digits", (int)m_sessionData.vscPin.length());
        m_statusText = RDPQR_STATUS_ERROR_PIN;
        m_bAuthenticationComplete = false;
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        }
        return;
    }

    // Validate PIN contains only digits
    bool allDigits = true;
    for (size_t i = 0; i < m_sessionData.vscPin.length(); i++)
    {
        if (m_sessionData.vscPin[i] < L'0' || m_sessionData.vscPin[i] > L'9')
        {
            allDigits = false;
            break;
        }
    }

    if (!allDigits)
    {
        LogDebugMessage(L"ERROR: vsc_pin contains non-digit characters");
        m_statusText = RDPQR_STATUS_ERROR_PIN;
        m_bAuthenticationComplete = false;
        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        }
        return;
    }

    LogDebugMessage(L"PIN validation passed: %s", m_sessionData.vscPin.c_str());

    // ✅ CALL THIS to fetch certificate
    HRESULT hr = HandleAuthenticationSuccess();

    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to handle authentication success: hr=0x%08X", hr);
        m_statusText = RDPQR_STATUS_ERROR;
        m_bAuthenticationComplete = false;

        if (m_pCredProvCredentialEvents)
        {
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        }
        return;
    }

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
// REPLACE HandleAuthenticationSuccess(): switch to PFX import + status updates
HRESULT CCredential::HandleAuthenticationSuccess()
{
    LogDebugMessage(L"=== Authentication Success ===");

#if RDPQR_IMPORT_PFX_AT_RUNTIME
    // Old path: fetch PFX from server and import
    m_statusText = RDPQR_STATUS_AUTHENTICATED;
    if (m_pCredProvCredentialEvents)
        m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());

    HRESULT hr = FetchCertificateFromAuthServer();
    if (FAILED(hr)) {
        LogDebugMessage(L"Failed to fetch/import PFX: hr=0x%08X", hr);
        m_statusText = RDPQR_STATUS_ERROR;
        if (m_pCredProvCredentialEvents)
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        return hr;
    }
#else
    // New path: use smart card key (VSC over RDP) via Smart Card KSP, not LocalMachine\MY

    // Derive a UPN to search. Prefer m_sessionData.username; fall back if needed.
    std::wstring upn = m_sessionData.username;
    if (upn.find(L'@') == std::wstring::npos)
    {
        // convert DOMAIN\user -> user@securitaas.com (adjust suffix to your real UPN suffix)
        auto bs = upn.find(L'\\');
        if (bs != std::wstring::npos)
            upn = upn.substr(bs + 1) + L"@securitaas.com";
    }

    PCCERT_CONTEXT pCtx = nullptr;
    std::wstring container;
    std::wstring provider;
    DWORD        keySpec = 0;

    HRESULT hr = FindSmartCardKeyByUPN(upn, container, provider, keySpec, &pCtx);
    if (FAILED(hr))
    {
        LogDebugMessage(L"No smart card key found for UPN '%s' via Smart Card KSP (hr=0x%08X)",
            upn.c_str(), hr);
        m_statusText = RDPQR_STATUS_ERROR;
        if (m_pCredProvCredentialEvents)
            m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
        return hr;
    }

    // Fill session data from smart card key
    m_sessionData.containerName = container;
    m_sessionData.providerName = provider;
    m_sessionData.keySpec = keySpec;
    m_sessionData.pCertContext = pCtx;
    m_sessionData.hCertStore = NULL;  // cert is from the key; no LM\MY store

    LogDebugMessage(L"Using SMARTCARD/VSC key - Container: %s, Provider: %s, KeySpec: %lu",
        m_sessionData.containerName.c_str(),
        m_sessionData.providerName.c_str(),
        m_sessionData.keySpec);

    m_statusText = RDPQR_STATUS_SUCCESS;
    if (m_pCredProvCredentialEvents)
        m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());
#endif

    m_bAuthenticationComplete = true;
    if (m_pCredProvCredentialEvents)
        m_pCredProvCredentialEvents->SetFieldString(this, RDPQR_FI_STATUS_TEXT, m_statusText.c_str());

    LogDebugMessage(L"✅ Ready to serialize Kerb cert logon");
    return S_OK;
}




// FIX for Credential.cpp - Replace FetchCertificateFromAuthServer() method

// MODIFY FetchCertificateFromAuthServer to also fetch PIN:
HRESULT CCredential::FetchCertificateFromAuthServer()
{
    LogDebugMessage(L"Fetching certificate from auth server...");

    if (!m_pAuthClient)
    {
        return E_FAIL;
    }

    // Call GET /api/session/<session_id>
    std::wstring sessionUrl = L"/api/session/";
    sessionUrl += m_sessionData.sessionId;

    std::wstring response;
    HRESULT hr = m_pAuthClient->HttpRequest(L"GET", sessionUrl.c_str(), nullptr, response);

    if (FAILED(hr))
    {
        LogDebugMessage(L"HTTP request failed: hr=0x%08X", hr);
        return hr;
    }

    LogDebugMessage(L"Auth server response received");

    // Extract certificate
    size_t certPos = response.find(L"\"certificate\"");
    if (certPos == std::wstring::npos)
    {
        LogDebugMessage(L"No certificate field in response");
        return E_FAIL;
    }

    std::wstring pkcs12Wide;
    hr = m_pAuthClient->ParseJsonString(response, L"pkcs12", pkcs12Wide);

    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to parse pkcs12 field");
        return hr;
    }

    // Convert to narrow string
    int size = WideCharToMultiByte(CP_UTF8, 0, pkcs12Wide.c_str(), -1, NULL, 0, NULL, NULL);
    if (size <= 0) return E_FAIL;

    m_sessionData.pkcs12Base64.resize(size);
    WideCharToMultiByte(CP_UTF8, 0, pkcs12Wide.c_str(), -1, &m_sessionData.pkcs12Base64[0], size, NULL, NULL);

    if (!m_sessionData.pkcs12Base64.empty() && m_sessionData.pkcs12Base64.back() == '\0')
    {
        m_sessionData.pkcs12Base64.pop_back();
    }

    LogDebugMessage(L"PKCS12 data extracted, length: %d", m_sessionData.pkcs12Base64.length());

  

    // Extract domain
    if (!m_sessionData.username.empty())
    {
        size_t backslashPos = m_sessionData.username.find(L'\\');
        if (backslashPos != std::wstring::npos)
        {
            m_sessionData.domain = m_sessionData.username.substr(0, backslashPos);
            //LogDebugMessage(L"Extracted domain: %s", m_sessionData.domain.c_str());
            LogDebugMessage(L"Domain: %s", m_sessionData.domain.empty() ? L"(empty)" : m_sessionData.domain.c_str());
        }
        else
        {
            m_sessionData.domain = L".";
            LogDebugMessage(L"No domain in username, using workgroup mode");
        }
    }

    // Import certificate
    hr = ImportPFXCertificate(m_sessionData.pkcs12Base64, &m_sessionData.pCertContext);

    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to import certificate: hr=0x%08X", hr);
        return hr;
    }

    LogDebugMessage(L"Certificate imported successfully");

    // Get container info
    hr = GetCertificateContainerInfo(
        m_sessionData.pCertContext,
        m_sessionData.containerName,
        m_sessionData.providerName,
        m_sessionData.keySpec
    );

    if (FAILED(hr))
    {
        LogDebugMessage(L"Failed to get container info: hr=0x%08X", hr);
        return hr;
    }

    LogDebugMessage(L"Certificate ready - Container: %s, Provider: %s",
        m_sessionData.containerName.c_str(),
        m_sessionData.providerName.c_str());

    return S_OK;
}
HRESULT CCredential::ImportPFXCertificate(const std::string& pkcs12Base64, PCCERT_CONTEXT* ppCertContext)
{
    LogDebugMessage(L"Importing PFX certificate...");

    // Base64 decode
    DWORD decodedLen = 0;
    if (!CryptStringToBinaryA(pkcs12Base64.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL))
    {
        DWORD err = GetLastError();
        LogDebugMessage(L"CryptStringToBinaryA size failed: %d", err);
        return HRESULT_FROM_WIN32(err);
    }

    std::vector<BYTE> pfxData(decodedLen);
    if (!CryptStringToBinaryA(pkcs12Base64.c_str(), 0, CRYPT_STRING_BASE64, pfxData.data(), &decodedLen, NULL, NULL))
    {
        DWORD err = GetLastError();
        LogDebugMessage(L"CryptStringToBinaryA decode failed: %d", err);
        return HRESULT_FROM_WIN32(err);
    }

    LogDebugMessage(L"Base64 decoded, size: %d bytes", decodedLen);

    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = decodedLen;
    pfxBlob.pbData = pfxData.data();

    //DWORD dwFlags = CRYPT_EXPORTABLE | CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_INCLUDE_EXTENDED_PROPERTIES;
    DWORD dwFlags = CRYPT_EXPORTABLE | CRYPT_MACHINE_KEYSET;
    LogDebugMessage(L"Importing with flags: 0x%08X", dwFlags);

    // Step 1: Import to temporary in-memory store
    HCERTSTORE hTempStore = PFXImportCertStore(&pfxBlob, L"", dwFlags);
    if (!hTempStore)
    {
        DWORD err = GetLastError();
        LogDebugMessage(L"PFXImportCertStore failed: %d", err);
        return HRESULT_FROM_WIN32(err);
    }

    LogDebugMessage(L"PFX imported to temporary store");

    // Step 2: Find certificate with private key in temp store
    PCCERT_CONTEXT pCertContext = NULL;
    PCCERT_CONTEXT pCertWithKey = NULL;

    while ((pCertContext = CertEnumCertificatesInStore(hTempStore, pCertContext)) != NULL)
    {
        DWORD cbData = 0;

        // Check for CERT_KEY_PROV_INFO_PROP_ID (normal case)
        if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbData))
        {
            LogDebugMessage(L"Found certificate with CERT_KEY_PROV_INFO_PROP_ID");
            pCertWithKey = CertDuplicateCertificateContext(pCertContext);
            break;
        }

        // Check for CERT_KEY_CONTEXT_PROP_ID (ephemeral case)
        cbData = 0;
        if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, NULL, &cbData))
        {
            LogDebugMessage(L"Found certificate with CERT_KEY_CONTEXT_PROP_ID");
            pCertWithKey = CertDuplicateCertificateContext(pCertContext);
            break;
        }

        LogDebugMessage(L"Certificate has no private key property, checking next...");
    }

    if (!pCertWithKey)
    {
        LogDebugMessage(L"No certificate with private key found in PFX!");
        CertCloseStore(hTempStore, 0);
        return E_FAIL;
    }

    // Step 3: ✅ CRITICAL FIX - Open Current User MY store
    HCERTSTORE hMyStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        L"MY"
    );

    if (!hMyStore)
    {
        DWORD err = GetLastError();
        LogDebugMessage(L"Failed to open CurrentUser\\MY store: %d", err);
        CertFreeCertificateContext(pCertWithKey);
        CertCloseStore(hTempStore, 0);
        return HRESULT_FROM_WIN32(err);
    }

    LogDebugMessage(L"Opened LocalMachine\\MY store");

    // Step 4: ✅ CRITICAL FIX - Add certificate to MY store (this makes it accessible to LSA)
    PCCERT_CONTEXT pCertInMyStore = NULL;
    if (!CertAddCertificateContextToStore(
        hMyStore,
        pCertWithKey,
        CERT_STORE_ADD_REPLACE_EXISTING,
        &pCertInMyStore))
    {
        DWORD err = GetLastError();
        LogDebugMessage(L"Failed to add certificate to MY store: %d", err);
        CertFreeCertificateContext(pCertWithKey);
        CertCloseStore(hMyStore, 0);
        CertCloseStore(hTempStore, 0);
        return HRESULT_FROM_WIN32(err);
    }

    LogDebugMessage(L"✅ Certificate added to LocalMachine\\MY store (accessible to LSA)");
    // ✅ ADD VALIDATION - Check for identity extension
    PCERT_EXTENSION pExtUPN = CertFindExtension(
        szOID_NT_PRINCIPAL_NAME,  // UPN extension
        pCertInMyStore->pCertInfo->cExtension,
        pCertInMyStore->pCertInfo->rgExtension
    );

    PCERT_EXTENSION pExtSAN = CertFindExtension(
        szOID_SUBJECT_ALT_NAME2,  // Subject Alternative Name
        pCertInMyStore->pCertInfo->cExtension,
        pCertInMyStore->pCertInfo->rgExtension
    );

    if (!pExtUPN && !pExtSAN)
    {
        LogDebugMessage(L"⚠️ Warning: Certificate has no UPN/SAN extension");
        LogDebugMessage(L"⚠️ Certificate must be explicitly mapped in AD");
    }
    else
    {
        if (pExtUPN) LogDebugMessage(L"✅ Certificate has UPN extension");
        if (pExtSAN) LogDebugMessage(L"✅ Certificate has SAN extension");
    }

    // ✅ Certificate has SAN extension
    if (pExtSAN)
    {
        LogDebugMessage(L"✅ Certificate has SAN extension");

        // ✅ ADD THIS - Decode and log the SAN contents
        DWORD cbSAN = 0;
        if (CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            szOID_SUBJECT_ALT_NAME2,
            pExtSAN->Value.pbData,
            pExtSAN->Value.cbData,
            CRYPT_DECODE_ALLOC_FLAG,
            NULL,
            &cbSAN,
            &cbSAN))
        {
            PCERT_ALT_NAME_INFO pAltName = (PCERT_ALT_NAME_INFO)LocalAlloc(LPTR, cbSAN);
            if (pAltName && CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                szOID_SUBJECT_ALT_NAME2,
                pExtSAN->Value.pbData,
                pExtSAN->Value.cbData,
                0,
                NULL,
                pAltName,
                &cbSAN))
            {
                for (DWORD i = 0; i < pAltName->cAltEntry; i++)
                {
                    if (pAltName->rgAltEntry[i].dwAltNameChoice == CERT_ALT_NAME_OTHER_NAME)
                    {
                        // Check for UPN
                        PCERT_OTHER_NAME pOtherName = pAltName->rgAltEntry[i].pOtherName;
                        if (strcmp(pOtherName->pszObjId, szOID_NT_PRINCIPAL_NAME) == 0)
                        {
                            // Decode UPN value
                            DWORD cbUPN = 0;
                            CERT_NAME_VALUE* pUPN = NULL;
                            if (CryptDecodeObjectEx(
                                X509_ASN_ENCODING,
                                X509_UNICODE_ANY_STRING,
                                pOtherName->Value.pbData,
                                pOtherName->Value.cbData,
                                CRYPT_DECODE_ALLOC_FLAG,
                                NULL,
                                &pUPN,
                                &cbUPN))
                            {
                                LogDebugMessage(L"✅ Certificate UPN: %s", (WCHAR*)pUPN->Value.pbData);
                                LocalFree(pUPN);
                            }
                        }
                    }
                }
                LocalFree(pAltName);
            }
        }
    }
    // Step 5: ✅ CRITICAL - Grant SYSTEM and NETWORK SERVICE access to private key
    LogDebugMessage(L"Setting private key permissions for LSA access...");

    // Get the private key container name from the certificate
    DWORD cbData = 0;
    if (CertGetCertificateContextProperty(pCertInMyStore, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbData))
    {
        std::vector<BYTE> keyProvInfo(cbData);
        if (CertGetCertificateContextProperty(pCertInMyStore, CERT_KEY_PROV_INFO_PROP_ID, keyProvInfo.data(), &cbData))
        {
            CRYPT_KEY_PROV_INFO* pKeyInfo = (CRYPT_KEY_PROV_INFO*)keyProvInfo.data();

            // Open the key container
            HCRYPTPROV hProv = 0;
            if (CryptAcquireContextW(&hProv, pKeyInfo->pwszContainerName, pKeyInfo->pwszProvName,
                pKeyInfo->dwProvType, CRYPT_MACHINE_KEYSET | CRYPT_SILENT))
            {
                LogDebugMessage(L"Acquired key container for permission update");

                // Get current security descriptor size
                DWORD dwSDSize = 0;
                CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, NULL, &dwSDSize, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);

                if (dwSDSize > 0)
                {
                    std::vector<BYTE> sdBuffer(dwSDSize);
                    if (CryptGetProvParam(hProv, PP_KEYSET_SEC_DESCR, sdBuffer.data(), &dwSDSize, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION))
                    {
                        PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)sdBuffer.data();

                        // Get existing DACL
                        PACL pOldDacl = NULL;
                        BOOL bDaclPresent = FALSE;
                        BOOL bDaclDefaulted = FALSE;

                        if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pOldDacl, &bDaclDefaulted))
                        {
                            // Create SIDs for SYSTEM and NETWORK SERVICE
                            SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
                            PSID pSystemSid = NULL;
                            PSID pNetworkServiceSid = NULL;

                            AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid);
                            AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_NETWORK_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &pNetworkServiceSid);

                            if (pSystemSid && pNetworkServiceSid)
                            {
                                // Set up explicit access for SYSTEM and NETWORK SERVICE
                                EXPLICIT_ACCESS ea[2] = { 0 };

                                // SYSTEM - Full access
                                ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
                                ea[0].grfAccessMode = GRANT_ACCESS;
                                ea[0].grfInheritance = NO_INHERITANCE;
                                ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
                                ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
                                ea[0].Trustee.ptstrName = (LPTSTR)pSystemSid;

                                // NETWORK SERVICE - Read and execute
                                ea[1].grfAccessPermissions = KEY_READ | KEY_EXECUTE;
                                ea[1].grfAccessMode = GRANT_ACCESS;
                                ea[1].grfInheritance = NO_INHERITANCE;
                                ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
                                ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
                                ea[1].Trustee.ptstrName = (LPTSTR)pNetworkServiceSid;

                                // Merge with existing ACL
                                PACL pNewDacl = NULL;
                                DWORD dwResult = SetEntriesInAcl(2, ea, pOldDacl, &pNewDacl);

                                if (dwResult == ERROR_SUCCESS && pNewDacl)
                                {
                                    // Create new security descriptor with updated DACL
                                    SECURITY_DESCRIPTOR newSD = { 0 };
                                    InitializeSecurityDescriptor(&newSD, SECURITY_DESCRIPTOR_REVISION);
                                    SetSecurityDescriptorDacl(&newSD, TRUE, pNewDacl, FALSE);

                                    // Apply new security descriptor to key
                                    if (CryptSetProvParam(hProv, PP_KEYSET_SEC_DESCR, (BYTE*)&newSD, DACL_SECURITY_INFORMATION))
                                    {
                                        LogDebugMessage(L"✅ Private key permissions set: SYSTEM + NETWORK SERVICE have access");
                                    }
                                    else
                                    {
                                        DWORD err = GetLastError();
                                        LogDebugMessage(L"Failed to set private key permissions: %d", err);
                                    }

                                    LocalFree(pNewDacl);
                                }
                            }

                            if (pSystemSid) FreeSid(pSystemSid);
                            if (pNetworkServiceSid) FreeSid(pNetworkServiceSid);
                        }
                    }
                }

                CryptReleaseContext(hProv, 0);
            }
            else
            {
                DWORD err = GetLastError();
                LogDebugMessage(L"Failed to acquire key container for permissions: %d", err);
            }
        }
    }

    // Clean up temp resources
    CertFreeCertificateContext(pCertWithKey);
    CertCloseStore(hTempStore, 0);

    // Step 5: Keep MY store open and return certificate from it
    m_sessionData.hCertStore = hMyStore;
    *ppCertContext = pCertInMyStore;

    LogDebugMessage(L"✅ Certificate with private key ready for authentication");

    return S_OK;
}

HRESULT CCredential::GetCertificateContainerInfo(
    PCCERT_CONTEXT pCertContext,
    std::wstring& containerName,
    std::wstring& providerName,
    DWORD& keySpec)
{
    LogDebugMessage(L"Getting certificate container info...");

    containerName.clear();
    providerName.clear();
    keySpec = 0;

#ifndef CERT_NCRYPT_KEY_SPEC
#define CERT_NCRYPT_KEY_SPEC ((DWORD)0xFFFFFFFF)
#endif

    // ---- Path 1: Use CERT_KEY_PROV_INFO_PROP_ID (authoritative) ----
    DWORD cb = 0;
    if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cb))
    {
        std::vector<BYTE> prov(cb);
        if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, prov.data(), &cb))
        {
            auto* p = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(prov.data());
            if (p->pwszProvName) providerName.assign(p->pwszProvName);
            if (p->pwszContainerName) containerName.assign(p->pwszContainerName);

            // KSP special case: treat dwKeySpec as CNG spec and confirm real key name
            if (_wcsicmp(providerName.c_str(), L"Microsoft Software Key Storage Provider") == 0)
            {
                // Acquire CNG handle
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
                DWORD ksTmp = 0; BOOL bFree = FALSE;
                if (CryptAcquireCertificatePrivateKey(
                    pCertContext,
                    CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
                    NULL, &hKey, &ksTmp, &bFree))
                {
                    // Prefer the NAME (not UNIQUE)
                    DWORD cbName = 0;
                    if (NCryptGetProperty(hKey, NCRYPT_NAME_PROPERTY, NULL, 0, &cbName, 0) == ERROR_SUCCESS && cbName)
                    {
                        std::vector<wchar_t> n(cbName / sizeof(wchar_t));
                        if (NCryptGetProperty(hKey, NCRYPT_NAME_PROPERTY, (PBYTE)n.data(), cbName, &cbName, 0) == ERROR_SUCCESS)
                            containerName.assign(n.data());
                    }
                    if (bFree) NCryptFreeObject(hKey);
                }

                // Verify the name we will return really opens
                auto CanOpenKspKey = [&](const std::wstring& name, DWORD flags)->bool {
                    NCRYPT_PROV_HANDLE hProv = 0; NCRYPT_KEY_HANDLE hK = 0;
                    if (NCryptOpenStorageProvider(&hProv, L"Microsoft Software Key Storage Provider", 0) != ERROR_SUCCESS)
                        return false;
                    SECURITY_STATUS ss = NCryptOpenKey(hProv, &hK, name.c_str(), 0, flags);
                    if (ss != ERROR_SUCCESS && (flags & NCRYPT_MACHINE_KEY_FLAG))
                        ss = NCryptOpenKey(hProv, &hK, name.c_str(), 0, 0);
                    if (ss == ERROR_SUCCESS) { NCryptFreeObject(hK); NCryptFreeObject(hProv); return true; }
                    NCryptFreeObject(hProv);
                    return false;
                    };

                // Try: NAME -> simple (from CRYPT_KEY_PROV_INFO) -> UNIQUE
                std::wstring name_ncrypt = containerName;      // may be empty if NAME property missing
                std::wstring name_simple = p->pwszContainerName ? p->pwszContainerName : L"";
                std::wstring name_unique;

                // Try to fetch UNIQUE for last resort
                {
                    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0; DWORD ks = 0; BOOL bFree = FALSE;
                    if (CryptAcquireCertificatePrivateKey(
                        pCertContext,
                        CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
                        NULL, &hKey, &ks, &bFree))
                    {
                        DWORD cbUni = 0;
                        if (NCryptGetProperty(hKey, NCRYPT_UNIQUE_NAME_PROPERTY, NULL, 0, &cbUni, 0) == ERROR_SUCCESS && cbUni)
                        {
                            std::vector<wchar_t> u(cbUni / sizeof(wchar_t));
                            if (NCryptGetProperty(hKey, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)u.data(), cbUni, &cbUni, 0) == ERROR_SUCCESS)
                                name_unique.assign(u.data());
                        }
                        if (bFree) NCryptFreeObject(hKey);
                    }
                }

                const DWORD scopeFlag = NCRYPT_MACHINE_KEY_FLAG; // you used MachineKeySet=TRUE
                std::wstring chosen;

                if (!name_ncrypt.empty() && CanOpenKspKey(name_ncrypt, scopeFlag))
                    chosen = name_ncrypt;
                else if (!name_simple.empty() && CanOpenKspKey(name_simple, scopeFlag))
                    chosen = name_simple;
                else if (!name_unique.empty() && CanOpenKspKey(name_unique, scopeFlag))
                    chosen = name_unique;

                if (!chosen.empty())
                {
                    containerName = chosen;
                    keySpec = CERT_NCRYPT_KEY_SPEC; // KSP must be -1
                    LogDebugMessage(L"✅ KSP resolved: Container='%s', Provider='%s'", containerName.c_str(), providerName.c_str());
                    return S_OK;
                }

                LogDebugMessage(L"❌ KSP name resolution failed: NAME='%s' SIMPLE='%s' UNIQUE='%s'",
                    name_ncrypt.c_str(), name_simple.c_str(), name_unique.c_str());
                // fall through to global fallback
            }
            else
            {
                // Legacy CSP path: honor dwKeySpec (1/2) and simple names
                keySpec = p->dwKeySpec;
                LogDebugMessage(L"CSP via CRYPT_KEY_PROV_INFO: Container='%s', Provider='%s', KeySpec=%lu",
                    containerName.c_str(), providerName.c_str(), keySpec);
                if (!containerName.empty() && !providerName.empty() && keySpec)
                    return S_OK;
            }
        }
    }

    // ---- Path 2: Fallback – probe the live key handle ----
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
    DWORD dwKeySpec = 0; BOOL bFree = FALSE;

    if (!CryptAcquireCertificatePrivateKey(
        pCertContext,
        CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
        NULL, &hKey, &dwKeySpec, &bFree))
    {
        DWORD err = GetLastError();
        LogDebugMessage(L"CryptAcquireCertificatePrivateKey failed: %lu", err);
        return HRESULT_FROM_WIN32(err);
    }

    HRESULT hr = S_OK;

    if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
    {
        // CNG fallback: prefer NAME
        DWORD cbName = 0;
        if (NCryptGetProperty(hKey, NCRYPT_NAME_PROPERTY, NULL, 0, &cbName, 0) == ERROR_SUCCESS && cbName)
        {
            std::vector<wchar_t> name(cbName / sizeof(wchar_t));
            if (NCryptGetProperty(hKey, NCRYPT_NAME_PROPERTY, (PBYTE)name.data(), cbName, &cbName, 0) == ERROR_SUCCESS)
                containerName.assign(name.data());
        }

        // Provider display name
        DWORD cbProv = 0;
        if (NCryptGetProperty(hKey, NCRYPT_PROVIDER_HANDLE_PROPERTY, NULL, 0, &cbProv, 0) == ERROR_SUCCESS)
        {
            std::vector<BYTE> pbuf(cbProv);
            if (NCryptGetProperty(hKey, NCRYPT_PROVIDER_HANDLE_PROPERTY, pbuf.data(), cbProv, &cbProv, 0) == ERROR_SUCCESS)
            {
                NCRYPT_PROV_HANDLE hProv = *reinterpret_cast<NCRYPT_PROV_HANDLE*>(pbuf.data());
                DWORD cbProvName = 0;
                if (NCryptGetProperty(hProv, NCRYPT_NAME_PROPERTY, NULL, 0, &cbProvName, 0) == ERROR_SUCCESS && cbProvName)
                {
                    std::vector<wchar_t> provName(cbProvName / sizeof(wchar_t));
                    if (NCryptGetProperty(hProv, NCRYPT_NAME_PROPERTY, (PBYTE)provName.data(), cbProvName, &cbProvName, 0) == ERROR_SUCCESS)
                        providerName.assign(provName.data());
                }
            }
        }

        if (bFree) NCryptFreeObject(hKey);
        keySpec = CERT_NCRYPT_KEY_SPEC;

        LogDebugMessage(L"CNG fallback: Container(Name)='%s', Provider='%s'", containerName.c_str(), providerName.c_str());
    }
    else
    {
        // Legacy CSP fallback: PP_CONTAINER/PP_NAME (ANSI -> wide)
        DWORD cbProp = 0;

        if (CryptGetProvParam((HCRYPTPROV)hKey, PP_CONTAINER, NULL, &cbProp, 0))
        {
            std::string a; a.resize(cbProp);
            if (CryptGetProvParam((HCRYPTPROV)hKey, PP_CONTAINER, reinterpret_cast<BYTE*>(&a[0]), &cbProp, 0))
                containerName.assign(a.begin(), a.end());
        }

        cbProp = 0;
        if (CryptGetProvParam((HCRYPTPROV)hKey, PP_NAME, NULL, &cbProp, 0))
        {
            std::string a; a.resize(cbProp);
            if (CryptGetProvParam((HCRYPTPROV)hKey, PP_NAME, reinterpret_cast<BYTE*>(&a[0]), &cbProp, 0))
                providerName.assign(a.begin(), a.end());
        }

        if (bFree) CryptReleaseContext((HCRYPTPROV)hKey, 0);
        keySpec = dwKeySpec;

        LogDebugMessage(L"CSP fallback: Container='%s', Provider='%s', KeySpec=%lu",
            containerName.c_str(), providerName.c_str(), keySpec);
    }

    if (containerName.empty() || providerName.empty() || keySpec == 0)
    {
        LogDebugMessage(L"Failed to resolve container/provider/keyspec from fallback path");
        return E_FAIL;
    }

    return S_OK;
}



HRESULT CCredential::BuildKerbCertificateLogon(BYTE** ppbBuffer, DWORD* pcbBuffer)
{
    LogDebugMessage(L"Building KERB_CERTIFICATE_LOGON structure...");
    LogDebugMessage(L"Scenario: %d (%s)", m_cpus,
        (m_cpus == CPUS_UNLOCK_WORKSTATION) ? L"UNLOCK" : L"LOGON");
    LogDebugMessage(L"Username: %s", ObfuscateString(m_sessionData.username, 6).c_str());
    LogDebugMessage(L"Container: %s", m_sessionData.containerName.c_str());
    LogDebugMessage(L"Provider: %s", m_sessionData.providerName.c_str());
    LogDebugMessage(L"KeySpec: %d", m_sessionData.keySpec);

    // sizes (WCHAR lengths in BYTES)
    const DWORD cbCardName = sizeof(WCHAR); // empty + NUL
    const DWORD cbReaderName = sizeof(WCHAR); // empty + NUL
    const DWORD cbContainer = (DWORD)((m_sessionData.containerName.length() + 1) * sizeof(WCHAR));
    const DWORD cbProvider = (DWORD)((m_sessionData.providerName.length() + 1) * sizeof(WCHAR));

    // Worst-case reserve: struct + 3 empty WCHARs + CSP header + all strings
    const BOOL  bUnlock = (m_cpus == CPUS_UNLOCK_WORKSTATION);
    const DWORD cbStruct = bUnlock ? sizeof(KERB_CERTIFICATE_UNLOCK_LOGON)
        : sizeof(KERB_CERTIFICATE_LOGON);
    const DWORD cbCspMax = (DWORD)offsetof(KERB_SMARTCARD_CSP_INFO, bBuffer)
        + cbCardName + cbReaderName + cbContainer + cbProvider;

    /*const DWORD cbReserve = cbStruct
        + (3 * sizeof(WCHAR)) // 3 empty strings (Domain/User/Pin)
        + cbCspMax;*/

    // Get PIN from session data (from authentication response)
    // PIN should already be validated in OnAuthenticationComplete()
    std::wstring pinStr = m_sessionData.vscPin;
    if (pinStr.empty() || pinStr.length() != 8)
    {
        LogDebugMessage(L"ERROR: Invalid PIN in GetSerialization - this should not happen");
        return E_FAIL;
    }
    const DWORD cbPin = (DWORD)((pinStr.length() + 1) * sizeof(WCHAR));

    const DWORD cbReserve = cbStruct
        + (2 * sizeof(WCHAR)) // empty Domain + empty User
        + cbPin               // non-empty PIN
        + cbCspMax;

    BYTE* base = (BYTE*)CoTaskMemAlloc(cbReserve);
    if (!base) return E_OUTOFMEMORY;
    ZeroMemory(base, cbReserve);

    BYTE* cur = base + cbStruct;

    // Handle both scenarios
    KERB_CERTIFICATE_LOGON* pLogon = nullptr;
    if (bUnlock)
    {
        auto* pUnlock = (KERB_CERTIFICATE_UNLOCK_LOGON*)base;

        // Prefer your LSA enumeration helper here. If you still call
        // GetActiveSessionLogonLuid, keep it — but enumeration is more robust.
        LUID luid{};
        HRESULT hrLuid = GetActiveSessionLogonLuid(&luid);
        if (FAILED(hrLuid)) { CoTaskMemFree(base); return hrLuid; }
        pUnlock->LogonId = luid;

        pLogon = &pUnlock->Logon;
        LogDebugMessage(L"Using UNLOCK structure with LogonId: 0x%08X:0x%08X",
            pUnlock->LogonId.HighPart, pUnlock->LogonId.LowPart);
    }
    else
    {
        pLogon = (KERB_CERTIFICATE_LOGON*)base;
        LogDebugMessage(L"Using LOGON structure");
    }

    // Outer header
    pLogon->MessageType = KerbCertificateLogon;

    // Helper to push an empty UNICODE_STRING as a RELATIVE offset (2-byte aligned)
    auto PushEmpty = [&](UNICODE_STRING* us)
        {
            *(WCHAR*)cur = L'\0';
            us->Length = 0;
            us->MaximumLength = sizeof(WCHAR);
            us->Buffer = (PWSTR)(cur - base);   // RELATIVE offset
            cur += sizeof(WCHAR);
        };

    auto PushString = [&](UNICODE_STRING* us, const std::wstring& s)
        {
            const size_t cch = s.length();
            const USHORT cbLen = (USHORT)(cch * sizeof(WCHAR));
            const USHORT cbMax = (USHORT)((cch + 1) * sizeof(WCHAR));

            us->Length = cbLen;
            us->MaximumLength = cbMax;
            us->Buffer = (PWSTR)(cur - base);   // RELATIVE offset

            memcpy(cur, s.c_str(), cbLen);
            ((WCHAR*)cur)[cch] = L'\0';
            cur += cbMax;
        };


    // Domain/User/Pin are empty for cert logon (UPN/SID mapping is used)
    // Domain & User omitted – KDC will use certificate mapping (UPN/SID)
    PushEmpty(&pLogon->DomainName);
    PushEmpty(&pLogon->UserName);

    // PIN comes from our hardcoded value (instead of LogonUI textbox)
    LogDebugMessage(L"Filling KERB_CERTIFICATE_LOGON.Pin with hardcoded PIN (len=%d)",
        (int)pinStr.length());
    PushString(&pLogon->Pin, pinStr);
    ;
    
    // CSP data begins here (MUST be a RELATIVE offset)
    pLogon->CspData = (PUCHAR)(cur - base);
    //const DWORD KERB_CSP_FLAG_MACHINE_KEYSET = 0x20;
    // ---- Build KERB_SMARTCARD_CSP_INFO with character offsets ----
    auto* csp = (KERB_SMARTCARD_CSP_INFO*)cur;
    csp->MessageType = 1;                   // REQUIRED for CSP info block
    csp->ContextInformation = NULL;
    csp->flags = 0;
    // KeySpec MUST be exactly what CryptAcquireCertificatePrivateKey returned:
//  - 1 or 2 for legacy CSP keys
//  - CERT_NCRYPT_KEY_SPEC (0xFFFFFFFF) for CNG keys
    csp->KeySpec = m_sessionData.keySpec;
    LogDebugMessage(L"Building CSP: Provider=%s, Container=%s, KeySpec=%d, Flags=0x%08X",
        m_sessionData.providerName.c_str(),
        m_sessionData.containerName.c_str(),
        m_sessionData.keySpec,
        0);
    /*
    WCHAR* w = csp->bBuffer;
    size_t offChars = 0;                            // offsets are in WCHARs

    // Card name (empty string)
    
    csp->nCardNameOffset = (ULONG)offChars;
    *w++ = L'\0'; offChars += 1;

    // Reader name (empty string)
    csp->nReaderNameOffset = (ULONG)offChars;
    *w++ = L'\0'; offChars += 1;

    // Container name (MUST NOT be empty)
    csp->nContainerNameOffset = (ULONG)offChars;
    const size_t contChars = m_sessionData.containerName.length() + 1; // incl NUL
    wcscpy_s(w, contChars, m_sessionData.containerName.c_str());
    w += contChars;
    offChars += contChars;

    // Provider name
    csp->nCSPNameOffset = (ULONG)offChars;
    const size_t provChars = m_sessionData.providerName.length() + 1;  // incl NUL
    wcscpy_s(w, provChars, m_sessionData.providerName.c_str());
    w += provChars;
    offChars += provChars;

    // Final sizes
    csp->dwCspInfoLen = (ULONG)((BYTE*)w - (BYTE*)csp); // BYTES written for CSP block
    pLogon->CspDataLength = csp->dwCspInfoLen;
    
    // advance end-of-blob pointer
    cur = (BYTE*)w;
    */
    WCHAR* pszBuffer = csp->bBuffer;
    ULONG offset = 0;

    // Card name (empty)
    csp->nCardNameOffset = offset;
    pszBuffer[offset++] = L'\0';

    // Reader name (empty)
    csp->nReaderNameOffset = offset;
    pszBuffer[offset++] = L'\0';

    // Container name
    csp->nContainerNameOffset = offset;
    wcscpy_s(&pszBuffer[offset],
        m_sessionData.containerName.length() + 1,
        m_sessionData.containerName.c_str());
    offset += (ULONG)(m_sessionData.containerName.length() + 1);

    // CSP name
    csp->nCSPNameOffset = offset;
    wcscpy_s(&pszBuffer[offset],
        m_sessionData.providerName.length() + 1,
        m_sessionData.providerName.c_str());
    offset += (ULONG)(m_sessionData.providerName.length() + 1);

    // dwCspInfoLen recompute:
    csp->dwCspInfoLen = (ULONG)(
        (BYTE*)(&pszBuffer[offset]) - (BYTE*)csp
        );
    pLogon->CspDataLength = csp->dwCspInfoLen;
    cur = (BYTE*)(&pszBuffer[offset]);

    *ppbBuffer = base;
    *pcbBuffer = (DWORD)(cur - base);

    LogDebugMessage(L"CSP Info built: len=%lu, nCard=%lu, nReader=%lu, nCont=%lu, nCSP=%lu",
        csp->dwCspInfoLen, csp->nCardNameOffset, csp->nReaderNameOffset,
        csp->nContainerNameOffset, csp->nCSPNameOffset);

    LogDebugMessage(L"Structure built successfully, size: %lu bytes", *pcbBuffer);
    return S_OK;
}


void CCredential::CleanupCertificate()
{
    if (m_sessionData.pCertContext)
    {
        CertFreeCertificateContext(m_sessionData.pCertContext);
        m_sessionData.pCertContext = nullptr;
    }

    // ✅ ADD THIS - Close the certificate store
    if (m_sessionData.hCertStore)
    {
        CertCloseStore(m_sessionData.hCertStore, 0);
        m_sessionData.hCertStore = NULL;
    }
}