//
// Credential.h
// Credential tile that displays QR code and handles authentication
//

#pragma once

#include "common.h"

class CProvider;
class AuthClient;
class CCommandWindow;

class CCredential : public ICredentialProviderCredential, public ICredentialProviderCredential2
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&m_cRef);
    }
    SessionData& GetSessionData() { return m_sessionData; }
    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&m_cRef);
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv);
    IFACEMETHODIMP GetUserSid(__deref_out LPWSTR* ppszSid);
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(__in ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(__out BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                  __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                  __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, __deref_out LPWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, __out HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, __out BOOL* pbChecked, __deref_out LPWSTR* ppwszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, __out DWORD* pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, __out DWORD* pcItems, __out DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, __deref_out LPWSTR* ppwszItem);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, __in LPCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                     __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                     __deref_out_opt LPWSTR* ppwszOptionalStatusText,
                                     __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                 NTSTATUS ntsSubstatus,
                                 __deref_out_opt LPWSTR* ppwszOptionalStatusText,
                                 __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       const FIELD_STATE_PAIR* rgfsp,
                       CProvider* pProvider);
    
    CCredential();

    // Called by CommandWindow when polling detects authentication
    void OnAuthenticationComplete();

private:
    virtual ~CCredential();
    
    HRESULT CreateAuthSession();
    HRESULT StartPolling();
    void StopPolling();
    HRESULT HandleAuthenticationSuccess();
    
private:
    LONG m_cRef;
    
    // Provider and usage scenario
    CProvider* m_pProvider;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    
    // Event interface for updating UI
    ICredentialProviderCredentialEvents* m_pCredProvCredentialEvents;
    
    // Field descriptors
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR m_rgFieldDescriptors[RDPQR_FI_NUM_FIELDS];
    FIELD_STATE_PAIR m_rgFieldStatePairs[RDPQR_FI_NUM_FIELDS];
    PWSTR m_rgFieldStrings[RDPQR_FI_NUM_FIELDS];
    
    // Authentication components
    AuthClient* m_pAuthClient;
    SessionData m_sessionData;
    HBITMAP m_hQRCodeBitmap;
    CCommandWindow* m_pCommandWindow;
    
    // Status tracking
    std::wstring m_statusText;
    bool m_bAuthenticationComplete;
    bool m_bPollingActive;
   
};
