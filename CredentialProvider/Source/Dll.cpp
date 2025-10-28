//
// Dll.cpp
// DLL implementation - entry points and registration
//

#include "Dll.h"
#include "ClassFactory.h"
#include "Provider.h"
#include <initguid.h>
// Define the GUID in this compilation unit
// {8B5C9F21-3A4D-4E2F-9C1B-7A8E6D5F4C3B}
DEFINE_GUID(CLSID_RDPQRProvider,
    0x8b5c9f21, 0x3a4d, 0x4e2f, 0x9c, 0x1b, 0x7a, 0x8e, 0x6d, 0x5f, 0x4c, 0x3b);
// Global DLL instance handle
HINSTANCE g_hInst = nullptr;

// DLL reference count for COM
static LONG g_cRef = 0;

BOOL WINAPI DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void*)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        g_hInst = hinstDll;
        LogDebugMessage(L"========================================");
        LogDebugMessage(L"DllMain - DLL_PROCESS_ATTACH");
        LogDebugMessage(L"DLL loaded into process");
        LogDebugMessage(L"TickCount: %lu", GetTickCount());
        LogDebugMessage(L"========================================");
        break;
        
    case DLL_PROCESS_DETACH:
        break;
    }
    
    return TRUE;
}

void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

STDAPI DllCanUnloadNow()
{
    HRESULT hr = (g_cRef > 0) ? S_FALSE : S_OK;
    LogDebugMessage(L"DllCanUnloadNow - RefCount=%ld, Result=%s", g_cRef, (hr == S_OK) ? L"Can unload" : L"Cannot unload");
    return hr;
}

STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;
    LogDebugMessage(L"========================================");
    LogDebugMessage(L"DllGetClassObject - Windows requesting class object");
    LogDebugMessage(L"========================================");
    if (CLSID_RDPQRProvider == rclsid)
    {
        CClassFactory* pClassFactory = new(std::nothrow) CClassFactory();
        if (pClassFactory)
        {
            hr = pClassFactory->QueryInterface(riid, ppv);
            pClassFactory->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    
    return hr;
}

STDAPI DllRegisterServer()
{
    HRESULT hr;
    LogDebugMessage(L"========================================");
    LogDebugMessage(L"DllRegisterServer - Registering credential provider");
    LogDebugMessage(L"========================================");
    WCHAR szModule[MAX_PATH];
    if (GetModuleFileNameW(g_hInst, szModule, ARRAYSIZE(szModule)) == 0)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    
    // Register CLSID
    WCHAR szCLSID[MAX_PATH];
    StringFromGUID2(CLSID_RDPQRProvider, szCLSID, ARRAYSIZE(szCLSID));
    
    WCHAR szSubkey[MAX_PATH];
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    
    hr = HRESULT_FROM_WIN32(RegSetKeyValueW(HKEY_CLASSES_ROOT, szSubkey, nullptr, REG_SZ, 
                                             L"RDP QR Credential Provider", sizeof(L"RDP QR Credential Provider")));
    if (FAILED(hr)) return hr;
    
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s\\InprocServer32", szCLSID);
    hr = HRESULT_FROM_WIN32(RegSetKeyValueW(HKEY_CLASSES_ROOT, szSubkey, nullptr, REG_SZ, 
                                             szModule, (DWORD)((wcslen(szModule) + 1) * sizeof(WCHAR))));
    if (FAILED(hr)) return hr;
    
    hr = HRESULT_FROM_WIN32(RegSetKeyValueW(HKEY_CLASSES_ROOT, szSubkey, L"ThreadingModel", REG_SZ,
                                             L"Apartment", sizeof(L"Apartment")));
    if (FAILED(hr)) return hr;
    
    // Register credential provider
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), 
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", szCLSID);
    hr = HRESULT_FROM_WIN32(RegSetKeyValueW(HKEY_LOCAL_MACHINE, szSubkey, nullptr, REG_SZ,
                                             L"RDP QR Credential Provider", sizeof(L"RDP QR Credential Provider")));
    
    if (SUCCEEDED(hr))
    {
        LogDebugMessage(L"========================================");
        LogDebugMessage(L"DllRegisterServer - SUCCESS");
        LogDebugMessage(L"========================================");
    }
    else
    {
        LogDebugMessage(L"========================================");
        LogDebugMessage(L"DllRegisterServer - FAILED: hr=0x%08X", hr);
        LogDebugMessage(L"========================================");
    }
    return hr;
}

STDAPI DllUnregisterServer()
{
    HRESULT hr;
    
    WCHAR szCLSID[MAX_PATH];
    StringFromGUID2(CLSID_RDPQRProvider, szCLSID, ARRAYSIZE(szCLSID));
    
    WCHAR szSubkey[MAX_PATH];
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey), L"CLSID\\%s", szCLSID);
    hr = HRESULT_FROM_WIN32(RegDeleteTreeW(HKEY_CLASSES_ROOT, szSubkey));
    
    StringCchPrintfW(szSubkey, ARRAYSIZE(szSubkey),
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", szCLSID);
    HRESULT hr2 = HRESULT_FROM_WIN32(RegDeleteTreeW(HKEY_LOCAL_MACHINE, szSubkey));
    
    return FAILED(hr) ? hr : hr2;
}
