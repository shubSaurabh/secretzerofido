//
// ClassFactory.cpp
// Implementation of COM class factory
//

#include "ClassFactory.h"
#include "Provider.h"

CClassFactory::CClassFactory() : m_cRef(1)
{
    extern void DllAddRef();
}

CClassFactory::~CClassFactory()
{
    extern void DllRelease();
}

HRESULT CClassFactory::QueryInterface(__in REFIID riid, __deref_out void **ppv)
{
    HRESULT hr;
    
    if (ppv != nullptr)
    {
        if (IID_IClassFactory == riid || IID_IUnknown == riid)
        {
            *ppv = static_cast<IClassFactory*>(this);
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

ULONG CClassFactory::AddRef()
{
    return InterlockedIncrement(&m_cRef);
}

ULONG CClassFactory::Release()
{
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (!cRef)
    {
        delete this;
    }
    return cRef;
}

HRESULT CClassFactory::CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv)
{
    HRESULT hr;
    
    if (!pUnkOuter)
    {
        hr = CProvider_CreateInstance(riid, ppv);
    }
    else
    {
        hr = CLASS_E_NOAGGREGATION;
    }
    
    return hr;
}

HRESULT CClassFactory::LockServer(__in BOOL fLock)
{
    if (fLock)
    {
        extern void DllAddRef();
    }
    else
    {
        extern void DllRelease();
    }
    return S_OK;
}
