//
// ClassFactory.h
// COM class factory for creating credential provider instances
//

#pragma once

#include "common.h"

class CClassFactory : public IClassFactory
{
public:
    // IUnknown
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // IClassFactory
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv);
    IFACEMETHODIMP LockServer(__in BOOL fLock);

    CClassFactory();

private:
    ~CClassFactory();
    LONG m_cRef;
};
