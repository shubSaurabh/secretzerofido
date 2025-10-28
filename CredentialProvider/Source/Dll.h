//
// Dll.h
// DLL exports and entry points
//

#pragma once

#include "common.h"

void DllAddRef();
void DllRelease();

// COM DLL exports
STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv);
STDAPI DllCanUnloadNow();
STDAPI DllRegisterServer();
STDAPI DllUnregisterServer();
