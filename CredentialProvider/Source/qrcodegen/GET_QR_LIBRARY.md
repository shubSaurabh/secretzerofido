# QR Code Generation Library

## Download Required

The QR code generation library is from **Project Nayuki** (MIT Licensed):
https://github.com/nayuki/QR-Code-generator

## Quick Download

```bash
cd CredentialProvider/Source/qrcodegen

# Download the C++ library files
curl -O https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/cpp/QrCode.hpp
curl -O https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/cpp/QrCode.cpp
```

## Or Manual Download

1. Go to: https://github.com/nayuki/QR-Code-generator/tree/master/cpp
2. Download `QrCode.hpp` (~400 lines)
3. Download `QrCode.cpp` (~800 lines)
4. Place both files in this directory

## Why This Library?

- ✅ Pure C++ (no dependencies)
- ✅ MIT Licensed (permissive)
- ✅ High quality, well-tested
- ✅ Generates QR codes of any size
- ✅ Used in production worldwide

## Integration

The library is already integrated in `AuthClient.cpp`:

```cpp
#include "qrcodegen/QrCode.hpp"
using namespace qrcodegen;

// Usage in AuthClient::GenerateQRCodeBitmap()
QrCode qr = QrCode::encodeText(utf8Data.c_str(), QrCode::Ecc::MEDIUM);
```

No additional configuration needed - just download and build!
